import os
import hashlib
import logging
import socket
import subprocess
import datetime
import time
import iptc
import psycopg2
import psutil
import signal
import re

# Configuracion del sistema de logeo
LOGS_DIR = '/var/log/hips'
ALARM_LOG_FILE = os.path.join(LOGS_DIR, 'alarmas.log')
PREVENTION_LOG_FILE = os.path.join(LOGS_DIR, 'prevencion.log')
USER_LOG_FILE = os.path.join(LOGS_DIR, 'usuarios.log')
CHECK_INTERVAL = 180
PREVENT_FILE = '/var/log/hips/prevention.log'

# Configuracion de la base de datos 

DB_NAME = "hips_database"
DB_USER = "hips_user"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_HOST = "localhost"
DB_PORT = "5432"
#Lista de herramientas de captura de paquetes 
packet_capture_tools = [
    {"name": "tcpdump", "uninstall_cmd": "apt-get remove tcpdump -y"},
    {"name": "wireshark", "uninstall_cmd": "apt-get remove wireshark -y"},
    {"name": "tshark", "uninstall_cmd": "apt-get remove tshark -y"},
    {"name": "ethereal", "uninstall_cmd": "apt-get remove ethereal -y"},
]

# Definir los binarios del sistema a ser monitoreados
system_binaries = [
    "/bin/ls",
    "/bin/ps",
    "/usr/bin/gcc",
    "usr/bin/passwd",
    "/bin/ping",
    "/bin/su",
    "/sbin/ifconfig"
    "/usr/bin/sudo"
    "/bin/mount"
    "/sbin/ip"
    # Agregar mas de binarios segun se necesite
]

# Definir archivos a monitorear 
files_to_monitor = [
    "/etc/shadow",
    "/etc/passwd"

    # Agregar mas segun sea necesario
]

# Lista de direcciones de correo electrónico a monitorear
monitored_email_addresses = ["sender@example.com", "another_sender@example.com"]

# Constants for tracking counts
AUTH_FAILURE_THRESHOLD = 10
EMAIL_THRESHOLD = 10

# Define the DDoS threshold
DDOS_THRESHOLD = 10
DDOS_TIME_WINDOW = 60  # 60 seconds (1 minute) time window

# Track occurrences of unique source IPs within a time window
ddos_ips = {}

# Dictionary to track counts for each IP address
ip_auth_failures = {}
ip_email_count = {}

def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash value of a file.
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read the file in chunks to avoid memory issues with large files
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()
def store_hash_in_db(connection, file_name, hash_value, table_name):
    print(f"hola insertado")
    query = f"INSERT INTO {table_name} (filename, hash, timestamp) VALUES (%s, %s, NOW())"
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, (file_name, hash_value))
        connection.commit()
        print(f"Hash stored in database: {file_name}")
    except Exception as e:
        log_alarm(f"Error storing hash in database: {e}")
        print(f"hash not stored")
def get_hash_from_db(connection, file_name, table_name):
    query = f"SELECT hash FROM {table_name} WHERE filename = %s"
    with connection.cursor() as cursor:
        cursor.execute(query, (file_name,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return None
def calculate_and_store_hashes_for_binaries(connection):
    table_name = "binary_hashes"
    for binary in system_binaries:
        if os.path.isfile(binary):
            current_hash = calculate_file_hash(binary)
            stored_hash = get_hash_from_db(connection, binary, table_name)
            if stored_hash is None:
                store_hash_in_db(connection, binary, current_hash, table_name)
            elif current_hash != stored_hash:
                log_alarm(f"Binary file {binary} has been modified.")

def calculate_and_store_hashes_for_extra_files(connection):
    table_name = "file_hashes"
    for file_path in files_to_monitor:
        if os.path.isfile(file_path):
            current_hash = calculate_file_hash(file_path)
            stored_hash = get_hash_from_db(connection, file_path, table_name)
            if stored_hash is None:
                store_hash_in_db(connection, file_path, current_hash, table_name)
            elif current_hash != stored_hash:
                log_alarm(f"File {file_path} has been modified.")


def log_alarm(message):
    """
    Logear una alarma con timestamp, mensaje e IP.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = socket.gethostbyname(socket.gethostname())
    alarm_message = f"{timestamp} - {message} - IP: {ip_address}"
    logging.info(alarm_message)

def log_prevention(message):
    """
    Logear un evento de prevencion con timestamp, mensaje e IP.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = socket.gethostbyname(socket.gethostname())
    prevention_message = f"{timestamp} - {message} - IP: {ip_address}"
    logging.info(prevention_message)
    with open(PREVENTION_LOG_FILE, "a") as f:
        f.write(prevention_message + "\n")

def log_connected_users(users):
    """
    Logear informacion de usuarios conectados.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(USER_LOG_FILE, "a") as f:
        f.write(f"Timestamp: {timestamp}\n")
        for user in users:
            user_info = f"User: {user['user']}, Terminal: {user['terminal']}, Origin: {user['origin']}"
            f.write(user_info + "\n")
        f.write("\n")

# logger de alarmas

alarm_logger = logging.getLogger('alarms')
alarm_logger.setLevel(logging.INFO)
alarm_handler = logging.FileHandler(ALARM_LOG_FILE)
alarm_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
alarm_logger.addHandler(alarm_handler)

prevention_logger = logging.getLogger('prevention')
prevention_logger.setLevel(logging.INFO)
prevention_handler = logging.FileHandler(PREVENTION_LOG_FILE)
prevention_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
prevention_logger.addHandler(prevention_handler)

connected_users_logger = logging.getLogger('connected_users')
connected_users_logger.setLevel(logging.INFO)
users_handler = logging.FileHandler(USER_LOG_FILE)
users_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
connected_users_logger.addHandler(users_handler)

def check_system_binaries():
    """
    Check system binaries for modifications.
    """
    for binary in system_binaries:
        if os.path.isfile(binary):
            current_hash = calculate_file_hash(binary)
            stored_hash = get_hash_from_db(connection, binary, "binary_hashes")  # Retrieve hash from the database
            if stored_hash is None:
                store_hash_in_db(connection, binary, current_hash, "binary_hashes")  # Store hash in the database
                log_alarm(f"New binary detected: {binary}")
            elif current_hash != stored_hash:
                log_alarm(f"Modified binary detected: {binary}")

def check_files():
    """
    Check monitored files for modifications.
    """
    for file_path in files_to_monitor:
        if os.path.isfile(file_path):
            current_hash = calculate_file_hash(file_path)
            stored_hash = get_hash_from_db(connection, file_path, "file_hashes")  # Retrieve hash from the database
            if stored_hash is None:
                store_hash_in_db(connection, file_path, current_hash, "file_hashes")  # Store hash in the database
                log_alarm(f"New file detected: {file_path}")
            elif current_hash != stored_hash:
                log_alarm(f"Modified file detected: {file_path}")

def get_logged_in_users():
    """
    Obtener una lista de usuarios logeados, sus IP y el origen de su conexion.
    """
    output = subprocess.check_output(["ps", "-ef"], universal_newlines=True)
    lines = output.strip().split("\n")
    users = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 8:
            user = parts[0]
            terminal = parts[6]
            origin = parse_origin(parts[7])
            users.append({"user": user, "terminal": terminal, "origin": origin})
    return users

def parse_origin(field):
    """
    Analizar el campo de origen para extraer el orgigen de conexion (SSH, Telnet o su).
    """
    if "sshd" in field:
        return "SSH"
    elif "telnetd" in field:
        return "Telnet"
    elif "su" in field:
        return "Switched User"
    else:
        return None

    """ 
    Revisar los usuarios logeados actualmente.
    """
def check_logged_in_users():
    logged_in_users = get_logged_in_users()
    log_connected_users(logged_in_users) 

def check_packet_capture_tools():
    """
    Check for common packet capture tools running.
    """ 
    log_alarm("Checking packet capture tools...")
    for tool in packet_capture_tools:
        try:
            subprocess.check_output(["pgrep", tool["name"]], universal_newlines=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            log_alarm(f"Packet capture tool not found: {tool['name']}")
        else:
            log_prevention(f"Packet capture tool detected: {tool['name']}")
            kill_process(tool["name"])
            uninstall_tool(tool["uninstall_cmd"])
            log_prevention(f"Uninstalled packet capture tool: {tool['name']}")

def kill_process(process_name):
    """
    Kill the process associated with the specified name.
    """
    subprocess.run(["pkill", process_name])

def uninstall_tool(uninstall_cmd):
    """
    Uninstall the tool using the specified uninstall command.
    """
    subprocess.run(uninstall_cmd, shell=True)


def block_ip_with_iptables(ip_address):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.src = ip_address
    rule.target = iptc.Target(rule, "DROP")
    chain.insert_rule(rule)
    log_prevention(f"Blocked IP address: {ip_address}")


def check_auth_log():
    """
    Check /var/log/auth.log for failed password and authentication failure messages.
    """
    auth_log_file = "/var/log/auth.log"
    with open(auth_log_file, "r") as log_file:
        for line in log_file:
            if "Failed password" in line:
                ip_address = line.split()[-2]
                ip_auth_failures[ip_address] = ip_auth_failures.get(ip_address, 0) + 1
                if ip_auth_failures[ip_address] >= AUTH_FAILURE_THRESHOLD:
                    log_alarm(f"Blocking IP {ip_address} due to excessive authentication failures")
                    block_ip_with_iptables(ip_address)
                # Perform additional actions based on the detected pattern (e.g., notify, etc.)
            elif "Authentication failure" in line:
                # Perform actions based on the detected pattern (e.g., notify, etc.)
                pass

def check_mail_log(email_addresses):
    """
    Check /var/log/mail.log for massive email sending from the specified email addresses.
    """
    mail_log_file = "/var/log/mail.log"
    with open(mail_log_file, "r") as log_file:
        for line in log_file:
            for email_address in email_addresses:
                if f"from=<{email_address}>" in line:
                    ip_address = line.split()[9][1:-1]
                    ip_email_count[ip_address] = ip_email_count.get(ip_address, 0) + 1
                    if ip_email_count[ip_address] >= EMAIL_THRESHOLD:
                        log_alarm(f"Blocking email account for IP {ip_address} due to excessive emails sent")

QUARANTINE_DIR = '/var/log/hips/quarantine'

def check_tmp_directory():
    """
    Check the /tmp directory for scripts or executables and move them to the quarantine folder.
    """
    log_alarm("Checking /tmp directory...")
    for root, dirs, files in os.walk('/tmp'):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.X_OK) or file.endswith(".sh") or file.endswith(".py"):
                # Change permissions to read-only for the owner, group, and others
                os.chmod(file_path, 0o444)
                log_prevention(f"Moving suspicious file to quarantine: {file_path}")
                # Move the file to the quarantine folder
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
                new_file_path = os.path.join(QUARANTINE_DIR, file)
                os.replace(file_path, new_file_path)

def analyze_tcpdump():
    """
    Analyze logs for potential DDoS attacks and other patterns.
    """
    with open("/var/log/tcpdump.txt", "r") as log_file:  # Open the tcpdump.txt file
        for log_entry in log_file:
            # Check for failed password and authentication failure messages
            if "Failed Password" in log_entry or "Authentication Failure" in log_entry:
                log_alarm("Potential brute-force attack: " + log_entry)

            # Check for DDoS pattern
            if "IP " in log_entry:
                parts = log_entry.split(" ")
                timestamp = parts[0]
                source_ip = parts[2].split(".")[0:4]
                source_ip = ".".join(source_ip)
                dest_ip = parts[4].split(".")[0:4]
                dest_ip = ".".join(dest_ip)

                key = f"{source_ip} > {dest_ip}"

                current_time = time.time()
                if key in ddos_ips:
                    occurrences, start_time = ddos_ips[key]
                    if current_time - start_time > DDOS_TIME_WINDOW:
                        # Reset the count if the time window has passed
                        occurrences = 1
                        start_time = current_time
                    else:
                        occurrences += 1
                else:
                    occurrences = 1
                    start_time = current_time

                ddos_ips[key] = (occurrences, start_time)

                if occurrences >= DDOS_THRESHOLD:
                    log_alarm(f"Potential DDoS attack from {source_ip} to {dest_ip} with {occurrences} occurrences in {DDOS_TIME_WINDOW} seconds.")
                    block_ip_with_iptables(source_ip)  # Block the IP using iptables

def get_process_info(pid):
    try:
        output = subprocess.check_output(["ps", "-o", "%cpu,%mem", "-p", str(pid)], universal_newlines=True)
        lines = output.strip().split("\n")
        
        if len(lines) >= 2:
            stats_line = lines[1]
            stats = re.split(r'\s+', stats_line.strip())
            
            if len(stats) >= 2:
                cpu_percent = float(stats[0])
                memory_percent = float(stats[1])
                return cpu_percent, memory_percent
        
        return None, None
    except subprocess.CalledProcessError:
        return None, None

def monitor_and_kill_processes():
    while True:
        for process in os.listdir('/proc'):
            if process.isdigit():
                pid = int(process)
                cpu_percent, memory_percent = get_process_info(pid)
                if cpu_percent is not None and memory_percent is not None:
                    if cpu_percent > 60 or memory_percent > 50:
                        log_prevention(f"Killing process {pid} (CPU: {cpu_percent:.2f}%, Memory: {memory_percent:.2f}%) "
                                       f"due to high resource usage.")
                        print(f"Killing process {pid} (CPU: {cpu_percent:.2f}%, Memory: {memory_percent:.2f}%) "
                              f"due to high resource usage.")
                        os.kill(pid, 9)  # Use SIGKILL (signal 9) to forcefully terminate the process`


def run_hips():
    last_binaries_check = 0
    last_files_check = 0
    last_packet_tools_check = 0
    last_users_check = 0
    last_auth_log_check = 0
    last_mail_log_check = 0
    last_tcpdump_analysis = 0
    last_process_monitor = 0

    while True:
        current_time = time.time()

        if current_time - last_binaries_check >= CHECK_INTERVAL:
            calculate_and_store_hashes_for_binaries(connection)
            last_binaries_check = current_time

        if current_time - last_files_check >= CHECK_INTERVAL:
            calculate_and_store_hashes_for_extra_files(connection)
            last_files_check = current_time

        if current_time - last_packet_tools_check >= CHECK_INTERVAL:
            check_packet_capture_tools()
            last_packet_tools_check = current_time

        if current_time - last_users_check >= CHECK_INTERVAL:
            print("Checking logged in users...")
            try:
                check_logged_in_users()
            except Exception as e:
                print(f"Error in check_logged_in_users: {e}")
            last_users_check = current_time
        if current_time - last_auth_log_check >= CHECK_INTERVAL:
            check_auth_log()
            last_auth_log_check = current_time
        if current_time - last_mail_log_check >= CHECK_INTERVAL:
            check_mail_log(monitored_email_addresses)  # Pass the list of monitored email addresses
            last_mail_log_check = current_time

        if current_time - last_tcpdump_analysis >= CHECK_INTERVAL:
            analyze_tcpdump()
            last_tcpdump_analysis = current_time

        if current_time - last_process_monitor >= CHECK_INTERVAL:
            print(f"procesos")
            monitor_and_kill_processes()
            last_process_monitor = current_time

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    try:
        connection = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            host=DB_HOST, port=DB_PORT
        )
        calculate_and_store_hashes_for_binaries(connection)
        calculate_and_store_hashes_for_extra_files(connection)
        run_hips()
    finally:
        # Close the database connection when the script exits
        if connection:
            connection.close()
    
