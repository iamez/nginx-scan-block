import os
import time
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import Counter

# Define ANSI escape codes for colors
class Colors:
    WHITE = '\033[97m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    DARK_BLUE = '\033[34m'
    END = '\033[0m'

class NginxLogMonitor(FileSystemEventHandler):
    # ... (rest of the class remains unchanged)

    def print_statistics(self):
        connection = sqlite3.connect(self.database)
        cursor = connection.cursor()

        # Get top blocked IPs
        cursor.execute("SELECT ip, seen_count, potential_threat FROM nginx_offenders ORDER BY seen_count DESC LIMIT 5;")
        top_ips_activity = cursor.fetchall()

        print(f"{Colors.WHITE}\nIP Activity Log:")
        for ip, seen_count, potential_threat in top_ips_activity:
            color = Colors.WHITE

            # Highlight blocked IPs in red
            if self.is_iptables_blocked(ip):
                color = Colors.RED

            # Highlight potential threat IPs in yellow
            elif self.is_potential_threat(ip):
                color = Colors.YELLOW

            print(f"{color}IP: {ip} | Seen Count: {seen_count} | Potential Threat: {potential_threat}{Colors.END}")

        # Count total unique IPs logged
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM nginx_offenders;")
        total_unique_ips = cursor.fetchone()[0]
        print(f"\nTotal Unique IPs Logged: {Colors.DARK_BLUE}{total_unique_ips}{Colors.END}")

        connection.close()
        
class NginxLogMonitor(FileSystemEventHandler):
    def __init__(self, log_file, database, threshold, whitelist):
        super(NginxLogMonitor, self).__init__()
        self.log_file = log_file
        self.database = database
        self.threshold = threshold
        self.whitelist = whitelist
        self.ip_counter = Counter()

    def on_modified(self, event):
        if event.src_path.endswith(self.log_file):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Log file modified: {self.log_file}")
            self.read_logs()

    def read_logs(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                if "HTTP/1.1\" 200" in line:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {line.strip()}")
                    self.update_ip_counter(line)

        self.process_logs()

    def update_ip_counter(self, log_line):
        # Extracting the IP address from the log line
        ip_address = log_line.split(' ')[0]
        self.ip_counter[ip_address] += 1

    def process_logs(self):
        for ip, count in self.ip_counter.items():
            # Add your logic here to update the database and perform actions
            self.update_database(ip, count)
            if count >= self.threshold and ip not in self.whitelist:
                self.block_ip_in_iptables(ip)

        self.ip_counter.clear()

    def update_database(self, ip, count):
        connection = sqlite3.connect(self.database)
        cursor = connection.cursor()

        # Check if IP is whitelisted
        if ip in self.whitelist:
            print(f"Whitelisted IP: {ip}. Ignoring.")
        else:
            # Check if IP is seen
            cursor.execute(f"SELECT seen_count FROM nginx_offenders WHERE ip = '{ip}';")
            seen_count = cursor.fetchone()

            if seen_count is None:
                # New IP detected, add to the database
                print(f"New IP detected: {ip}. Adding to the database.")
                cursor.execute(f"INSERT INTO nginx_offenders (ip, seen_count, potential_threat) VALUES ('{ip}', 1, '0');")
            else:
                seen_count = seen_count[0]

                # Update seen count
                cursor.execute(f"UPDATE nginx_offenders SET seen_count = seen_count + 1 WHERE ip = '{ip}';")

                # Check for potential threat
                if seen_count >= self.threshold and not self.is_potential_threat(ip):
                    print(f"IP {ip} is a potential threat. Adding to special log.")
                    print(f"Special Logging for IP {ip} (Seen Count: {seen_count})")
                    cursor.execute(f"UPDATE nginx_offenders SET potential_threat = '1' WHERE ip = '{ip}';")

            connection.commit()

    def is_potential_threat(self, ip):
        connection = sqlite3.connect(self.database)
        cursor = connection.cursor()

        # Use grep to count the number of 403 and 404 responses for the given IP
        cursor.execute(f"SELECT COUNT(*) FROM nginx_access_logs WHERE ip = '{ip}' AND status = 403;")
        num_403_responses = cursor.fetchone()[0]

        cursor.execute(f"SELECT COUNT(*) FROM nginx_access_logs WHERE ip = '{ip}' AND status = 404;")
        num_404_responses = cursor.fetchone()[0]

        connection.close()

        # If the total number of 403 and 404 responses is above a threshold, consider it a potential threat
        total_responses = num_403_responses + num_404_responses
        return total_responses > 20  # Adjust the threshold as needed

    def block_ip_in_iptables(self, ip):
        # Add iptables rule to block the IP for incoming traffic
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        # Add iptables rule to block ICMP echo-request for outgoing traffic
        os.system(f"sudo iptables -A OUTPUT -d {ip} -p icmp --icmp-type echo-request -j DROP")
        print(f"Blocked IP {ip} in iptables.")

    def print_statistics(self):
        connection = sqlite3.connect(self.database)
        cursor = connection.cursor()

        # Get top blocked IPs
        cursor.execute("SELECT ip, seen_count FROM nginx_offenders ORDER BY seen_count DESC LIMIT 5;")
        top_blocked_ips = cursor.fetchall()
        print("\nTop Blocked IPs:")
        for ip, count in top_blocked_ips:
            print(f"{ip}: {count} requests")

        connection.close()

if __name__ == "__main__":
    # Initialize a SQLite database (you might want to use a more robust database for production)
    database_path = "/home/et/nginx_ips.db"

    # Ensure the database and required tables are set up
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nginx_offenders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            seen_count INTEGER DEFAULT 0,
            potential_threat TEXT DEFAULT '0'
        );
    ''')
    connection.commit()

    # Load statistics at the start
    nginx_monitor = NginxLogMonitor("/var/log/nginx/access.log", database_path, 30, ["127.0.0.1", "185.107.96.127", "93.103.149.102"])
    nginx_monitor.print_statistics()

    connection.close()

    # Start live/watchdog operations
    observer = Observer()
    observer.schedule(nginx_monitor, path="/var/log/nginx/")
    observer.start()

    try:
        while True:
            time.sleep(60)  # Sleep for 60 seconds (1 minute)
            nginx_monitor.process_logs()
    except KeyboardInterrupt:
        nginx_monitor.print_statistics()  # Print statistics when exiting
        observer.stop()

    observer.join()
