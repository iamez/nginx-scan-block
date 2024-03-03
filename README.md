#nginx-scan-block.sh
**nginx-scan-block.sh - nmap_scan.sh - match.sh - nginx_ips.db Instructions by ChatGPT**

Below is a step-by-step tutorial on setting up and using the `nginx_ips.db` database for logging and monitoring IP activity in Nginx. This tutorial assumes that you already have SQLite installed on your system.

## Step 1: Create the Database

Run the following commands in your terminal to create the SQLite database:

```bash
sqlite3 nginx_ips.db
```

## Step 2: Create Tables

Inside the SQLite prompt, you can create the necessary tables for your use case. Copy and paste the following commands:
```sql
-- Create the nginx_offenders table
CREATE TABLE nginx_offenders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    scanned INTEGER DEFAULT 0,
    last_seen_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    iptables_blocked INTEGER DEFAULT 0,
    seen_count INTEGER DEFAULT 0,
    potential_threat INTEGER DEFAULT 0
);
--access.log...log
CREATE TABLE nginx_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    timestamp TIMESTAMP,
    request_method TEXT,
    uri TEXT,
    status_code INTEGER,
    user_agent TEXT,
    referer TEXT
);

--create the nmap table
CREATE TABLE nmap_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    scan_results TEXT,
    scanned INTEGER DEFAULT 0
);

```
This creates two tables: nginx_offenders for tracking offender information and nginx_audit_logs for storing detailed logs.

## Step 3: Set Permissions
```bash
chmod 644 /path/to/nginx_ips.db
```
ou can now use SQL queries to monitor and analyze IP activity.
nginx-scan-block Script

The nginx-scan-block script is a monitoring and security tool designed to analyze Nginx access logs, identify potential threats, and take appropriate actions to enhance server security. It is particularly useful for detecting and blocking malicious activity in real-time.
Features:

    IP Tracking: The script maintains a database (nginx_ips.db) to track the activity of various IP addresses accessing the Nginx server.

    Whitelisting: You can specify a whitelist of IP addresses that should be excluded from monitoring. These might include trusted sources or internal services.

    Potential Threat Detection: The script analyzes Nginx access logs for 403 and 404 responses and identifies IPs with potentially malicious behavior based on customizable thresholds.

    Iptables Blocking: For identified potential threats, the script uses iptables to block incoming and outgoing traffic from those IP addresses, enhancing server security.

    Logging: The script logs important information, such as IPs seen, potential threats, and actions taken, in a special log file (special_nginx_ip.log).

How It Works:

    IP Extraction: The script extracts IP addresses from Nginx access logs.

    Whitelist Check: It checks if the IP is in the whitelist. If yes, it skips further processing.

    Tracking and Logging: The script updates the last-seen time for each IP, maintains a count of times an IP has been seen, and logs new IPs in the database.

    Potential Threat Check: For IPs exceeding a specified threshold, it checks if the IP exhibits potential threat behavior based on the number of 403 and 404 responses.

    Blocking: If an IP is identified as a potential threat, it is added to a special log, and iptables rules are applied to block incoming and outgoing traffic for that IP.

## Example SQL Commands

```sql
-- Total number of distinct IPs logged
SELECT COUNT(DISTINCT ip) FROM nginx_offenders;

-- Number of distinct IPs blocked in IPTables
SELECT COUNT(DISTINCT ip) FROM nginx_offenders WHERE iptables_blocked = 1;

-- Retrieve the top 10 most seen IPs
SELECT ip, seen_count FROM nginx_offenders ORDER BY seen_count DESC LIMIT 10;

-- Replace 'x.x.x.x' with the specific IP address you're interested in
SELECT * FROM nginx_offenders WHERE ip = 'x.x.x.x';

-- Replace 'y' with the specific ID you're interested in
SELECT * FROM nginx_offenders WHERE id = y;

-- Replace 'x.x.x.x' with the specific IP address you're interested in
SELECT * FROM nginx_audit_logs WHERE ip = 'x.x.x.x';

-- Replace 'x.x.x.x' with the specific IP address you're interested in
SELECT * FROM nginx_offenders WHERE ip = 'x.x.x.x' ORDER BY last_seen_time DESC;

-- Show all
SELECT * FROM nginx_offenders;

--Browse IPs with scanned flag set to 1:
SELECT * FROM nginx_offenders WHERE scanned = 1;

--Browse IPs with iptables_blocked flag set to 1:
SELECT * FROM nginx_offenders WHERE iptables_blocked = 1;

--Browse IPs marked as potential threats:
SELECT * FROM nginx_offenders WHERE potential_threat = 1;

--Search for a specific IP:
SELECT * FROM nginx_offenders WHERE ip = 'your_target_ip';

--Sort IPs by last seen time (recent first):
SELECT * FROM nginx_offenders ORDER BY last_seen_time DESC;

--Sort IPs by seen count (high to low):
SELECT * FROM nginx_offenders ORDER BY seen_count DESC;

--Filter IPs based on a threshold seen count (e.g., 10):
SELECT * FROM nginx_offenders WHERE seen_count >= 10;

--Count of IPs with non-null scan_results:
SELECT COUNT(*) FROM nmap_info WHERE scan_results IS NOT NULL;

--Count of IPs with scanned flag set to 1:
SELECT COUNT(*) FROM nmap_info WHERE scanned = 1;

--Count of distinct IPs in nmap_info:
SELECT COUNT(DISTINCT ip) FROM nmap_info;

--List distinct IPs in nmap_info:
SELECT DISTINCT ip FROM nmap_info;

--To get the Nmap info for a specific IP address from the nmap_info table, you can use the following SQLite command:
SELECT * FROM nmap_info WHERE ip = 'your_target_ip';

--If you only want to see the scan_results for a specific IP, you can modify the query as follows:
SELECT scan_results FROM nmap_info WHERE ip = 'your_target_ip';


```
### Available Audit Information
### The columns in the nginx_audit_logs table include:

    ID: A unique identifier for each record.
    IP: The IP address associated with the audit log entry.
    Timestamp: The timestamp indicating when the log entry occurred.
    Request Method: The HTTP request method (e.g., GET, POST).
    Request URL: The URL that was requested.
    Status: The HTTP status code of the response.

## nginx-scan-block.sh
Bash script for monitoring the Nginx access log (/var/log/nginx/access.log), analyzing the incoming requests, and updating a SQLite database (nginx_ips.db) based on certain criteria. Let's break down the main components of the script:

    Functions:
        update_last_seen_time: Updates the last_seen_time field in the nginx_offenders table for a given IP.
        insert_audit_log: Inserts an entry into the nginx_audit_logs table with relevant information from the Nginx access log.
        is_iptables_blocked: Checks if an IP is blocked in iptables by querying the iptables_blocked field in the nginx_offenders table.
        block_ip_in_iptables: Blocks an IP in iptables and updates the iptables_blocked field in the nginx_offenders table.
        handle_blank_ghost_ip: Handles cases where the detected IP is empty or invalid.
        is_ip_whitelisted: Checks if an IP is whitelisted based on a predefined whitelist.
        is_ip_seen: Checks if an IP has been seen in the logs by querying the seen_count field in the nginx_offenders table.
        is_potential_threat: Checks if an IP is a potential threat based on the number of 403 and 404 responses.

    Main Logic:
        Uses a persistent tail command to continuously monitor the last 3 lines of the Nginx access log for new entries.
        Extracts the IP, timestamp, request method, URI, status code, user agent, and referer from each log entry.
        Performs various checks and updates the database accordingly:
            Updates the last_seen_time.
            Checks for whitelisted IPs.
            Handles cases of empty or invalid IPs.
            Adds new IPs to the nginx_offenders table.
            Checks for potential threats and logs them in a special log file (special_nginx_ip.log).
            Blocks potential threats in iptables.

The script is designed to run continuously, reacting to new log entries and updating the database dynamically.
