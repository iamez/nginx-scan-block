# scripts 
**nginx-scan-block.sh - nginx_ips.db Instructions by ChatGPT**

Below is a step-by-step tutorial on setting up and using the `nginx_ips.db` database for logging and monitoring IP activity in Nginx. This tutorial assumes that you already have SQLite installed on your system.

## Step 1: Create the Database

Run the following commands in your terminal to create the SQLite database:

```bash
sqlite3 /path/to/nginx_ips.db
```

Replace /path/to/nginx_ips.db with the actual path where you want to store your database.
##Step 2: Create Tables

Inside the SQLite prompt, you can create the necessary tables for your use case. Copy and paste the following commands:
```sql
-- Create the nginx_offenders table
CREATE TABLE nginx_offenders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    seen_count INTEGER DEFAULT 0,
    potential_threat INTEGER DEFAULT 0,
    last_seen_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    iptables_blocked INTEGER DEFAULT 0
);

-- Create the nginx_audit_logs table
CREATE TABLE nginx_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    request_method TEXT,
    request_url TEXT,
    status INTEGER
);
```
This creates two tables: nginx_offenders for tracking offender information and nginx_audit_logs for storing detailed logs.
##Step 3: Set Permissions
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

### How many IPs have we logged?

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
```
##Available Audit Information
The columns in the nginx_audit_logs table include:

    ID: A unique identifier for each record.
    IP: The IP address associated with the audit log entry.
    Timestamp: The timestamp indicating when the log entry occurred.
    Request Method: The HTTP request method (e.g., GET, POST).
    Request URL: The URL that was requested.
    Status: The HTTP status code of the response.


