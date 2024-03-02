# scripts 
nginx-scan-block.sh - nginx_ips.db instructions by chatGPT
Below is a step-by-step tutorial on setting up and using the nginx_ips.db database
for logging and monitoring IP activity in Nginx. This tutorial assumes that you already have SQLite installed on your system.
Step 1: Create the Database
Run the following commands in your terminal to create the SQLite database:

sqlite3 /path/to/nginx_ips.db

Replace /path/to/nginx_ips.db with the actual path where you want to store your database.
Step 2: Create Tables

Inside the SQLite prompt, you can create the necessary tables for your use case. Copy and paste the following commands:

sql

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

This creates two tables: nginx_offenders for tracking offender information and nginx_audit_logs for storing detailed logs.
Step 3: Set Permissions


chmod 644 /path/to/nginx_ips.db

You can now use SQL queries to monitor and analyze IP activity
