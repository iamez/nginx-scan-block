#!/bin/bash

LOG_FILE="/var/log/nginx/access.log"
DATABASE="/home/et/nginx_ips.db"
THRESHOLD=30
WHITELIST=("127.0.0.1" "185.107.96.127" "93.103.149.102")

# Function to update last_seen_time in the database
update_last_seen_time() {
    local ip="$1"
    sqlite3 "$DATABASE" "UPDATE nginx_offenders SET last_seen_time = CURRENT_TIMESTAMP WHERE ip = '$ip';"
}

# Function to insert audit log into the database
insert_audit_log() {
    local ip="$1"
    local timestamp="$2"
    local request_method="$3"
    local uri="$4"
    local status_code="$5"
    local user_agent="$6"
    local referer="$7"

    sqlite3 "$DATABASE" "INSERT INTO nginx_audit_logs (ip, timestamp, request_method, uri, status_code, user_agent, referer) VALUES ('$ip', '$timestamp', '$request_method', '$uri', '$status_code', '$user_agent', '$referer');"
}

# Function to check if IP is blocked in iptables
is_iptables_blocked() {
    local ip="$1"
    local iptables_blocked
    iptables_blocked=$(sqlite3 "$DATABASE" "SELECT iptables_blocked FROM nginx_offenders WHERE ip = '$ip';")

    # Check if iptables_blocked is not empty and is equal to 1
    [[ -n "$iptables_blocked" && "$iptables_blocked" == 1 ]]
}

# Function to block IP in iptables
block_ip_in_iptables() {
    local ip="$1"
    # Add iptables rule to block the IP for incoming traffic
    sudo iptables -A INPUT -s "$ip" -j DROP
    # Add iptables rule to block ICMP echo-request for outgoing traffic
    sudo iptables -A OUTPUT -d "$ip" -j DROP
    # Update iptables_blocked flag in the database
    sqlite3 "$DATABASE" "UPDATE nginx_offenders SET iptables_blocked = 1 WHERE ip = '$ip';"
}

# Function to handle "blank/ghost IP" case
handle_blank_ghost_ip() {
    local ip="$1"
    local count="$2"

    if [[ "$ip" == "" ]]; then
        echo "WARNING: Invalid or empty IP address: $ip. Skipping."
    else
        echo "IP $ip seen $count times. Checking for potential threat."
        # Add your threat-checking logic here
    fi
}

# Function to check if IP is whitelisted
is_ip_whitelisted() {
    local ip="$1"
    for whitelisted_ip in "${WHITELIST[@]}"; do
        if [ "$ip" == "$whitelisted_ip" ]; then
            return 0  # IP is whitelisted
        fi
    done
    return 1  # IP is not whitelisted
}

# Function to check if IP has been seen in logs
is_ip_seen() {
    local ip="$1"
    local seen_count
    seen_count=$(sqlite3 "$DATABASE" "SELECT seen_count FROM nginx_offenders WHERE ip = '$ip';")
    [ -n "$seen_count" ]
}

# Function to check if IP is a potential threat based on 403 and 404 responses
is_potential_threat() {
    local ip="$1"
    local potential_threat

    # Use grep to count the number of 403 and 404 responses for the given IP
    local num_403_responses
    num_403_responses=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM nginx_access_logs WHERE ip = '$ip' AND status = 403;")

    local num_404_responses
    num_404_responses=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM nginx_access_logs WHERE ip = '$ip' AND status = 404;")

    # If the total number of 403 and 404 responses is above a threshold, consider it a potential threat
    local threshold=20  # Adjust the threshold as needed
    total_responses=$((num_403_responses + num_404_responses))
    [ "$total_responses" -gt "$threshold" ]
}

# Main logic with persistent tail
tail -n 3 -F "$LOG_FILE" | while read -r line; do
    ip=""

    if [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        ip="${BASH_REMATCH[1]}"
        timestamp=$(echo "$line" | awk '{print $4}' | sed 's/\[//')

        # Check if the IP is whitelisted or empty
        if ! is_ip_whitelisted "$ip" && [[ "$ip" != "" ]]; then
            handle_blank_ghost_ip "$ip"
            update_last_seen_time "$ip"  # Update last_seen_time for each IP encountered
            if ! is_ip_seen "$ip"; then
                echo "New IP detected: $ip. Adding to the database."
                sqlite3 "$DATABASE" "INSERT INTO nginx_offenders (ip, seen_count, potential_threat) VALUES ('$ip', 1, '0');"
            else
                seen_count=$(sqlite3 "$DATABASE" "SELECT TRIM(seen_count) FROM nginx_offenders WHERE ip = '$ip';")

                if [ -n "$seen_count" ] && [[ "$seen_count" =~ ^[0-9]+$ ]] && [ "$seen_count" -ge "$THRESHOLD" ]; then
                    echo "IP $ip seen $seen_count times. Checking for potential threat."
                    if ! is_potential_threat "$ip"; then
                        echo "IP $ip is a potential threat. Adding to special log."
                        echo "Special Logging for IP $ip (Seen Count: $seen_count)" >> "/home/et/special_nginx_ip.log"
                        block_ip_in_iptables "$ip"  # Block the IP if it's a potential threat
                        echo "Blocked IP $ip in iptables."
                    fi
                fi

                sqlite3 "$DATABASE" "UPDATE nginx_offenders SET seen_count = seen_count + 1 WHERE ip = '$ip';"
            fi
        fi

        # Extract relevant information for audit log
        request_method=$(echo "$line" | awk '{print $6}')
        uri=$(echo "$line" | awk '{print $7}')
        status_code=$(echo "$line" | awk '{print $9}')
        user_agent=$(echo "$line" | awk -F'"' '{print $6}')
        referer=$(echo "$line" | awk -F'"' '{print $8}')

        # Insert into audit log
        insert_audit_log "$ip" "$timestamp" "$request_method" "$uri" "$status_code" "$user_agent" "$referer"
    elif [[ $line =~ WARNING:\ Invalid\ or\ empty\ IP\ address:\ (.*)\ Skipping\. ]]; then
        invalid_ip="${BASH_REMATCH[1]}"
        echo "WARNING: Invalid or empty IP address: $invalid_ip. Skipping."
    fi
done
