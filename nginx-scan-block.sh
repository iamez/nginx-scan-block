#!/bin/bash

LOG_FILE="/var/log/nginx/access.log"
DATABASE="/home/et/nginx_ips.db"
THRESHOLD=30
WHITELIST=("127.0.0.1" "185.107.96.127" "93.103.149.102")

# Function to extract IPs and relevant data from nginx access log
extract_ips() {
    local ips
    while read -r line; do
        local ip
        if [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            ip="${BASH_REMATCH[1]}"
            
            # Check if the IP is whitelisted or empty
            if ! is_ip_whitelisted "$ip" && [[ "$ip" != "" ]]; then
                ips+="$ip\n"
            fi
        elif [[ $line =~ WARNING:\ Invalid\ or\ empty\ IP\ address:\ (.*)\ Skipping\. ]]; then
            local invalid_ip="${BASH_REMATCH[1]}"
            echo "WARNING: Invalid or empty IP address: $invalid_ip. Skipping."
        fi
    done < "$LOG_FILE"
    echo -e "$ips"
}
# Function to update last_seen_time in the database
update_last_seen_time() {
    local ip="$1"
    sqlite3 "$DATABASE" "UPDATE nginx_offenders SET last_seen_time = CURRENT_TIMESTAMP WHERE ip = '$ip';"
}

# Function to check if IP is in the top offenders list
is_top_offender() {
    local ip="$1"
    local seen_count
    seen_count=$(sqlite3 "$DATABASE" "SELECT seen_count FROM nginx_offenders WHERE ip = '$ip';")

    # Check if seen_count is not empty and is greater than or equal to the threshold
    # If empty, consider it a new IP, and if less than the threshold, do nothing for now
    [[ -n "$seen_count" && "$seen_count" -ge "$THRESHOLD" ]]
}

# Function to check if IP is blocked in iptables
is_iptables_blocked() {
    local ip="$1"
    local iptables_blocked
    iptables_blocked=$(sqlite3 "$DATABASE" "SELECT iptables_blocked FROM nginx_offenders WHERE ip = '$ip';")
    [ "$iptables_blocked" -eq 1 ]
}

# Function to block IP in iptables
block_ip_in_iptables() {
    local ip="$1"
    # Add iptables rule to block the IP for incoming traffic
    sudo iptables -A INPUT -s "$ip" -j DROP
    # Add iptables rule to block ICMP echo-request for outgoing traffic
    sudo iptables -A OUTPUT -d "$ip" -p icmp --icmp-type echo-request -j DROP
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



# Function to update the database with IP information
update_database() {
    local ip="$1"
    # Check if the IP is empty or invalid
    if [ -z "$ip" ] || [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Invalid or empty IP address: $ip. Skipping."
        return
    fi

    if ! is_ip_whitelisted "$ip"; then
        if ! is_ip_seen "$ip"; then
            echo "New IP detected: $ip. Adding to the database."
            sqlite3 "$DATABASE" "INSERT INTO nginx_offenders (ip, seen_count, potential_threat) VALUES ('$ip', 1, '0');"
        else
            local seen_count
            seen_count=$(sqlite3 "$DATABASE" "SELECT TRIM(seen_count) FROM nginx_offenders WHERE ip = '$ip';")

            if [ -n "$seen_count" ] && [[ "$seen_count" =~ ^[0-9]+$ ]] && [ "$seen_count" -ge "$THRESHOLD" ]; then
                echo "IP $ip seen $seen_count times. Checking for potential threat."
                if ! is_potential_threat "$ip"; then
                    echo "IP $ip is a potential threat. Adding to special log."
                    echo "Special Logging for IP $ip (Seen Count: $seen_count)" >> "/home/et/special_nginx_ip.log"
                    sqlite3 "$DATABASE" "UPDATE nginx_offenders SET potential_threat = '1' WHERE ip = '$ip';"
                fi
            fi

            sqlite3 "$DATABASE" "UPDATE nginx_offenders SET seen_count = seen_count + 1 WHERE ip = '$ip';"
        fi
    fi
}


# Main logic
while true; do
    extract_ips | while read -r ip; do
        handle_blank_ghost_ip "$ip"
        update_database "$ip"
        update_last_seen_time "$ip"  # Update last_seen_time for each IP encountered
        if is_top_offender "$ip" && ! is_iptables_blocked "$ip"; then
            block_ip_in_iptables "$ip"
            echo "Blocked IP $ip in iptables."
        fi
        if is_potential_threat "$ip"; then
            block_ip_in_iptables "$ip"  # Block the IP if it's a potential threat
            echo "Potential threat detected for IP $ip. Blocked in iptables."
        fi
    done
    sleep 60  # Sleep for 60 seconds before processing new entries again
done
