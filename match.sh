#!/bin/bash

DATABASE="/home/et/nginx_ips.db"
ERROR_LOG="/var/log/nginx/error.log"
SUPER_USER_IP="93.103.149.102"
HIDDEN_TEXT="Super user detected! IP hidden"

# Function to extract IPs from error.log
extract_ips_from_error_log() {
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$ERROR_LOG" | sort -u > error_ips.txt
}

# Function to compare IPs between database and error.log
compare_ips() {
    # Extract IPs from nginx database
    sqlite3 "$DATABASE" "SELECT DISTINCT ip FROM nginx_offenders;" | sort -u > database_ips.txt

    # Compare the two sets of IPs
    comm -12 database_ips.txt error_ips.txt > common_ips.txt
    comm -23 database_ips.txt error_ips.txt > unique_database_ips.txt
    comm -13 database_ips.txt error_ips.txt > unique_error_ips.txt

    # Calculate the match percentage
    total_database_ips=$(wc -l < database_ips.txt)
    total_error_ips=$(wc -l < error_ips.txt)
    total_common_ips=$(wc -l < common_ips.txt)

    if [ "$total_database_ips" -eq 0 ]; then
        echo "Error: No IPs found in the nginx database."
        exit 1
    fi

    match_percentage=$((total_common_ips * 100 / total_database_ips))

    # Display results
    echo "Total IPs in nginx database: $total_database_ips"
    echo "Total IPs in error.log: $total_error_ips"
    echo "Total common IPs: $total_common_ips"
    echo "Match Percentage: $match_percentage%"

    # Display IPs not in the database
    echo "IPs in error.log but not in the nginx database:"
    while IFS= read -r line; do
        if [ "$line" == "$SUPER_USER_IP" ]; then
            echo "$HIDDEN_TEXT"
        else
            echo "$line"
        fi
    done < unique_error_ips.txt

    # Check for super user IP
    if grep -Fxq "$SUPER_USER_IP" unique_error_ips.txt; then
        echo "$HIDDEN_TEXT"
        # You can add additional actions or messages for super user detection here
    fi

    # Clean up temporary files
    rm -f error_ips.txt database_ips.txt common_ips.txt unique_database_ips.txt unique_error_ips.txt
}

# Main logic
extract_ips_from_error_log
compare_ips
