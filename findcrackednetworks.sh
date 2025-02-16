#!/bin/bash

DEBUG=0

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Scan nearby WiFi networks and check for matches in CRACKED.txt"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo "  --debug       Enable debug output"
    exit 0
}

# Process command line arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
        --debug)
            DEBUG=1
            ;;
    esac
done

# Debug function
debug_print() {
    if [ $DEBUG -eq 1 ]; then
        echo "[DEBUG] $1"
    fi
}

# Scan for networks and look for matches in CRACKED.txt
echo "Scanning for networks..."
nmcli dev wifi list ifname wlan1 --rescan yes | while read -r line; do
    # Skip the header line
    if [[ $line == *"IN-USE"* ]]; then continue; fi
    
    # Extract BSSID from nmcli output
    bssid=$(echo "$line" | awk '{print $2}')
    ssid=$(echo "$line" | awk '{$1=$2=""; print substr($0,3)}' | awk '{print $1}')
    
    # If we found a BSSID, look for it in CRACKED.txt
    if [[ -n "$bssid" ]]; then
        debug_print "Checking BSSID: $bssid (SSID: $ssid)"
        match=$(grep -i "$bssid" CRACKED.txt)
        if [[ -n "$match" ]]; then
            echo "MATCH FOUND!"
            echo "$match"
            echo "------------------------"
        else
            debug_print "No match found for $bssid"
        fi
    fi
done

debug_print "Scan complete" 
