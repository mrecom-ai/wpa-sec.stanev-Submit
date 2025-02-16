#!/bin/bash

# Constants
CAPTURES_DIR="captures"
PROCESSED_DIR="processed"
INVALID_DIR="invalid"
SUBMITTED_FILE="submitted.txt"
DEBUG=0

# Initialize counters
declare -i TOTAL_FILES=0
declare -i VALID_FILES=0
declare -i INVALID_FILES=0
declare -i TOTAL_HANDSHAKES=0
declare -i NEW_HANDSHAKES=0
declare -i ALREADY_SUBMITTED=0
declare -i SUCCESSFUL_SUBMISSIONS=0
declare -A PROCESSED_BSSIDS
declare -A SKIPPED_BSSIDS

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Automatically process and submit WPA handshake captures to wpa-sec.stanev.org"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --debug        Run in debug mode with detailed output"
    echo
    echo "Debug Mode Features:"
    echo "  - Shows detailed hcxpcapngtool analysis for each capture"
    echo "  - Displays all validation steps and results"
    echo "  - Shows exact commands being executed"
    echo
    echo "Directory Structure:"
    echo "  $CAPTURES_DIR/     - Place new captures here"
    echo "  $PROCESSED_DIR/  - Successfully processed captures"
    echo "  $INVALID_DIR/    - Invalid captures"
    echo
    echo "File Types:"
    echo "  - Processes .pcapng files only"
    echo "  - Tracks submitted BSSIDs in $SUBMITTED_FILE"
    exit 0
}

# Debug print function with colors
debug_print() {
    if [ $DEBUG -eq 1 ]; then
        echo -e "\n${BLUE}[DEBUG]${NC} $1"
    fi
}

# Simple status messages (always shown)
status_print() {
    echo -e "→ $1"
}

# Success messages (always shown)
success_print() {
    echo -e "${GREEN}✓${NC} $1"
}

# Warning messages (always shown)
warning_print() {
    echo -e "${YELLOW}!${NC} $1"
}

# Error messages (always shown)
error_print() {
    echo -e "${RED}✗${NC} $1"
}

# Info print function
info_print() {
    if [ $DEBUG -eq 1 ]; then
        echo -e "${CYAN}[INFO]${NC} $1"
    fi
}

# Section header print function
print_section_header() {
    if [ $DEBUG -eq 1 ]; then
        echo -e "\n${BOLD}=== $1 ===${NC}"
    fi
}

# Network info (always shown but format depends on mode)
print_network_info() {
    local bssid="$1"
    local essid="$2"
    local status="$3"
    
    if [ $DEBUG -eq 1 ]; then
        if [ "$status" = "new" ]; then
            echo -e "  ${GREEN}•${NC} ${BOLD}${essid}${NC} (${GRAY}${bssid}${NC})"
        else
            echo -e "  ${YELLOW}•${NC} ${BOLD}${essid}${NC} (${GRAY}${bssid}${NC}) - Already submitted"
        fi
    else
        if [ "$status" = "new" ]; then
            echo -e "  ${GREEN}+${NC} ${essid}"
        else
            echo -e "  ${YELLOW}•${NC} ${essid} (already submitted)"
        fi
    fi
}

# User confirmation function
confirm() {
    if [ $DEBUG -eq 1 ]; then
        read -p "Press Enter to continue or Ctrl+C to abort..."
    fi
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

# Create required directories and files
mkdir -p "$CAPTURES_DIR" "$PROCESSED_DIR" "$INVALID_DIR"
touch "$SUBMITTED_FILE" "bssids.txt"

# Cleanup temporary and unnecessary files
cleanup_temp_files() {
    debug_print "Cleaning up temporary files..."
    
    # Remove temporary hc22000 files
    find . -maxdepth 1 -name "*.hc22000" -type f -delete
    find "$CAPTURES_DIR" -name "*.hc22000" -type f -delete
    
    # Remove Kismet files (not needed for handshake submission)
    find . -maxdepth 1 -name "*.kismet" -type f -delete
    find "$CAPTURES_DIR" -name "*.kismet" -type f -delete
    
    # Remove any temporary files from failed extractions
    rm -f /tmp/temp_*.22000
    rm -f /tmp/validate_*.22000
    rm -f /tmp/filtered_*.pcapng
    
    debug_print "Cleanup complete"
    confirm
}

# Cleanup AngryOxide generated files when all BSSIDs are already submitted
cleanup_angryoxide_files() {
    local capture="$1"
    debug_print "Cleaning up AngryOxide generated files for: $(basename "$capture")"
    
    # Remove the capture file itself
    rm -f "$capture"
    
    # Remove associated Kismet and hash files
    local base_name="${capture%.*}"
    rm -f "${base_name}.kismet"
    rm -f "${base_name}.hc22000"
    
    debug_print "AngryOxide files cleanup complete"
    confirm
}

# Initial analysis of capture file
analyze_capture() {
    local file="$1"
    local info_output
    
    debug_print "Analyzing capture file: $(basename "$file")"
    
    info_output=$(hcxpcapngtool --all "$file" 2>&1)
    if [ $? -ne 0 ]; then
        error_print "Failed to analyze capture file"
        return 1
    fi
    
    # Extract key information
    local total_packets=$(echo "$info_output" | grep "packets inside" | cut -d':' -f2 | tr -d ' ')
    local unique_essids=$(echo "$info_output" | grep "ESSID (total unique)" | cut -d':' -f2 | tr -d ' ')
    local eapol_pairs=$(echo "$info_output" | grep "EAPOL pairs (total)" | cut -d':' -f2 | tr -d ' ')
    
    if [ $DEBUG -eq 1 ]; then
        print_section_header "Capture Analysis"
        echo -e "${BOLD}File:${NC} $(basename "$file")"
        echo -e "${BOLD}Total packets:${NC}$total_packets"
        echo -e "${BOLD}Unique ESSIDs:${NC}$unique_essids"
        echo -e "${BOLD}EAPOL pairs:${NC}$eapol_pairs"
        echo -e "${BOLD}Duration:${NC}$(echo "$info_output" | grep "duration of the dump" | cut -d':' -f2)"
        
        if echo "$info_output" | grep -q "Warning:"; then
            print_section_header "Warnings"
            echo -e "${YELLOW}$(echo "$info_output" | grep "Warning:" | sed 's/Warning: //')${NC}"
        fi
    fi
    
    # Validate capture has potential handshakes
    if [[ -z "$eapol_pairs" || "$eapol_pairs" -eq 0 ]]; then
        error_print "No valid EAPOL pairs found"
        return 1
    fi
    
    # Return the number of unique ESSIDs for --max-essids parameter
    echo "$unique_essids"
    return 0
}

# Extract BSSIDs from pcapng file that have valid handshakes
get_valid_bssids() {
    local file="$1"
    local temp_hash="/tmp/temp_$$.22000"
    declare -A bssids
    
    # Get ESSID count from analysis
    local essid_count
    essid_count=$(analyze_capture "$file")
    if [ $? -ne 0 ]; then
        error_print "Capture analysis failed"
        return 1
    fi
    
    # Add 1 to essid_count for safety
    local max_essids=$((essid_count + 1))
    info_print "Extracting handshakes with max_essids=$max_essids"
    
    # Extract handshakes
    if ! hcxpcapngtool --all --max-essids="$max_essids" -o "$temp_hash" "$file" >/dev/null 2>&1; then
        error_print "Failed to extract handshakes"
        rm -f "$temp_hash"
        return 1
    fi
    
    # Process the hash file
    if [ -s "$temp_hash" ]; then
        print_section_header "Networks Found"
        
        # Write BSSIDs to file first
        cat "$temp_hash" | cut -d '*' -f 4 | tr -d ':' | sort -u > bssids.txt
        
        while IFS='*' read -r p1 p2 p3 mac_ap mac_sta essid rest; do
            [ -z "$mac_ap" ] && continue
            
            # Convert BSSID to lowercase and ESSID from hex
            mac_ap=$(echo "$mac_ap" | tr '[:upper:]' '[:lower:]')
            local essid_decoded
            essid_decoded=$(echo -n "$essid" | xxd -r -p 2>/dev/null || echo "Unknown")
            
            if [[ -n "$mac_ap" && "$mac_ap" != "000000000000" ]]; then
                bssids["$mac_ap"]="$essid_decoded"
                    
                if [ $DEBUG -eq 1 ]; then
                    if is_bssid_submitted "$mac_ap" >/dev/null 2>&1; then
                        print_network_info "$mac_ap" "$essid_decoded" "submitted"
                    else
                        print_network_info "$mac_ap" "$essid_decoded" "new"
                    fi
                fi
            fi
        done < "$temp_hash"
        
        # Output unique BSSIDs
        printf '%s\n' "${!bssids[@]}" | sort
    fi
    
    rm -f "$temp_hash"
    return 0
}

# Filter pcapng to only include new BSSIDs
filter_new_handshakes() {
    local input_file="$1"
    local output_file="$2"
    local temp_bssids="/tmp/new_bssids_$$.txt"
    
    info_print "Filtering handshakes from: $(basename "$input_file")"
    
    # Create list of new BSSIDs
    while read bssid; do
        if ! grep -q "$bssid" "$SUBMITTED_FILE" 2>/dev/null; then
            echo "$bssid"
        fi
    done < bssids.txt > "$temp_bssids"
    
    if [ ! -s "$temp_bssids" ]; then
        warning_print "No new networks found"
        rm -f "$temp_bssids"
        return 1
    fi
    
    # Build tshark filter for new BSSIDs
    local filter
    filter=$(cat "$temp_bssids" | while read bssid; do 
        echo -n "(wlan.bssid == $bssid || wlan.da == $bssid || (wlan.fc.type_subtype == 0x04)) || "
    done | sed 's/ || $//')
    
    debug_print "Using filter: $filter"
    
    # Create filtered capture
    if ! tshark -r "$input_file" -w "$output_file" -Y "$filter" >/dev/null 2>&1; then
        error_print "Failed to create filtered capture"
        rm -f "$temp_bssids"
        return 1
    fi
    
    # Verify filtered capture
    local temp_hash="/tmp/verify_$$.22000"
    if ! hcxpcapngtool -o "$temp_hash" "$output_file" >/dev/null 2>&1; then
        error_print "Filtered capture contains no valid handshakes"
        rm -f "$temp_bssids" "$temp_hash" "$output_file"
        return 1
    fi
    
    # Verify we have all expected networks
    local found_count=0
    while read bssid; do
        if grep -q "$bssid" "$temp_hash"; then
            ((found_count++))
        fi
    done < "$temp_bssids"
    
    if [ "$found_count" -eq 0 ]; then
        error_print "No valid handshakes found in filtered capture"
        rm -f "$temp_bssids" "$temp_hash" "$output_file"
        return 1
    fi
    
    success_print "Successfully created filtered capture with $found_count new networks"
    rm -f "$temp_bssids" "$temp_hash"
    return 0
}

# Check if BSSID has been submitted
is_bssid_submitted() {
    local bssid="$1"
    if [[ -z "$bssid" || "$bssid" =~ [^0-9a-fA-F] || ${#bssid} != 12 ]]; then
        return 0  # Skip invalid BSSIDs silently
    fi
    grep -qi "^$bssid$" "$SUBMITTED_FILE"
    return $?
}

# Validate capture file
validate_capture() {
    local file="$1"
    
    debug_print "Validating capture: $file"
    
    # Only process pcapng files
    if [[ "$file" != *.pcapng ]]; then
        debug_print "Skipping non-pcapng file: $file"
        return 1
    fi
    
    # Get detailed stats first
    local validation_output
    validation_output=$(hcxpcapngtool --all "$file" 2>&1)
    
    if [ $DEBUG -eq 1 ]; then
        echo -e "\nValidation output:"
        echo "$validation_output"
        confirm
    fi
    
    # Check for valid handshake indicators in the detailed output
    if echo "$validation_output" | grep -q -E "EAPOL pairs.*total.*: [1-9]|EAPOL pairs.*best.*: [1-9]|EAPOL M12E2.*challenge.*: [1-9]"; then
        # Verify we can extract a hash
        if hcxpcapngtool -o /tmp/validate_$$.22000 "$file" >/dev/null 2>&1; then
            if [ -s "/tmp/validate_$$.22000" ] && grep -q "WPA.*02" "/tmp/validate_$$.22000"; then
                rm -f "/tmp/validate_$$.22000"
                debug_print "Found valid handshakes"
                return 0
            fi
            rm -f "/tmp/validate_$$.22000"
        fi
    fi
    
    debug_print "No valid handshakes found"
    return 1
}

# Submit to wpa-sec and return true only if submission was successful
submit_to_stanev() {
    local file="$1"
    local temp_hash="/tmp/submit_verify_$$.22000"
    
    info_print "Verifying capture before submission..."
    
    # Extract and verify handshakes
    if ! hcxpcapngtool -o "$temp_hash" "$file" >/dev/null 2>&1; then
        error_print "Failed to verify handshakes before submission"
        rm -f "$temp_hash"
        return 1
    fi
    
    # Get list of networks being submitted
    local networks=()
    while IFS='*' read -r p1 p2 p3 mac_ap mac_sta essid rest; do
        [ -z "$mac_ap" ] && continue
        mac_ap=$(echo "$mac_ap" | tr '[:upper:]' '[:lower:]')
        essid_decoded=$(echo -n "$essid" | xxd -r -p 2>/dev/null || echo "Unknown")
        networks+=("$mac_ap: $essid_decoded")
    done < "$temp_hash"
    
    if [ ${#networks[@]} -eq 0 ]; then
        error_print "No valid networks to submit"
        rm -f "$temp_hash"
        return 1
    fi
    
    info_print "Submitting ${#networks[@]} networks to wpa-sec..."
    if [ $DEBUG -eq 1 ]; then
        print_section_header "Networks being submitted"
        printf '%s\n' "${networks[@]}" | sort
    fi
    
    # Submit to wpa-sec
    local response
    response=$(curl -s -X POST \
            -F "webfile=@${file}" \
            --cookie "key=PUTYOURAPIKEYHERE" \
            https://wpa-sec.stanev.org/\?submit)
    
    if [ $DEBUG -eq 1 ]; then
        print_section_header "Server Response"
        echo "$response" | grep -A 5 "summary capture file" | head -n 6
    fi
    
    # Check for success
    if echo "$response" | grep -q "EAPOL pairs written to 22000 hash file"; then
        local pairs_written
        pairs_written=$(echo "$response" | grep "EAPOL pairs written to 22000 hash file" | grep -o "[0-9]*")
        success_print "Successfully submitted $pairs_written handshakes to wpa-sec"
        
        # Add networks to submitted.txt and PROCESSED_BSSIDS
        while read -r mac_ap essid; do
            mac_ap=${mac_ap%:}  # Remove colon
            if ! grep -q "^$mac_ap$" "$SUBMITTED_FILE" 2>/dev/null; then
                echo "$mac_ap" >> "$SUBMITTED_FILE"
                PROCESSED_BSSIDS["$mac_ap"]="$essid"  # Add to processed networks
                success_print "Added network: $mac_ap ($essid)"
            fi
        done < <(printf '%s\n' "${networks[@]}" | sort)
        
        rm -f "$temp_hash"
        return 0
    else
        error_print "Submission failed - $(echo "$response" | grep -v "^$" | head -n 1)"
        rm -f "$temp_hash"
        return 1
    fi
}

# Process a single file
process_file() {
    local capture="$1"
    status_print "Processing $(basename "$capture")..."
    ((TOTAL_FILES++))
    
    # Skip non-pcapng files silently
    [[ "$capture" == *.pcapng ]] || return 0
    
    # Step 1: Initial Analysis
    local essid_count
    essid_count=$(analyze_capture "$capture")
    if [ $? -ne 0 ]; then
        error_print "Invalid capture file"
        mv "$capture" "$INVALID_DIR/"
        ((INVALID_FILES++))
        return 1
    fi
    ((VALID_FILES++))
    
    # Step 2: Extract Handshakes
    mapfile -t bssids < <(get_valid_bssids "$capture")
    if [ ${#bssids[@]} -eq 0 ]; then
        error_print "No valid handshakes found"
        mv "$capture" "$INVALID_DIR/"
        return 1
    fi
    
    success_print "Found ${#bssids[@]} networks with handshakes"
    ((TOTAL_HANDSHAKES+=${#bssids[@]}))
    
    # Step 3: Check for new networks
    local new_count=0
    local submitted_count=0
    for bssid in "${bssids[@]}"; do
        if [[ -n "$bssid" ]]; then
            if is_bssid_submitted "$bssid"; then
                ((submitted_count++))
                ((ALREADY_SUBMITTED++))
                SKIPPED_BSSIDS["$bssid"]=1
            else
                ((new_count++))
            fi
        fi
    done
    
    if [ "$new_count" -gt 0 ]; then
        success_print "Found $new_count new networks to submit"
    fi
    [ "$submitted_count" -gt 0 ] && status_print "Skipping $submitted_count already submitted networks"
    
    if [ "$new_count" -eq 0 ]; then
        warning_print "All networks already submitted"
        cleanup_angryoxide_files "$capture"
        return 0
    fi
    
    # Step 4: Filter and submit new networks
    local filtered_file="/tmp/filtered_$$.pcapng"
    if filter_new_handshakes "$capture" "$filtered_file"; then
        status_print "Submitting to wpa-sec.stanev.org..."
        if submit_to_stanev "$filtered_file"; then
            success_print "Successfully submitted $new_count networks"
            mv "$capture" "$PROCESSED_DIR/"
            rm -f "$filtered_file"
            ((SUCCESSFUL_SUBMISSIONS++))
            ((NEW_HANDSHAKES+=new_count))
        else
            error_print "Submission failed"
            rm -f "$filtered_file"
            return 1
        fi
    else
        error_print "Failed to filter handshakes"
        rm -f "$filtered_file"
        return 1
    fi
    
    [ $DEBUG -eq 0 ] && echo # Add spacing between files
    return 0
}

# Show processing summary (simplified for non-debug mode)
show_summary() {
    if [ $DEBUG -eq 1 ]; then
        print_section_header "Processing Summary"
        echo -e "${BOLD}Files processed:${NC} $TOTAL_FILES"
        echo -e "  ${BOLD}Valid captures:${NC} ${GREEN}$VALID_FILES${NC}"
        echo -e "  ${BOLD}Invalid captures:${NC} ${RED}$INVALID_FILES${NC}"
        echo
        print_section_header "Handshake Statistics"
        echo -e "${BOLD}Total handshakes found:${NC} $TOTAL_HANDSHAKES"
        echo -e "${BOLD}New handshakes submitted:${NC} ${GREEN}$NEW_HANDSHAKES${NC}"
        echo -e "${BOLD}Already submitted:${NC} ${YELLOW}$ALREADY_SUBMITTED${NC}"
        echo -e "${BOLD}Successful submissions:${NC} ${GREEN}$SUCCESSFUL_SUBMISSIONS${NC}"
        
        if [ ${#PROCESSED_BSSIDS[@]} -gt 0 ]; then
            print_section_header "Successfully Submitted Networks"
            for bssid in "${!PROCESSED_BSSIDS[@]}"; do
                echo -e "  ${GREEN}•${NC} ${GRAY}${bssid}${NC}"
            done
        fi
        
        if [ ${#SKIPPED_BSSIDS[@]} -gt 0 ]; then
            print_section_header "Skipped Networks"
            for bssid in "${!SKIPPED_BSSIDS[@]}"; do
                echo -e "  ${YELLOW}•${NC} ${GRAY}${bssid}${NC}"
            done
        fi
        echo -e "${BOLD}=========================${NC}"
    else
        echo -e "\n${BOLD}Summary${NC}"
        echo -e "Files processed: $TOTAL_FILES"
        [ $INVALID_FILES -gt 0 ] && echo -e "${RED}Invalid captures: $INVALID_FILES${NC}"
        
        echo -e "\nHandshakes:"
        echo -e "${GREEN}New submitted: $NEW_HANDSHAKES${NC}"
        [ $ALREADY_SUBMITTED -gt 0 ] && echo -e "${YELLOW}Already submitted: $ALREADY_SUBMITTED${NC}"
        
        if [ $SUCCESSFUL_SUBMISSIONS -gt 0 ]; then
            echo -e "\n${GREEN}Successfully submitted networks:${NC}"
            for bssid in "${!PROCESSED_BSSIDS[@]}"; do
                echo -e "  ${GREEN}•${NC} ${PROCESSED_BSSIDS[$bssid]}"
            done
        fi
    fi
}

# Main execution
debug_print "Starting script execution..."

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

# Create required directories
mkdir -p "$CAPTURES_DIR" "$PROCESSED_DIR" "$INVALID_DIR"
touch "$SUBMITTED_FILE"

# Process files in current directory
debug_print "Processing files in current directory..."
shopt -s nullglob
files_found=0

for capture in *.pcapng; do
    [ -f "$capture" ] || continue
    ((files_found++))
    process_file "$capture"
done

# Process files in captures directory
debug_print "Processing files in captures directory..."
if [ -d "$CAPTURES_DIR" ]; then
    for capture in "$CAPTURES_DIR"/*.pcapng; do
        [ -f "$capture" ] || continue
        ((files_found++))
        process_file "$capture"
    done
else
    debug_print "Captures directory not found, skipping"
fi

if [ $files_found -eq 0 ]; then
    error_print "No pcapng files found in current directory or $CAPTURES_DIR/"
    echo "Please provide a pcapng capture file or place it in the $CAPTURES_DIR directory"
    exit 1
fi

# Show processing summary
show_summary

# Clean up at the end
cleanup_temp_files

