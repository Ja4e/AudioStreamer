#!/bin/bash

# Function: List GATT characteristics using bluetoothctl.
list_gatt_characteristics() {
    local device_mac=$1
    # Select the device first, then enter the GATT menu and list attributes.
    echo -e "select $device_mac\nmenu gatt\nlist-attributes\nexit" | bluetoothctl
}

# Function: Get attribute information for a specific characteristic.
get_attribute_info() {
    local device_mac=$1
    local uuid=$2
    # Select the device, then request attribute info for the given UUID.
    echo -e "select $device_mac\nmenu gatt\nattribute-info $uuid\nexit" | bluetoothctl
}

# Function: Attempt to write 0xff to a given characteristic UUID.
try_write_characteristic() {
    local device_mac=$1
    local uuid=$2
    # First select the attribute before writing.
    echo -e "select $device_mac\nmenu gatt\nselect-attribute $uuid\nwrite 0xff\nexit" | bluetoothctl 2>&1
}

# Main function:
main() {
    local device_mac=$1
    local output_file=$2

    if [ -z "$device_mac" ] || [ -z "$output_file" ]; then
        echo "Usage: $0 <device-mac-address> <output-file>"
        exit 1
    fi
	
	echo "Warning! this script will attempt to set that volume to its maximum, please do lower the volume if needed"
	sleep 2
	echo "Warning! this script will attempt to set that volume to its maximum, please do lower the volume if needed"
	sleep 2
	echo "Warning! this script will attempt to set that volume to its maximum, please do lower the volume if needed"
	sleep 3
	
    echo "[*] Fetching GATT characteristics for device $device_mac ..."
    characteristics=$(list_gatt_characteristics "$device_mac")

    # Empty the output file if it exists.
    > "$output_file"

    # Process the output line-by-line.
    while IFS= read -r line; do
        # Extract a UUID in the standard 128-bit format (8-4-4-4-12)
        if [[ $line =~ ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}) ]]; then
            uuid="${BASH_REMATCH[1]}"
            echo "[*] Found UUID: $uuid"

            # Retrieve attribute information for the UUID.
            attr_info=$(get_attribute_info "$device_mac" "$uuid")
            # Check if the attribute information indicates write support.
            if echo "$attr_info" | grep -qi "write-without-response"; then
                echo "[*] UUID $uuid supports write-without-response."

                # Attempt the write and capture the output.
                result=$(try_write_characteristic "$device_mac" "$uuid")
                # Check for error outputs from the attempt.
                if echo "$result" | grep -qi "error"; then
                    echo "[-] Error while writing to $uuid; skipping this UUID."
                    continue
                fi

                echo "[+] Write command executed on $uuid (0xff sent)."
                # Force the prompt to read from the terminal.
                read -p "[?] Did you observe any effect from writing to $uuid? (y/n): " effect_response </dev/tty
                if [[ "$effect_response" =~ ^[Yy]$ ]]; then
                    echo "[+] UUID $uuid is working." | tee -a "$output_file"
                    break
                else
                    echo "[-] No observable effect for $uuid."
                fi

            else
                echo "[-] UUID $uuid does not support write – skipping."
            fi
        fi
    done <<< "$characteristics"

    echo "[*] Testing complete. Working writable UUIDs have been saved to: $output_file"
}

# Call the main function with provided command-line arguments.
main "$@"
