import os
import pty
import subprocess
import time
import sys
import signal
import threading
import select
import argparse  # Added for command-line argument parsing
from colorama import init as colorama_init, Fore, Style

# Initialize colorama
colorama_init(autoreset=True)

# Configuration
DEBUG = os.getenv('DEBUG', '0') == '1'

# Update this if needed, this script tracks devices by name
PRIMARY_DEVICE = "RTL's Hearing Device"
SECONDARY_DEVICE = "AudioStream Adapter"

REPO_URL = "https://github.com/thewierdnut/asha_pipewire_sink.git"
CLONE_DIR = os.path.expanduser("~/asha_pipewire_sink")
BUILD_DIR = os.path.join(CLONE_DIR, "build")
EXECUTABLE = os.path.join(BUILD_DIR, "asha_pipewire_sink")

RETRY_DELAY = 0  # Delay in seconds between retries

# Global flag to ensure perform_gatt_operations triggers only once.
gatt_triggered = False

def debug_print(message):
    if DEBUG:
        print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")

def run_command(command, check=True, capture_output=False, input_text=None, cwd=None):
    debug_print(f"Running command: {command} in cwd: {cwd}")
    result = subprocess.run(
        command,
        shell=True,
        check=check,
        text=True,
        capture_output=capture_output,
        input=input_text,
        cwd=cwd
    )
    return result.stdout.strip() if capture_output else None

def start_asha():
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Checking ASHA PipeWire Sink...")

    if not os.path.isdir(CLONE_DIR):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Cloning ASHA repository...")
        run_command(f"git clone {REPO_URL} {CLONE_DIR}")

    if not os.path.isfile(EXECUTABLE):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Building ASHA PipeWire Sink...")
        os.makedirs(BUILD_DIR, exist_ok=True)
        run_command("cmake ..", cwd=BUILD_DIR)
        run_command("make", cwd=BUILD_DIR)

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Launching ASHA PipeWire Sink using PTY...")

    # Fork a child process attached to a PTY so that the child (executable)
    # thinks it is running in an interactive terminal, preserving ANSI output.
    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        # Child process: execute the ASHA executable.
        try:
            os.execvp(EXECUTABLE, [EXECUTABLE])
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to execute ASHA: {e}")
            sys.exit(1)
    else:
        # Parent returns the child pid and PTY file descriptor.
        return (child_pid, master_fd)

def stream_asha_output(asha_handle, clean_state=False):
    global gatt_triggered
    child_pid, master_fd = asha_handle
    buffer = b""
    
    while True:
        try:
            rlist, _, _ = select.select([master_fd], [], [], 0.1)
            if master_fd in rlist:
                chunk = os.read(master_fd, 1024)
                if not chunk:
                    break  # EOF reached
                buffer += chunk
                # Process complete lines
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    decoded_line = line.decode(errors="ignore")
                    # Print the line with the [ASHA] tag only if DEBUG is enabled
                    if DEBUG:
                        print(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded_line}")
                    # Check for trigger keywords within the decoded line
                    if ("on_change_state" in decoded_line and 
                        ("new: PAUSED" in decoded_line or "new: STREAMING" in decoded_line) and 
                        not gatt_triggered and not clean_state):
                        gatt_triggered = True
                        # Brief sleep to allow output processing
                        time.sleep(0.1)
                        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Detected PAUSED state. Triggering GATT operations...")
                        for i in range(3):
							# Just to make sure its working
                            perform_gatt_operations(PRIMARY_DEVICE)
            else:
                # No data available; small pause to avoid busy-looping.
                time.sleep(0.1)
        except Exception as e:
            debug_print(f"Error reading from ASHA PTY: {e}")
            break


def initialize_bluetooth():
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Initializing Bluetooth stack...")
    run_command("rfkill unblock bluetooth")
    run_command("bluetoothctl power on")
    run_command("bluetoothctl agent on")

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Waiting for Bluetooth service to become ready...")
    while True:
        output = run_command("bluetoothctl show", capture_output=True)
        if "Powered: yes" in output:
            break
        time.sleep(RETRY_DELAY)
        run_command("bluetoothctl power on")
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Bluetooth is powered and agent is active.")

def get_mac_address(device_name):
    output = run_command("bluetoothctl devices", capture_output=True)
    for line in output.splitlines():
        if device_name in line:
            return line.split()[1]
    return None

def connect_device(device_name):
    mac_address = get_mac_address(device_name)
    if not mac_address:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
        return False

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting to connect to {device_name} ({mac_address})...")

    while True:
        try:
            mac_address = get_mac_address(device_name)
            if not mac_address:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found. Retrying lookup...")
                time.sleep(RETRY_DELAY)
                continue
            output = run_command(f"bluetoothctl connect {mac_address}", capture_output=True)
            if "Failed to connect" in output:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection failed: {output}")
            else:
                time.sleep(RETRY_DELAY)
                info_output = run_command(f"bluetoothctl info {mac_address}", capture_output=True)
                if "Connected: yes" in info_output:
                    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Connected to {device_name}!")
                    return True
                else:
                    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection unstable. Retrying...")
            print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
        except KeyboardInterrupt:
            sys.exit(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Exiting on user interrupt.")
        except Exception as e:
            debug_print(f"Exception in connect_device: {e}")
            time.sleep(RETRY_DELAY)
            continue

def remove_and_reconnect(device_name):
    mac_address = get_mac_address(device_name)
    if not mac_address:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
        return False

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Removing device {device_name} ({mac_address})...")
    run_command(f"bluetoothctl remove {mac_address}")
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Device removed. Restarting connection attempts...")
    time.sleep(RETRY_DELAY)
    return connect_device(device_name)

def perform_gatt_operations(device_name):
    mac_address = get_mac_address(device_name)
    if not mac_address:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
        return False

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing GATT operations on {device_name} ({mac_address})...")

    commands = f"""connect {mac_address}
    gatt.select-attribute 00e4ca9e-ab14-41e4-8823-f9e70c7e91df
    gatt.write 0xff
    exit
    """ 
    # the attribute uuid may differ please use this bash script:
    # Do save this script and chomod it and run it while this python script running with -c state
    """ 

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

    """
    process = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = process.communicate(commands)
    
    if process.returncode == 0:
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} GATT operations completed successfully on {device_name}.")
        return True
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} GATT operations failed on {device_name}. Error: {stderr}")
        return False

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Connect to Bluetooth devices and manage ASHA PipeWire Sink.')
    parser.add_argument('-c', '--clean-state', action='store_true', 
                        help='Skip automatic GATT operations on state change')
    args = parser.parse_args()

    asha_handle = None
    try:
        initialize_bluetooth()

        while True:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying to connect to primary device: {PRIMARY_DEVICE}...")
            if connect_device(PRIMARY_DEVICE):
                break

            response = input(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Primary device failed. Remove and retry? (y/n): ").strip().lower()
            if response == 'y':
                if remove_and_reconnect(PRIMARY_DEVICE):
                    break

            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying to connect to secondary device: {SECONDARY_DEVICE}...")
            if connect_device(SECONDARY_DEVICE):
                break

            print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Both devices failed. Restarting connection attempts...")
            time.sleep(RETRY_DELAY)
        # Do comment the if and else if needed
        
        #response = input(f"{Fore.CYAN}[PROMPT]{Style.RESET_ALL} Do you want to start ASHA PipeWire Sink? (y/n): ").strip().lower()
        # if response == 'y':
        asha_handle = start_asha()
        asha_thread = threading.Thread(target=stream_asha_output, args=(asha_handle, args.clean_state), daemon=True)
        asha_thread.start()

        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} ASHA PipeWire Sink is running. Press Ctrl+C to interrupt and exit.")
        while True:
            time.sleep(1)
        # else:
        #     print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Skipping ASHA connection.")

    except KeyboardInterrupt:
        print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} KeyboardInterrupt received. Terminating ASHA process and exiting...")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An exception occurred: {e}")
    finally:
        if asha_handle is not None:
            try:
                # Kill the child process associated with the PTY.
                child_pid, master_fd = asha_handle
                os.kill(child_pid, signal.SIGTERM)
                print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} ASHA process terminated.")
            except Exception as e:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Could not terminate ASHA process: {e}")
        sys.exit(0)

if __name__ == "__main__":
    main()
