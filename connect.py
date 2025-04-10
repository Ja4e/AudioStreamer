import os
import pty
import subprocess
import time
import sys
import signal
import threading
import select
import argparse
from colorama import init as colorama_init, Fore, Style

# Initialize colorama
colorama_init(autoreset=True)

# Configuration
DEBUG = os.getenv('DEBUG', '0') == '1'

# Update this if needed, this script tracks devices by name
PRIMARY_DEVICE = "RTL's Hearing Device"
SECONDARY_DEVICE = "AudioStream Adapter"

GATT_ATTRIBUTE= "00e4ca9e-ab14-41e4-8823-f9e70c7e91df" # Your device's GATT ATTRIBUTE may differ from mine try to use volume.sh provided in the repo and test

# This script is very sophiscated, it have higher chances to get a sucessful connection rather than having reported org.bluez.Error.Failed le-connection-abort-by-local issues by bluetoothctl
# I am using Intel AX210 with it, um i think this script should work other functional bluetooth adapter well just incase. Its now very comparable to apple's bluetooth approach to ASHA devices

REPO_URL = "https://github.com/thewierdnut/asha_pipewire_sink.git"
CLONE_DIR = os.path.expanduser("~/asha_pipewire_sink")
BUILD_DIR = os.path.join(CLONE_DIR, "build")
EXECUTABLE = os.path.join(BUILD_DIR, "asha_pipewire_sink")

RETRY_DELAY = 0  # Delay in seconds between retries

# Global variables for scan management
scan_process = None
scan_thread = None
scan_running = threading.Event()

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

def start_scan():
	global scan_process, scan_thread
	if scan_running.is_set():
		return

	def scan_thread_function():
		global scan_process
		try:
			scan_process = subprocess.Popen(
				['bluetoothctl'],
				stdin=subprocess.PIPE,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
				bufsize=1,
				universal_newlines=True
			)
			scan_process.stdin.write('scan on\n')
			scan_process.stdin.flush()
			scan_running.set()
			while scan_running.is_set():
				time.sleep(0.1)
		except Exception as e:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scan thread failed: {e}")
		finally:
			if scan_process:
				scan_process.stdin.write('scan off\n')
				scan_process.stdin.flush()
				time.sleep(1)
				scan_process.terminate()
				scan_process = None

	scan_thread = threading.Thread(target=scan_thread_function, daemon=True)
	scan_thread.start()
	time.sleep(0.4)  # Allow time for scan to start

def stop_scan():
	global scan_process, scan_thread
	if not scan_running.is_set():
		return

	scan_running.clear()
	if scan_thread:
		scan_thread.join(timeout=2)
		scan_thread = None

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

	# Fork a child process attached to a PTY
	child_pid, master_fd = pty.fork()
	if child_pid == 0:
		try:
			os.execvp(EXECUTABLE, [EXECUTABLE])
		except Exception as e:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to execute ASHA: {e}")
			sys.exit(1)
	else:
		return (child_pid, master_fd)

def stream_asha_output(asha_handle, clean_state, shutdown_event, asha_restart_event):
	global gatt_triggered
	child_pid, master_fd = asha_handle
	buffer = b""

	while not shutdown_event.is_set():
		try:
			rlist, _, _ = select.select([master_fd], [], [], 0.1)
			if master_fd in rlist:
				chunk = os.read(master_fd, 1024)
				if not chunk:
					break  # EOF reached
				buffer += chunk
				while b"\n" in buffer:
					line, buffer = buffer.split(b"\n", 1)
					decoded_line = line.decode(errors="ignore")
					if DEBUG:
						print(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded_line}")
					
					if "Connected: false" in decoded_line and (PRIMARY_DEVICE in decoded_line or SECONDARY_DEVICE in decoded_line):
						print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} ASHA reports device disconnected.")
						asha_restart_event.set()
						return

					if ("on_change_state" in decoded_line and 
						("new: PAUSED" in decoded_line or "new: STREAMING" in decoded_line) and 
						not gatt_triggered and not clean_state):
						gatt_triggered = True
						time.sleep(0.1)
						print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Detected PAUSED state. Triggering GATT operations...")
						for i in range(3):
							time.sleep(0.2)
							perform_gatt_operations(PRIMARY_DEVICE)
			else:
				time.sleep(0.1)
		except Exception as e:
			if not shutdown_event.is_set():
				debug_print(f"Error reading from ASHA PTY: {e}")
			break
	debug_print("ASHA output streaming thread exiting")

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

def get_all_mac_addresses(device_name):
	output = run_command("bluetoothctl devices", capture_output=True)
	addresses = []
	for line in output.splitlines():
		if device_name in line:
			parts = line.strip().split()
			if len(parts) >= 2:
				addresses.append(parts[1])
	return addresses

def connect_device(device_name):
	mac_addresses = get_all_mac_addresses(device_name)
	
	if not mac_addresses:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
		return False

	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Found {len(mac_addresses)} MAC addresses for {device_name}")

	for mac_address in mac_addresses:
		print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting connection to {mac_address}...")
		try:
			output = run_command(f"bluetoothctl connect {mac_address}", capture_output=True)
			if "Failed to connect" in output:
				print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection failed: {output}")
				run_command(f"bluetoothctl remove {mac_address}", check=False)
				continue
			
			time.sleep(RETRY_DELAY)
			info_output = run_command(f"bluetoothctl info {mac_address}", capture_output=True)
			if "Connected: yes" in info_output:
				print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Connected to {device_name} via {mac_address}!")
				return True
			else:
				print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection unstable. Trying next address...")
				run_command(f"bluetoothctl remove {mac_address}", check=False)
				
		except Exception as e:
			debug_print(f"Connection error: {e}")
			continue

	print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} All MAC addresses failed for {device_name}")
	return False

def scan_and_connect():
	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting BLE scan...")
	start_scan()
	time.sleep(10)
	stop_scan()
	
	devices = {}
	output = run_command("bluetoothctl devices", capture_output=True)
	for line in output.splitlines():
		parts = line.strip().split()
		if len(parts) >= 2:
			mac = parts[1]
			name = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
			devices[mac] = name

	print(f"\n{Fore.CYAN}[DISCOVERED DEVICES]{Style.RESET_ALL}")
	for mac, name in devices.items():
		print(f"{mac}: {name}")

	while True:
		selection = input(f"\n{Fore.CYAN}[INPUT]{Style.RESET_ALL} Enter MAC address or device name to connect (q to quit): ").strip()
		if selection.lower() == 'q':
			return False
			
		for mac, name in devices.items():
			if selection.lower() == mac.lower() or selection.lower() in name.lower():
				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting connection to {mac} ({name})...")
				output = run_command(f"bluetoothctl connect {mac}", capture_output=True, check=False)
				if "Connection successful" in output:
					print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Connected to {name}!")
					return True
				else:
					print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Connection failed")
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No matching device found")

def remove_and_reconnect(device_name):
	mac_address = get_all_mac_addresses(device_name)
	if not mac_address:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
		return False

	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Removing device {device_name} ({mac_address})...")
	run_command(f"bluetoothctl remove {mac_address}")
	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Device removed. Restarting connection attempts...")
	time.sleep(RETRY_DELAY)
	return connect_device(device_name)

def perform_gatt_operations(device_name):
	mac_addresses = get_all_mac_addresses(device_name)
	if not mac_addresses:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
		return False

	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing GATT operations on {device_name}...")

	for mac_address in mac_addresses:
		print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying MAC: {mac_address}...")
		commands = f"""connect {mac_address}
		gatt.select-attribute {GATT_ATTRIBUTE}
		gatt.write 0xff
		exit
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
			print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} GATT operations completed on {mac_address}!")
			return True
		else:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed on {mac_address}: {stderr}")

	print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} All MAC addresses failed for GATT operations")
	return False

def main():
	parser = argparse.ArgumentParser(description='Connect to Bluetooth devices and manage ASHA PipeWire Sink.')
	parser.add_argument('-c', '--clean-state', action='store_true', 
						help='Skip automatic GATT operations on state change')
	parser.add_argument('-r', '--reconnect', action='store_true',
						help='Enable automatic ASHA restart if device disconnects')
	parser.add_argument('-d', '--disconnect', action='store_true',
						help='Disconnect upon Keyboard Interrupt')
	args = parser.parse_args()

	shutdown_event = threading.Event()
	asha_restart_event = threading.Event()

	try:
		# Main connection loop
		while not shutdown_event.is_set():
			# Initialize Bluetooth fresh on each restart
			global gatt_triggered
			gatt_triggered = False
			
			initialize_bluetooth()
			
			print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Enabling bluetoothctl scan...")
			run_command("bluetoothctl discoverable on", check=False)
			start_scan()
			
			# Device connection loop
			connected = False
			while not connected and not shutdown_event.is_set():
				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying primary device: {PRIMARY_DEVICE}...")
				if connect_device(PRIMARY_DEVICE):
					connected = True
					break

				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying secondary device: {SECONDARY_DEVICE}...")
				if connect_device(SECONDARY_DEVICE):
					connected = True
					break

				print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Retrying in {RETRY_DELAY} seconds...")
				time.sleep(RETRY_DELAY)

			if not connected:
				print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to connect to any device")
				break
			
			print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Disabling bluetoothctl scan...")
			stop_scan()
			run_command("bluetoothctl discoverable off", check=False)

			# ASHA management loop
			while not shutdown_event.is_set():
				gatt_triggered = False

				# Start ASHA sink
				asha_handle = start_asha()
				asha_thread = threading.Thread(
					target=stream_asha_output,
					args=(asha_handle, args.clean_state, shutdown_event, asha_restart_event),
					daemon=True
				)
				asha_thread.start()

				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} ASHA PipeWire Sink is running. Press Ctrl+C to exit.")

				try:
					# Wait for exit or restart condition
					while not shutdown_event.is_set() and not asha_restart_event.is_set():
						time.sleep(1)
				except KeyboardInterrupt:
					print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} KeyboardInterrupt received. Exiting...")
					shutdown_event.set()
					break

				# Handle restart condition
				if asha_restart_event.is_set():
					print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Restarting Bluetooth stack...")
					try:
						# Cleanup ASHA
						os.kill(asha_handle[0], signal.SIGTERM)
						asha_thread.join(timeout=2)
					except Exception as e:
						print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} ASHA cleanup error: {e}")

					# Cleanup Bluetooth
					run_command("bluetoothctl disconnect", check=False)
					run_command("bluetoothctl power off", check=False)
					
					if args.reconnect:
						print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Preparing for reconnection...")
						asha_restart_event.clear()
						break  # Exit ASHA loop to restart entire process
					else:
						shutdown_event.set()
						break

	except Exception as e:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An error occurred: {e}")
		shutdown_event.set()
	finally:
		# Final cleanup
		print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing final cleanup...")
		shutdown_event.set()
		stop_scan()
		run_command("bluetoothctl discoverable off", check=False)
		if args.disconnect:
			run_command("bluetoothctl power off", check=False)
		else:
			None
		
		if 'asha_handle' in locals() and asha_handle is not None:
			try:
				os.kill(asha_handle[0], signal.SIGTERM)
				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Terminated ASHA process.")
			except Exception as e:
				print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Error terminating ASHA process: {e}")
		
		sys.exit(0)

if __name__ == "__main__":
	while True:
		try:
			main()
		except KeyboardInterrupt:
			exit()
