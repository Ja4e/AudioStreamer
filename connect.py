#!/usr/bin/env python3
"""
MIT License
Copyright (c) 2025 Saul Gman
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
"""
This is a very sophisticated script that should improve the chances of a successful connection
reduces the chances of getting reported org.bluez.Error.Failed connection abort-by-local issues.
Tested with Intel AX210 – it should also work with other functional Bluetooth adapters.
It is now comparable to Apple's Bluetooth approach to ASHA devices.
"""
import os
import pty
import subprocess
import time
import sys
import signal
import threading
import select
import argparse
import re
import asyncio
import random
from colorama import init as colorama_init, Fore, Style
import dbus
import dbus.exceptions
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

colorama_init(autoreset=True)

# ------------------------------
# CONFIGURATION
# ------------------------------
DEBUG = os.getenv('DEBUG', '0') == '1'
PRIMARY_FILTER = "RTL's Hearing Device" # THe name of your device that setup at first
SECONDARY_FILTER = "AudioStream Adapter" # The default name of your device
REPO_URL = "https://github.com/thewierdnut/asha_pipewire_sink.git"  # please do read these documentation in this its only 1 page long
CLONE_DIR = os.path.expanduser("~/asha_pipewire_sink")
BUILD_DIR = os.path.join(CLONE_DIR, "build")
EXECUTABLE = os.path.join(BUILD_DIR, "asha_pipewire_sink")
GATT_ATTRIBUTE = "00e4ca9e-ab14-41e4-8823-f9e70c7e91df" # update if your volume is not good enough, use ./volume.sh while running this script with -c  in clean mode to find them if connected successfully 
VOLUME_VALUE = "0xff"
RETRY_DELAY = random.uniform(0.4, 1.0)
DEFAULT_RETRY_INTERVAL = random.uniform(0.4, 1.0)
DEFAULT_DELAY_AFTER_CONNECT = random.uniform(0.4, 1.0)
MAX_TIMEOUT = random.uniform(600, 1200)
BLACKLIST = ["AudioStream Adapter DFU"] # Just in case your device has DFU, renamed here if it has it.

# Global state management
gatt_triggered = False
shutdown_evt = threading.Event()         # Renamed from shutdown_event
reconnect_evt = threading.Event()          # Renamed from reconnect_trigger
asha_restart_evt = threading.Event()       # Renamed from asha_restart_event
processed_devices = set()
processed_lock = threading.Lock()
connected_list_lock = threading.Lock()
global_connected_list = []  # List of tuples: (mac, device_name)

# Process/Thread handles
asha_handle = None  # Tuple: (pid, master_fd)
scan_thread = None
adv_loop = None
adv_thread = None
ad_obj = None

# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------
def debug_print(message):
	if DEBUG:
		print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")

def run_command(command, check=True, capture_output=False, input_text=None, cwd=None, debug=True):
	if debug:
		debug_print(f"Running command: {command} [cwd={cwd}]")
	try:
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
	except subprocess.CalledProcessError as e:
		debug_print(f"Command error: {e}")
		return e.stdout.strip() if capture_output and e.stdout else ''

# ------------------------------
# BLUETOOTH MANAGEMENT
# ------------------------------
def initialize_bluetooth():
	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Initializing Bluetooth...")
	run_command("rfkill unblock bluetooth")
	run_command("bluetoothctl power on")
	
	if args.pair:
		run_command("bluetoothctl discoverable on")
		run_command("bluetoothctl agent KeyboardDisplay")
	else:
		run_command("bluetoothctl agent on")
	
	run_command("bluetoothctl pairable on")
	
	while True:
		output = run_command("bluetoothctl show", capture_output=True)
		if "Powered: yes" in output:
			break
		time.sleep(1)
	
	print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Bluetooth initialized")

def get_devices_by_types():
	output = run_command("bluetoothctl devices", capture_output=True, debug=False)
	primary, secondary = [], []
	device_pattern = re.compile(r'^Device (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) (.*)$')
	
	for line in output.splitlines():
		match = device_pattern.match(line.strip())
		if match:
			mac, name = match.groups()[0], match.groups()[2]
			if any(bl in name for bl in BLACKLIST):
				continue
			if PRIMARY_FILTER in name:
				primary.append((mac, name))
			elif SECONDARY_FILTER in name:
				secondary.append((mac, name))
	
	return primary, secondary

# ------------------------------
# ADVERTISEMENT MANAGEMENT
# ------------------------------
class Advertisement(dbus.service.Object):
	PATH_BASE = '/org/bluez/example/advertisement'
	
	def __init__(self, bus, index, ad_type, service_uuids, local_name, includes):
		self.path = self.PATH_BASE + str(index)
		self.bus = bus
		self.ad_type = ad_type
		self.service_uuids = service_uuids
		self.local_name = local_name
		self.includes = includes
		dbus.service.Object.__init__(self, bus, self.path)

	def get_properties(self):
		return {
			'org.bluez.LEAdvertisement1': {
				'Type': self.ad_type,
				'ServiceUUIDs': dbus.Array(self.service_uuids, signature='s'),
				'Includes': dbus.Array(self.includes, signature='s'),
				'LocalName': self.local_name,
			}
		}

	def get_path(self):
		return dbus.ObjectPath(self.path)

	@dbus.service.method('org.bluez.LEAdvertisement1')
	def Release(self):
		print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Advertisement released")

def start_advertising(disabled=False):
	global ad_obj, adv_loop, adv_thread
	if disabled:
		return

	try:
		dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
		bus = dbus.SystemBus()
		
		adapter = bus.get_object('org.bluez', '/org/bluez/hci0')
		ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')
		
		ad_obj = Advertisement(
			bus, 0, "peripheral",
			[GATT_ATTRIBUTE], "ASHA Stream", ["tx-power"]
		)
		
		ad_manager.RegisterAdvertisement(
			ad_obj.get_path(), {},
			reply_handler=lambda: print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Advertisement registered"),
			error_handler=lambda e: print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to register advertisement: {e}")
		)
		
		adv_loop = GLib.MainLoop()
		adv_thread = threading.Thread(target=adv_loop.run, daemon=True)
		adv_thread.start()
	except Exception as e:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Advertising setup failed: {e}")

def stop_advertising(disabled=False):
	global ad_obj, adv_loop, adv_thread
	if disabled or not ad_obj:
		return
	try:
		bus = dbus.SystemBus()
		adapter = bus.get_object('org.bluez', '/org/bluez/hci0')
		ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')
		ad_manager.UnregisterAdvertisement(ad_obj.get_path())

		try:
			ad_obj.remove_from_connection()
		except Exception as inner_error:
			print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Failed to remove advertisement from connection: {inner_error}")

		ad_obj = None

		if adv_loop:
			adv_loop.quit()

		if adv_thread:
			adv_thread.join(timeout=2)
	except Exception as e:
		print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Error stopping advertisement: {e}")

# ------------------------------
# SCAN MANAGEMENT
# ------------------------------
def start_continuous_scan():
	def scan_worker():
		new_pattern = re.compile(r'^\[NEW\] Device (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) (.*)$')
		chg_pattern = re.compile(r'^\[CHG\] Device (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) Name: (.*)$')
		
		while not shutdown_evt.is_set():
			try:
				proc = subprocess.Popen(
					["bluetoothctl"],
					stdin=subprocess.PIPE,
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT,
					text=True
				)
				proc.stdin.write("scan on\n")
				proc.stdin.flush()
				
				while not shutdown_evt.is_set():
					line = proc.stdout.readline()
					if not line:
						continue
					line = line.strip()
					
					mac = None
					name = None
					
					new_match = new_pattern.match(line)
					if new_match:
						mac = new_match.group(1)
						name = new_match.group(3)
					else:
						chg_match = chg_pattern.match(line)
						if chg_match:
							mac = chg_match.group(1)
							name = chg_match.group(3)
					
					if mac and name:
						if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
							debug_print(f"Invalid MAC {mac} from line: {line}")
							continue
						with processed_lock:
							if mac not in processed_devices:
								processed_devices.add(mac)
								threading.Thread(
									target=handle_new_device,
									args=(mac, name),
									daemon=True
								).start()
				try:
					proc.stdin.write("scan off\n")
					proc.stdin.flush()
				except Exception:
					pass
				proc.terminate()
				proc.wait(timeout=2)
				break
			except Exception as e:
				if not shutdown_evt.is_set():
					print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scan error: {e}")
				time.sleep(1)
	
	threading.Thread(target=scan_worker, daemon=True).start()

# ------------------------------
# DEVICE CONNECTION HANDLING
# ------------------------------
async def async_connect_specific(mac_address):
	try:
		return await asyncio.wait_for(_connect_attempt(mac_address), timeout=MAX_TIMEOUT)
	except asyncio.TimeoutError:
		return False

async def _connect_attempt(mac_address):
	if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac_address):
		debug_print(f"Invalid MAC address in connect attempt: {mac_address}")
		return False

	attempts = 0
	while not shutdown_evt.is_set() and attempts < 3:
		try:
			output = await asyncio.to_thread(
				run_command, 
				f"bluetoothctl connect {mac_address}", 
				capture_output=True
			)
			
			if any(s in output for s in ["Connection successful", "already connected"]):
				info_output = await asyncio.to_thread(
					run_command, 
					f"bluetoothctl info {mac_address}", 
					capture_output=True
				)
				if "Connected: yes" in info_output:
					return True

			attempts += 1
			await asyncio.sleep(DEFAULT_RETRY_INTERVAL)
		except Exception as e:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Connection attempt failed: {e}")
			attempts += 1
			await asyncio.sleep(DEFAULT_RETRY_INTERVAL * 2)
	
	return False

def handle_new_device(mac, name):
	if any(black in name for black in BLACKLIST):
		print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Device {name} ({mac}) is blacklisted. Skipping connection.")
		return

	if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid MAC address: {mac}")
		with processed_lock:
			processed_devices.discard(mac)
		return

	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} New device detected: {name} ({mac})")
	
	success = asyncio.run(async_connect_specific(mac))
	if success:
		with connected_list_lock:
			if not any(m == mac for m, _ in global_connected_list):
				global_connected_list.append((mac, name))
				print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Connected to {name} ({mac})!")
				run_command("bluetoothctl pairable off", check=False)
				run_command(f"bluetoothctl trust {mac}", check=False)
	else:
		with processed_lock:
			processed_devices.discard(mac)

# ------------------------------
# ASHA PIPEWIRE SINK MANAGEMENT
# ------------------------------
def start_asha():
	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Initializing ASHA sink...")
	
	if not os.path.isdir(CLONE_DIR):
		print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Cloning repository...")
		run_command(f"git clone {REPO_URL} {CLONE_DIR}")
		
	if not os.path.isfile(EXECUTABLE):
		print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Building ASHA sink...")
		os.makedirs(BUILD_DIR, exist_ok=True)
		run_command("cmake ..", cwd=BUILD_DIR)
		run_command("make", cwd=BUILD_DIR)

	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting ASHA sink...")
	master, slave = pty.openpty()
	try:
		proc = subprocess.Popen(
			[EXECUTABLE],
			preexec_fn=os.setsid,
			stdin=slave,
			stdout=slave,
			stderr=slave,
			close_fds=True
		)
		os.close(slave)
		return proc.pid, master
	except Exception as e:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} ASHA startup failed: {e}")
		os.close(master)
		raise

def stream_asha_output(asha_handle, shutdown_evt, asha_restart_evt):
	global gatt_triggered, global_connected_list
	child_pid, master_fd = asha_handle
	buffer = b""
	
	while not shutdown_evt.is_set():
		try:
			rlist, _, _ = select.select([master_fd], [], [], 0.1)
			if master_fd in rlist:
				data = os.read(master_fd, 1024)
				if not data:
					break
				buffer += data
				
				while b"\n" in buffer:
					line, buffer = buffer.split(b"\n", 1)
					decoded = line.decode(errors="ignore")
					
					if DEBUG:
						print(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded}")
					
					if  (("Connected: false" in decoded) or 
						("Assertion `!m_sock' failed." in decoded) or 
						("GDBus.Error:org.bluez.Error.InProgress: In Progress" in decoded) or 
						("GDBus.Error:org.freedesktop.DBus.Error.NoReply: Remote peer disconnected" in decoded) or 
						#("GDBus.Error:org.bluez.Error.Failed: Operation failed with ATT error: 0x0e") or 
						("Timeout was reached" in decoded)):
						print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} ASHA connection dropped")
						gatt_triggered = False
						if args.reconnect:
							with connected_list_lock:
								global_connected_list.clear()
							reconnect_evt.set()
							asha_restart_evt.set()
						return
					
					if ("on_change_state" in decoded and 
						("new: PAUSED" in decoded or "new: STREAMING" in decoded) and 
						not gatt_triggered and not args.clean_state):
						
						gatt_triggered = True
						print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Detected audio state change")
						
						with connected_list_lock:
							for mac, name in global_connected_list:
								print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Triggering GATT operations on {name}...")
								for i in range(3):
									time.sleep(0.2)
									perform_gatt_operations(mac, name)
					
		except Exception as e:
			if not shutdown_evt.is_set():
				print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} ASHA stream error: {e}")
			break

# ------------------------------
# GATT OPERATIONS
# ------------------------------
def perform_gatt_operations(mac_address, device_name):
	print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting GATT operations for {device_name}")
	try:
		process = subprocess.Popen(
			["bluetoothctl"],
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
		)
		commands = f"""connect {mac_address}
gatt.select-attribute {GATT_ATTRIBUTE}
gatt.write {VOLUME_VALUE}
exit
"""
		stdout, stderr = process.communicate(commands)
		
		if process.returncode == 0:
			print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} GATT operations completed")
			return True
		else:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} GATT operations failed: {stderr.strip()}")
			return False
	except Exception as e:
		print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} GATT exception: {e}")
		return False

# ------------------------------
# DEVICE MONITORING
# ------------------------------
def monitor_mac_changes():
	while not shutdown_evt.is_set():
		try:
			with connected_list_lock:
				current_connected = set(mac for mac, _ in global_connected_list)
			
			output = run_command("bluetoothctl devices", capture_output=True, debug=False)
			actual_connected = set()
			for line in output.splitlines():
				if "Device" in line:
					parts = line.strip().split()
					if len(parts) >= 2:
						actual_connected.add(parts[1])
			
			missing = current_connected - actual_connected
			if missing:
				print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Missing connections: {', '.join(missing)}")
				with connected_list_lock:
					global_connected_list[:] = [
						(mac, name) for mac, name in global_connected_list 
						if mac in actual_connected
					]
				reconnect_evt.set()
			
			time.sleep(5)
		except Exception as e:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Monitor error: {e}")
			time.sleep(2)

# ------------------------------
# ASHA PROCESS TERMINATION
# ------------------------------
def terminate_asha():
	global asha_handle
	if asha_handle:
		child_pid, master_fd = asha_handle
		try:
			pgid = os.getpgid(child_pid)
			print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Terminating ASHA process group {pgid}...")
			os.killpg(pgid, signal.SIGTERM)
			timeout = 5
			end_time = time.time() + timeout
			while True:
				try:
					res = os.waitpid(child_pid, os.WNOHANG)
					if res != (0, 0):
						print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} ASHA process terminated gracefully")
						break
				except ChildProcessError:
					break
				if time.time() > end_time:
					print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Timeout reached; forcing kill")
					os.killpg(pgid, signal.SIGKILL)
					break
				time.sleep(0.1)
		except Exception as e:
			print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error terminating ASHA process: {e}")
		finally:
			try:
				os.close(master_fd)
			except Exception:
				pass
			asha_handle = None

# ------------------------------
# SIGNAL HANDLING & CLEANUP
# ------------------------------
def cleanup():
	global asha_handle
	print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Cleaning up...")
	stop_advertising(args.disable_advertisement)
	if args.disconnect:
		run_command("bluetoothctl agent off", check=False)
		run_command("bluetoothctl power off", check=False)
	if asha_handle:
		terminate_asha()
	run_command("bluetoothctl pairable off", check=False)
	shutdown_evt.set()
	print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Cleanup complete")

def signal_handler(sig, frame):
	print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Received signal {sig}, shutting down...")
	cleanup()
	sys.exit(0)

# ------------------------------
# MAIN LOGIC
# ------------------------------
def main():
	global args, asha_handle, global_connected_list

	parser = argparse.ArgumentParser(description="Bluetooth ASHA Manager")
	parser.add_argument('-c', '--clean-state', action='store_true',
						help='Skip automatic GATT operations on state change')
	parser.add_argument('-r', '--reconnect', action='store_true',
						help='Enable automatic ASHA restart if device disconnects')
	parser.add_argument('-d', '--disconnect', action='store_true',
						help='Disconnect Bluetooth devices on exit')
	parser.add_argument('-p', '--pair', action='store_true',
						help='Enable persistent pairing mode')
	parser.add_argument('-da', '--disable-advertisement', action='store_true',
						help='Disable Bluetooth LE advertising')
	global args
	args = parser.parse_args()
	
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	
	try:
		initialize_bluetooth()
		start_advertising(args.disable_advertisement)
		start_continuous_scan()
		
		threading.Thread(target=monitor_mac_changes, daemon=True).start()
		
		while not shutdown_evt.is_set():
			# Process devices from bluetoothctl output
			primary, secondary = get_devices_by_types()
			all_devices = primary + secondary
			
			if all_devices:
				with processed_lock, connected_list_lock:
					current_macs = set(mac for mac, _ in all_devices)
					new_macs = current_macs - processed_devices
					for mac in new_macs:
						name = next((name for m, name in all_devices if m == mac), "Unknown")
						processed_devices.add(mac)
						threading.Thread(
							target=handle_new_device,
							args=(mac, name),
							daemon=True
						).start()
			
			# Check if ASHA should be started or restarted only when there is at least one connected device.
			with connected_list_lock:
				if not asha_handle and global_connected_list:
					print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting ASHA sink as a connection is active")
					asha_handle = start_asha()
					# Start a thread to monitor ASHA output
					threading.Thread(
						target=stream_asha_output,
						args=(asha_handle, shutdown_evt, asha_restart_evt),
						daemon=True
					).start()
				elif asha_restart_evt.is_set():
					# Restart ASHA if required and if there remains an active connection.
					terminate_asha()
					if global_connected_list:
						asha_handle = start_asha()
						asha_restart_evt.clear()
						threading.Thread(
							target=stream_asha_output,
							args=(asha_handle, shutdown_evt, asha_restart_evt),
							daemon=True
						).start()
			
			if reconnect_evt.is_set():
				print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Reconnect triggered, restarting the script...")
				reconnect_evt.clear()
				cleanup()
				os.execv(sys.executable, [sys.executable] + sys.argv)
			
			time.sleep(2)
			
	except Exception as e:
		print(f"{Fore.RED}[FATAL]{Style.RESET_ALL} {e}")
	finally:
		cleanup()

if __name__ == "__main__":
	main()
