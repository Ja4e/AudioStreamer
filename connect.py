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


This script minimizes **unintended disconnections** with ASHA G.722 hearing aids
by handling edge cases and reduces real-world timing unpredictability that 
normally affect connection success. Without it, stable connections often rely 
on physical-layer 'luck' and system-specific timing.

If the audio is choppy, delayed, or sounds like it is shifting from ear to ear, then your adapter may not be able to keep up with the bandwidth requirements.
Try connecting a single device and see if the quality improves or restart this script it usually fixes for me.


PLEASE DO GO https://github.com/thewierdnut/asha_pipewire_sink.git documentations BEFORE USE

Required by SIG documentations:

/etc/modprobe.d/bluetooth_asha.conf
options bluetooth enable_ecred=1

/etc/bluetooth/main.conf
PLease do make sure you include these into that main.conf
These configuration items will already already be present, but they are commented out, and have the wrong values. Note that these values are set in units of 1.25ms, so 20 / 1.25 = 16

[LE]
# LE default connection parameters.  These values are superceeded by any
# specific values provided via the Load Connection Parameters interface
MinConnectionInterval=16
MaxConnectionInterval=16
ConnectionLatency=10
ConnectionSupervisionTimeout=100

I find setting from ConnectionSupervisionTimeout=100 to 2000 to be better in connections

My personal config:
DiscoverableTimeout = 0
ControllerMode = le #This might not even be necessary just igore this if you actually wanted to use this
FastConnectable = true

KernelExperimental = true
ReconnectIntervals=1,1,2,3,5,8,13,21,34,55 # under policy section

these may not suitable for all so just ignore them

dont turn on if you have this particular MEDEL product:
Experimental = true


For people who has MEDEL's latest products it inbuilt low energy capabilities but not for audio streaming but rather for controlling and "find-my" app functionalities, and the audio stream adapter is for ble audio streaming capabilities
but currently it does not work properly buecase My laptop has not managed to find them thus renders these passive advertising useless however I find pairing between two are more solid with it so its may or may not worthed it
the latest updated program by a guy does proper active advertising connection between devices requires proper setup that requires you to uncomment in that /etc/bluetooth/main.conf command to Experimental = true
but this isnt the case it causes problems which will report undocumented error: DBus.Error:org.bluez.Error.Failed: Operation failed with ATT error: 0x48 
So for people who owns this device please do not enable this it will leads to problematic in reconnections.

Enable 2M PHY (optional):
Each devices may present different result during the handshake connection will implement a feature to execute them on the go making it more configurable through json

# Check the existing phys
sudo btmgmt phy
Supported phys: BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX LE2MTX LE2MRX LECODEDTX LECODEDRX
Configurable phys: BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE2MTX LE2MRX LECODEDTX LECODEDRX
Selected phys: BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX

# copy the Selected phys, and add the new LE2MTX LE2MRX values to it
sudo btmgmt phy BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX LE2MTX LE2MRX


#The latest three commits from that asha is currently very broken (Fixed)
#try attempt running git reset --hard HEAD~1 in that commit before compiling 

Setcap is implemented for 1/2 phy protocols for convience 
I chose 1mphy because of it's reliabilities during the streaming
you could set when to use or not

If it's connected sucessfully please do not unpair them because you got the security key to get connect them back, only unpair when your devices refused to connect them back multiple times and then try to attempt to repair them back. Usually for MEDEL's audiostream adapter requires the AudioKey 2 app on your mobile phone in the audiostream section to "update" them connect them back will give you higher chances to get it paired sucessfully usually sucess in one shot, one time, it somehow more reliable than having it your devices restarted multiple times to attempt it connect back.

Usually, if connection return try to restart this device and try to rerun the script. 


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
import logging
from typing import List, Tuple, Optional, Set
from colorama import init as colorama_init, Fore, Style
import dbus
import dbus.exceptions
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import fcntl
import termios


colorama_init(autoreset=True)

# ------------------------------
# CONFIGURATION
# ------------------------------
DEBUG: bool = os.getenv('DEBUG', '0') == '1'

PRIMARY_FILTER: str = "RTL's Hearing Device"   # Primary device name filter
SECONDARY_FILTER: str = "AudioStream Adapter"    # Secondary device name filter, add one if you needed Or just one devices rename it to none if required
REPO_URL: str = "https://github.com/thewierdnut/asha_pipewire_sink.git"
CLONE_DIR: str = os.path.expanduser("~/asha_pipewire_sink")
BUILD_DIR: str = os.path.join(CLONE_DIR, "build")
EXECUTABLE: str = os.path.join(BUILD_DIR, "asha_pipewire_sink")
GATT_ATTRIBUTE: str = "00e4ca9e-ab14-41e4-8823-f9e70c7e91df" # update this if different devices can be changed to none if you dont want it 
VOLUME_VALUE: str = "0xff"  # Adjust volume value (0-255 range) 0xf0 represents it as 240 Currently its at 255 but varies on different devices
RETRY_DELAY: float = random.uniform(0.4, 1.0)
#DEFAULT_RETRY_INTERVAL: float = random.uniform(0.4, 1.0)
DEFAULT_RETRY_INTERVAL: float = 0.0
# DEFAULT_DELAY_AFTER_CONNECT: float = random.uniform(0.4, 1.0) # leave it like this 
MAX_TIMEOUT: float = random.uniform(600, 1200) # uniform timeouts to keep the connection stable and you could set it to static if you wanted to, but i find this better, just in case you need em'
BLACKLIST: List[str] = ["AudioStream Adapter DFU"]  # Blacklist devices to avoid interfering with successful connections.

# Global state (protected by locks where needed)
processed_devices: Set[str] = set()
connected_list_lock = threading.Lock()
processed_lock = threading.Lock()
global_connected_list: List[Tuple[str, str]] = []  # (mac, device_name)

# Threading & process events
shutdown_evt = threading.Event()
reconnect_evt = threading.Event()
reset_evt = threading.Event()
asha_restart_evt = threading.Event()

asha_handle: Optional[Tuple[int, int]] = None  # Tuple: (pid, master_fd)


# ------------------------------
# Logging Setup
# ------------------------------
LOG_FORMAT = f"%(asctime)s {Fore.CYAN}[DEBUG]%(message)s{Style.RESET_ALL}" if DEBUG else "%(asctime)s [INFO] %(message)s"
logging.basicConfig(
	level=logging.DEBUG if DEBUG else logging.INFO,
	format="%(asctime)s %(levelname)s: %(message)s",
	datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------
def run_command(command: str, check: bool = True, capture_output: bool = False,
				input_text: Optional[str] = None, cwd: Optional[str] = None,
				debug: bool = True) -> Optional[str]:
	"""
	Run a shell command and return output if requested.
	"""
	if debug and DEBUG:
		logger.debug(f"Running command: {Fore.BLUE}{command}{Style.RESET_ALL} [cwd={Fore.BLUE}{cwd}{Style.RESET_ALL}]")
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
		if debug:
			logger.error(f"Command error: {e}")
		if capture_output and e.stdout:
			return e.stdout.strip()
		return None

def run_trust_background(mac: str) -> None:
	"""
	Launch `bluetoothctl trust <MAC>` in the background non-blocking.
	"""
	try:
		subprocess.Popen(
			["bluetoothctl", "trust", mac],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
	except Exception as e:
		logger.warning(f"Failed to run bluetoothctl trust for {mac}: {e}")

def run_pair_devices(mac: str) -> None:
	"""
	Launch `bluetoothctl pair <MAC>` in the background non-blocking.
	"""
	try:
		subprocess.Popen(
			["bluetoothctl", "pair", mac],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
	except Exception as e:
		logger.warning(f"Failed to run bluetoothctl pair for {mac}: {e}")
		
def run_remove_devices(mac: str) -> None:
	"""
	Launch `bluetoothctl remove <MAC>` in the background non-blocking.
	"""
	try:
		subprocess.Popen(
			["bluetoothctl", "remove", mac],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
	except Exception as e:
		logger.warning(f"Failed to run bluetoothctl remove for {mac}: {e}")

def disable_pairable_background() -> None:
	"""
	Launch `bluetoothctl pairable off` in the background non-blocking.
	"""
	try:
		subprocess.Popen(
			["bluetoothctl", "pairable", "off"],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
	except Exception as e:
		logger.warning(f"Failed to run bluetoothctl pairable off: {e}")

# ------------------------------
# ADVERTISEMENT MANAGEMENT
# ------------------------------
class Advertisement(dbus.service.Object):
	"""
	Manages a Bluetooth LE advertisement via DBus.
	"""
	PATH_BASE = '/org/bluez/example/advertisement'

	def __init__(self, bus, index: int, ad_type: str, service_uuids: List[str],
				 local_name: str, includes: List[str]) -> None:
		self.path = self.PATH_BASE + str(index)
		self.bus = bus
		self.ad_type = ad_type
		self.service_uuids = service_uuids
		self.local_name = local_name
		self.includes = includes
		super().__init__(bus, self.path)

	def get_properties(self) -> dict:
		return {
			'org.bluez.LEAdvertisement1': {
				'Type': self.ad_type,
				'ServiceUUIDs': dbus.Array(self.service_uuids, signature='s'),
				'Includes': dbus.Array(self.includes, signature='s'),
				'LocalName': self.local_name,
				'LegacyAdvertising': dbus.Boolean(True)
			}
		}

	def get_path(self) -> dbus.ObjectPath:
		return dbus.ObjectPath(self.path)

	@dbus.service.method('org.bluez.LEAdvertisement1')
	def Release(self) -> None:
		logger.info("Advertisement released")


# ------------------------------
# MAIN MANAGER CLASS
# ------------------------------
class BluetoothAshaManager:
	def __init__(self, args: argparse.Namespace) -> None:
		self.args = args
		self.ad_obj = None
		self.adv_loop = None
		self.adv_thread = None
		self.scan_thread: Optional[threading.Thread] = None
		self.gatt_triggered: bool = False  # Instance flag for GATT trigger
		self.ad_registered: bool = False   # Track advertisement registration status

	# Bluetooth Initialization

	def initialize_bluetooth(self) -> None:
		"""
		Initialize Bluetooth by unblocking it, powering on, and setting up agents.
		"""
		logger.info(f"{Fore.BLUE}Initializing Bluetooth...{Style.RESET_ALL}")
		run_command("rfkill unblock bluetooth")
		run_command("bluetoothctl power on")
		if self.args.pair:
			run_command("bluetoothctl discoverable on")
			run_command("bluetoothctl agent KeyboardDisplay")
		else:
			run_command("bluetoothctl agent on")
		run_command("bluetoothctl pairable on")

		# Wait until the adapter is powered on.
		while True:
			output = run_command("bluetoothctl show", capture_output=True, debug=False)
			if output and "Powered: yes" in output:
				break
			time.sleep(1)
		logger.info(f"{Fore.GREEN}Bluetooth initialized{Style.RESET_ALL}")

	def start_advertising(self, disable_advertisement: bool = False) -> None:
		"""
		Start Bluetooth LE advertising unless disabled. Logs the result of registration.
		"""
		if disable_advertisement:
			logger.info("Advertisement disabled via CLI argument")
			return

		try:
			dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
			bus = dbus.SystemBus()
			adapter = bus.get_object('org.bluez', '/org/bluez/hci0')  # Change if your Bluetooth adapter is under a different address
			ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')

			self.ad_obj = Advertisement(
				bus, 0, "peripheral",
				[GATT_ATTRIBUTE], "ASHA Stream", ["tx-power"]  # the "proper" advertising should not be a requirement but is good enough
			)

			def register_reply_handler() -> None:
				self.ad_registered = True
				logger.info(f"{Fore.GREEN}Advertisement registered successfully{Style.RESET_ALL}")

			def register_error_handler(e: Exception) -> None:
				self.ad_registered = False
				logger.error(f"{Fore.RED}Failed to register advertisement: {e}{Style.RESET_ALL}")

			ad_manager.RegisterAdvertisement(
				self.ad_obj.get_path(), {},
				reply_handler=register_reply_handler,
				error_handler=register_error_handler
			)

			self.adv_loop = GLib.MainLoop()
			self.adv_thread = threading.Thread(target=self.adv_loop.run, daemon=True)
			self.adv_thread.start()

		except Exception as e:
			logger.error(f"{Fore.RED}Advertising setup failed: {e}{Style.RESET_ALL}")
			if reconnect_evt.is_set():
				logger.info("Reconnect triggered, restarting the script...")
				reconnect_evt.clear()
				self.cleanup()
				os.execv(sys.executable, [sys.executable] + sys.argv)

	def stop_advertising(self, disable_advertisement: bool = False) -> None:
		"""
		Stop active advertisement.
		"""
		if disable_advertisement or not self.ad_obj:
			return
		try:
			bus = dbus.SystemBus()
			adapter = bus.get_object('org.bluez', '/org/bluez/hci0')
			ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')
			ad_manager.UnregisterAdvertisement(self.ad_obj.get_path())
			try:
				self.ad_obj.remove_from_connection()
			except Exception as inner_error:
				logger.warning(f"Failed to remove advertisement: {inner_error}")
			self.ad_obj = None
			if self.adv_loop:
				self.adv_loop.quit()
			if self.adv_thread:
				self.adv_thread.join(timeout=2)
		except Exception as e:
			logger.warning(f"Error stopping advertisement: {e}")

	# Device Scanning and Connection

	def get_devices_by_types(self) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
		"""
		Query bluetoothctl devices and filter based on primary and secondary names.
		Returns a tuple of lists: (primary, secondary) devices.
		"""
		output = run_command("bluetoothctl devices", capture_output=True, debug=False) or ""
		primary, secondary = [], []
		device_pattern = re.compile(r'^Device (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) (.*)$')
		for line in output.splitlines():
			match = device_pattern.match(line.strip())
			if match:
				mac, name = match.group(1), match.group(3)
				if any(bl in name for bl in BLACKLIST):
					continue
				if PRIMARY_FILTER in name:
					primary.append((mac, name))
				elif SECONDARY_FILTER in name:
					secondary.append((mac, name))
		return primary, secondary

	def start_continuous_scan(self) -> None:
		"""
		Start continuous scan in a separate thread.
		"""
		def scan_worker() -> None:
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
						mac: Optional[str] = None
						name: Optional[str] = None

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
								logger.debug(f"Invalid MAC {mac} from line: {line}")
								continue
							with processed_lock:
								if mac not in processed_devices:
									processed_devices.add(mac)
									threading.Thread(
										target=self.handle_new_device,
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
						logger.error(f"Scan error: {e}")
					time.sleep(1)

		self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
		self.scan_thread.start()

	async def async_connect_specific(self, mac_address: str) -> bool:
		"""
		Asynchronously attempt to connect to a given device up to three times.
		"""
		try:
			return await asyncio.wait_for(self._connect_attempt(mac_address), timeout=MAX_TIMEOUT)
		except asyncio.TimeoutError:
			run_remove_devices(mac_address)
			return False

	async def _connect_attempt(self, mac_address: str) -> bool:
		if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac_address):
			logger.debug(f"Invalid MAC address in connection attempt: {mac_address}")
			return False

		attempts = 0
		while not shutdown_evt.is_set() and attempts < 2:
			try:
				output = await asyncio.to_thread(run_command,
												 f"bluetoothctl connect {mac_address}", # trying "pair" 
												 capture_output=True)
				if output and any(s in output for s in ["Connection successful", "already connected"]):
					info_output = await asyncio.to_thread(run_command,
														  f"bluetoothctl info {mac_address}",
														  capture_output=True)
					if info_output and "Connected: yes" in info_output:
						return True
				attempts += 1
				await asyncio.sleep(DEFAULT_RETRY_INTERVAL)
			except Exception as e:
				logger.error(f"Connection attempt failed: {e}")
				if attempts == 0 and self.args.reset_on_failure:
					logger.warning("First connection attempt failed — scheduling adapter reset")
					reset_evt.set()
				attempts += 1
				await asyncio.sleep(DEFAULT_RETRY_INTERVAL * 2)
		return False

	def handle_new_device(self, mac: str, name: str) -> None:
		"""
		Process a newly discovered device. Blacklisted devices are skipped.
		"""
		if any(black in name for black in BLACKLIST):
			logger.info(f"Device {name} ({mac}) is blacklisted. Skipping connection.")
			return

		if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
			logger.error(f"Invalid MAC address: {mac}")
			with processed_lock:
				processed_devices.discard(mac)
			return

		logger.info(f"{Fore.BLUE}New device detected: {name} ({mac}){Style.RESET_ALL}")
		success = asyncio.run(self.async_connect_specific(mac))
		if success:
			with connected_list_lock:
				if not any(m == mac for m, _ in global_connected_list):
					run_pair_devices(mac)
					run_trust_background(mac)
					global_connected_list.append((mac, name))
					logger.info(f"{Fore.GREEN}Connected to {name} ({mac})!{Style.RESET_ALL}")
					run_trust_background(mac)
					disable_pairable_background()
		else:
			with processed_lock:
				processed_devices.discard(mac)

	# ASHA Sink Management

	def start_asha(self) -> Tuple[int, int]:
		"""
		Ensure the ASHA sink repository is available, build the executable if needed,
		then start it in a new process group.
		"""
		logger.info(f"{Fore.BLUE}Initializing ASHA sink...{Style.RESET_ALL}")
		if not os.path.isdir(CLONE_DIR):
			logger.info("Cloning repository...")
			run_command(f"git clone {REPO_URL} {CLONE_DIR}")

		if not os.path.isfile(EXECUTABLE):
			logger.info("Building ASHA sink...")
			os.makedirs(BUILD_DIR, exist_ok=True)
			run_command("cmake ..", cwd=BUILD_DIR)
			run_command("make", cwd=BUILD_DIR)

		try:
			# Check if cap_net_raw is already set
			result = subprocess.run(["getcap", EXECUTABLE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
			
			if f"{EXECUTABLE} cap_net_raw=ep" not in result.stdout.strip():
				logger.info("Setting cap_net_raw=ep on ASHA sink executable...")
				# Recommend preconfiguring sudoers to allow passwordless execution of setcap
				subprocess.run(["sudo", "/usr/sbin/setcap", "cap_net_raw=ep", EXECUTABLE], check=True)
			else:
				logger.info("ASHA sink already has cap_net_raw=ep.")
				
		except subprocess.CalledProcessError as e:
			logger.error(f"Failed to set/get capabilities: {e}")
			# sys.exit(1)

		logger.info("Starting ASHA sink...")
		master_fd, slave_fd = pty.openpty()
		# Launch the ASHA sink wrapped in stdbuf to force line buffering.
		try:
			proc = subprocess.Popen(
				["stdbuf", "-oL", EXECUTABLE, "--buffer_algorithm", "threaded", "--phy2m"], #can be changed to --phy1m
				preexec_fn=os.setsid,
				stdin=slave_fd,
				stdout=slave_fd,
				stderr=slave_fd,
				close_fds=True
			)
			os.close(slave_fd)
			# Set the master_fd to non-blocking mode
			flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
			fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
			return proc.pid, master_fd
		except Exception as e:
			logger.error(f"ASHA startup failed: {e}")
			os.close(master_fd)
			raise

	def stream_asha_output(self, asha_handle: Tuple[int, int]) -> None:
		"""
		Reads the ASHA output and watches for connection drops or GATT triggers.
		"""
		child_pid, master_fd = asha_handle
		buffer = b""
		last_stats: Optional[dict] = None

		# Updated regex to optionally capture Rssi: <val>, <val>
		ring_regex = re.compile(
			r"Ring Occupancy:\s*(\d+)\s+High:\s*(\d+)\s+Ring Dropped:\s*(\d+)\s+Total:\s*(\d+)\s+"
			r"Adapter Dropped:\s*(\d+)\s+Total:\s*(\d+)\s+Silence:\s*(\d+)\s+Total:\s*(\d+)"
			r"(?:\s+Rssi:\s*(\d+),\s*(\d+))?"
		)

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
						if "Ring Occupancy:" in decoded:
							match = ring_regex.search(decoded)
							if match:
								# Fields for core stats
								fields = [
									"Ring Occupancy",
									"High",
									"Ring Dropped",
									"Ring Total",
									"Adapter Dropped",
									"Adapter Total",
									"Silence",
									"Silence Total",
								]
								values = match.groups()

								# Main numeric values
								current_stats = {field: int(val) for field, val in zip(fields, values[:8])}

								# Optional Rssi values
								rssi_str = ""
								if values[8] is not None and values[9] is not None:
									rssi_str = f" Rssi: {values[8]}, {values[9]}"

								highlighted_parts = {}
								if last_stats is None:
									highlighted_parts = {field: str(current_stats[field]) for field in fields}
								else:
									for field in fields:
										if field == "Ring Occupancy":
											highlighted_parts[field] = str(current_stats[field])
										elif current_stats[field] != last_stats.get(field):
											highlighted_parts[field] = f"{Fore.YELLOW}{current_stats[field]}{Style.RESET_ALL}"
										else:
											highlighted_parts[field] = str(current_stats[field])

								highlighted_line = (
									f"Ring Occupancy: {highlighted_parts['Ring Occupancy']} "
									f"High: {highlighted_parts['High']} "
									f"Ring Dropped: {highlighted_parts['Ring Dropped']} "
									f"Total: {highlighted_parts['Ring Total']} "
									f"Adapter Dropped: {highlighted_parts['Adapter Dropped']} "
									f"Total: {highlighted_parts['Adapter Total']} "
									f"Silence: {highlighted_parts['Silence']} "
									f"Total: {highlighted_parts['Silence Total']}"
									f"{rssi_str}"
								)

								logger.debug(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {highlighted_line}")
								last_stats = current_stats
							else:
								logger.debug(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded}")
						else:
							logger.debug(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded}")

						if any(phrase in decoded for phrase in [
							"Connected: false",
							"Assertion !m_sock' failed.",
							"GDBus.Error:org.bluez.Error.InProgress: In Progress",
							"GDBus.Error:org.freedesktop.DBus.Error.NoReply: Remote peer disconnected",
							"Timeout was reached",
							"GDBus.Error:org.bluez.Error.Failed: Not connected",
							"Removing Sink",
						]):
							logger.warning("ASHA connection dropped")
							self.gatt_triggered = False
								
							if self.args.reconnect:
								with connected_list_lock:
									global_connected_list.clear()
								reconnect_evt.set()
								asha_restart_evt.set()
							return

						if ("on_change_state" in decoded and
								("new: PAUSED" in decoded or "new: STREAMING" in decoded) and
								not self.gatt_triggered and not self.args.clean_state):
							self.gatt_triggered = True
							logger.info("Detected audio state change")
							with connected_list_lock:
								for mac, name in global_connected_list:
									logger.info(f"Triggering GATT operations on {name}...")
									for _ in range(3):
										time.sleep(0.2)
										self.perform_gatt_operations(mac, name)
			except Exception as e:
				if not shutdown_evt.is_set():
					logger.error(f"ASHA stream error: {e}")
				break


	def perform_gatt_operations(self, mac_address: str, device_name: str) -> bool:
		"""
		Perform GATT operations by connecting to the device, selecting the attribute,
		and writing the volume.
		"""
		logger.info(f"Starting GATT operations for {device_name}")
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
				logger.info(f"{Fore.GREEN}GATT operations completed{Style.RESET_ALL}")
				return True
			else:
				logger.error(f"{Fore.RED}GATT operations failed: {stderr.strip()}{Style.RESET_ALL}")
				return False
		except Exception as e:
			logger.error(f"{Fore.RED}GATT exception: {e}{Style.RESET_ALL}")
			return False


	def monitor_mac_changes(self) -> None:
		"""
		Periodically monitor the list of connected devices and trigger a reconnect if required.
		"""
		while not shutdown_evt.is_set():
			try:
				with connected_list_lock:
					current_connected = {mac for mac, _ in global_connected_list}
				output = run_command("bluetoothctl devices", capture_output=True, debug=False) or ""
				actual_connected: Set[str] = set()
				for line in output.splitlines():
					if "Device" in line:
						parts = line.strip().split()
						if len(parts) >= 2:
							actual_connected.add(parts[1])
				missing = current_connected - actual_connected
				if missing:
					logger.warning(f"Missing connections: {', '.join(missing)}")
					with connected_list_lock:
						global_connected_list[:] = [
							(mac, name) for mac, name in global_connected_list if mac in actual_connected
						]
					reconnect_evt.set()
				time.sleep(0.2)
			except Exception as e:
				logger.error(f"Monitor error: {e}")
				time.sleep(2)

	def terminate_asha(self) -> None:
		"""
		Gracefully terminate the ASHA sink process.
		"""
		global asha_handle
		if asha_handle:
			child_pid, master_fd = asha_handle
			try:
				pgid = os.getpgid(child_pid)
				logger.info(f"Terminating ASHA process group {pgid}...")
				os.killpg(pgid, signal.SIGTERM)
				timeout = 5
				end_time = time.time() + timeout
				while True:
					try:
						res = os.waitpid(child_pid, os.WNOHANG)
						if res != (0, 0):
							logger.info(f"{Fore.GREEN}ASHA process terminated gracefully{Style.RESET_ALL}")
							break
					except ChildProcessError:
						break
					if time.time() > end_time:
						logger.warning(f"{Fore.YELLOW}Timeout reached; forcing kill{Style.RESET_ALL}")
						os.killpg(pgid, signal.SIGKILL)
						break
					time.sleep(0.1)
			except Exception as e:
				logger.error(f"Error terminating ASHA process: {e}")
			finally:
				try:
					os.close(master_fd)
				except Exception:
					pass
				asha_handle = None

	def cleanup(self) -> None:
		"""
		Cleanup routine for shutting down all components gracefully.
		"""
		logger.info(f"{Fore.BLUE}Cleaning up...{Style.RESET_ALL}")
		self.stop_advertising(self.args.disable_advertisement)
		if self.args.disconnect:
			run_command("bluetoothctl agent off", check=False)
			run_command("bluetoothctl power off", check=False)
		if asha_handle:
			self.terminate_asha()
		run_command("bluetoothctl pairable off", check=False)
		shutdown_evt.set()
		logger.info(f"{Fore.GREEN}Cleanup complete{Style.RESET_ALL}")

	def signal_handler(self, sig, frame) -> None:
		"""
		Handle signals for graceful shutdown.
		"""
		logger.warning(f"Received signal {sig}, shutting down...")
		self.cleanup()
		sys.exit(0)

	# Main loop
	def run(self) -> None:
		"""
		Main loop to initialize Bluetooth, start scanning, monitor devices, and manage the ASHA sink.
		"""
		signal.signal(signal.SIGINT, self.signal_handler)
		signal.signal(signal.SIGTERM, self.signal_handler)
		signal.signal(signal.SIGHUP, self.signal_handler)
		try:
			self.initialize_bluetooth()
			self.start_advertising(self.args.disable_advertisement)
			self.start_continuous_scan()
			threading.Thread(target=self.monitor_mac_changes, daemon=True).start()

			global asha_handle, global_connected_list
			while not shutdown_evt.is_set():
				primary, secondary = self.get_devices_by_types()
				all_devices = primary + secondary
				if all_devices:
					with processed_lock, connected_list_lock:
						current_macs = {mac for mac, _ in all_devices}
						new_macs = current_macs - processed_devices
						for mac in new_macs:
							name = next((n for m, n in all_devices if m == mac), "Unknown")
							processed_devices.add(mac)
							threading.Thread(
								target=self.handle_new_device,
								args=(mac, name),
								daemon=True
							).start()

				with connected_list_lock:
					if not asha_handle and global_connected_list:
						logger.info("Starting ASHA sink as a connection is active")
						asha_handle = self.start_asha()
						threading.Thread(
							target=self.stream_asha_output,
							args=(asha_handle,),
							daemon=True
						).start()
					elif asha_restart_evt.is_set():
						self.terminate_asha()
						if global_connected_list:
							asha_handle = self.start_asha()
							asha_restart_evt.clear()
							threading.Thread(
								target=self.stream_asha_output,
								args=(asha_handle,),
								daemon=True
							).start()

				if reset_evt.is_set():
					logger.info("Controller resetting...")
					reset_evt.clear()
					self.cleanup()
					os.execv(sys.executable, [sys.executable] + sys.argv)

				if reconnect_evt.is_set():
					logger.info("Reconnect triggered, restarting the script...")
					reconnect_evt.clear()
					self.cleanup()
					os.execv(sys.executable, [sys.executable] + sys.argv)

				time.sleep(1)
		except Exception as e:
			logger.critical(f"Fatal error: {e}", exc_info=True)
		finally:
			self.cleanup()


# ------------------------------
# ENTRY POINT
# ------------------------------
def main() -> None:
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
	parser.add_argument('-rof','--reset-on-failure', action='store_true', 
						help='Auto-reset adapter on ASHA connect failure')
	args = parser.parse_args()

	manager = BluetoothAshaManager(args)
	manager.run()


if __name__ == "__main__":
	main()
