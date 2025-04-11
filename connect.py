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
from colorama import init as colorama_init, Fore, Style

# For LE Advertising via BlueZ DBus API
import dbus
import dbus.exceptions
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

# Initialize colorama for colored terminal output
colorama_init(autoreset=True)

# ------------------------------
# CONFIGURATION
# ------------------------------
DEBUG = os.getenv('DEBUG', '0') == '1'

# Device names: adjust to your actual device names
PRIMARY_DEVICE = "RTL's Hearing Device"
SECONDARY_DEVICE = "AudioStream Adapter"

# GATT Attribute and value to be written (ensure these match your actual device)
GATT_ATTRIBUTE = "00e4ca9e-ab14-41e4-8823-f9e70c7e91df"
VOLUME_VALUE = "0xff"  # Maximum volume (0-255 range)

# Repository information for the ASHA PipeWire Sink
REPO_URL = "https://github.com/thewierdnut/asha_pipewire_sink.git"
CLONE_DIR = os.path.expanduser("~/asha_pipewire_sink")
BUILD_DIR = os.path.join(CLONE_DIR, "build")
EXECUTABLE = os.path.join(BUILD_DIR, "asha_pipewire_sink")

# Other configuration
RETRY_DELAY = 0  # Seconds delay between retry attempts

# Global flag for GATT trigger prevention
gatt_triggered = False

# Global variables for scan management
scan_process = None
scan_thread = None
scan_running = threading.Event()

# Global variables for advertisement management
adv_loop = None
adv_thread = None
ad_obj = None

# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------
def debug_print(message):
    if DEBUG:
        print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")

def run_command(command, check=True, capture_output=False, input_text=None, cwd=None):
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
        debug_print(f"Command error ({command}): {e}")
        if capture_output:
            return e.stdout.strip() if e.stdout else ''
        raise

def run_command_silent(command, check=True, capture_output=False, input_text=None, cwd=None):
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

# ------------------------------
# ADVERTISING CLASSES & FUNCTIONS
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
        properties = {
            'Type': self.ad_type,
            'ServiceUUIDs': dbus.Array(self.service_uuids, signature='s'),
            'Includes': dbus.Array(self.includes, signature='s'),
            'LocalName': self.local_name
        }
        return { 'org.bluez.LEAdvertisement1': properties }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method('org.bluez.LEAdvertisement1', in_signature='', out_signature='')
    def Release(self):
        print('Advertisement released')

def register_advertisement():
    global ad_obj
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = bus.get_object('org.bluez', '/org/bluez/hci0')
    ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')
    
    ad_obj = Advertisement(
        bus,
        0,
        ad_type="peripheral",
        service_uuids=[GATT_ATTRIBUTE],
        local_name="ASHA Stream",
        includes=["tx-power"]
    )
    ad_path = ad_obj.get_path()
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Registering advertisement at {ad_path}...")
    ad_manager.RegisterAdvertisement(ad_path, {},
                                     reply_handler=lambda: print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Advertisement registered."),
                                     error_handler=lambda e: print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to register advertisement: {e}"))
                                     
def unregister_advertisement():
    global ad_obj
    try:
        if ad_obj is not None:
            bus = dbus.SystemBus()
            adapter = bus.get_object('org.bluez', '/org/bluez/hci0')
            ad_manager = dbus.Interface(adapter, 'org.bluez.LEAdvertisingManager1')
            ad_manager.UnregisterAdvertisement(ad_obj.get_path())
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Advertisement unregistered.")
            # Explicitly remove the DBus object to free its object path
            ad_obj.remove_from_connection()
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Error unregistering advertisement: {e}")
    finally:
        ad_obj = None

def start_advertising():
    global adv_loop, adv_thread
    register_advertisement()
    adv_loop = GLib.MainLoop()
    def adv_loop_runner():
        try:
            adv_loop.run()
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Advertisement loop error: {e}")
    adv_thread = threading.Thread(target=adv_loop_runner, daemon=True)
    adv_thread.start()
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Advertising thread started.")

def stop_advertising():
    global adv_loop, adv_thread
    unregister_advertisement()
    if adv_loop is not None:
        adv_loop.quit()
    if adv_thread is not None:
        adv_thread.join(timeout=2)
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Advertising stopped.")

# ------------------------------
# SCAN MANAGEMENT FUNCTIONS
# ------------------------------
def start_scan():
    global scan_process, scan_thread
    if scan_running.is_set():
        return

    def scan_thread_function():
        global scan_process
        try:
            debug_print("Starting bluetoothctl scan process...")
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
            debug_print("Scan started; thread is idling while scan is active.")
            while scan_running.is_set():
                time.sleep(0.1)
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scan thread failed: {e}")
        finally:
            if scan_process:
                try:
                    scan_process.stdin.write('scan off\n')
                    scan_process.stdin.flush()
                except Exception as e:
                    debug_print(f"Error sending scan off command: {e}")
                time.sleep(1)
                scan_process.terminate()
                scan_process = None
                debug_print("Scan process terminated.")

    scan_thread = threading.Thread(target=scan_thread_function, daemon=True)
    scan_thread.start()
    time.sleep(0.4)

def stop_scan():
    global scan_process, scan_thread
    if not scan_running.is_set():
        return
    scan_running.clear()
    if scan_thread:
        scan_thread.join(timeout=2)
        scan_thread = None
    debug_print("Scan stopped.")

# ------------------------------
# ASHA PIPEWIRE SINK FUNCTIONS
# ------------------------------
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
    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        try:
            os.execvp(EXECUTABLE, [EXECUTABLE])
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to execute ASHA: {e}")
            sys.exit(1)
    else:
        return (child_pid, master_fd)

def stream_asha_output(asha_handle, connected_device, clean_state, shutdown_event, asha_restart_event):
    global gatt_triggered
    child_pid, master_fd = asha_handle
    buffer = b""
    while not shutdown_event.is_set():
        try:
            rlist, _, _ = select.select([master_fd], [], [], 0.1)
            if master_fd in rlist:
                chunk = os.read(master_fd, 1024)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    decoded_line = line.decode(errors="ignore")
                    if DEBUG:
                        print(f"{Fore.BLUE}[ASHA]{Style.RESET_ALL} {decoded_line}")

                    # Detect disconnection for target devices
                    if "Connected: false" in decoded_line and \
                       (PRIMARY_DEVICE in decoded_line or SECONDARY_DEVICE in decoded_line):
                        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} ASHA reports device disconnected.")
                        asha_restart_event.set()
                        return

                    # Trigger GATT operations on PAUSED or STREAMING state if not already triggered
                    if ("on_change_state" in decoded_line and 
                        ("new: PAUSED" in decoded_line or "new: STREAMING" in decoded_line) and 
                        not gatt_triggered and not clean_state):
                        gatt_triggered = True
                        time.sleep(0.1)
                        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Detected PAUSED state. Triggering GATT operations on {connected_device}...")
                        for i in range(3):
                            time.sleep(0.2)
                            perform_gatt_operations(connected_device)
            else:
                time.sleep(0.1)
        except Exception as e:
            if not shutdown_event.is_set():
                debug_print(f"Error reading from ASHA PTY: {e}")
            break
    debug_print("ASHA output streaming thread exiting.")

# ------------------------------
# BLUETOOTH INITIALIZATION & PAIRING
# ------------------------------
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

async def async_run_command(command, check=True, capture_output=False, input_text=None, cwd=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: run_command_silent(command, check=check, capture_output=capture_output, input_text=input_text, cwd=cwd)
    )

async def async_get_first_mac_address(device_name, poll_interval=1):
    while True:
        output = await async_run_command("bluetoothctl devices", capture_output=True)
        addresses = []
        for line in output.splitlines():
            if device_name.lower() in line.lower():
                parts = line.strip().split()
                if len(parts) >= 2:
                    addresses.append(parts[1])
        if addresses:
            return addresses[0]
        await asyncio.sleep(poll_interval)

async def async_connect_device(device_name, retry_interval=1, delay_after_connect=1):
    while True:
        mac_address = await async_get_first_mac_address(device_name)
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Using MAC address: {mac_address} for device '{device_name}'")
        try:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting connection to {mac_address}...")
            output = await async_run_command(f"bluetoothctl connect {mac_address}", capture_output=True)
            if "Failed to connect" in output:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection attempt failed for {mac_address}: {output}")
                await async_run_command(f"bluetoothctl remove {mac_address}", check=False)
                await asyncio.sleep(retry_interval)
                continue

            await asyncio.sleep(delay_after_connect)
            info_output = await async_run_command(f"bluetoothctl info {mac_address}", capture_output=True)
            if "Connected: yes" in info_output:
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Successfully connected to '{device_name}' with {mac_address}!")
                return mac_address
            else:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Connection unstable with {mac_address}. Retrying.")
                await async_run_command(f"bluetoothctl remove {mac_address}", check=False)
                await asyncio.sleep(retry_interval)
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error connecting to {mac_address}: {e}")
            await asyncio.sleep(retry_interval)

async def async_connect_any(device1, device2):
    task1 = asyncio.create_task(async_connect_device(device1))
    task2 = asyncio.create_task(async_connect_device(device2))
    done, pending = await asyncio.wait({task1, task2}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    if task1 in done:
        return task1.result(), device1
    else:
        return task2.result(), device2

async def async_pair_device():
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting pairing mode...")
    initialize_bluetooth()
    
    start_scan()
    devices = {}
    refresh_event = asyncio.Event()
    paired_mac = None

    async def update_device_list():
        nonlocal devices
        while True:
            output = await async_run_command("bluetoothctl devices", capture_output=True)
            current_devices = {}
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    mac = parts[1]
                    name = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                    current_devices[mac] = name
            new_devices = set(current_devices.keys()) - set(devices.keys())
            for mac in new_devices:
                print(f"{Fore.GREEN}[NEW]{Style.RESET_ALL} Found device: {mac} - {current_devices[mac]}")
            devices = current_devices
            refresh_event.set()
            await asyncio.sleep(2)

    async def get_user_input():
        loop = asyncio.get_running_loop()
        while True:
            prompt = f"\n{Fore.CYAN}[INPUT]{Style.RESET_ALL} Enter MAC/name to pair (Enter=refresh, q=quit): "
            try:
                selection = await loop.run_in_executor(None, lambda: input(prompt))
            except asyncio.CancelledError:
                return None
            selection = selection.strip().lower()
            if selection == 'q':
                return None
            if selection == '':
                refresh_event.clear()
                await refresh_event.wait()
                continue
            for mac, name in devices.items():
                if selection in [mac.lower(), name.lower()]:
                    return mac
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device not found. Current devices:")
            for mac, name in devices.items():
                print(f"  {mac} - {name}")

    update_task = asyncio.create_task(update_device_list())
    input_task = asyncio.create_task(get_user_input())
    done, pending = await asyncio.wait(
        [update_task, input_task],
        return_when=asyncio.FIRST_COMPLETED
    )
    update_task.cancel()
    try:
        await update_task
    except asyncio.CancelledError:
        pass

    if input_task.done():
        selected_mac = input_task.result()
        if selected_mac:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting to pair with {selected_mac}...")
            try:
                await async_run_command(f"bluetoothctl pair {selected_mac}")
                await async_run_command(f"bluetoothctl trust {selected_mac}")
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Successfully paired and trusted {selected_mac}!")
                paired_mac = selected_mac
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Pairing failed: {e}")
    return paired_mac

# ------------------------------
# LEGACY SYNC FUNCTIONS
# ------------------------------
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
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Removing and reconnecting device '{device_name}'...")
    asyncio.run(async_connect_device(device_name))
    return True

def perform_gatt_operations(device_name):
    output = run_command("bluetoothctl devices", capture_output=True)
    addresses = []
    for line in output.splitlines():
        if device_name.lower() in line.lower():
            parts = line.strip().split()
            if len(parts) >= 2:
                addresses.append(parts[1])
    if not addresses:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Device '{device_name}' not found.")
        return False

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing GATT operations on {device_name}...")
    for mac_address in addresses:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Trying MAC: {mac_address}...")
        commands = f"""connect {mac_address}
gatt.select-attribute {GATT_ATTRIBUTE}
gatt.write {VOLUME_VALUE}
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

# ------------------------------
# MAIN FUNCTIONALITY
# ------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Connect to Bluetooth devices and manage ASHA PipeWire Sink.'
    )
    parser.add_argument('-c', '--clean-state', action='store_true',
                        help='Skip automatic GATT operations on state change')
    parser.add_argument('-r', '--reconnect', action='store_true',
                        help='Enable automatic ASHA restart if device disconnects')
    parser.add_argument('-d', '--disconnect', action='store_true',
                        help='Disconnect Bluetooth upon Keyboard Interrupt')
    parser.add_argument('-p', '--pair', action='store_true',
                        help='Enable pairing mode')
    args = parser.parse_args()

    shutdown_event = threading.Event()
    asha_restart_event = threading.Event()
    restart_needed = False

    connected_mac = None

    try:
        # Initialize Bluetooth and start advertising if valid.
        initialize_bluetooth()
        uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        if not uuid_regex.match(GATT_ATTRIBUTE):
            print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} GATT_ATTRIBUTE '{GATT_ATTRIBUTE}' is invalid. Advertisement disabled.")
        else:
            start_advertising()

        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Enabling bluetoothctl scan...")
        run_command("bluetoothctl discoverable on", check=False)
        start_scan()

        if not args.pair:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Attempting asynchronous connection to devices...")
            connected_mac, connected_device = asyncio.run(async_connect_any(PRIMARY_DEVICE, SECONDARY_DEVICE))
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Connected to {connected_device} using MAC {connected_mac}!")
        else:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Entering pairing mode...")
            paired_mac = asyncio.run(async_pair_device())
            if paired_mac:
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Pairing complete with {paired_mac}")
            else:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Pairing process aborted")
            return False  # Exit pairing mode without restart

        # Stop scanning and disable discoverability.
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Disabling bluetoothctl scan...")
        stop_scan()
        run_command("bluetoothctl discoverable off", check=False)

        # Main loop: launch ASHA and monitor output.
        while not shutdown_event.is_set():
            global gatt_triggered
            gatt_triggered = False
            asha_handle = start_asha()
            asha_thread = threading.Thread(
                target=stream_asha_output,
                args=(asha_handle, connected_device, args.clean_state, shutdown_event, asha_restart_event),
                daemon=True
            )
            asha_thread.start()
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} ASHA PipeWire Sink is running. Press Ctrl+C to exit.")
            try:
                while not shutdown_event.is_set() and not asha_restart_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} KeyboardInterrupt received. Exiting...")
                shutdown_event.set()
                break

            if asha_restart_event.is_set():
                print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Restarting Bluetooth stack...")
                try:
                    os.kill(asha_handle[0], signal.SIGTERM)
                    asha_thread.join(timeout=2)
                except Exception as e:
                    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} ASHA cleanup error: {e}")
                run_command(f"bluetoothctl disconnect {connected_mac}", check=False)
                run_command("bluetoothctl power off", check=False)
                if args.reconnect:
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Preparing for reconnection...")
                    restart_needed = True
                    time.sleep(0)
                    break
                else:
                    shutdown_event.set()
                    break
            else:
                break

    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} An error occurred: {e}")
        shutdown_event.set()
    finally:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing final cleanup...")
        shutdown_event.set()
        stop_scan()
        run_command("bluetoothctl discoverable off", check=False)
        stop_advertising()
        if args.disconnect:
            run_command("bluetoothctl power off", check=False)
        if 'asha_handle' in locals() and asha_handle is not None:
            try:
                os.kill(asha_handle[0], signal.SIGTERM)
                print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Terminated ASHA process.")
            except Exception as e:
                print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Error terminating ASHA process: {e}")
        return restart_needed

if __name__ == "__main__":
    reconnect_mode = False
    if "-r" in sys.argv or "--reconnect" in sys.argv:
        reconnect_mode = True

    while True:
        restart_flag = main()
        if reconnect_mode and restart_flag:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Restarting main connection loop...")
            time.sleep(0)  # allow some time before restarting
            continue
        else:
            break



