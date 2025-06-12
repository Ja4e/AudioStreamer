# AudioStreamer
Script for streaming ASHA hearing aids

Supports other ASHA devices for volume control with provided bash script (volume.sh)

I would recommend using this:
python connect2.py -d -r -rof

if debug try use
DEBUG=1 python connect2.py -d -r -rof

append DEBUG=1 to set the env  to output

sucess rate connecting to that audiostream adapter is now 100% sometimes its scary 

i might want to add timer so it will repeatly request for initial handshake until sucessful

If the audio is choppy, delayed, or sounds like it is shifting from ear to ear, then your adapter may not be able to keep up with the bandwidth requirements.
Try connecting a single device and see if the quality improves or restart this script it usually fixes for me.


PLEASE DO GO https://github.com/thewierdnut/asha_pipewire_sink.git documentations BEFORE USE

Required by SIG documentations:

/etc/modprobe.d/bluetooth_asha.conf
options bluetooth enable_ecred=1

/etc/bluetooth/main.conf
PLease do make sure you include these into that main.conf
These configuration items will already already be present, but they are commented out, and have the wrong values. Note that these values are set in units of 1.25ms, so 20 / 1.25 = 16
```
[LE]
# LE default connection parameters.  These values are superceeded by any
# specific values provided via the Load Connection Parameters interface
MinConnectionInterval=16
MaxConnectionInterval=16
ConnectionLatency=10
ConnectionSupervisionTimeout=100
```
I find setting from ConnectionSupervisionTimeout=100 to 2000 to be better in connections

My personal config:
```
DiscoverableTimeout = 0
ControllerMode = le #This might not even be necessary just igore this if you actually wanted to use this
FastConnectable = true

KernelExperimental = true
ReconnectIntervals=1,1,2,3,5,8,13,21,34,55 # under policy section
```
these may not suitable for all so just ignore them

dont turn on if you have this particular MEDEL product:
```
Experimental = true
```

For people who has MEDEL's latest products it inbuilt low energy capabilities but not for audio streaming but rather for controlling and "find-my" app functionalities, and the audio stream adapter is for ble audio streaming capabilities but currently it does not work properly buecase My laptop has not managed to find them thus renders these passive advertising useless however I find pairing between two are more solid with it so its may or may not worthed it the latest updated program by a guy does proper active advertising connection between devices requires proper setup that requires you to uncomment in that /etc/bluetooth/main.conf command to Experimental = true but this isnt the case it causes problems which will report undocumented error: DBus.Error:org.bluez.Error.Failed: Operation failed with ATT error: 0x48 So for people who owns this device please do not enable this it will leads to problematic in reconnections.

Enable 2M PHY (optional):
Each devices may present different result during the handshake connection will implement a feature to execute them on the go making it more configurable through json


Check the existing phys
sudo btmgmt phy

Supported phys: BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX LE2MTX LE2MRX LECODEDTX LECODEDRX

Configurable phys: BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE2MTX LE2MRX LECODEDTX LECODEDRX

Selected phys: BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX

copy the Selected phys, and add the new LE2MTX LE2MRX values to it

sudo btmgmt phy BR1M1SLOT BR1M3SLOT BR1M5SLOT EDR2M1SLOT EDR2M3SLOT EDR2M5SLOT EDR3M1SLOT EDR3M3SLOT EDR3M5SLOT LE1MTX LE1MRX LE2MTX LE2MRX


Currently theres a stupid bug where:
14:01:47 INFO: Starting ASHA sink...
14:01:47 DEBUG: [ASHA] ** INFO: 14:01:47.059: Starting...
14:01:47 DEBUG: [ASHA] ** INFO: 14:01:47.067: <-- monitor_manager.RegisterMonitor(/org/bluez/asha/monitor)
14:01:47 DEBUG: [ASHA] ** INFO: 14:01:47.067: <-- Path::InterfacesAdded(/org/bluez/asha/monitor/monitor0 {})
14:01:47 DEBUG: [ASHA] 
14:01:47 DEBUG: [ASHA] ** (process:41838): WARNING **: 14:01:47.067: Error calling RegisterMonitor: GDBus.Error:org.freedesktop.DBus.Error.UnknownMethod: Method "RegisterMonitor" with signature "o" on interface "org.bluez.AdvertisementMonitorManager1" doesn't exist
14:01:47 DEBUG: [ASHA] 
14:01:47 DEBUG: [ASHA] 
14:01:47 DEBUG: [ASHA] ** (process:41838): WARNING **: 14:01:47.068: Null result when calling RegisterMonitor

will hang something you will not liking it 
so there will need to use import time to actually measure and kill it restart to work.
