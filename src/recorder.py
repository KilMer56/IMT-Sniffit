import pyshark
import sys

capture = pyshark.LiveCapture(interface='eth0',  display_filter="tcp&&(ipv6.dst==fe80::f816:3eff:fef6:de3a||ip.dst==137.74.196.58)", output_file="./src/capture/"+sys.argv[1]+".pcap")
# Interface eth0 on VPS
# capture = pyshark.LiveCapture(interface='en0',  display_filter="tcp&&(ipv6.dst==2a01:e0a:455:7b0:dcd3:b238:3423:6cce||ip.dst==192.168.0.10)", output_file="./src/capture.pcap")

duration = 900

if sys.argv[2] is not None:
   duration = int(sys.argv[2])

print('Launching Pyshark for '+str(duration)+'secs')

capture.sniff(timeout=duration)

