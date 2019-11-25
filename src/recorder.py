import pyshark
import sys

capture = pyshark.LiveCapture(interface='en0',  display_filter="tcp", output_file="./src/capture/"+sys.argv[1]+".pcap")
# Interface eth0 on VPS
# capture = pyshark.LiveCapture(interface='en0',  display_filter="tcp&&(ipv6.dst==2a01:e0a:455:7b0:dcd3:b238:3423:6cce||ip.dst==192.168.0.10)", output_file="./src/capture.pcap")

capture.sniff(timeout=120)

