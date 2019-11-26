import pyshark
import sys
import os

from dotenv import load_dotenv

# LOAD ENV VARIABLES

load_dotenv()

IP_SSH = os.getenv('IP_SSH')
IPV6_SSH = os.getenv('IPV6_SSH')
IP_CLIENT = os.getenv('IP_CLIENT')
IPV6_CLIENT = os.getenv('IPV6_CLIENT')

print("Filters on : ",IP_SSH, IPV6_SSH, IP_CLIENT, IPV6_CLIENT)

# SET FILTERS

filters = "tcp"
filters += "&&(ipv6.dst==fe80::f816:3eff:fef6:de3a||ip.dst==137.74.196.58)"
filters += "&&!(ip.src==" + IP_CLIENT + ")&&!(ipv6.src==" + IPV6_CLIENT + ")"
filters += "&&!(ip.src==" + IP_SSH + ")&&!(ipv6.src=="+ IPV6_SSH + ")"

target_file = "capture"

if len(sys.argv) > 1 and sys.argv[1] is not None:
  target_file = sys.argv[1]

# CONFIGURE CAPTURE

capture = pyshark.LiveCapture(interface='eth0', display_filter="", output_file="./src/capture/"+target_file+".pcap")

duration = 900

if len(sys.argv) > 2 and sys.argv[2] is not None:
   duration = int(sys.argv[2])

# LAUNCH CAPTURE

print('Launching Pyshark for '+str(duration)+'secs')

capture.sniff(timeout=duration)

