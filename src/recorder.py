import pyshark
import sys
import os
import argparse

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

# GET ARGUMENTS

parser = argparse.ArgumentParser()
parser.add_argument('--output', '-o', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--time', '-t', type=int, nargs='?', help='The capture period in seconds')

args = parser.parse_args()

# CONFIGURE CAPTURE

print("Output file : src/"+args.output+".pcap")
capture = pyshark.LiveCapture(interface='eth0', display_filter=filters, output_file="./src/capture/"+args.output+".pcap")

# LAUNCH CAPTURE

if args.time is not None:
  print('Launching Pyshark for '+str(args.time)+'secs')
  capture.sniff(timeout=args.time)
else:
  print('Launching Pyshark in continuous mode')
  capture.sniff()

