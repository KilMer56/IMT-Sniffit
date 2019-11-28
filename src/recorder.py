import pyshark
import sys
import os
import argparse

from dotenv import load_dotenv

# GET ARGUMENTS

parser = argparse.ArgumentParser()
parser.add_argument('--output', '-o', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--time', '-t', type=int, nargs='?', help='The capture period in seconds')
parser.add_argument('--protocol', '-p', nargs="?", help="The protocol to capture", default="tcp", choices=['tcp','udp', 'both'])

args = parser.parse_args()

# LOAD ENV VARIABLES

load_dotenv()

IP_SSH = os.getenv('IP_SSH')
IPV6_SSH = os.getenv('IPV6_SSH')
IP_CLIENT = os.getenv('IP_CLIENT')
IPV6_CLIENT = os.getenv('IPV6_CLIENT')
IP_VPN = os.getenv('IP_VPN')
IPV6_VPN = os.getenv('IPV6_VPN')

protocol = args.protocol

# SET FILTERS

## TCP or UDP or BOTH
filters = "(tcp||udp)" if protocol=='both' else protocol
## EITHER
### Destination is VPN
filters += "&&(((ip.dst==" + IP_VPN
if IPV6_VPN != None and IPV6_VPN != "":
   filters += "|| ipv6.dst==" + IPV6_VPN + ")"
else:
  filters+= ")"
### And source is not client
filters += "&&!(ip.src==" + IP_CLIENT + ")"
if IPV6_CLIENT != None and IPV6_CLIENT != "":
   filters += "&&!(ipv6.src==" + IPV6_CLIENT + ")"
### And source is not ssh
filters += "&&!(ip.src==" + IP_SSH + ")"
if IPV6_SSH != None and IPV6_SSH != "":
   filters += "&&!(ipv6.src==" + IPV6_SSH + ")"
filters += ")"
## EITHER
### Source is VPN
filters += "||((ip.src==" + IP_VPN
if IPV6_VPN != None and IPV6_VPN != "":
   filters += "|| ipv6.src==" + IPV6_VPN + ")"
else:
  filters+= ")"
### And destination is not client
filters += "&&!(ip.dst==" + IP_CLIENT + ")"
if IPV6_CLIENT != None and IPV6_CLIENT != "":
   filters += "&&!(ipv6.dst==" + IPV6_CLIENT + ")"
### And destination is not ssh
filters += "&&!(ip.dst==" + IP_SSH + ")"
if IPV6_SSH != None and IPV6_SSH != "":
   filters += "&&!(ipv6.dst==" + IPV6_SSH + ")"
filters+="))"

# CONFIGURE CAPTURE
print("Output file : src/capture/"+args.output+".pcap")
capture = pyshark.LiveCapture(interface='en0', display_filter=filters, output_file="./src/capture/"+args.output+".pcap")

# LAUNCH CAPTURE

if args.time is not None:
  print('Launching Pyshark for '+str(args.time)+'secs')
  capture.sniff(timeout=args.time)
else:
  print('Launching Pyshark in continuous mode')
  capture.sniff()

