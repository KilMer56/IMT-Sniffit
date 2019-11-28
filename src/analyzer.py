import pyshark
import time
import sys
import argparse
import os
import traceback
from dotenv import load_dotenv

from stream import Stream
from dao import post_data
from store import set_output_type, set_output_name, init_es, open_udp_file, open_tcp_file, close_tcp_file, close_udp_file

# We need to handle udp and tcp separately
# Wireshark is supposed to give a stream index depending on the protocol, but we've had collision during
# the testing process.
stream_maps = {"udp" : {'from_client': {}, 'to_client':{}}, "tcp":  {"from_client": {}, "to_client": {}}}

load_dotenv()

IP_VPN = os.getenv('IP_VPN')
IPV6_VPN = os.getenv('IPV6_VPN')

# GET ARGUMENTS
parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--mode', '-m', choices=['packet','stream'], default='stream', nargs='?', help='The mode of capture')
parser.add_argument('--outputType', '-o', choices=['ES','JSON'], default='ES', nargs='?', help='The output type of the result')

args = parser.parse_args()

set_output_type(args.outputType)

# Prepare file or es system
if args.outputType == "ES":
    init_es()
elif args.outputType == "JSON":
    set_output_name(args.input)
    open_udp_file()
    open_tcp_file()

isStreamMode = args.mode == "stream"

def is_processable(packet):
    return (('tcp' in packet or 'udp' in packet) and ('ip' in packet or 'ipv6' in packet))

def calculate_average_delta(packet):
    """
    Calculate average delta for a stream

    :param packet : packet to handle
    :type packet : Packet
    """
    if is_processable(packet):
        protocol = "tcp" if hasattr(packet, "tcp") else "udp"
        index = packet.tcp.stream.showname_value if protocol == "tcp" else packet.udp.stream.showname_value
        src = packet.ip.src if hasattr(packet, "ip") else packet.ipv6.src
        dst = packet.ip.dst if hasattr(packet, "ip") else packet.ipv6.dst
        stream_map = stream_maps[protocol]["from_client"] if src == IP_VPN or src == IPV6_VPN else stream_maps[protocol]["to_client"]

        if index not in stream_map:
            stream_map[index] = Stream(src, dst, protocol)
        if stream_map[index].time == 0:
            stream_map[index].set_time(float(packet.sniff_timestamp))
        else:
            stream_map[index].update_delta(float(packet.sniff_timestamp))

def handle_packet(packet):
    """
    Handle packet and stream creation.

    :param packet : packet to handle
    :type packet : Packet
    """
    if is_processable(packet):
        protocol = "tcp" if hasattr(packet, "tcp") else "udp"
        if isStreamMode:
            index = packet.tcp.stream.showname_value if protocol == "tcp" else packet.udp.stream.showname_value
            src = packet.ip.src if hasattr(packet, "ip") else packet.ipv6.src
            dst = packet.ip.dst if hasattr(packet, "ip") else packet.ipv6.dst
            stream_map = stream_maps[protocol]["from_client"] if src == IP_VPN or src == IPV6_VPN else stream_maps[protocol]["to_client"]
            stream_map[index].add_packet(packet)
        else:
            post_data("packet", packet.ip.src, packet.ip.dst, float(packet.sniff_timestamp), int(packet.length.raw_value, 16), protocol)

def flush_remaining_streams():
    """
    Flush the stream that still have non flushed content.
    """
    print("Flushing non flushed stream")
    end_time = time.time()
    for protocol in stream_maps:
        for key in stream_maps[protocol]["from_client"]:
            stream = stream_maps[protocol]["from_client"][key]
            if stream.time != 0:
                stream.flush(end_time)
        for key in stream_maps[protocol]["to_client"]:
            stream = stream_maps[protocol]["to_client"][key]
            if stream.time != 0:
                stream.flush(end_time)

# ANALYZE THE FILE

print("Input file : capture/"+args.input+".pcap")
capture = pyshark.FileCapture('./capture/'+args.input+'.pcap')
try:
    if isStreamMode:
        print("Calculating average delta")
        capture.apply_on_packets(calculate_average_delta)
        for protocol in stream_maps:
            for key in stream_maps[protocol]["from_client"]:
                stream_maps[protocol]["from_client"][key].set_time(0)
            for key in stream_maps[protocol]["to_client"]:
                stream_maps[protocol]["to_client"][key].set_time(0)
except:
    print(traceback.print_exc())
    pass

print("Starting packet analyzing process")
try:
    capture.apply_on_packets(handle_packet)
except:
    print("Caught exception during process, last process might have been cut during reception")
    print(traceback.print_exc())
    pass

if isStreamMode:
    flush_remaining_streams()

if args.outputType == "JSON":
    close_udp_file()
    close_tcp_file()

print("Done")