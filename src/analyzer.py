import pyshark
import time
import sys
import argparse
import os
import traceback
from dotenv import load_dotenv

from stream import Stream
from es_dao import post_data

stream_map_from_client = {}
stream_map_to_client = {}

load_dotenv()

IP_VPN = os.getenv('IP_VPN')
IPV6_VPN = os.getenv('IPV6_VPN')

# GET ARGUMENTS

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--mode', '-m', choices=['packet','stream'], default='stream', nargs='?', help='The mode of capture')

args = parser.parse_args()

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
        stream_map = stream_map_from_client if src == IP_VPN or src == IPV6_VPN else stream_map_to_client

        if index not in stream_map:
            if hasattr(packet, "ip") :
                stream_map[index] = Stream(src, dst, protocol)
            else:
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
            stream_map = stream_map_from_client if src == IP_VPN or src == IPV6_VPN else stream_map_to_client
            stream_map[index].add_packet(packet)
        else:
            post_data("packet", packet.ip.src, packet.ip.dst, float(packet.sniff_timestamp), int(packet.length.raw_value, 16), protocol)

def flush_remaining_streams():
    """
    Flush the stream that still have non flushed content.
    """
    print("Flushing non flushed stream")
    end_time = time.time()
    for key in stream_map_from_client:
        stream = stream_map_from_client[key]
        if stream.time != 0:
            stream.flush(end_time)
    for key in stream_map_to_client:
        stream = stream_map_to_client[key]
        if stream.time != 0:
            stream.flush(end_time)

# ANALYZE THE FILE

print("Input file : src/"+args.input+".pcap")
capture = pyshark.FileCapture('./src/capture/'+args.input+'.pcap')
try:
    if isStreamMode:
        print("Calculating average delta")
        capture.apply_on_packets(calculate_average_delta)
        for key in stream_map_from_client:
            stream_map_from_client[key].set_time(0)
        for key in stream_map_to_client:
            stream_map_to_client[key].set_time(0)
except:
    print(traceback.print_exc())
    pass

print("Starting packet analyzing process")
capture.apply_on_packets(handle_packet)


if isStreamMode:
    flush_remaining_streams()
