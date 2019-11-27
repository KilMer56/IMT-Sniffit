import pyshark
import time
import sys
import argparse

from stream import Stream
from es_dao import post_data

stream_map = {}

# GET ARGUMENTS

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--mode', '-m', choices=['packet','stream'], default='stream', nargs='?', help='The mode of capture')

args = parser.parse_args()

isStreamMode = args.mode == "stream"

def calculate_average_delta(packet):
    """
    Calculate average delta for a stream

    :param packet : packet to handle
    :type packet : Packet
    """
    if ('TCP' in packet and 'IP' in packet):
            index = packet.tcp.stream.showname_value
            if index not in stream_map:
                if hasattr(packet, "ip") :
                    stream_map[index] = Stream(packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport)
                else:
                    stream_map[index] = Stream(packet.ipv6.src, packet.tcp.srcport, packet.ipv6.dst, packet.tcp.dstport)
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
    if ('TCP' in packet and 'IP' in packet):
        if isStreamMode:
            index = packet.tcp.stream.showname_value
            stream_map[index].add_packet(packet)
        else:
            post_data("packet", float(packet.sniff_timestamp), int(packet.length.raw_value, 16))

def flush_remaining_streams():
    """
    Flush the stream that still have non flushed content.
    """
    print("Flushing non flushed stream")
    end_time = time.time()
    for key in stream_map:
        stream = stream_map[key]
        if stream.time != 0:
            stream.flush(end_time)

# ANALYZE THE FILE

print("Input file : src/"+args.input+".pcap")
capture = pyshark.FileCapture('./src/capture/'+args.input+'.pcap')
try:
    if isStreamMode:
        print("Calculating average delta")
        capture.apply_on_packets(calculate_average_delta)
        for key in stream_map:
            stream_map[key].set_time(0)

    print("Starting packet analyzing process")
    capture.apply_on_packets(handle_packet)
except:
    pass

if isStreamMode:
    flush_remaining_streams()
