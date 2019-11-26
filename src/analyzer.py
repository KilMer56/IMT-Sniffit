import pyshark
import time
import sys
import argparse

from stream import Stream

stream_map = {}


def handle_packet(packet):
    """
    Handle packet and stream creation.

    :param packet : packet to handle
    :type packet : Packet
    """
    if ('TCP' in packet and 'IP' in packet):
        
        index = packet.tcp.stream.showname_value
        if index not in stream_map:
            if hasattr(packet, "ip") :
                stream_map[index] = Stream(packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport, 1)
            else:
                stream_map[index] = Stream(packet.ipv6.src, packet.tcp.srcport, packet.ipv6.dst, packet.tcp.dstport, 1)
        stream_map[index].add_packet(packet)

def flush_remaining_streams():
    """
    Flush the stream that still have non flushed content.
    """
    print("Flushing non flushed stream")
    end_time = round(time.time())
    for key in stream_map:
        stream = stream_map[key]
        if stream.time != 0:
            stream.flush(end_time)

# GET ARGUMENTS

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', default='capture', nargs='?', help='The name of the output .pcap file')
parser.add_argument('--mode', '-m', choices=['packet','stream'], default='stream', nargs='?', help='The mode of capture')
parser.add_argument('--verbose', '-v', nargs='?', help='Is in verbose mode')

args = parser.parse_args()

# ANALYZE THE FILE

print("Input file : src/"+args.input+".pcap")
capture = pyshark.FileCapture('./src/capture/'+args.input+'.pcap')

print("Starting packet analyzing process")
capture.apply_on_packets(handle_packet)

flush_remaining_streams()