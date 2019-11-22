import pyshark
from stream import Stream

capture = pyshark.FileCapture('capture.pcap')

stream_map = {}

def handle_packet(packet):
    """
    Handle packet and stream creation.

    :param packet : packet to handle
    :type packet : Packet
    """
    index = packet.tcp.stream.showname_value
    if index not in stream_map:
        stream_map[index] = Stream(packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport, 1)
    
    stream_map[index].add_packet(packet)

capture.apply_on_packets(handle_packet, timeout=10)

print("Closing non flushed stream")
for key in stream_map:
    stream = stream_map[key]
    if stream.time != 0:
        stream.flush()