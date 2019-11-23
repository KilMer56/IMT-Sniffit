import pyshark
import time
from stream import Stream

capture = pyshark.FileCapture('./src/capture.pcap')

stream_map = {}

def handle_packet(packet):
    """
    Handle packet and stream creation.

    :param packet : packet to handle
    :type packet : Packet
    """
    index = packet.tcp.stream.showname_value
    if index not in stream_map:
        if hasattr(packet, "ip") :
            stream_map[index] = Stream(packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport, 10)
        else:
            stream_map[index] = Stream(packet.ipv6.src, packet.tcp.srcport, packet.ipv6.dst, packet.tcp.dstport, 10)
    stream_map[index].add_packet(packet)

capture.apply_on_packets(handle_packet, timeout=100)

print("Closing non flushed stream")
end_time = round(time.time())
for key in stream_map:
    stream = stream_map[key]
    if stream.time != 0:
        stream.flush(end_time)