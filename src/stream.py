import socket
from es_dao import post_data

class Stream:
    
    def __init__(self, ip_source, ip_dest, protocol):
        self.ip_source = ip_source
        self.ip_dest = ip_dest
        self.protocol = protocol
        self.payload = 0
        self.time = 0
        self.deltaNumber = 0
        self.deltaSum = 0
        self.averageDelta = 0

    def update_delta(self, time):
        delta = time - self.time
        self.time = time
        self.deltaNumber += 1
        self.deltaSum += delta
        self.averageDelta = self.deltaSum / self.deltaNumber

    def set_time(self, time):
        """
        Set time of the last packet received.
        If the time is over the max-gap, will trigger a flush
        :param time : the time of the last packet
        :type time: long
        """
        if self.time != 0 and time - self.time > self.averageDelta:
            self.flush(time)
        else:
            self.time = time
    
    def add_packet(self, packet):
        """
        Handle packet and stream creation.
        :param packet : the packet to add to the stream
        :type packet : Packet
        """
        self.payload += int(packet.length.raw_value, 16)
        self.set_time(float(packet.sniff_timestamp))

    def flush(self, time):
        """
        Flush stream to ElasticSearch.
        Reset the payload and time.
        """
        post_data("stream", self.ip_source, self.ip_dest, self.time, self.payload, self.protocol)
        self.payload = 0
        self.time = 0

