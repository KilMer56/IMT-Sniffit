import socket
from es_dao import post_data

class Stream:
    
    def __init__(self, ip_server, port_server, ip_client, port_client, max_timestamp_gap):
        self.ip_server = ip_server
        self.port_server = port_server
        self.ip_client = ip_client
        self.port_client = port_client
        self.max_timestamp_gap = max_timestamp_gap
        self.payload = 0
        self.time = 0

    def set_time(self, time):
        """
        Set time of the last packet received.
        If the time is over the max-gap, will trigger a flush
        :param time : the time of the last packet
        :type time: long
        """
        if self.time != 0 and time - self.time > self.max_timestamp_gap:
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
        self.set_time(round(float(packet.sniff_timestamp)))

    def flush(self, time):
        """
        Flush stream to ElasticSearch.
        Reset the payload and time.
        """
        host = None
        try:
            host = socket.gethostbyaddr(self.ip_server)[0]
        except:
            host = self.ip_server
        print(host)
        print("flushing ", self.ip_server, ":", self.port_server, "at", time, "payload:", self.payload)
        post_data(self.time,  self.payload)
        self.payload = 0
        self.time = 0

