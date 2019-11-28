import os
import socket
from datetime import datetime
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()
IP_VPN = os.getenv('IP_VPN')
IP_ES = os.getenv('IP_ES')
PORT_ES = os.getenv('PORT_ES')
es = Elasticsearch([{'host': IP_ES, 'port': PORT_ES}])

def find_host_name(ip):
    """
    Perform a reverse DNS query to get the host name

    :param ip : timestamp of the data
    :type ip : str
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def post_data(index, source, dest, timestamp, size, protocol):
    """
    Index data in the ElasticSearch index

    :param index : name of the elasticsearch index
    :type index : str

    :param source : ip of the packet/stream source
    :type source : str

    :param dest : ip of the packet/stream destination
    :type dest : str

    :param size : size of the data
    :type size : int

    :param protocol : tcp or udp
    :type protocol : str
    """
    sourceName = "vpn" if source == IP_VPN else find_host_name(source)
    destName = "vpn" if dest == IP_VPN else find_host_name(dest)
    packet = {
        'timestamp': datetime.fromtimestamp(timestamp),
        'size': size,
        'protocol': protocol,
        'source': sourceName,
        'dest': destName
    }
    
    es.index(index=index, doc_type="packet", body=packet)
