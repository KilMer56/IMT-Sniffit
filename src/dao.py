import socket
import os
import json

from dotenv import load_dotenv
from datetime import datetime
from store import get_es, get_output_type, append_to_file
load_dotenv()

IP_VPN = os.getenv('IP_VPN')
es = get_es()

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
    Index data in the ElasticSearch index or write to the json file

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
    is_json_output = get_output_type() == "JSON"
    packet = {
        'timestamp': timestamp if is_json_output else datetime.fromtimestamp(timestamp),
        'size': size,
        'protocol': protocol,
        'source': sourceName,
        'dest': destName
    }

    if is_json_output:
        append_to_file(protocol, json.dumps(packet))
    else:
        es.index(index=index, doc_type="packet", body=packet)
