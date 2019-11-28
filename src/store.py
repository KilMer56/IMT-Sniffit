import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()
IP_VPN = os.getenv('IP_VPN')
IP_ES = os.getenv('IP_ES')
PORT_ES = os.getenv('PORT_ES')

global settings

settings = {'tcp_first_write': True, 'udp_first_write': True, 'es': None}

def init_es():
    """
    Initialize the ES connection
    """
    if not hasattr(settings, "es"):
        settings["es"] = Elasticsearch([{'host': IP_ES, 'port': PORT_ES}])

def get_es():
    """ 
    Return the ES connection
    """
    init_es()
    return settings["es"]

def set_output_name(name):
    """
    Set the name of the output file
    :param name : name of the output file
    :type name: str
    """
    settings["outputName"] = name

def append_to_file(protocolName, string):
    """
    Append the given JSON string to file.
    Take care of the comma
    :param protocolName : TCP or UDP
    :type protocolName: str
    :param string : string representing the data
    :type string: str
    """
    if settings[protocolName + "_first_write"]:
        settings[protocolName].write(string)
        settings[protocolName + "_first_write"] = False
    else:
        settings[protocolName].write(", " + string)

def set_output_type(outputType):
    """
    Set the output type
    :param outputType : JSON or ES
    :type outputType: str
    """
    settings["outputType"] = outputType

def open_tcp_file():
    """
    Open the tcp file for this analysis
    """
    fileName = settings["outputName"] + "_tcp.json"
    # Empty file
    tempFile = open(fileName, "w")
    tempFile.write("[")
    tempFile.close
    settings["tcp"] = open(fileName, "a")

def open_udp_file():
    """
    Open the udp file for this analysis
    """
    fileName = settings["outputName"] + "_udp.json"
    # Empty file
    tempFile = open(fileName, "w")
    tempFile.write("[")
    tempFile.close
    settings["udp"] = open(fileName, "a")

def close_tcp_file():
    """
    Close the tcp file for this analysis
    """
    settings["tcp"].write("]")
    settings["tcp"].close()

def close_udp_file():
    """
    Close the udp file for this analysis
    """
    settings["udp"].write("]")
    settings["udp"].close()

def get_output_type():
    """
    Return the outputType of this analysis
    """
    return settings["outputType"]