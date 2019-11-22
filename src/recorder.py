import pyshark

capture = pyshark.LiveCapture(interface='en0',  display_filter="ip.dst==192.168.0.10&&tcp", output_file="./capture.pcap")

capture.sniff(timeout=10)

