"""
=====slicer.py>=========================
Description: <.pcap> File Slicer
Author: u$3r_h0n3$T
Colaboration: K3vIn
Created_Date: 20/03/2023
Patched: 01/06/2023
Version 1.1 

Requierements modules

scapy
base64
binascii

====================================
"""
# === <Modules> ========================== #
import argparse
from scapy.all import *
from collections import Counter
from scapy.utils import hexdump
from scapy.error import Scapy_Exception
import base64
import binascii
# ======================================== #

## =================================================================================== ##
#	Function to count amount of packets, and determines the protocol in a given packet
#	seeing a lot of FTP traffic might suggest file transfers are taking place, while a 
#	lot of DNS traffic might suggest a lot of domain name resolutions (e.g. due to web 
#	browsing or other network connections
# =====================================================================================##
def get_protocol(packet):
	proto = "Other"
	if packet.haslayer(IP) or packet.haslayer(IPv6):
		if packet.haslayer(TCP):
			proto = "TCP"
			if packet[TCP].dport == 21 or packet[TCP].sport == 21:
				proto = "FTP"
			elif packet[TCP].dport == 143 or packet[TCP].sport == 143:
				proto = "IMAP"
			elif packet[TCP].dport == 389 or packet[TCP].sport == 389:
				proto = "LDAP"
		elif packet.haslayer(UDP):
			proto = "UDP"
			if packet[UDP].dport == 53 or packet[UDP].sport == 53:
				proto = "DNS"
			elif packet[UDP].dport == 5683 or packet[UDP].sport == 5683:
				proto = "LLRP"
		else:
			proto = "IP"
	return proto

# ==================================================================================== #
#	This function can be used to get an overview of the types and protocols of 
#	packets in a pcap file. It helps in understanding the composition of network 
#	traffic captured in the pcap file. Different types and protocols of packets might 
#	indicate different types of network activities or behaviors	
# ==================================================================================== #
def count_packet_types(pcap_file):
	
	try:
		packets = rdpcap(pcap_file)
	except Scapy_Exception as e:
		print(f"Scapy Error: {e}")
		return Counter()
		
	packet_info = [(type(packet).__name__, get_protocol(packet)) for packet in packets]
	packet_counter = Counter(packet_info)
	
	return packet_counter

# ===================================================================================== # 
#	function is used to print a hexdump (hexadecimal view) of the payload data for each 
#	IP or UDP packet in the provided pcap file. Hexdump is a utility that displays the 
#	content of data buffers in hexadecimal
# ===================================================================================== #
def print_hexdump_data(pcap_file):
	packets = rdpcap(pcap_file)
	for i, packet in enumerate(packets):
		if packet.haslayer(IP) or packet.haslayer(UDP):
			print(f"Packet{i}: {packet.summary()}")
			hex_payload = hexdump(packet.payload, dump=True)
			print(f"Data: \n{hex_payload}\n") 

# ====================================================================================== #
#	The function ends up printing a summary for each packet of the specified type 
#	(IP or UDP) in the pcap file. Each summary includes the packet number (how many 
#	packets of this type have been encountered so far), the index of the packet in the 
#	pcap file, and a brief description of the packet.
# ====================================================================================== #
def print_packet_data(pcap_file, packet_type):
	packets = rdpcap(pcap_file)
	packet_count = 0
	for i, packet in enumerate(packets):
		if packet_type == "IP" and packet.haslayer(IP):
			packet_count += 1
			print(f"IP Packet {packet_count} (Index: {i}): {packet.summary()}\n")
		elif packet_type == "UDP" and packet.haslayer(UDP):
			packet_count += 1
			print(f"UDP Packet {packet_count} (Index: {i}): {packet.summary()}\n")

# ====================================================================================== #
#	Through this function, you get a clear printout of the source information 
#	(IP and MAC addresses) of each packet in the input list that has either an IP or a 
#	UDP layer. This information can be helpful for understanding where the packets are 
#	originating from.
# ====================================================================================== # 
def print_source_info(packets):
	for i, packet in enumerate(packets):
		if packet.haslayer(IP) or packet.haslayer(UDP):
			source_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
			source_mac = packet[Ether].src if packet.haslayer(Ether) else "N/A"
			print(f"Packet {i + 1}: Source IP: {source_ip}, Source MAC: {source_mac}")



# ========================================================================================= #
#	This function is essentially a packet extraction function - it doesn't filter anything 
#	by itself, but instead it serves as a foundation for further packet analysis. You would 
#	use this function to load packet data from a PCAP file and then perform additional 
#	operations on the returned packets, such as filtering based on packet type, analyzing 
#	packet contents.
# ==========================================================================================#
def filter_packets(pcap_file):
	packets = rdpcap(pcap_file)
	return packets
	

## ---- decryption colaboration: K3vIn --- ##
# =============================================================================================== # 
# 	This function reads a PCAP file, extracts the raw data from each packet, attempts to decode 
#	this data as base64-encoded data, and then attempts to decode this data as a UTF-8 
#	encoded string
# =============================================================================================== #
def decode_base64_data(pcap_file):
	
	packets = rdpcap(pcap_file)
	base64_bytes = []
	for packet in packets:
		if packet.haslayer(Raw):
			raw_data = packet[Raw].load
			try:
				base64_bytes.append(raw_data)
			except:
				print(f'Error reading {raw_data}')
				continue
	
	try: 
		base64_string_bytes = b''.join(base64_bytes)
		print(f'Bytes: {base64_string_bytes}')
		decoded_bytes = base64.b64decode(base64_string_bytes)
		print(f'\nDecoded bytes: {decoded_bytes}')
		decoded = decoded_bytes.decode("utf-8", errors='ignore')
		print(f'\nDecoded: {decoded}')
	
	except binascii.Error as e:
		print(f'Error decoding base64: {e}')
		return
		
# =======< MAIN FUNCTION >========================================================================== #
def main():

# ------------------------------------------------------------------------------------------------ #
# --<Comandline arguments with argparse module>----------------------------------------------------#
	parser = argparse.ArgumentParser(description="Count the type of packets in the file")
	parser.add_argument("-F", "--pcap_file", required=True, help="Path to the PCAP file")
	parser.add_argument("-udp" "--print_udp_data", action="store_true", help="Print out the data from the UDP protocol")
	parser.add_argument("-ipData", "--print_ip_data", action="store_true", help="Print out the data for the IP")
	parser.add_argument("-hexdump", "--hexdump_data", action="store_true", help="Display hexdump of packet data")
	parser.add_argument("-dB64", "--decode_base64", action="store_true", help="Decode base64 data from pcap file")
	parser.add_argument("-source", "--print_source_info", action="store_true", help="Print source IP and MAC addresses of IP and UDP packets")

# ======================================================================== #
# 	These lines are using the argparse library to handle command line 
#	arguments. They extract the path to the PCAP file that the user 
#	has provided.
# ======================================================================== #
	args = parser.parse_args()
	pcap_file = args.pcap_file
	
	# check if we have an error 
	try:
		packet_counter = count_packet_types(pcap_file)
	
	except FileNotFoundError as e:
		print(f"\nFileNotFoundError: {e}. Please check if the PCAP file exists and the path is correct.")
		return
	
	except PermissionError as e:
		print(f"\nPermissionError: {e}. Please check the permissions on the file.")
		return
	
	except Exeption as e:
		print(f"\nUnexpected Error: {e}")
		return
	
	# --<print the count of each type of packet found in the PCAP file>------# 
	print("Total packet types")
	for (packet_type, protocol), count in packet_counter.items():
		print(f"{packet_type} (Protocol: {protocol}): {count}")
	
	# --< Data for UDP arument > ---# 	
	if args.udp__print_udp_data:
		print("\nData of UDP Packets:")
		print_packet_data(pcap_file ,"UDP")
	
	
	# --< Print data related to the IP packets> ---- # 
	if args.print_ip_data:
		print("\nData of IP packets:")
		print_packet_data(pcap_file, "IP")
		
	# --<Priting the Hexdump data >---- # 
	if args.hexdump_data:
		print("\nHexdump of packet data:")
		print_hexdump_data(pcap_file)
	
	# --< Base64 decode> --- # 
	if args.decode_base64:
		print("\nDecoding base64 data from pcap file: ")
		decode_base64_data(pcap_file)
		
	packets = filter_packets(pcap_file)
	
	if args.print_source_info:
		print_source_info(packets)


# ======== <INIT_Main> ======= # 				
if __name__== "__main__":
	main()
	
	
# ==== END_OF_FILE ==================================== #
