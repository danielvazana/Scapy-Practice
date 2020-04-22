#!/usr/bin/python

from scapy.all import *


def facebook_filter(packet):
	return TCP in packet and IP in packet and packet[IP].dst == '157.240.1.35'


def main():
	packet_to_send = IP(dst='www.google.com') / Raw('Hello')
	packet_to_send.show()
	send(packet_to_send)
	# Now we sniff
	packets_to_sniff = sniff(count=2, lfilter=facebook_filter)
	print packets_to_sniff.summary()


if __name__ == '__main__':
	main()
