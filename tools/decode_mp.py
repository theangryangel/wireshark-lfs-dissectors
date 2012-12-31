#!/usr/bin/env python
import pure_pcapy as pcapy
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP
import struct

def grab_tcp(decoder, next, debug = False):
	packet = decoder.decode(next[1])
	l2 = packet.child()
	if not isinstance(l2, IP):
		return ''

	l3 = l2.child()

	proto = 'TCP'
	src_ip = l2.get_ip_src()
	dst_ip = l2.get_ip_dst()
	src_port = 0
	dst_port = 0
	payload = ''

	if isinstance(l3, TCP):
		dst_port = l3.get_th_sport()
		src_port = l3.get_th_dport()

		payload = l3.get_data_as_string()

		if (payload == None):
			return ''

	if debug:
		print "%s from %s (%s) to %s(%s) " % (proto, src_ip, src_port, dst_ip, dst_port)

	return payload

def grab_udp(decoder, next, debug = False):
	packet = decoder.decode(next[1])
	l2 = packet.child()
	if not isinstance(l2, IP):
		return

	l3 = l2.child()

	proto = 'TCP'
	src_ip = l2.get_ip_src()
	dst_ip = l2.get_ip_dst()
	src_port = 0
	dst_port = 0
	
	if isinstance(l3, UDP):
		proto = 'UDP'
		dst_port = l3.get_uh_sport()
		src_port = l3.get_uh_dport()


reader = pcapy.open_offline('../LFS Client-Server 0.6E.pcap')

decoder = EthDecoder()
next = reader.next()
data = ''

while next and next[0] <> None:

	print ".",
	data += grab_tcp(decoder, next)
	next = reader.next()

print "Done parsing pcap. Got TCP data. Attempting to splt packets."

size = len(data)
offset = 0
i = 0

found = dict()

while offset < size:
	next = struct.unpack("<BB", data[offset:offset+2])
	print i, next[0], next[1]

	if not next[1] in found:
		found[next[1]] = dict()

	if not next[0] in found[next[1]]:
		found[next[1]][next[0]] = 0

	found[next[1]][next[0]] += 1

	#found.setdefault(next[1], []).append(next[0])

	if (next[0] == 0):
		raise Exception('It\'s all wrong.')
	offset += next[0] + 1
	i += 1

i -= 1

print '@ offset %d, total data received %d, total packets received %d' % (offset, size, i)

# Outputs a nested dictionary
# dimension 0 = packet id
# dimension 1 = packet size
# dimension 2 = number of times seen at this size
print found
