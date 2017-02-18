__author__ = 'ryan.ohoro'

import ctypes
import sys
from ctypes.util import find_library

if sys.platform == "darwin":
    _pcap = ctypes.cdll.LoadLibrary(find_library("libpcap"))
elif sys.platform == "linux2":
    _pcap = ctypes.cdll.LoadLibrary("libpcap.so")

errbuf = ctypes.create_string_buffer(256)

pcap_lookupdev = _pcap.pcap_lookupdev
pcap_lookupdev.restype = ctypes.c_char_p
dev = pcap_lookupdev(errbuf)
print dev

# create handler
pcap_create = _pcap.pcap_create
handle = pcap_create(dev, errbuf)
print handle
if not handle:
    print "failed creating handler:", errbuf
    exit()

# monitor mode
pcap_can_set_rfmon = _pcap.pcap_can_set_rfmon
print "can rfmon:", pcap_can_set_rfmon(handle)