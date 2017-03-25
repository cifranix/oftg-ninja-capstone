__author__ = 'ryan.ohoro'

import socket
import sys

from classes.oftgplugin import *


class OFTGTCP(OFTGPacketPlugin):
    INFO = {
        'Title': 'TCP Data',
        'Usage': '',
        'Author': 'Ryan O\'Horo'
    }

    # The PROPERTIES object specifies the parameters required by the plugin
    # and is used to generate the UI for the case configuration

    PROPERTIES = {'portspec':
                      {'Label': 'TCP Port',
                       'Default': '1-65535',
                       'Sample': '23,25,137-139',
                       'Type': 'string',
                       'Value': None},
                  'portrandomize':
                      {'Label': 'Randomize Ports',
                       'Default': True,
                       'Type': 'boolean',
                       'Value': None}
    }


    def emitter(self):
        # for port in hyphen_range(self.kwargs.get('portspec', self.PROPERTIES['portspec']['Default'])):
        #     print "TCP target:", self.target, port

        #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     sock.sendto(self.payload, (self.target, port))

        #     sock.close()
        # return None

        test()


        return None

    # The collector function is a filter through which collected packets are
    # sent and emitted packets are identified.

    def collector(self, packet):
        # print 'TCPRaw Analyzed: %s' % packet

        #if re.search('.*OFTG.*', packet):
        #    print 'Collector matched packet: %s' % binascii.hexlify(packet)

        return


def test():
    import sys
            # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = ('10.0.0.12', 10000)
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)

    try:
        
        # Send data
        message = 'Sri is a monkey puncher.  It will be repeated.'
        print >>sys.stderr, 'sending "%s"' % message
        sock.sendall(message)

        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print >>sys.stderr, 'received "%s"' % data
        print "**ping"       
    finally:
        print >>sys.stderr, 'closing socket'
        sock.close()

