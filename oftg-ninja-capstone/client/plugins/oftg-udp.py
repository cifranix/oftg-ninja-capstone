__author__ = 'ryan.ohoro'

import socket
import random
from impacket import ImpactDecoder, ImpactPacket

from classes.oftgplugin import OFTGPacketPlugin


class OFTGUDP(OFTGPacketPlugin):
    INFO = {
        'Title': 'UDP Data',
        'Usage': '',
        'Author': 'Ryan O\'Horo'
    }

    PROPERTIES = {'portspec':
                      {'Label': 'UDP Ports',
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

    # This value is the maximum practical payload size for the given protocol.
    # It's used to limit the chunk size of large payloads
    DATASIZE = 65507

    def emitter(self):

        try:

            ports = self.listproperty('portspec')

            if self.PROPERTIES['portrandomize']['Value'] == True:
                random.shuffle(ports)

            for payload in self.encoder(self.payload):
                for port in ports:
                    self.logger.debug('UDPRaw Port %i' % port)
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.sendto(payload, (self.target, port))
                        s.close()
                    except Exception:
                        raise

        except socket.error:
            raise
        except Exception:
            raise

        return True

    def collector(self, buffer):

        try:
            decoder = ImpactDecoder.EthDecoder()
            packet = decoder.decode(buffer)
            if packet.get_ether_type() == ImpactPacket.IP.ethertype:
                ip = packet.child()
                if ip and ip.get_ip_p() == ImpactPacket.UDP.protocol:

                    udppacket = ip.child()
                    data = udppacket.get_data_as_string()
                    payload = self.decoder(data)

                    if payload:
                        self.logger.debug('%s got a payload from %s' % (self.__class__.__name__, ip.get_ip_src()))
                        # print '%s got a payload from %s' % (self.__class__.__name__, ip.get_ip_src())
                        result = payload
                        result['Source Host'] = ip.get_ip_src()
                        result['Protocol Subtype'] = 'Port'
                        result['Subtype'] = str(udppacket.get_uh_dport())
                        return result

                else:
                    return

        except Exception as e:
            # If the decoding fails, it just wasn't meant to be.
            pass

        return



