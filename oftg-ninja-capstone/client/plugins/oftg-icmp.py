__author__ = 'ryan.ohoro'

import socket

from impacket import ImpactDecoder, ImpactPacket

from classes.oftgplugin import OFTGPacketPlugin


class OFTGICMP(OFTGPacketPlugin):

    INFO = {
        'Title': 'ICMP Data',
        'Usage': """ This plugin appends arbitrary data to an ICMP packet of various types.

        Select a set of ICMP types to test. The default is 8 (echo). Common types include:

          0	Echo Reply
          1	Unassigned
          2	Unassigned
          3	Destination Unreachable
          4	Source Quench
          5	Redirect
          6	Alternate Host Address
          7	Unassigned
          8	Echo
          9	Router Advertisement
         10	Router Selection
         11	Time Exceeded
         12	Parameter Problem
         13	Timestamp
         14	Timestamp Reply
         15	Information Request
         16	Information Reply
         17	Address Mask Request
         18	Address Mask Reply
         30	Traceroute
         33 IPv6 Where-Are-You
         34 IPv6 I-Am-Here

        """,
        'Author': 'Ryan O\'Horo'
    }

    # The PROPERTIES object specifies the parameters required by the plugin
    # and is used to generate the UI for the case configuration

    PROPERTIES = {'icmptype':
                      {'Label': 'ICMP Type(s)',
                       'Default': '0,8,30',
                       'Sample': '0,8,11,13-15,30',
                       'Type': 'string',
                       'Value': None}
    }

    # This value is the maximum practical payload size for the given protocol.
    # It's used to limit the chunk size of large payloads
    DATASIZE = 65507

    def emitter(self):
        """ The emitter method is responsible for establishing the connections or sending the packets associated with
        the plugin. Emitter MUST use the encoder() method to assemble payloads
        :return: True if successful
        """

        try:

            src = self.getlocaladdr()

            try:
                dst = socket.gethostbyname(self.target)
            except Exception as e:
                dst = self.target
                self.logger.error('Failed to resolve target hostname for %s: %s' % (self.__class__.__name__, e))
                raise e

            # Fetch the icmptype property as a list
            icmptypes = self.listproperty('icmptype')
            print icmptypes
            if not icmptypes:
                icmptypes = [8]

            # Send the payload to the encoder which returns a generator, then iterate over the chunked and encoded
            # payload
            for payload in self.encoder(self.payload):
                # Iterate over all of the specified types for this payload and execute the delivery
                for icmptype in icmptypes:
                    ip = ImpactPacket.IP()
                    ip.set_ip_src(src)
                    ip.set_ip_dst(dst)

                    icmp = ImpactPacket.ICMP()
                    icmp.set_icmp_type(icmptype)

                    seq_id = 0

                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                    icmp.contains(ImpactPacket.Data(payload))
                    ip.contains(icmp)

                    icmp.set_icmp_id(seq_id)
                    icmp.set_icmp_cksum(0)
                    icmp.auto_checksum = 1

                    s.sendto(ip.get_packet(), (self.target, 0))
                    seq_id += 1


        except socket.error:
            raise
        except Exception:
            raise

        return True

    def collector(self, buffer):
        """ The collector method for OFTGPacket plugin is responsible for analyzing collected packet data for OFTG-Ninja
        payloads. The collector method MUST use the decoder() method to analyze extracted data.
        :return: Dict, as returned by decoder()
        """
        try:
            decoder = ImpactDecoder.EthDecoder()
            packet = decoder.decode(buffer)
            if packet.get_ether_type() == ImpactPacket.IP.ethertype:
                ip = packet.child()
                if ip and ip.get_ip_p() == ImpactPacket.ICMP.protocol:
                    icmppacket = ip.child()
                    data = icmppacket.get_data_as_string()
                    result = self.decoder(data)
                    if result:
                        # self.logger.debug('%s got a payload from %s' % (self.__class__.__name__, ip.get_ip_src()))
                        result['Source Host'] = ip.get_ip_src()
                        result['Protocol Subtype'] = 'ICMP Type'
                        result['Subtype'] = str(icmppacket.get_icmp_type())
                        return result
                    else:
                        return
                else:
                    return

        except Exception as e:
            raise

        return



