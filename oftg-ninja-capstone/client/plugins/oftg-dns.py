__author__ = 'ryan.ohoro'

import base64
import socket

from dns import rdatatype, rdataclass, message, rrset
from dns.exception import DNSException
from dns.resolver import Resolver
from dns.resolver import get_default_resolver
from dns.exception import Timeout
from dns.rdtypes.IN.A import A
from dns.resolver import Resolver
from impacket import ImpactDecoder, ImpactPacket, IP6

from classes.oftgplugin import OFTGPacketPlugin


class OFTGDNS(OFTGPacketPlugin):
    INFO = {
        'Title': 'DNS Query',
        'Usage': '',
        'Author': 'Ryan O\'Horo'
    }

    PROPERTIES = {'portspec':
                      {'Label': 'DNS Port(s)',
                       'Default': '53',
                       'Sample': '23,25,137-139',
                       'Type': 'string',
                       'Value': None},
                  'protocol':
                      {'Label': 'Protocol',
                       'Default': 'UDP',
                       'Options': ['UDP', 'TCP'],
                       'Type': 'option',
                       'Value': None},
                  'domain':
                      {'Label': 'Domain',
                       'Default': None,
                       'Sample': 'example.com',
                       'Type': 'string',
                       'Value': None},
                  'subdomain':
                      {'Label': 'Subdomain',
                       'Default': '_domainkeys',
                       'Sample': '_domainkeys',
                       'Type': 'string',
                       'Value': None},
                    'resolvers':
                   {'Label': 'Alternate Resolvers',
                    'Default': None,
                    'Sample': '8.8.8.8,8.8.4.4',
                    'Type': 'string',
                    'Value': None}
    }

    DATASIZE = 45

    def emitter(self):

        try:
            if self.PROPERTIES['resolvers']['Value']:
                nameservers = [x.strip() for x in self.PROPERTIES['resolvers']['Value'].split(',')]
                nameservers = self.PROPERTIES['resolvers']['Value'].split(',')
            else:
                nameservers = get_default_resolver().nameservers

            for payload in self.encoder(self.payload):
                try:
                    if self.PROPERTIES['subdomain']['Value']:
                        dnsname = '%s.%s.%s.' % (self.dnsb64escape(payload), self.PROPERTIES['subdomain']['Value'],
                                                 self.PROPERTIES['domain']['Value'])
                    else:
                        dnsname = '%s.%s.' % (self.dnsb64escape(payload), self.PROPERTIES['domain']['Value'])

                        print nameservers
                    for ns in nameservers:
                        r = Resolver()
                        r.lifetime = 1
                        print ns, dnsname
                        r.nameservers = [ns]
                        try:
                            r.query(dnsname, 'A', raise_on_no_answer=False)
                        except Timeout:
                            pass # Timed out, that's fine

                except Exception as e:
                    self.logger.error('Exception in %s: %s' % (self.__class__.__name__, e))
                    pass
        except Exception as e:
            raise

        return True

    def collector(self, packet):

        packetdata = None

        try:
            eth = ImpactDecoder.EthDecoder().decode(packet)
            off = eth.get_header_size()

            if eth.get_ether_type() == ImpactPacket.IP.ethertype:
                ip_decoder = ImpactDecoder.IPDecoder()
                ip = ip_decoder.decode(packet[off:])
                dst = ip.get_ip_dst()
                src = ip.get_ip_src()
                if ip.get_ip_p() == ImpactPacket.UDP.protocol:
                    udp = ip.child()
                    payload = udp.child().get_bytes().tostring()
                    try:
                        import hexdump

                        try:
                            msg = message.from_wire(payload)
                        except Exception as e:
                            # Not an acceptable DNS packet
                            return None

                        if len(msg.answer) > 0:
                            # Packet should not have an answer section
                            return None

                        if len(msg.question) > 0:
                            for q in msg.question:
                                #if hasattr(q, 'name'):
                                if q.rdtype == rdatatype.A:

                                    if self.PROPERTIES['subdomain']['Value']:
                                        prefix = '.%s.%s.' % (
                                        self.PROPERTIES['subdomain']['Value'], self.PROPERTIES['domain']['Value'])
                                    else:
                                        prefix = '.%s.' % (self.PROPERTIES['domain']['Value'])

                                    if prefix == q.name.to_text()[-len(prefix):]:

                                        # Send a reply to the DNS packet
                                        try:
                                            r = message.make_response(msg)
                                            a = A(rdataclass.IN, rdatatype.A, '79.70.84.71')  # OFTG in dotted-decimal
                                            rrs = rrset.from_rdata(q.name.to_text(), 30, a)
                                            r.answer.append(rrs)

                                            data = ImpactPacket.Data(r.to_wire())
                                            rudp = ImpactPacket.UDP()
                                            rudp.set_uh_sport(53)
                                            rudp.set_uh_dport(12345)
                                            rudp.contains(data)
                                            rip = ImpactPacket.IP()

                                            rip.set_ip_dst(src)
                                            rip.set_ip_src(self.getlocaladdr())
                                            rip.contains(rudp)
                                            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                                            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                                            s.sendto(rip.get_packet(), (src, 12345))
                                        except Exception as e:
                                            self.logger.error('Failed to send reply packet with %s: %s' % (
                                            self.__class__.__name__, e))

                                        dnsdata = q.name.to_text()[:-len(prefix)]
                                        dnsdata = self.dnsb64unescape(dnsdata)
                                        payload = self.decoder(dnsdata)
                                        result = payload
                                        # TODO: Fix results
                                        result['Source Host'] = src
                                        result['Protocol Subtype'] = 'Port'
                                        result['Subtype'] = 53  #str(ip.child().get_uh_sport())

                                        return result
                    except DNSException:
                        pass
                    except Exception as e:
                        if e:
                            print 'Error %s' % e.message
                        raise


            elif eth.get_ether_type() == IP6.IP6.ethertype:
                ip6_decoder = ImpactDecoder.IP6Decoder()
                ip6 = ip6_decoder.decode(packet[off:])
                src = ip6.get_source_address()
                packetdata = ip6.get_data_as_string()
                self.logger.debug('Skipping IPv6 packet (not supported for this plugin)')

            if not packetdata:
                return None

            return None

        except Exception as e:
            raise

        return None


    # TODO: Remove and replace padding
    def dnsb64escape(self, payload):

        payload = base64.b64encode(payload)
        payload = payload.replace('=', '._')
        payload = payload.replace('+', '-')
        payload = payload.replace('/', '_')
        #payload = 'a%sz' % (payload)

        return payload


    def dnsb64unescape(self, payload):

        #payload = payload[1:-1]
        payload = payload.replace('._', '=')
        payload = payload.replace('-', '+')
        payload = payload.replace('_', '/')
        payload = base64.b64decode(payload)

        return payload

