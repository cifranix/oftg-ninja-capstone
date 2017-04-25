__author__ = 'ryan.ohoro'

import os
import imp
import inspect
import struct
import binascii
from hashlib import sha256
import zlib
import logging


def hyphen_range(s):
    """ Translates an arbitrary range into a list
    :param s: A range delimited with dashes and commas, e.g. 1-50,75,76
    :return: A list of the specified values
    """
    l = []
    for x in s.split(','):
        elem = x.split('-')
        if len(elem) == 1:
            l.append(int(elem[0]))
        elif len(elem) == 2:
            start, end = map(int, elem)
            for i in xrange(start, end + 1):
                l.append(i)
        else:
            raise ValueError('Format error in %s' % x)
    return l


def chunks(data, length):
    for z in xrange(0, len(data), length):
        yield data[z:z + length]


def safe64_decode(string):
    pass
    return None


def safe64_encode(string):
    pass
    return None


class OFTGControl():
    ENCR = 0b00000001
    COMP = 0b00000010


class OFTGPlugin(object):
    """ This is the base class of all OFTG plugins
        All plugin files should define a uniquely named plugin class which inherits the OFTGPacketPlugin or OFTGAPIPlugin class
    """

    MINCHUNKSIZE = 20
    MAXCHUNKSIZE = 1500000000  # 1.5gib
    OVERHEAD = 19

    #def __init__(self, logger=None):
    #    self.logger = logger

    def __loadproperties__(self, case):

        self.__properties__()

        for prop in self.PROPERTIES:
            if not self.PROPERTIES[prop]['Value']:
                #self.logger.debug(self.PROPERTIES[prop]['Default'])
                self.PROPERTIES[prop]['Value'] = self.PROPERTIES[prop]['Default']

        if not case:
            return

        for prop in case['plugins'][self.__class__.__name__]:
            try:
                self.PROPERTIES[prop]['Value'] = case['plugins'][self.__class__.__name__][prop]
            except Exception as e:
                # FIXME: No logger available
                #self.logger.error('Property error in %s: %s' % (self.__class__.__name__, e.message))
                pass

    def __properties__(self):

        PROPERTIES = self.PROPERTIES

        for prop in PROPERTIES:
            if 'Function' in PROPERTIES[prop]:
                func = getattr(self, PROPERTIES[prop]['Function'])
                if 'Type' in PROPERTIES[prop]:
                    if PROPERTIES[prop]['Type'] == 'list':
                        PROPERTIES[prop]['List'] = func()
                    else:
                        PROPERTIES[prop]['Default'] = func()

        self.PROPERTIES = PROPERTIES

        return PROPERTIES

    def getlocaladdr(self):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print "this is s" + str(s.getsockname())


        # where it
        # s.connect(('example.com', 0))
        print "after the connect statement"
        return s.getsockname()[0]

    def listproperty(self, property):
        if self.PROPERTIES[property]['Value']:
            return hyphen_range(self.PROPERTIES[property]['Value'])
        else:
            # FIXME: No logger available
            #self.logger.error('Error in %s: No property %s' % (__name__, property))
            return None

    # TODO: Create proper result object
    class Result(object):
        def __init__(self, sourcehost, payloaddata):
            self.sourcehost = sourcehost
            self.payloaddata = payloaddata

    def decompress(self, payload):
        return zlib.decompress(payload)

    def decrypt(self, payload, key, iv):
        # TODO: Client-side decryption
        return

    # TODO: Move to OFTGPacketPlugin class
    def encoder(self, payload=None, key='OFTG', encrypt=False, compress=False):
        """
        :param payload: Data
        :param sessionkey: Pre-shared key
        :param encrypt: Encrypt the payload data
        :param compress: Compress the payload data
        :return: Payload generator
        """

        # TODO: Allow empty payloads for single-packet testing

        if self.DATASIZE < self.MINCHUNKSIZE:
            raise ValueError(' ! Payload size too small for normal encoding')
        elif self.DATASIZE > self.MAXCHUNKSIZE:
            raise ValueError(' ! Payload size too large for normal encoding')

        if compress:
            payload = zlib.compress(payload)

        if encrypt:
            # TODO: Client-side decryption
            # unpad = lambda s : s[:-ord(s[len(s)-1:])]
            from Crypto.Cipher import AES

            BS = 16
            s = sha256()
            s.update(key)
            iv = os.urandom(BS)
            aes = AES.new(s.digest()[:BS], AES.MODE_CBC, iv)
            pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
            payload = pad(payload)
            payload = iv + aes.encrypt(payload)

        if self.DATASIZE == 4:
            # TODO: IP address encoding
            pass

        # Compute payload length
        length = len(payload)

        # Compute the message digest
        s = sha256()
        s.update(payload)
        digest = s.digest()[:4]

        # Hash the plugin name to generate a somewhat unique identifier
        s = sha256()
        s.update(self.__class__.__name__)
        pluginhash = s.digest()[:4]

        # Generate a random token to uniquely identify the payload
        exfilid = os.urandom(4)

        # Subtract the header/footer data from the final size length
        self.DATASIZE = self.DATASIZE - self.OVERHEAD

        chunknum = 0

        # Chunk the payload data
        for off in xrange(0, length, self.DATASIZE):

            # Set the payload control bits
            control = 0b10000000
            if compress:
                control = control | OFTGControl.COMP
            if encrypt:
                control = control | OFTGControl.ENCR

            # Assemble the final payload without the checksum
            crcdata = pluginhash + \
                      exfilid + \
                      digest + \
                      struct.pack('!B', control) + \
                      struct.pack('!H', chunknum) + \
                      payload[off:off + self.DATASIZE]

            chunknum = chunknum + 1

            # Yield the payload chunk with a checksum
            yield crcdata + struct.pack('!L', binascii.crc32(crcdata) & 0xffffffff)


    def decoder(self, payload=None, sessionkey='OFTG'):
        encrypted = False
        compressed = False
        encryptiv = None
        payloadhash = None
        pluginhash = None
        exfilid = None

        crc = struct.pack('!L', binascii.crc32(payload[:-4]) & 0xffffffff)

        # Data contains a valid OFTG-Ninja checksum footer
        if crc == payload[-4:]:
            try:
                # Extract header data
                crcdata = payload[:-4]
                pluginhash = binascii.hexlify(crcdata[:4])
                exfilid = binascii.hexlify(crcdata[4:8])
                payloadhash = binascii.hexlify(crcdata[8:12])
                control = struct.unpack('!B', crcdata[12])[0]
                chunk = struct.unpack('!H', crcdata[13:15])[0]

                # Remove header
                payload = crcdata[18:]

                # Check control bits
                if control & OFTGControl.ENCR == OFTGControl.ENCR:
                    encrypted = True
                    encryptiv = payload[:16]
                    payload = payload[16:]

                if control & OFTGControl.COMP == OFTGControl.COMP:
                    compressed = True

                # Extract payload
                payload = crcdata[15:]

                result = {}
                result['Payload'] = payload
                result['Payload Hash'] = payloadhash
                result['Plugin Hash'] = pluginhash
                result['Exfil ID'] = exfilid
                result['Encrypt IV'] = encryptiv
                result['Encrypted'] = encrypted
                result['Compressed'] = compressed

                return result

            except Exception as e:
                raise

        return


class OFTGPacketPlugin(OFTGPlugin):
    def __init__(self, source=None, target=None, payload=None, payloadname='Generic Data', logger=None, **kwargs):
        self.source = source
        self.target = target
        self.payload = payload
        self.payloadname = payloadname
        self.kwargs = kwargs
        self.logger = logger


class OFTGAPIPlugin(OFTGPlugin):
    def __init__(self, source=None, case=None, target=None, payload=None, payloadname='Generic Data', logger=None,
                 **kwargs):
        self.source = source
        self.target = target
        self.payload = payload
        self.payloadname = payloadname
        self.kwargs = kwargs
        self.logger = logger
        self.case = case
        self.__loadproperties__(case)


class OFTGPluginLibrary(object):
    """ Enumerate and verify available plugin files and classes
    """

    def __init__(self, path=None):
        if not path:
            self.collect()
        self.path = path
        self.plugins = self.enumerate()

    def collect(self):
        # TODO: Get plugins from OFTGPacketPlugin.__subclasses__
        pass

    def enumerate(self):
        """ Checks the plugin directory for well-defined plugin classes and loads them
        :return: Dictionary of available classes
        """
        if not self.path: raise ValueError('Cannot enumerate without a path definition')

        pluginDict = {}

        for r, d, f in os.walk(self.path):
            for files in f:
                if files.endswith(".py"):
                    try:
                        path = os.path.join(r, files)
                        plugin = imp.load_source(files[:-3], path)
                        members = inspect.getmembers(plugin, predicate=inspect.isclass)
                        for membername, memberclass in members:
                            # issubclass matches the parent to itself (silly), ignore the parent
                            if not membername == 'OFTGPacketPlugin' and not membername == 'OFTGAPIPlugin':
                                if issubclass(memberclass, OFTGPacketPlugin) or issubclass(memberclass, OFTGAPIPlugin):
                                    # TODO: Convert print statements to log entries
                                    title = None
                                    if not hasattr(memberclass, 'INFO'):
                                        print 'Plugin warning: %s has no attribute INFO in %s' % (membername, path)
                                        title = membername
                                    else:
                                        if not 'Title' in memberclass.INFO:
                                            print 'Plugin warning: %s has no value Title for attribute INFO in %s' % (
                                            membername, path)
                                            title = membername
                                    if not hasattr(memberclass, 'PROPERTIES'):
                                        print 'Plugin warning: %s has no attribute PROPERTIES in %s' % (
                                        membername, path)
                                    if not hasattr(memberclass, 'emitter'):
                                        print 'Plugin error: %s has no method emitter() in %s' % (membername, path)
                                        continue
                                    if not hasattr(memberclass, 'collector'):
                                        print 'Plugin error: %s has no method collector() in %s' % (membername, path)
                                        continue
                                    if membername in pluginDict:
                                        print 'Plugin error: Class %s duplicated in %s' % (membername, path)
                                        continue
                                    if not title:
                                        title = memberclass.INFO['Title']
                                    pluginDict[membername] = {'Title': title, 'Name': memberclass.__name__,
                                                              'Path': path}
                    except Exception as e:
                        print 'Plugin error: Failed to load plugin file %s with %s' % (path, e)

        return pluginDict

    def update(self):
        """ Refresh the available plugins
        """
        self.plugins = self.enumerate()