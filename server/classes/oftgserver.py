import imp
import logging
import logging.handlers
import time
import pickle
import uuid

import requests

from classes.windump import *
from classes.oftgplugin import OFTGPacketPlugin


logger = None


class QueueHandler(logging.Handler):
    """
    This is a logging handler which sends events to a multiprocessing queue.

    The plan is to add it to Python 3.2, but this can be copy pasted into
    user code for use with earlier Python versions.
    """

    def __init__(self, queue):
        """
        Initialise an instance, using the passed queue.
        """
        logging.Handler.__init__(self)
        self.queue = queue

    def emit(self, record):
        """
        Emit a record.

        Writes the LogRecord to the queue.
        """
        try:
            ei = record.exc_info
            if ei:
                dummy = self.format(record)  # just to get traceback text into record.exc_text
                record.exc_info = None  # not needed any more
            self.queue.put_nowait(record)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)


def interfaces():
    alldevs = POINTER(pcap_if_t)()
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
        print (' * Error in pcap_findalldevs: %s\n' % errbuf.value)
        return None

    i = 0
    devicelist = None
    devices = []

    try:
        devicelist = alldevs.contents
    except:
        print (' * Error in pcap_findalldevs: %s' % errbuf.value)
        print (' * Maybe you need admin privilege?\n')
        return None

    while devicelist:
        i = i + 1
        if (devicelist.description):
            devices.append([devicelist.name, devicelist.description])
        else:
            devices.append([devicelist.name, devicelist.name])
        if devicelist.next:
            devicelist = devicelist.next.contents
        else:
            devicelist = False

    return devices


class ServerAPI():
    def __init__(self, plugin, case, pluginclasses, loggerqueue):
        self.running = True
        self.pluginclasses = pluginclasses
        self.loggerqueue = loggerqueue
        self.plugin = plugin
        self.case = case

    def filter_load(self, pluginclasses):
        filterclasses = []

        return filterclasses

    def run(self):
        def _bucket_dump(result):
            try:
                # pipe.send(pickle.dumps(result))
                # TODO: Thread needs config, 'http://%s:%i/bucket' % (config.get('Web Server', 'host_addr'), int(config.get('Web Server', 'http_port')))
                requests.post('http://127.0.0.1:7331/bucket', data={'item': pickle.dumps(result)})
                #self.bucket.append(result)
                #loggerqueue.put(result)
                #logger.info('bam')
            except Exception as e:
                print e
                raise

        logger = logging.getLogger('oftg')
        # for plugin in self.pluginclasses:
        #    imp.load_source('plugins', self.pluginclasses[self.plugin]['Path'])
        if True:  #self.plugin.__name__ in self.pluginclasses:
            monitor = self.plugin(logger=logger, case=self.case)
            if monitor.__class__.__name__ in self.case['plugins']:
                for prop in self.case['plugins'][monitor.__class__.__name__]:
                    logger.debug('api load prop %s' % prop)
                    try:
                        monitor.PROPERTIES[prop]['Value'] = self.case['plugins'][monitor.__class__.__name__][prop]
                    except Exception as e:
                        logger.error('Property error in %s: %s' % (monitor.__class__.__name__, e))
                        pass
            for prop in monitor.PROPERTIES:
                if 'Value' not in monitor.PROPERTIES[prop]:
                    monitor.PROPERTIES[prop]['Value'] = monitor.PROPERTIES[prop]['Default']
                else:
                    if not monitor.PROPERTIES[prop]['Value']:
                        monitor.PROPERTIES[prop]['Value'] = monitor.PROPERTIES[prop]['Default']
            try:
                # Retrieve the components for this filter process
                apigenerator, apitype, api_filter = monitor.collector(None)
                # Grab responses from the plugin's generator
                for apiresponse in apigenerator:
                    # Run the API response through the filter function to determine if an appropriate payload is present
                    try:
                        result = api_filter(apiresponse)
                        if result:
                            result['UUID'] = str(uuid.uuid4())
                            result['Timestamp'] = time.time()
                            try:
                                result['Plugin Name'] = self.plugin.INFO['Title']
                            except Exception:
                                result['Plugin Name'] = self.plugin.__name__
                            _bucket_dump(result)
                    except ValueError:
                        logger.debug('No payload found in API response')
                    except Exception as e:
                        raise

            except Exception as e:
                print e
                raise


class Server():
    def __init__(self, devicename, case, pluginclasses, loggerqueue):
        self.devicename = devicename
        self.running = True
        self.pluginclasses = pluginclasses
        self.loggerqueue = loggerqueue
        self.logger = None
        self.case = case

        # qh = QueueHandler(loggerqueue) # Just the one handler needed
        #root = logging.getLogger()
        #root.addHandler(qh)
        #root.setLevel(logging.DEBUG)

    def filter_load(self, pluginclasses):
        filterclasses = []

        return filterclasses

    def run(self, ns, event, pipe):
        """ This class implements the packet capture loop and packet handler flow
        :param ns:
        :param event:
        :param pipe:
        :return:
        """

        def _bucket_dump(result):
            try:
                # TODO: Thread needs config, 'http://%s:%i/bucket' % (config.get('Web Server', 'host_addr'), int(config.get('Web Server', 'http_port')))
                requests.post('http://127.0.0.1:7331/bucket', data={'item': pickle.dumps(result)})
            except Exception as e:
                print e

        def _packet_handler(param, header, pkt_data):
            local_tv_sec = header.contents.ts.tv_sec
            ltime = time.localtime(local_tv_sec)
            timestr = time.strftime('%H:%M:%S', ltime)
            # print('Packet: %s.%.6d len:%d' % (timestr, header.contents.ts.tv_usec, header.contents.len))
            for plugin in OFTGPacketPlugin.__subclasses__():
                if plugin.__name__ in self.pluginclasses:
                    filter = plugin(logger=logger, case=self.case)
                    if plugin.__name__ in self.case['plugins']:
                        for prop in self.case['plugins'][plugin.__name__]:
                            logger.debug('api load prop %s' % prop)
                            try:
                                filter.PROPERTIES[prop]['Value'] = self.case['plugins'][plugin.__name__][prop]
                            except Exception as e:
                                logger.error('Property error in %s: %s' % (plugin.__name__, e))
                                pass
                    for prop in filter.PROPERTIES:
                        if 'Value' not in filter.PROPERTIES[prop]:
                            filter.PROPERTIES[prop]['Value'] = filter.PROPERTIES[prop]['Default']
                        else:
                            if not filter.PROPERTIES[prop]['Value']:
                                filter.PROPERTIES[prop]['Value'] = filter.PROPERTIES[prop]['Default']
                    try:
                        result = filter.collector(string_at(pkt_data, header.contents.len))
                        if result:
                            result['UUID'] = str(uuid.uuid4())
                            result['Timestamp'] = time.time()
                            try:
                                result['Plugin Name'] = plugin.INFO['Title']
                            except Exception:
                                result['Plugin Name'] = plugin.__name__
                            _bucket_dump(result)
                    except Exception as e:
                        print e
                        raise


        errbuf = None
        alldevs = None

        # from socketIO_client import SocketIO, BaseNamespace
        # class BucketNamespace(BaseNamespace):
        #
        # def on_aaa_response(self, *args):
        #         print('on_aaa_response', args)
        #
        # with SocketIO('127.0.0.1', 8080, BucketNamespace) as socketio:
        #     bucket_namespace = socketio.define(BucketNamespace, '/bucket')
        #     bucket_namespace.send('awooooooo')


        logger = logging.getLogger('oftg')

        logger.info('Opening capture interface')

        try:
            for plugin in self.pluginclasses:
                imp.load_source('plugins', self.pluginclasses[plugin]['Path'])

            PHAND = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))

            packet_handler = PHAND(_packet_handler)
            alldevs = POINTER(pcap_if_t)()
            errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

            handle = pcap_open_live(self.devicename, 1024, 1, 500, errbuf)
            if (handle == None):
                logging.error('Unable to open the adapter. %s is not supported' % self.devicename)
                pcap_freealldevs(alldevs)
                return None

            logger.info('Listening on %s' % (self.devicename))

            while self.running:
                pcap_loop(handle, 1, packet_handler, None)

            logger.info('Closing capture process')
            pcap_close(handle)

        except:
            if alldevs:
                pcap_freealldevs(alldevs)
            raise

        if alldevs:
            pcap_freealldevs(alldevs)

    def stop(self):
        self.running = False
