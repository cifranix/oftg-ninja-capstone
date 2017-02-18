import imp
import logging
import base64


class Client():
    """ Defines the packet emitter framework
    """

    def __init__(self, pluginlist, case, source, target, qhClass, loggerqueue, bucketqueue):

        self.case = case
        self.pluginlist = pluginlist
        self.source = source
        self.target = target
        self.qhClass = qhClass
        self.loggerqueue = loggerqueue

    def run(self, ns, event, pipe):  # None, None, (parent_pipe, child_pipe), QueueHandler, loggerqueue
        """ Executes the packet emitter function of the specified plugins based on the selected case file
        :return:
        """

        # Start logger for this process
        qh = self.qhClass(self.loggerqueue)
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.addHandler(qh)
        logger = logging.getLogger('client')

        if not self.target:
            logger.error('No server host specified')

        plugins = {}
        for plugin in self.pluginlist:
            p = imp.load_source(plugin, self.pluginlist[plugin]['Path'])
            plugins[p.__name__] = p
            # print 'Loaded module %s' % p.__name__

        if not plugins:
            raise Exception('No plugins loaded')

        for pluginname in self.case['plugins']:
            logger.info('Executing %s' % pluginname)
            for payload in self.case['payloads']:
                try:
                    if pluginname == 'OFTGTCP':
                        p = plugins['OFTGTCP'].OFTGTCP(source=self.source, case=self.case, target=self.target,
                                                       payload=base64.b64decode(self.case['payloads'][payload]['data']),
                                                       logger=logger)
                    if pluginname == 'OFTGUDP':
                        p = plugins['OFTGUDP'].OFTGUDP(source=self.source, case=self.case, target=self.target,
                                                       payload=base64.b64decode(self.case['payloads'][payload]['data']),
                                                       logger=logger)
                    if pluginname == 'OFTGDNS':
                        p = plugins['OFTGDNS'].OFTGDNS(source=self.source, case=self.case, target=self.target,
                                                       payload=base64.b64decode(self.case['payloads'][payload]['data']),
                                                       logger=logger)
                    if pluginname == 'OFTGICMP':
                        p = plugins['OFTGICMP'].OFTGICMP(source=self.source, case=self.case, target=self.target,
                                                         payload=base64.b64decode(self.case['payloads'][payload]['data']),
                                                         logger=logger)
                    if pluginname == 'OFTGTwitterPastebin':
                        p = plugins['OFTGTwitterPastebin'].OFTGTwitterPastebin(source=self.source, case=self.case,
                                                                               target=self.target,
                                                                               payload=base64.b64decode(
                                                                                   self.case['payloads'][payload]['data']),
                                                                               logger=logger)
                    if pluginname == 'OFTGDropbox':
                        p = plugins['OFTGDropbox'].OFTGDropbox(source=self.source, case=self.case, target=self.target,
                                                               payload=base64.b64decode(self.case['payloads'][payload]['data']),
                                                               logger=logger)
                    if not p: raise Exception('Plugin %s not loaded' % pluginname)
                    for prop in self.case['plugins'][pluginname]:
                        try:
                            p.PROPERTIES[prop]['Value'] = self.case['plugins'][pluginname][prop]
                        except Exception as e:
                            logger.error('Property error in %s: %s' % (pluginname, e))
                            pass
                    #for prop in p.PROPERTIES:
                    #    if not p.PROPERTIES[prop]['Value']:
                    #        p.PROPERTIES[prop]['Value'] = p.PROPERTIES[prop]['Default']
                    # Start the plugin
                    print p
                    p.emitter()

                except Exception as e:
                    logger.error('Failed to execute plugin %s ' % pluginname)
                    raise
            logger.info('Finished %s' % pluginname)

