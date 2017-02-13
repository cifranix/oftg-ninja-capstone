__author__ = 'ryan.ohoro'

import random
import StringIO
import string
import dropbox

from classes.oftgplugin import OFTGAPIPlugin


class OFTGDropbox(OFTGAPIPlugin):
    INFO = {
        'Title': 'Dropbox',
        'Usage': '''
        1. Create a Dropbox account
        2. Create a Dropbox application
        3. Generate an access token for the account from the developer console
        4. Configure the plugin with the Dropbox API key, secret, and account access token\
        ''',
        'Author': 'Ryan O\'Horo'
    }

    PROPERTIES = {'account_nickname':
                      {'Label': 'Nickname',
                       'Default': '',
                       'Sample': 'oftgninjaexfil',
                       'Type': 'string',
                       'Value': None},
                  'dropbox_key':
                      {'Label': 'Developer Key',
                       'Default': '',
                       'Sample': 'pi5us8uswopdc91',
                       'Type': 'string',
                       'Value': None},
                  'dropbox_secret':
                      {'Label': 'API Secret',
                       'Default': '',
                       'Sample': 'c9v3vt17q4s2gj3',
                       'Type': 'string',
                       'Value': None},
                  'dropbox_access_token':
                      {'Label': 'Account Access Token',
                       'Default': '',
                       'Sample': 'AAAAAABnTJtcfUF01K4npM3RJfKnj3V1eOa3A8ETbge1pdEYUd',
                       'Type': 'string',
                       'Value': None}
    }

    # This value is the maximum practical payload size for the given protocol.
    # It's used to limit the chunk size of large payloads
    DATASIZE = 1000000

    def emitter(self):

        try:
            client = dropbox.client.DropboxClient(self.PROPERTIES['dropbox_access_token']['Value'])
            for payload in self.encoder(self.payload):
                f = StringIO.StringIO(payload)
                response = client.put_file(
                    '%s.txt' % ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)), f)
                self.logger.debug('Dropbox upload: %s' % response)
        except Exception:
            raise

    def collector(self, undefined):

        # Parses the API response and retrieves the specified resource
        def apifilter(apiresponse):

            try:
                payload = None
                result = {}

                # Start the API client
                client = dropbox.client.DropboxClient(self.PROPERTIES['dropbox_access_token']['Value'])

                # Download the file and decode the payload
                f, metadata = client.get_file_and_metadata(apiresponse)
                payload = f.read()
                result = self.decoder(payload)

                self.logger.debug('Drobox metadata: %s' % metadata)

                # Clean up the uploaded file
                client.file_delete(apiresponse)

                # TODO: Match plugin hashes

                if result:
                    result['Subtype'] = apiresponse
                    result['Protocol Subtype'] = 'Path'
                    result['Source Host'] = 'Dropbox'
                    return result

            except Exception as e:
                self.logger.error('API filter failed for %s: %s' % (self.__class__.__name__, e))
                raise


        def dropbox_longpoll():

            try:
                # Start the API client
                client = dropbox.client.DropboxClient(self.PROPERTIES['dropbox_access_token']['Value'])

                cursor = None
                while True:
                    result = client.delta(cursor)
                    cursor = result['cursor']
                    if result['reset']:
                        self.logger.debug('Dropbox Reset')

                    for path, metadata in result['entries']:
                        if metadata is not None:
                            self.logger.debug('Dropbox: %s was created/updated' % path)
                            yield path

                    if not result['has_more']:
                        changes = False
                        while not changes:
                            data = client.longpoll_delta(cursor, 30)
                            changes = data['changes']

                            if not changes:
                                backoff = data.get('backoff', None)

                                if backoff is not None:
                                    self.logger.debug('Dropbox backoff requested. Sleeping for %d seconds...' % backoff)
                                    import time

                                    time.sleep(backoff)
            except Exception as e:
                # If the decoding fails, it just wasn't meant to be.
                self.logger.error('API failed for %s: %s' % (self.__class__.__name__, e))

        return [dropbox_longpoll(), 'Path', apifilter]

