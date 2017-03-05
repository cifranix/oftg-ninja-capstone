#!/usr/bin/python
__author__ = 'ryan.ohoro'
__version__ = '0.4'

# Outbound Filter Testing Gizmo - Ninja



import os
import sys
import ConfigParser
import argparse
import logging.config
import signal
import time
import multiprocessing
from multiprocessing import Process, Pipe
from Queue import Empty
import logging
import logging.handlers
import pickle
# import websocket
import cgi
import sqlite3
import hexdump
import datetime
import base64
import json
import csv

from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import Response
from flask import jsonify
from flask import Markup
from flask import make_response
from flask import url_for
from flask.ext.socketio import SocketIO
from gevent import monkey

from functools import wraps

import getpass
import hashlib
import binascii

from classes.oftgserver import Server
from classes.oftgserver import ServerAPI
from classes.oftgserver import interfaces

#from classes.oftgclient import Client
from classes.oftgplugin import OFTGPacketPlugin
from classes.oftgplugin import OFTGAPIPlugin
from classes.oftgcase import CaseLibrary
from classes.oftgplugin import OFTGPluginLibrary

asyncemitterqueue = None
asynccollector = None

logger = None
plugins = None

global bucket
bucket = []
global bucket_connection
bucket_connection = None

#### to test export to csv functionality
global result
result = []

auth_deny = {}

config = None
configfilename = None

monkey.patch_all()

app = Flask(__name__)
#app.config['DEBUG'] = True
socketio = SocketIO(app)

# from OpenSSL import SSL
# context = SSL.Context(SSL.SSLv23_METHOD)
# context.use_privatekey_file('yourserver.key')
# context.use_certificate_file('yourserver.crt')



# ----- Utility Functions ---------------------------------------------------------------------------------------------

def check_auth(username, password):
    '''This function is called to check if a username /
    password combination is valid.
    '''

    count = 0

    try:
        if username not in auth_deny:
            auth_deny[username] = []

        for denied in auth_deny[username]:
            if denied >= time.time() - 300:
                count += count

        if count > 3:
            return False

        passwordhash = config.get('users', username)
        try:
            if passwordhash == binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password, username, 100000)):
                auth_deny[username] = []
                return True
        except AttributeError:
            from passlib.hash import pbkdf2_sha256
            if passwordhash == binascii.hexlify(pbkdf2_sha256.encrypt(password, rounds=100000, salt=username)):
                auth_deny[username] = []
                return True
    except:
        auth_deny[username].append(time.time())
        return False

    auth_deny[username].append(time.time())
    return False


def authenticate():
    '''Sends a 401 response that enables basic auth'''
    return Response('Authorization Required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


def user_modify(username, password):
    try:
        #hashlib only has this module in python 2.7.8 and later. For older python installs, passlib is a prerequisite.
        try:
            passwordhash = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password, username, 100000))
        except AttributeError:
            from passlib.hash import pbkdf2_sha256
            passwordhash = binascii.hexlify(pbkdf2_sha256.encrypt(password, rounds=100000, salt=username))
        config.set('users', username, passwordhash)
        if config and configfilename:
            config.write(open(configfilename, 'w'))
        else:
            return False
    except AttributeError as e:
        print e
        return False
    return True


def user_update(username):
    if not config: raise ValueError('Configuration not loaded')
    if not config.has_section('users'):
        config.add_section('users')
    if config.has_option('users', username):
        print 'Changing password for %s' % username
    else:
        print 'Adding new user %s' % username
    password = getpass.getpass('Password: ')
    if user_modify(username, password):
        print ' * Updating OFTG-Ninja config ...'
        return True
    else:
        print ' * Failed to update user'
        return False


def logger_config():
    ''' Logger configuration parameters
    :return: None
    :rtype: None
    '''
    loggerdefinition = {
        'version': 1,
        'formatters': {
            'detailed': {
                'class': 'logging.Formatter',
                'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
            },
            'oftg-file': {
                'class': 'logging.FileHandler',
                'filename': 'oftg.log',
                'mode': 'w',
                'formatter': 'detailed',
            }
        },
        'loggers': {
            'oftg': {
                'handlers': ['console', 'oftg-file']
            },
        },
        'root': {
            'level': 'DEBUG',
            'handlers': ['console', 'oftg-file']
        },
    }

    logging.config.dictConfig(loggerdefinition)


def logger_thread(queue):
    ''' Spins up a logging thread for the main process
    :param queue: Logging queue
    :type queue: Queue
    :return: None
    :rtype: None
    '''
    logger_config()
    while True:
        try:
            record = queue.get()
            if record is None:
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)

        except Empty:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            import sys, traceback

            print >> sys.stderr, 'Logging Error:'
            traceback.print_exc(file=sys.stderr)


class QueueHandler(logging.Handler):
    ''' This is a logging handler which sends events to a multiprocessing queue. '''

    def __init__(self, queue):
        '''
        Initialise an instance, using the passed queue.
        '''
        logging.Handler.__init__(self)
        self.queue = queue

    def emit(self, record):
        '''
        Emit a record.

        Writes the LogRecord to the queue.
        '''
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


def database_init():
    ''' Initializes the in-memory SQLITE database for the appliation
    :return: None
    :rtype: None
    '''
    global bucket_connection

    try:
        bucket_connection = sqlite3.connect(':memory:')
        bucket_connection.row_factory = sqlite3.Row
        bucket_cursor = bucket_connection.cursor()
        bucket_cursor.execute('CREATE TABLE bucket("ID" INTEGER PRIMARY KEY AUTOINCREMENT, "Plugin Name",'
                              '"Plugin Hash", "Source Host", "Timestamp", "Payload", "Payload Hash", "Payload Size", '
                              '"Preview", "Protocol Subtype", "Subtype", "Exfil ID", "Encrypt IV", "Encrypted", '
                              '"Compressed", "Partial Hash")')
        bucket_connection.commit()
    except Exception as e:
        raise

# May be for exporting the populated bucket to a pdf
def create_pdf(pdf_data):
    ''' Create a PDF from XHTML content
    :param pdf_data: XHTML
    :type pdf_data: String
    :return: PDF data
    :rtype: Byte string
    '''
    from xhtml2pdf import pisa
    from StringIO import StringIO

    pdf = StringIO()
    pisa.CreatePDF(StringIO(pdf_data), pdf)
    return pdf


def safefile(reldir, filename):
    ''' Directory traversal prevention
    :param reldir: Base directory
    :type reldir: String
    :param filename: File name
    :type filename: String
    :return: Full absolute path
    :rtype: String
    '''
    normpath = os.path.abspath(os.path.join(reldir, filename))
    if normpath.startswith(os.path.join(os.path.abspath(os.curdir), reldir)):
        return normpath
    else:
        return None


def getlocaladdr(server_addr):
    ''' Returns the IPv4 source address of the host
    :return: Dotted decimal IPv4 address
    :rtype: String
    '''
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #seriously? Why was example.com hard coded here?
    #s.connect(('example.com', 0))
    s.connect((server_addr,0))
    return s.getsockname()[0]

def sizeof_fmt(num, suffix=''):
    ''' Return a formatted byte size string

    :param num: Number
    :type num: String or Int
    :param suffix: B(ytes) or b(its)
    :type suffix:
    :return: Formatted string
    :rtype: String
    '''
    try:
        num = int(num)
        for unit in ['Bytes','Kilobytes','Megabytes','Gigabytes','Terabytes','Petabytes','Exabytes','Zettabytes']:
            if abs(num) < 1024.0:
                if unit == 'Bytes':
                    fmt = '%.0f %s%s'
                else:
                    fmt = '%.2f %s%s'
                return fmt % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'YB', suffix)
    except Exception:
        return num


def bucket_sorted():
    ''' Return a dictionary representing the current state of the bucket
    :return:
    :rtype:
    '''
    global bucket
    import itertools

    def dedupe(seq):
        seen = set()
        seen_add = seen.add
        return [x for x in seq if not (x in seen or seen_add(x))]

    def list2range(i):
        c = []
        for a, b in itertools.groupby(enumerate(i), lambda (x, y): y - x):
            b = list(b)
            c.append([b[0][1], b[-1][1]])

        o = ''

        for z in c:
            if z[0] == z[1]:
                o += '%i' % z[0]
            elif not z[0] == z[1]:
                o += '%i-%i' % (z[0], z[1])
            o += ', '

        o = o[:-2]

        return o

    def string2list(s):
        if not s: return None
        try:
            s = map(int, s.split(','))
        except Exception:
            return s
        return list2range(s)


    if not bucket:
        bucket = []

    global bucket_connection

    cursor = bucket_connection.cursor()
    cursor.execute('SELECT "Plugin Name", "Source Host", "Timestamp", "Preview", "Payload", "Payload Hash",'
                   '"Payload Size", "Protocol Subtype", "Encrypted", "Compressed", "Exfil ID", "Partial Hash",'
                   'GROUP_CONCAT("Subtype", ", ") AS "Subtype" FROM bucket '
                   'GROUP BY "Plugin Name", "Exfil ID", "Source Host"')
    rows = cursor.fetchall()
    

    global result
    result = []


    for row in rows:
        if not row['Plugin Name'] == None:

            try:
                # TODO: Fix validation
                result.append({'Plugin Name': row['Plugin Name'], 'Source Host': row['Source Host'],
                               'Timestamp': datetime.datetime.fromtimestamp(int(row['Timestamp'])).strftime(
                                  '%Y-%m-%d %H:%M:%S'), 'Preview': row['Preview'],
                              'Payload Size': sizeof_fmt(row['Payload Size']),
                              'Protocol Subtype': row['Protocol Subtype'], 'Encrypted': row['Encrypted'],
                              'Compressed': row['Compressed'], 'Exfil ID': row['Exfil ID'],
                              'Subtype List': string2list(row['Subtype']), 'Complete': row['Payload Hash'] == row['Partial Hash']})
            except Exception as e:
                raise
    print(result)

   
    return result


def bucket_empty_():

    sql = 'DELETE FROM bucket'
    cursor = bucket_connection.cursor()
    cursor.execute(sql)
    bucket_connection.commit()

def export_to_csv(result):

    keys = result[0].keys()
    with open('bucket.csv', 'wb') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(result)





# ----- Flask Handlers ------------------------------------------------------------------------------------------------
@app.route('/')
@auth_required
def index():
    return redirect('/server', code=302)


@app.route('/bucket/report')
@auth_required
def bucket_report():
    bucket_sorted()

    error = None

    csscontent = ''
    cssfiles = ['static/css/bootstrap.min.css',
                'static/css/bootstrap-responsive.min.css',
                'static/css/style.css',
                'static/css/pages/dashboard.css']
    for fn in cssfiles:
        with open(fn) as f:
            csscontent = csscontent + '/* %s */\n\n' % fn + f.read() + '\n'

    datestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        error = cgi.escape(request.args.get('error'))
    except Exception:
        pass

    rt = render_template('bucketreport.html', tasks=tasks(), bucket=bucket_sorted(), datestamp=datestamp,
                         csscontent=csscontent, error=error, mimetype='text/html',
                         headers={'Content-Disposition': 'attachment;filename=report.html'})

    return rt


@app.route('/server')
@auth_required
def server():
    defaultinterface = None
    try:
        defaultinterface = config.get('Interface', 'server')
    except Exception:
        pass

    return render_template('server.html', cases=caselibrary.cases, interfaces=interfaces(),
                           defaultinterface=defaultinterface, tasks=tasks(), bucket=bucket_sorted())


@app.route('/server/start', methods=['GET', 'POST'])
@auth_required
def server_start():
    global plugins
    global parent_pipe

    # Validate parameters

    if not request.form['case']:
        return redirect('/server?error=%s' % 'You must select a valid case file.', code=302)

    if not request.form['case'] in caselibrary.cases:
        return redirect('/server?error=%s' % 'You must select a valid case file.', code=302)

    if not request.form['interface']:
        return redirect('/server?error=%s' % 'You must select a valid interface.', code=302)

    casename = request.form['case']
    case = caselibrary.cases[casename]
    # Start API Monitor plugins
    try:
        for api in OFTGAPIPlugin.__subclasses__():
            if 'plugins' in case:
                if api.__name__ in case['plugins']:

                    # Assign plugin properties based on case configuration and default values
                    for prop in case['plugins'][api.__name__]:
                        try:
                            api.PROPERTIES[prop]['Value'] = case['plugins'][api.__name__][prop]
                        except Exception as e:
                            logger.error('Property error in %s: %s' % (api.__name__, e))
                            pass

                    for prop in api.PROPERTIES:
                        if not api.PROPERTIES[prop]['Value']:
                            api.PROPERTIES[prop]['Value'] = api.PROPERTIES[prop]['Default']
                    apiclass = ServerAPI(api, case, plugins, loggerqueue)

                    # Fetch the plugin's title, if available
                    try:
                        plugintitle = api.INFO['Title']
                    except Exception:
                        plugintitle = api.__name__

                    # Spawn API monitor process
                    apimonitor = Process(target=apiclass.run, name='%s API Monitor|%s|%s' % (plugintitle, casename,
                                                                                                'API'))
                    apimonitor.daemon = True
                    apimonitor.start()
    except Exception as e:
        logger.error('API Monitor Error: %s ' % e)
        raise


    ######## commented out to allow server to listen for multiple processes at a time
    # for task in multiprocessing.active_children():
    #     if task.name.startswith('Packet Monitor'):
    #         return redirect('/server?error=%s' % 'A packet monitor process is already running.', code=302)



    # Start packet capture process and load filter plugins
    try:
        capturethread = Server(request.form['interface'], case, plugins, loggerqueue)

        interfacename = None

        for i in interfaces():
            if i[0] == request.form['interface']:
                interfacename = i[1]
                break

        if not interfacename:
            logger.error('Failed to open packet monitor interface')
            return redirect('/server', code=302)


        parent_pipe, child_pipe = multiprocessing.Pipe()

        multiprocessing.freeze_support()
        packetmonitorprocess = Process(target=capturethread.run, name='Packet Monitor|%s|%s' % (casename, '%s (0.0.0.0)' % interfacename),
                                 args=(None, None, child_pipe))
        packetmonitorprocess.daemon = True
        packetmonitorprocess.start()

    except Exception as e:
        logger.error('Packet Monitor Error: %s ' % e)
        raise

    return redirect('/server', code=302)


def sanefilename(filename):
    ok = (' ','.','_')
    return "".join(c for c in filename if c.isalnum() or c in ok).rstrip()

def tasks():
    children = []

    if multiprocessing.active_children():
        for c in multiprocessing.active_children():
            # Ignore utility processes
            if c.name == 'SyncManager-1':
                continue
            if c.name == 'Logger':
                continue
            children.append([c.name, c.pid])

    return children


@app.route('/stop/<pid>')
@auth_required
def stop(pid):
    global asynccollector

    # Terminate target process as long as it's a child of multiprocessing
    for task in multiprocessing.active_children():
        if str(task.pid) == pid:
            print ' ! Terminating process %s' % pid
            task.terminate()

    return redirect('/server', code=302)

@app.route('/bucket', methods=['POST'])
#@auth_required
def bucket_recieve():
    global bucket_connection

    entry = pickle.loads(request.form['item'])

    fields = ['Plugin Name', 'Plugin Hash', 'Source Host', 'Timestamp', 'Payload', 'Payload Hash', 'Preview',
              'Protocol Subtype', 'Subtype', 'Exfil ID', 'Encrypt IV', 'Encrypted', 'Compressed']

    for field in fields:
        if field not in entry:
            entry[field] = None

    if 'Payload' in entry:
        if entry['Payload']:
            entry['Preview'] = hexdump.hexdump(entry['Payload'][:64], result='return')
        else:
            entry['Preview'] = None
    else:
        entry['Preview'] = None

    entry['Payload Size'] = len(entry['Payload'])

    try:
        cursor = bucket_connection.cursor()
        sql = 'SELECT "ID", "Payload", "Payload Hash", "Partial Hash" FROM bucket WHERE "Exfil ID" = ? AND "Source Host" = ? AND "Subtype" = ?'
        cursor.execute(sql, [entry['Exfil ID'], entry['Source Host'], entry['Subtype']])

        rows = cursor.fetchall()

        from hashlib import sha256
        s = sha256()

        if rows:
            for row in rows:
                # FIXME: Address race condition
                # Update the existing entry
                payload = row['Payload'] + entry['Payload']
                s.update(payload)
                digest = s.hexdigest()[:8]
                sql = 'UPDATE bucket SET "Payload" = ?, "Payload Size" = ?, "Preview" = ?, "Partial Hash" = ? WHERE "ID" = ?'
                cursor.execute(sql, [payload, len(payload), hexdump.hexdump(payload[:64], result='return'), digest, row['ID']])
        else:
            # Commit the entry to the bucket table
            s.update(entry['Payload'])
            digest = s.hexdigest()[:8]
            sql = 'INSERT INTO bucket ("Plugin Name", "Plugin Hash", "Source Host", "Timestamp", "Payload", ' \
                  '"Payload Hash", "Payload Size", "Preview", "Protocol Subtype", "Subtype", "Exfil ID", "Encrypt IV", ' \
                  '"Encrypted", "Compressed", "Partial Hash") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            cursor.execute(sql, [entry['Plugin Name'], entry['Plugin Hash'], entry['Source Host'], entry['Timestamp'],
                                 entry['Payload'], entry['Payload Hash'], entry['Payload Size'], entry['Preview'],
                                 entry['Protocol Subtype'], entry['Subtype'], entry['Exfil ID'], entry['Encrypt IV'],
                                 entry['Encrypted'], entry['Compressed'], digest])

        bucket_connection.commit()
    except Exception as e:
        logger.error('SQL insert failed: %s' % e)
        raise

    bucket.append(entry)
    #print bucket
    return jsonify(status='ok')


@app.route('/bucket/payload/<uuid>')
@auth_required
def bucket_payload(uuid):
    global bucket
    payload = None

    for item in bucket:
        print item

        if item['UUID'] == uuid:
            payload = item['Payload']

    return jsonify(payload=payload)

@app.route('/bucket/csv')
@auth_required
def exportTo_CSV():
    global bucket
    global result 

    try:
        if not result:
            export_to_csv(result)
            print 'The bucket was successfully exported.'

            #### experimenting with flash messages
            # flash('The bucket was successfully exported.')
    except:
        return redirect('/server?error=%s' % 'The bucket must be populated to export.', code=302)

    return redirect('/server', code=302)  


@app.route('/bucket/empty')
@auth_required
def bucket_empty():
    global bucket

    # Emtpy the bucket
    bucket_empty_()

    return redirect('/server', code=302)


@socketio.on('connect', namespace='/websocket')
@auth_required
def bucket_connect():
    print 'Bucket connected'


@socketio.on('message', namespace='/websocket')
@auth_required
def bucket_packet(message):
    print message


@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':

    global parent_pipe

    parser = argparse.ArgumentParser()

    parser.add_argument('-l', dest='listen', help='Web Server Listener')
    parser.add_argument('-c', dest='config', help='Base Configuration File')
    parser.add_argument('-d', dest='debug', help='Base Configuration File')
    parser.add_argument('--user', help='Add or change user credentials e.g. admin ')
    parser.add_argument('case', nargs='?', help='Client Case')

    args = parser.parse_args()

    try:
        config = ConfigParser.RawConfigParser()
    except:
        quit()

    print ' * Starting OFTG-Ninja v%s ...' % (__version__)

    try:
        config = ConfigParser.ConfigParser(allow_no_value=True)
        if args.config:
            configfilename = os.path.abspath(args.config)
        else:
            configfilename = 'oftg.cfg'
        config.read(configfilename)
    except ConfigParser.Error as e:
        logger.error('Error reading configuration file: %s' % (e.message))
        quit()

    # Handle user account changes
    if args.user:
        user_update(args.user)
        quit()

    # Assure there are users configured
    if not config.has_section('users'):
        config.add_section('users')

    if len(config.items('users')) == 0:
        print 'To access OFTG-Ninja, you must first create a user...'
        username = str(raw_input('Username: '))
        if username:
            user_update(username)

    # Check to make sure the configuration now contains at least one user
    if len(config.items('users')) == 0:
        quit(' ! No users defined in configuration')

    sys.path.append('classes/')

    # Process manager
    global manager
    manager = multiprocessing.Manager()
    print ' * Process manager started'

    # Start dedicated logging thread
    loggerqueue = multiprocessing.Queue()
    logger_config()
    loggerthread = Process(target=logger_thread, name='Logger', args=(loggerqueue, ))
    loggerthread.start()

    # Main logger
    loggerhandler = QueueHandler(loggerqueue)
    logger = logging.getLogger('oftg')
    logger.addHandler(loggerhandler)
    logger.setLevel(logging.DEBUG)

    print ' * Logging started'

    if args.case: print args.case

    # Register cases
    caselibrary = CaseLibrary('cases')
    if not caselibrary:
        logger.warn('No cases available')

    # Add plugin directory to path
    sys.path.insert(0, 'plugins')

    # Register plugins
    pluginlibrary = OFTGPluginLibrary('plugins')
    plugins = pluginlibrary.plugins

    # Start database
    database_init()

    # Start web interface
    try:
        import ssl
        socketio.run(app, host=config.get('webserver', 'host_addr'), port=int(config.get('webserver', 'http_port')),
                     policy_server=False, transports=['websocket']) #, ssl_version=ssl.PROTOCOL_TLSv1, certfile='server.crt', keyfile='server.key')
    except KeyboardInterrupt as e:
        loggerqueue.put(None)
        loggerthread.terminate()
        raise e
    except Exception:
        raise

    # app.run(port=int(config.get('webserver', 'http_port')), debug=True)

    if bucket_connection:
        bucket_connection.close()

    loggerqueue.put(None)
    loggerthread.terminate()
    loggerthread.join()

    print ' * Logging stopped'
