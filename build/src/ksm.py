#!/usr/bin/python3
#
# Copyright (c) 2011-2014 Yubico AB
# See the file COPYING for licence statement.
#
"""
Small network server decrypting YubiKey OTPs using an attached YubiHSM.

To support unlimited numbers of YubiKeys, the YubiKey AES keys are
stored in AEAD's (Authenticated Encryption with Associated Data) on
the host computer.

When an OTP is received, we find the right AEAD for this key (based on
the public ID of the YubiKey), and then send the AEAD together with the
OTP to the YubiHSM. The YubiHSM is able to decrypt the AEAD (if it has
the appropriate key handle configured), and then able to decrypt the
YubiKey OTP using the AES key stored in the AEAD.

The information the YubiKey encrypted using it's AES key is then
returned in clear text from the YubiHSM. This includes the counter
information and also (relative) timestamps.

It is not the job of the KSM (or YubiHSM) to ensure that the OTP has
not been seen before - that is done by the validation server (using
the database) :

     O            +----------+
    /|\           |Validation|     +-----+   +---------+
     |  -- OTP--> |  server  | --> | KSM +---| YubiHSM |
    / \           +----------+     +-----+   +---------+
                        |
    user             +--+--+
                     | DB  |
                     +-----+
"""

from encodings import utf_8
from http.client import FORBIDDEN
import os
import string
import sys
import http.server
import socket
import argparse
import syslog
import re

import yubikey
import daemon
import sqlalchemy
import ksmexception
import aead_cmd
import util
import chardet

from functools import partial
from soft_hsm import SoftYHSM

default_device = "/dev/ttyACM0"
default_dir = "/var/cache/yubikey-ksm/aeads"
default_serve_url = "/wsapi/decrypt?otp="
default_listen_addr = "127.0.0.1"
default_port = 8002
default_reqtimeout = 2
default_pid_file = None
default_db_url = None

valid_input_from_key = re.compile('^[cbdefghijklnrtuv]{32,48}$')

stats = { 'ok': 0,
    'invalid': 0,
    'no_aead': 0,
    'err': 0 }

context = daemon.DaemonContext()

class YHSM_KSMRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Handle a HTTP request.

    Try to be careful and validate the input, and then look for an AEAD file matching the
    public id of the OTP. If an AEAD for one of our key handles is found, we ask the YubiHSM
    to decrypt the OTP using the AEAD and return the result (counter and timestamp information).
    """

    def __init__(self, hsm, aead_backend, args, *other_args, **kwargs):
        self.hsm = hsm
        self.verbose = args.debug or args.verbose
        self.serve_url = args.serve_url
        self.stats_url = args.stats_url
        self.key_handles = args.key_handles
        self.timeout = args.reqtimeout
        self.aead_backend = aead_backend
        self.proxy_ips = args.proxies
        self.protocol_version = "HTTP/1.0"
        http.server.BaseHTTPRequestHandler.__init__(self, *other_args, **kwargs)

    def do_GET(self):
        """ Handle a HTTP GET request. """
        # Example session:
        # in  : GET /wsapi/decrypt?otp=ftftftccccdvvbfcfduvvcubikngtchlubtutucrld HTTP/1.0
        # out : OK counter=0004 low=f585 high=3e use=03
        if self.path.startswith(self.serve_url):
            from_key = self.path[len(self.serve_url):]
            
            # val_res = self.decrypt_yubikey_otp(from_key)
            code = 200
            message = bytes(self.decrypt_yubikey_otp(from_key), encoding="utf-8")
            
            self.send_response_only(code)
            self.send_header('Connection', 'close')

            self.send_header("Content-Type", "text/html")
            self.send_header('Content-Length', str(len(message)))
            self.end_headers()

            self.wfile.write(message)

        else:
            self.log_error("Bad URL '{}' - I'm serving '{}' (responding 403)".format(self.path, self.serve_url))
            code = 403
            message = b"Forbidden"

            self.send_response(403)
            self.send_header('Connection', 'close')

            self.send_header("Content-Type", self.error_content_type)
            self.send_header('Content-Length', str(len(message)))
            self.end_headers()

            self.wfile.write(message)
        
        self.close_connection = 1

    def decrypt_yubikey_otp(self, from_key):
        """
        Try to decrypt a YubiKey OTP.

        Returns a string starting with either 'OK' or 'ERR' :

        'OK counter=ab12 low=dd34 high=2a use=0a'

        'ERR Unknown public_id'

        on YubiHSM errors (or bad OTP), only 'ERR' is returned.
        """
        if not re.match(valid_input_from_key, from_key):
            self.log_error("IN: {}, Invalid OTP".format(from_key))
            if self.stats_url:
                stats['invalid'] += 1
            return "ERR Invalid OTP"

        public_id, _otp = yubikey.split_id_otp(from_key)

        aead = ""
        try:
            aead = self.aead_backend.load_aead(public_id)
        except Exception as e:
            self.log_error(str(e))
            return "ERR Unknown public_id"

        try:

            res = yubikey.validate_yubikey_with_aead(self.hsm, from_key, aead, aead.key_handle)
            # XXX double-check public_id in res, in case BaseHTTPServer suddenly becomes multi-threaded
            # XXX fix use vs session counter confusion
            val_res = "OK counter={:04x} low={:04x} high={:02x} use={:02x}".format(res.use_ctr, res.ts_low, res.ts_high, res.session_ctr)
            self.log_message("SUCCESS OTP i %s PT hsm %s", from_key, val_res)

        except ksmexception.YHSM_Error as e:
            self.log_error ("IN: %s, Validate FAILED: %s" % (from_key, str(e)))
            val_res = "ERR"

        return val_res

    def log_error(self, fmt):
        """ Log to syslog. """
        msg = self.my_address_string() + " - - " + fmt
        my_log_message(self.verbose, syslog.LOG_ERR, msg)

    def log_message(self, fmt, *fmt_args):
        """ Log to syslog. """
        msg = self.my_address_string() + " - - " + fmt % fmt_args
        my_log_message(self.verbose, syslog.LOG_INFO, msg)

    def my_address_string(self):
        """ For logging client host without resolving. """
        addr = getattr(self, 'client_address', ('', None))[0]

        # If listed in proxy_ips, use the X-Forwarded-For header, if present.
        if addr in self.proxy_ips:
            return self.headers.getheader('x-forwarded-for', addr)
        return addr

def aead_filename(aead_dir, key_handle, public_id):
    """
    Return the filename of the AEAD for this public_id.
    """
    parts = [aead_dir, key_handle] + util.group(public_id, 2) + [public_id]
    return os.path.join(*parts)

class FSBackend(object):

    def __init__(self, aead_dir, key_handles):
        self.aead_dir = aead_dir
        self.key_handles = key_handles
        if not os.path.isdir(aead_dir):
            raise ValueError("AEAD directory '{}' does not exist.".format(aead_dir))

    def load_aead(self, public_id):
        fn_list = []
        for kh, kh_int in self.key_handles:
            aead = aead_cmd.YHSM_GeneratedAEAD(None, kh_int, '')
            filename = aead_filename(self.aead_dir, kh, public_id)
            fn_list.append(filename)
            try:
                aead.load(filename)
                if not aead.nonce:
                    aead.nonce = yubikey.modhex_decode(public_id).decode('hex')
                return aead
            except IOError:
                continue
        raise Exception("Attempted to load AEAD from : {}".format(fn_list))

class SQLBackend(object):
    def __init__(self, db_url):
        self.engine = sqlalchemy.create_engine(db_url, pool_pre_ping=True)
        metadata = sqlalchemy.MetaData()
        self.aead_table = sqlalchemy.Table('aead_table', metadata, autoload=True, autoload_with=self.engine)

    def load_aead(self, public_id):
        """ Loads AEAD from the specified database. """
        connection = self.engine.connect()
        trans = connection.begin()

        try:
            s = sqlalchemy.select([self.aead_table]).where(self.aead_table.c.public_id == public_id)
            result = connection.execute(s)
            for row in result:
                kh_int = row['keyhandle']
                aead_ = aead_cmd.YHSM_GeneratedAEAD(None, kh_int, '')
                #Benjamin
                if(type(row['aead']) == string):
                    aead_.data = bytes(row['aead'], encoding="utf-8")
                else:
                    aead_.data = row['aead']
                aead_.nonce = bytes([ ord(c) for c in row['nonce'] ])
                # aead_.nonce = bytes(row['nonce'], encoding="utf-8") // Good way but not compatible with old version
            return aead_

        except Exception as e:
            trans.rollback()
            #my_log_message(True, syslog.LOG_INFO, str(e))
            raise Exception("No AEAD in DB for public_id %s (%s)" % (public_id, "nothing"))
        finally:
            connection.close()

class YHSM_KSMServer(http.server.HTTPServer):
    """
    Wrapper class to properly initialize address_family for IPv6 addresses.
    """
    def __init__(self, server_address, req_handler):
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        http.server.HTTPServer.__init__(self, server_address, req_handler)

def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description="Decrypt YubiKey OTPs using YubiHSM",
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter
                                     )
    parser.add_argument('-D', '--device',
                        dest='device',
                        default=default_device,
                        required=False,
                        help='YubiHSM device'
                        )
    parser.add_argument('-B', '--aead-dir',
                        dest='aead_dir',
                        default=default_dir,
                        required=False,
                        help='AEAD directory - base directory of your AEADs',
                        metavar='DIR',
                        )
    parser.add_argument('-U', '--serve-url',
                        dest='serve_url',
                        default=default_serve_url,
                        required=False,
                        help='Base URL for decrypt web service',
                        metavar='URL',
                        )
    parser.add_argument('-S', '--stats-url',
                        dest='stats_url',
                        required=False,
                        help='URL where statistics can be retrieved',
                        metavar='URL',
                        )
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true', default=False,
                        help='Enable verbose operation'
                        )
    parser.add_argument('-d', '--daemon',
                        dest='daemon',
                        action='store_true', default=False,
                        help='Run as daemon'
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=True,
                        help='Enable debug operation'
                        )
    parser.add_argument('--port',
                        dest='listen_port',
                        type=int, default=default_port,
                        required=False,
                        help='Port to listen on',
                        metavar='PORT',
                        )
    parser.add_argument('--addr',
                        dest='listen_addr',
                        default=default_listen_addr,
                        required=False,
                        help='Address to bind to',
                        metavar='ADDR',
                        )
    parser.add_argument('--reqtimeout',
                        dest='reqtimeout',
                        type=int, default=default_reqtimeout,
                        required=False,
                        help='Request timeout in seconds',
                        metavar='SECONDS',
                        )
    parser.add_argument('--key-handle', '--key-handles',
                        dest='key_handles',
                        nargs='+',
                        required=True,
                        help='Key handle(s) to use to decrypt AEADs on the YHSM.',
                        metavar='HANDLE',
                        )
    parser.add_argument('--pid-file',
                        dest='pid_file',
                        default=default_pid_file,
                        required=False,
                        help='PID file',
                        metavar='FILENAME',
                        )
    parser.add_argument('--db-url',
                        dest='db_url',
                        default=default_db_url,
                        required=False,
                        help='The database url to read the AEADs from, you can '
                        'also use env:YOURENVVAR to instead read the URL from '
                        'the YOURENVVAR environment variable.',
                        metavar='DBURL',
                        )
    parser.add_argument('--proxy', '--proxies',
                        dest='proxies',
                        nargs='+',
                        required=False,
                        default=[],
                        help='IP addresses of proxies where the IP in '
                        'X-Forwarded-For should be used for logging purposes.',
                        metavar='IP',
                        )

    return parser.parse_args()


def args_fixup(args):
    """
    Additional checks/cleanups of parsed arguments.
    """
    # cache key_handle_to_int of all key handles, turning args.key_handles into
    # a list of tuples with both original value and integer
    res = []
    for kh in args.key_handles:
        kh_int = util.key_handle_to_int(kh)
        res.append((kh, kh_int,))
    args.key_handles = res

    # Check if the DB url should be read from an environment variable
    if args.db_url and args.db_url.startswith('env:'):
        env_var = args.db_url[4:]
        if env_var in os.environ:
            args.db_url = os.environ[env_var]


def write_pid_file(fn):
    """ Create a file with our PID. """
    if not fn:
        return None
    if fn == '' or fn == "''":
        # work around argument passings in init-scripts
        return None
    f = open(fn, "w")
    f.write("%s\n" % (os.getpid()))
    f.close()


def run(hsm, aead_backend, args):
    """
    Start a BaseHTTPServer.HTTPServer and serve requests forever.
    """

    write_pid_file(args.pid_file)

    server_address = (args.listen_addr, args.listen_port)
    httpd = YHSM_KSMServer(server_address,
                           partial(YHSM_KSMRequestHandler, hsm, aead_backend, args))
    my_log_message(args.debug or args.verbose, syslog.LOG_INFO,
                   "Serving requests to 'http://{}:{}{}' with key handle(s) {} (YubiHSM: '{}', AEADs in '{}', DB in '{}')".format(args.listen_addr, args.listen_port, args.serve_url, args.key_handles, args.device, args.aead_dir, args.db_url))
    httpd.serve_forever()


def my_log_message(verbose, prio, msg):
    """
    Log to syslog, and possibly also to stderr.
    """
    syslog.syslog(prio, msg)
    if verbose or prio == syslog.LOG_ERR:
        sys.stderr.write("{}\n".format(msg))


def main():
    """
    Main program.
    """
    my_name = os.path.basename(sys.argv[0])
    if not my_name:
        my_name = "yhsm-yubikey-ksm"
    syslog.openlog(my_name, syslog.LOG_PID, syslog.LOG_LOCAL0)

    args = parse_args()
    args_fixup(args)

    aead_backend = None

    if args.db_url:
        # Using an SQL database for AEADs
        try:
            aead_backend = SQLBackend(args.db_url)
        except Exception as e:
            my_log_message(args.debug or args.verbose, syslog.LOG_ERR,
                           'Could not connect to database "{}" : {}'.format(args.db_url, e))
            return 1
    else:
        # Using the filesystem for AEADs
        try:
            aead_backend = FSBackend(args.aead_dir, args.key_handles)
        except Exception as e:
            my_log_message(args.debug or args.verbose, syslog.LOG_ERR,
                           'Could not create AEAD FSBackend: {}'.format(e))
            return 1

    if args.device == '-':
        print("soft")
        # Using a soft-HSM with keys from stdin
        try:
            hsm = SoftYHSM.from_json(sys.stdin.read(), debug=args.debug)
        except ValueError as e:
            my_log_message(args.debug or args.verbose, syslog.LOG_ERR,
                           'Failed opening soft YHSM from stdin : {}'.format(e))
            return 1
    elif os.path.isfile(args.device):
        print("file")
        # Using a soft-HSM from file
        try:
            hsm = SoftYHSM.from_file(args.device, debug=args.debug)
        except ValueError as e:
            my_log_message(args.debug or args.verbose, syslog.LOG_ERR,
                           'Failed opening soft YHSM "{}" : {}'.format(args.device, e))
            return 1

    if args.daemon:
        with context:
            run(hsm, aead_backend, args)
    else:
        try:
            run(hsm, aead_backend, args)
        except KeyboardInterrupt:
            print ("")
            print ("Shutting down")
            print ("")

if __name__ == '__main__':
    sys.exit(main())