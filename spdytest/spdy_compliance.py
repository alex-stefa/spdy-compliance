#!/usr/bin/env python

"""
Testing tool for SPDY/3 implementations
"""

__author__ = "Alex Stefanescu <alex.stefa@gmail.com>"
__copyright__ = """\
Copyright (c) 2013 Alex Stefanescu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os
import sys
import json
import logging
import threading
import multiprocessing
import traceback
import time
import functools
import socket
import hashlib
import html
import inspect
import struct
import urllib.request
import urllib.parse

import thor
import thor.events
import thor.spdy.error as spdy_error
import thor.spdy.frames as spdy_frames
import thor.spdy.common as spdy_common


# TerminalColorEscapes contains strings that, when printed to a terminal, will
# cause subsequent text to be displayed in the given manner.
Colors = thor.enum(
    BLACK = r'[0;30m',
    RED = r'[0;31m',
    GREEN = r'[0;32m',
    YELLOW = r'[0;33m',
    BLUE = r'[0;34m',
    MAGENTA = r'[0;35m',
    CYAN = r'[0;36m',
    WHITE = r'[0;37m',
    BOLD = r'[1m',
    DIM = r'[2m',
    BLINK = r'[5m',
    NORMAL = r'[0m')
    
def setup_logger(settings):
    class ColorFilter(logging.Filter):
        def filter(self, record):
            if not hasattr(record, 'xcolor'):
                record.xcolor = ''
            return True    

    logger = multiprocessing.get_logger()
    logger.setLevel(logging.DEBUG)
    if settings['log_file_dir'] and settings['log_file_level']:
        pname = multiprocessing.current_process().name
        ctime = time.strftime('%Y-%m-%d_%H-%M-%S')
        filename = os.path.join(settings['log_file_dir'], 
            'log_%s_%s.txt' % (pname, ctime))
        filehandler = logging.FileHandler(filename, mode='w', encoding='utf8')
        filehandler.setLevel(settings['log_file_level'])
        fileformatter = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s %(message)s')
        filehandler.setFormatter(fileformatter)
        logger.addHandler(filehandler)
    if settings['log_stderr_level']:
        streamhandler = logging.StreamHandler(stream=sys.stderr)
        streamhandler.setLevel(settings['log_stderr_level'])
        streamhandler.addFilter(ColorFilter())
        streamformatter = logging.Formatter(
            '[%(levelname)s/%(processName)s] %(xcolor)s%(message)s' +
            Colors.NORMAL)
        streamhandler.setFormatter(streamformatter)
        logger.addHandler(streamhandler)
    return logger
    
def setup_formatter(logger):
    def _wrapper(level, color, str):
        logger.log(level, str, extra={'xcolor': color})

    return thor.enum(
        error = functools.partial(_wrapper, logging.ERROR, Colors.RED),
        frame = functools.partial(_wrapper, logging.DEBUG, Colors.DIM),
        exchange = functools.partial(_wrapper, logging.INFO, Colors.YELLOW),
        session = functools.partial(_wrapper, logging.INFO, Colors.GREEN),
        status = functools.partial(_wrapper, logging.WARNING, Colors.BOLD),
        notify = functools.partial(_wrapper, logging.WARNING, Colors.BLUE),
        test = functools.partial(_wrapper, logging.ERROR, Colors.CYAN))
        
def setup_tls_config(settings):
    return thor.TlsConfig(
        keyfile=settings['tls_keyfile'],
        certfile=settings['tls_certfile'],
        cafile=settings['tls_cafile'],
        capath=settings['tls_capath'],
        npn_prot=settings['tls_npn_prot'])
    
#-------------------------------------------------------------------------------

class FileServer(object):
    """
    Very simple file cache. Avoids repeated reads of the same file.
    Should not be used for very large files.
    """
    # TODO: sanitize path (prevent dir traversal)
    # TODO: implement LRU cache; limit total memory; etc.
    def __init__(self, rootdir='www'):
        self.rootdir = rootdir
    
    @functools.lru_cache(maxsize=32)
    def get_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except OSError:
            return None
            
    @functools.lru_cache(maxsize=32)
    def get_dir_listing(self, path, base_url):
        try:
            list = os.listdir(path)
        except os.error:
            return self.get_error((403, 'Forbidden'))
        list.sort(key=lambda a: a.lower())
        r = []
        displaypath = html.escape(base_url)
        enc = sys.getfilesystemencoding()
        title = 'Directory listing for %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">')
        r.append('<html>\n<head>')
        r.append('<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">' % enc)
        r.append('<title>%s</title>\n</head>' % title)
        r.append('<body>\n<h1>%s</h1>' % title)
        r.append('<hr>\n<ul>')
        upperlink = urllib.parse.quote(base_url.rsplit('/', 2)[0] + '/')
        r.append('<li><a href="%s">[..]</a></li>' % upperlink)
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            size = '%s bytes' % os.path.getsize(fullname)
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + '/'
                linkname = name + '/'
                size = 'directory'
            if os.path.islink(fullname):
                displayname = name + '@'
                size = 'link'
            size = '<i>' + size + '</i>'
            r.append('<li><a href="%s">%s</a>&nbsp;&nbsp;%s</li>' % (
                urllib.parse.quote(linkname), html.escape(displayname), size))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc)
        headers = [
            ('Content-type', 'text/html; charset=%s' % enc),
            ('Content-Length', str(len(encoded)))]
        return ((200, 'OK'), encoded, headers)

    ERROR_MESSAGE = """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>%s %s</h1>
    </body>
</html>
"""

    @functools.lru_cache(maxsize=32)
    def get_error(self, status):
        return (status,
            (self.ERROR_MESSAGE % tuple(map(str, status))).encode(
                'UTF-8', 'replace'),
            [('Content-type', 'text/html;charset=utf-8')])
                            
    def handle_request(self, hdr_dict):
        if hdr_dict.method.lower() != 'get':
            return self.get_error((501, 'Not Implemented'))
        path = urllib.request.url2pathname(hdr_dict.path_split[0])
        if path[0] != '/':
            return self.get_error((400, 'Bad Request'))
        path = path[1:]
        file_path = os.path.join(self.rootdir, path)
        if os.path.isdir(file_path):
            base_url = '/' + path
            if base_url[-1] != '/':
                base_url += '/'
            return self.get_dir_listing(file_path, base_url)
        data = self.get_file(file_path)
        if data is None:
            return self.get_error((404, 'Not Found'))
        return ((200, 'OK'), data, [('Content-Length', str(len(data)))])

#-------------------------------------------------------------------------------

class SpdyAdvertiser(multiprocessing.Process):
    """
    Server which listens to normal HTTP requests and replies with
    Alternate-Protocol header to advertise SPDY capability.
    
    Note: the advertised SPDY port must require admin rights to be 
        opened, otherwise Chrome ignores the Alternate-Protocol mapping
        (see: http://code.google.com/p/chromium/issues/detail?id=93351 )
    """
    def __init__(self, settings, name='SPDY-ADV'):
        multiprocessing.Process.__init__(self, name=name)
        self.settings = settings
        
    def setup(self):
        self.format = setup_formatter(setup_logger(self.settings))
        self.format.status('SpdyAdvertiser PID: %s' % os.getpid())
        self.loop = thor.loop.make()
        self.adv_server = thor.HttpServer(
            host=self.settings['server_host'],
            port=self.settings['spdy_advertiser_port'],
            loop=self.loop)
        adv_value = '%d:%s' % (
            self.settings['server_port'], 
            self.settings['spdy_advertiser_value'])
        self.format.status('Alternate-Protocol: %s advertised on %s:%d' % (
            adv_value,
            self.settings['server_host'],
            self.settings['spdy_advertiser_port']))
        
        def adv_handler(exchange):
            @thor.on(exchange, 'request_start')
            def advertise(method, path, req_hdrs):
                host = thor.http.get_header(req_hdrs, 'host')[-1]
                self.format.notify('Alternate-Protocol announce: %s %s %s' % 
                    (method, host, path))
                exchange.response_start(503, 'Service Unavailable', [
                    ('Alternate-Protocol', adv_value), 
                    ('Content-Length', '0')])
                exchange.response_done([])
            
        self.adv_server.on('exchange', adv_handler)
    
    def run(self):
        self.setup()
        try:
            self.loop.run()
        except KeyboardInterrupt:
            self.adv_server.shutdown()

#-------------------------------------------------------------------------------
    
class SimpleDNS(multiprocessing.Process):
    """
    Basic domain name server to be used to point clients to the SPDY server 
    working as a web proxy. Replies for A record only.
    
    see: https://gist.github.com/zeuxisoo/1205467
    see: http://code.activestate.com/recipes/491264/
    see: https://github.com/Crypt0s/FakeDns/blob/master/fakedns.py
    """
    def __init__(self, settings, name='DNS'):
        multiprocessing.Process.__init__(self, name=name)
        self.settings = settings
        self.dns_host = settings['server_host']
        self.dns_port = settings['dns_port']
        self.reply_ip = settings['dns_A_reply']
        
    def process_request(self, data):
        domain = b''
        type = (data[2] >> 3) & 15 # Opcode bits
        if type == 0: # Standard query
            start = 12
            size = data[start]
        else:
            self.format.notify('Unsupported request type: %d' % type)
            return (None, None)
        while size != 0:
            domain += data[(start + 1):(start + size + 1)] + b'.'
            start += size + 1
            size = data[start]
        if domain:
            reply = data[:2] + b'\x81\x80'
            # Questions and Answers Counts:
            reply += data[4:6] + data[4:6] + b'\x00\x00\x00\x00' 
            # Original Domain Name Question:
            reply += data[12:]
            # Pointer to domain name:
            reply += b'\xc0\x0c'
            # Response type, ttl and resource data length of 4 bytes:
            reply += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            # 4 bytes of IP:            
            reply += bytes(map(int, self.reply_ip.split('.'))) 
            return (domain.decode(), reply)
        else:
            self.format.notify('Failed to read request domain.')
            return (None, None)
        
    def run(self):
        self.format = setup_formatter(setup_logger(self.settings))
        self.format.status('SimpleDNS PID: %s' % os.getpid())
        self.format.status('DNS service running at %s:%d' % (
            self.dns_host, self.dns_port))
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind((self.dns_host, self.dns_port))
        
        try:
            while True:
                (data, address) = udps.recvfrom(1024)
                (domain, reply) = self.process_request(data)
                if reply:
                    self.format.notify('Replied to %s with %s for query %s.' % (
                        address, self.reply_ip, domain))
                    udps.sendto(reply, address)
        except KeyboardInterrupt:
            udps.close()

#-------------------------------------------------------------------------------
    
class SpdyRunner(multiprocessing.Process):
    _base_name = 'SPDY'
    _instances = 0
    
    def __init__(self, settings, name=None):
        type(self)._instances += 1
        if name is None:
            name = '%s-%d' % (self._base_name, self._instances)
        multiprocessing.Process.__init__(self, name=name)
        self.settings = settings
        
    def setup(self): # to be implemented by inheriting classes
        pass
        
    def run(self):
        self.format = setup_formatter(setup_logger(self.settings))
        self.loop = thor.loop.make()
        self.setup()
        try:
            self.loop.run()
        except KeyboardInterrupt:
            pass
            
    def setup_session(self, session):
    
        @thor.on(session, 'frame')
        def on_frame(frame):  
            self.format.frame('SESSION [%s] FRAME-IN %s' % 
                (session.origin, frame)) 
            
        @thor.on(session, 'output')
        def on_output(frame):  
            self.format.frame('SESSION [%s] FRAME-OUT %s' % 
                (session.origin, frame)) 

        @thor.on(session, 'error')
        def on_error(error):
            # traceback.print_stack()
            self.format.error('SESSION [%s] ERROR %s' % 
                (session.origin, error)) 
        
        @thor.on(session, 'bound')
        def on_bound(tcp_conn):
            self.format.session('SESSION [%s] BOUND' % 
                session.origin)
            
        @thor.on(session, 'goaway')
        def on_goaway(reason, last_stream_id):
            self.format.session('SESSION [%s] GOAWAY %s LSID=%d' % (
                session.origin, 
                spdy_frames.GoawayReasons.str[reason], 
                last_stream_id))
        
        @thor.on(session, 'pause')
        def on_pause(paused):
            self.format.session('SESSION [%s] PAUSE %s' % 
                (session.origin, paused))
            
        @thor.on(session, 'close')
        def on_close():
            # traceback.print_stack()
            self.format.session('SESSION [%s] CLOSED' % 
                session.origin)

#-------------------------------------------------------------------------------

class ServerRunner(SpdyRunner):
    _base_name = 'SERVER'
    _instances = 0
    
    def __init__(self, settings, name=None):
        SpdyRunner.__init__(self, settings, name)
        if self.settings['server_use_spdy_advertiser']:
            self.padv = SpdyAdvertiser(self.settings)
            self.padv.start()   
        if self.settings['server_use_dns']:
            self.pdns = SimpleDNS(self.settings)
            self.pdns.start()
        self.tls_config = None
        
    def setup(self):
        self.format.status('ServerRunner PID: %s' % os.getpid())
        if self.settings['server_use_tls']:
            self.tls_config = setup_tls_config(self.settings)
        if self.settings['server_use_proxy']:
            self.fetcher = thor.HttpClient(loop=self.loop)
        self.local_server = FileServer(self.settings['server_webroot'])
        self.server = thor.SpdyServer(
            host=self.settings['server_host'],
            port=self.settings['server_port'],
            idle_timeout=self.settings['server_idle_timeout'],
            tls_config=self.tls_config,
            loop=self.loop)
        self.format.status('LISTENING AT %s:%d' %
            (self.server._host, self.server._port))
        self.server.on('error', self.on_conn_error)
        self.server.on('session', self.on_session)
        
    def on_conn_error(self, error):
        self.format.error('ACCEPT ERROR %s' % error)
    
    def on_session(self, session):
        self.format.session('SESSION NEW %s' % session)
        self.setup_session(session)
        session.on('exchange', self.on_exchange)
        #session.ping_timer().ping()
    
    def on_exchange(self, exchange):
        self.format.exchange('EXCHG NEW %s' % exchange)
        
        @thor.on(exchange, 'error')
        def on_error(error):
            self.format.error('EXCHG [ID=%s] ERROR %s' % 
                (exchange.stream_id, error))
        
        @thor.on(exchange, 'request_start')
        def on_request_start(hdr_dict):
            self.format.exchange('EXCHG [ID=%s] REQ_START %s' % 
                (exchange.stream_id, hdr_dict))
            exchange.req_hdrs = hdr_dict
            exchange.req_body = b''
            exchange.is_local = hdr_dict.host[0] in [
                'localhost', '127.0.0.1', self.settings['server_host']]
        
        @thor.on(exchange, 'request_headers')
        def on_request_headers(hdr_dict):
            self.format.exchange('EXCHG [ID=%s] REQ_HDRS %s' % 
                (exchange.stream_id, hdr_dict))
            exchange.req_hdrs.update(hdr_dict)
        
        @thor.on(exchange, 'request_body')
        def on_request_body(chunk):
            self.format.exchange('EXCHG [ID=%s] REQ_BODY LEN=%d' % 
                (exchange.stream_id, len(chunk)))
            exchange.req_body += chunk
        
        @thor.on(exchange, 'request_done')
        def on_request_done():
            self.format.exchange('EXCHG [ID=%s] REQ_DONE' % 
                exchange.stream_id)
            if exchange.is_local:
                (res_status, res_body, res_hdrs) = \
                    self.local_server.handle_request(exchange.req_hdrs)
                self.format.notify('RESPONSE %s %s' % 
                    (res_status, exchange.req_hdrs.uri))
                exchange.response_start(res_hdrs, res_status)
                exchange.response_body(res_body)
                if res_status[1] == 'OK':
                    req_path = urllib.request.url2pathname(
                        exchange.req_hdrs.path_split[0])[1:]
                    push_paths = self.settings['server_push_map'].get(
                        req_path, []) 
                    for push_entry in push_paths:
                        push_path = push_entry["file"]
                        push_priority = push_entry["priority"]
                        file_path = os.path.join(self.local_server.rootdir, 
                            push_path)
                        push_body = self.local_server.get_file(file_path)
                        if push_body is None:
                            self.format.error('Could not read pushed resource'
                                ' %s associated to request %s' %
                                (file_path, exchange.req_hdrs.uri))
                        else:
                            push_exchg = exchange.push_response()
                            push_exchg.priority = push_priority
                            
                            @thor.on(push_exchg, 'error')
                            def on_push_error(error):
                                self.format.error('EXCHG [ID=%s] ERROR %s' % 
                                    (exchange.stream_id, error))
                            
                            self.format.exchange('EXCHG PUSHED %s' % 
                                push_exchg)
                            push_uri = urllib.parse.urlunsplit((
                                exchange.req_hdrs.scheme,
                                exchange.req_hdrs.authority,
                                urllib.parse.quote(push_path), '', ''))
                            self.format.notify('PUSH RESPONSE %s for %s' % 
                                (file_path, exchange.req_hdrs.uri))
                            push_exchg.response_start(None, uri=push_uri)
                            push_exchg.response_body(push_body)
                            push_exchg.response_done()
                exchange.response_done()
            else:
                if not self.settings['server_use_proxy']:
                    res_status = (503, 'Service unavailable')
                    self.format.notify('RESPONSE %s %s' % 
                        (res_status, exchange.req_hdrs.uri))
                    exchange.response_start(None, res_status, done=True)
                else:
                    http_exchg = self.fetcher.exchange()
                    
                    @thor.on(http_exchg, 'response_start')
                    def on_response_start(res_code, res_phrase, res_tuples):
                        exchange.res_status = (res_code, res_phrase)
                        exchange.res_body = ''
                        exchange.res_hdrs = res_tuples
                        
                    @thor.on(http_exchg, 'response_body')
                    def on_response_body(chunk):
                        exchange.res_body += chunk
                        
                    @thor.on(http_exchg, 'response_done')
                    def on_response_done(trailers):
                        self.format.notify('RESPONSE %s %s ' % 
                            (exchange.res_status, exchange.req_hdrs.uri))
                        exchange.response_start(
                            exchange.res_hdrs,
                            exchange.res_status)
                        if len(exchange.res_body) > 0:
                            exchange.response_body(exchange.res_body.encode())
                        exchange.response_done()
                        
                    @thor.on(http_exchg, 'error')
                    def on_http_error(error):
                        self.format.notify('Failed to fetch %s %s: %r' % (
                            exchange.req_hdrs.method, 
                            exchange.req_hdrs.uri, 
                            error))
                        res_status = (500, 'Internal Server Error')
                        self.format.notify('RESPONSE %s %s ' % 
                            (res_status, exchange.req_hdrs.uri))
                        exchange.response_start(None, res_status, done=True)
                        
                    http_hdrs = (
                        [('Content-Length', str(len(exchange.req_body)))] +  
                        [(n.title(), v) for (n, v) in exchange.req_hdrs.items() 
                            if n not in spdy_common.request_hdrs])
                    http_exchg.request_start(
                        exchange.req_hdrs.method,
                        exchange.req_hdrs.uri,
                        http_hdrs)
                    if len(exchange.req_body) > 0:
                        http_exchg.request_body(exchange.req_body)
                    http_exchg.request_done([])
        
        @thor.on(exchange, 'pause')
        def on_pause(paused):
            self.format.exchange('EXCHG [ID=%s] PAUSE %s' % 
                (exchange.stream_id, paused))
        
#-------------------------------------------------------------------------------
            
class ClientRunner(SpdyRunner):
    _base_name = 'CLIENT'
    _instances = 0
    
    def __init__(self, settings, name=None):
        SpdyRunner.__init__(self, settings, name)
        self.tls_config = None
        
    def setup(self):
        self.format.status('ClientRunner PID: %s' % os.getpid())
        if self.settings['client_use_tls']:
            self.tls_config = setup_tls_config(self.settings)
        self.client = thor.SpdyClient(
            connect_timeout=self.settings['client_connect_timeout'],
            read_timeout=self.settings['client_http_response_timeout'],
            idle_timeout=self.settings['client_idle_timeout'],
            tls_config=self.tls_config,
            loop=self.loop)
        for entry in self.settings['client_urls']:
            if not entry["enabled"]:
                continue
            session = self.client.session((entry['host'], entry['port']))
            self.format.session('SESSION NEW %s' % session)
            self.setup_session(session)
            session.connect()
            for url in  entry['urls']:
                self.do_request(session, url["method"], url["url"], 
                    url["headers"], url["body"], url["md5"])
        
    def do_request(self, session, method, uri, headers, body, checksum):
        exchange = session.exchange()
        # NOTE: this is a basic check; ideally we expect quoted URLs in the settings file
        if ' ' in uri:
            parts = urllib.parse.urlsplit(uri)
            uri = urllib.parse.urlunsplit((
                parts[0], 
                parts[1], 
                urllib.parse.quote(parts[2]), 
                urllib.parse.quote(parts[3]), 
                urllib.parse.quote(parts[4])))
        self.format.notify('REQUEST %s %s' % (method, uri))
        self.setup_exchange(exchange)
        exchange.checksum = checksum
        exchange.hasher = hashlib.md5()
        exchange.uri = uri
        req_hdrs = None
        if headers is not None:
            req_hdrs = [(p[0], p[1]) for p in headers]
        if body is not None:
            body = body.encode()
            exchange.request_start(method, uri, req_hdrs)
            exchange.request_body(body)
            exchange.request_done()
        else:
            exchange.request_start(method, uri, req_hdrs, done=True)
        self.format.exchange('EXCHG NEW %s' % exchange)
        
    def setup_exchange(self, exchange):
        @thor.on(exchange, 'error')
        def on_error(error):
            self.format.error('EXCHG [ID=%s] ERROR %s' % 
                (exchange.stream_id, error))
        
        @thor.on(exchange, 'response_start')
        def on_response_start(hdr_dict):
            self.format.exchange('EXCHG [ID=%s] RES_START %s' % 
                (exchange.stream_id, hdr_dict))
            if exchange._pushed:
                exchange.checksum = None
                exchange.hasher = hashlib.md5()
                exchange.uri = hdr_dict.uri
        
        @thor.on(exchange, 'response_headers')
        def on_response_headers(hdr_dict):
            self.format.exchange('EXCHG [ID=%s] RES_HDRS %s' % 
                (exchange.stream_id, hdr_dict))
        
        @thor.on(exchange, 'response_body')
        def on_response_body(chunk):
            self.format.exchange('EXCHG [ID=%s] RES_BODY LEN=%d' % 
                (exchange.stream_id, len(chunk)))
            exchange.hasher.update(chunk)
        
        @thor.on(exchange, 'response_done')
        def on_response_done():
            digest = exchange.hasher.hexdigest()
            if exchange.checksum:
                if exchange.checksum == digest:
                    self.format.exchange('EXCHG [ID=%s] RES_DONE'
                        ' [MD5 MATCH: %s]' % 
                        (exchange.stream_id, exchange.checksum))
                else:
                    self.format.exchange('EXCHG [ID=%s] RES_DONE'
                        ' [MD5 MISMATCH: GOT=%s, EXPECTED=%s]' % 
                        (exchange.stream_id, digest, exchange.checksum))
                    self.format.error('MD5 digest mismatch for %s:'
                        '\n\t%s computed\n\t%s expected' % 
                        (exchange.uri, digest, exchange.checksum))
            else:
                self.format.exchange('EXCHG [ID=%s] RES_DONE'
                    ' [MD5: %s]' % (exchange.stream_id, digest))
        
        @thor.on(exchange, 'pause')
        def on_pause(paused):
            self.format.exchange('EXCHG [ID=%s] PAUSE %s' % 
                (exchange.stream_id, paused))
        
        @thor.on(exchange, 'pushed_response')
        def on_pushed_response(pushed_exchange):
            self.format.exchange('EXCHG PUSHED %s' % 
                pushed_exchange)
            self.setup_exchange(pushed_exchange)
        
#-------------------------------------------------------------------------------

def frame_catcher(frame_types=None):
    if frame_types is None:
        return (lambda frame: True)
    else:
        sample = frame_types[0]
        if isinstance(sample, int):
            return (lambda frame: frame.type in frame_types)
        else:
            return (lambda frame: type(frame) in frame_types)

def error_catcher(error_types=None):
    if error_types is None:
        return (lambda error: True)
    else:
        return (lambda error: type(error) in error_types)


class MockFrame(spdy_frames.SpdyFrame):
    def __init__(self, type=0, length=0, flags=0, version=3):
        spdy_frames.SpdyFrame.__init__(self, type, flags)
        self.bytes = struct.pack("!HHI",
                0x8000 + version, type, (flags << 24) + length)
                
    def serialize(self, context):
        return self.bytes
        
    def __str__(self):
        return (spdy_frames.SpdyFrame.__str__(self) + 
            ' LEN=%s]' % (len(self.bytes) - 8))
        
#-------------------------------------------------------------------------------
 
class SpdyTestCase(thor.events.EventEmitter):
    """
    A collection of individual test methods.
    
    Event handlers that can be added:
        frame(frame)
        error(error)
        timeout()
    """
    test_prefix = 'test_'
    
    def __init__(self, runner, endpoint):
        thor.events.EventEmitter.__init__(self)
        self.runner = runner
        self.endpoint = endpoint
        self.session = None
        self.is_running = False
        self._method = None
        self._timeout_ev = None
        self.format = runner.format
        self.format.test('TEST %s Running %s: %s' % (
            self.str_endpoint, 
            self.__class__.__name__, 
            self.__doc__))
        
    @property
    def str_endpoint(self):
        return '[%s:%s]' % self.endpoint
        
    def set_up(self):
        pass
        
    def tear_down(self):
        pass
        
    @classmethod
    def set_up_class(cls):
        pass
        
    def fail(self, message=None):
        self.is_running = False
        self.format.error('TEST FAILED %s' % (message or ''))
        self._clear_timeout()
        self.removeListeners()
        self.tear_down()
        self.session.close()
        self.runner.next_test()
        
    def success(self, message=None, close=False):
        self.is_running = False
        self.format.test('TEST SUCCESS %s' % (message or ''))
        self._clear_timeout()
        self.removeListeners()
        self.tear_down()
        if close:
            self.session.close()
        self.runner.next_test()
        
    def run_test(self, session, method_name):
        self.is_running = True
        self._clear_timeout()
        self.removeListeners()
        self.session = session
        self._method = getattr(self, method_name)
        self.format.test('TEST %s Running %s.%s: %s' % (
            self.str_endpoint,
            self.__class__.__name__,
            self._method.__name__, 
            self._method.__doc__))
        self.set_up()
        self._method()
        
    def _set_timeout(self, fail_on_timeout=True):
        if self.runner.wait_timeout and self._timeout_ev is None:
            self._timeout_ev = self.session._loop.schedule(
                self.runner.wait_timeout, 
                self._handle_timeout,
                fail_on_timeout)
    
    def _clear_timeout(self):
        if self._timeout_ev:
            self._timeout_ev.delete()
            self._timeout_ev = None

    def _handle_timeout(self, is_fail):
        msg = 'Timed out %ss waiting for event.' % self.runner.wait_timeout
        if is_fail:
            self.fail(msg)
        else:
            self.success(msg)
        
    @classmethod
    def get_test_names(cls):
        methods = inspect.getmembers(cls, inspect.isfunction)
        return [name for (name, value) in methods 
            if name.startswith(cls.test_prefix)]
            
    def send_and_catch(self, events=[], frame=None, 
        priority=spdy_frames.Priority.MIN, fail_on_timeout=True):
        if frame is not None:
            self.session._queue_frame(frame, priority)
        self._clear_timeout()
        self.removeListeners()
        self._set_timeout(fail_on_timeout)
        if events:
            for (event, pred, handler) in events:
                def on_event(*args, x_pred=pred, x_handler=handler):
                    if x_pred(*args):
                        self._clear_timeout()
                        self.removeListeners()
                        x_handler(*args)
                self.on(event, on_event)

    def error_fail_event(self):
        catcher = error_catcher()
        def handler(error):
            self.fail('Unexpected error: %s' % error)
        return ('error', catcher, handler)
        
    def goaway_event(self, reasons=None, last_stream_id=None, strict=True):
        if strict:
            catcher = frame_catcher([
                spdy_frames.FrameTypes.GOAWAY, 
                spdy_frames.FrameTypes.RST_STREAM,
                spdy_frames.FrameTypes.DATA,
                spdy_frames.FrameTypes.SYN_STREAM,
                spdy_frames.FrameTypes.SYN_REPLY,
                spdy_frames.FrameTypes.HEADERS])
        else:
            catcher = frame_catcher([
                spdy_frames.FrameTypes.GOAWAY])
        def handler(frame):
            if frame.type != spdy_frames.FrameTypes.GOAWAY:
                self.fail('Expecting GOAWAY frame, received %s.' %
                    spdy_frames.FrameTypes.str[frame.type])
            else:
                str_reason = spdy_frames.GoawayReasons.str[frame.reason]
                if (reasons is not None) and (frame.reason not in reasons):
                    self.fail('Received GOAWAY frame with unexpected'
                        ' reason: %s.' % str_reason)
                    return
                if ((last_stream_id is not None) and 
                    (frame.last_stream_id != last_stream_id)):
                    self.fail('Received GOAWAY frame with unexpected'
                        ' last stream id: %s.' % frame.last_stream_id)
                    return
                self.success('Received GOAWAY frame'
                    ' (reason: %s, last stream id: %s).' %
                    (str_reason, frame.last_stream_id), close=True)
        return ('frame', catcher, handler)

    def rst_stream_event(self, codes=None, stream_id=None, strict=True):
        if strict:
            catcher = frame_catcher([
                spdy_frames.FrameTypes.GOAWAY, 
                spdy_frames.FrameTypes.RST_STREAM,
                spdy_frames.FrameTypes.DATA,
                spdy_frames.FrameTypes.SYN_STREAM,
                spdy_frames.FrameTypes.SYN_REPLY,
                spdy_frames.FrameTypes.HEADERS])
        else:
            catcher = frame_catcher([
                spdy_frames.FrameTypes.RST_STREAM])
        def handler(frame):
            if frame.type != spdy_frames.FrameTypes.RST_STREAM:
                self.fail('Expecting RST_STREAM frame, received %s.' %
                    spdy_frames.FrameTypes.str[frame.type])
            else:
                str_status = spdy_frames.StatusCodes.str[frame.status]
                if (codes is not None) and (frame.status not in codes):
                    self.fail('Received RST_STREAM frame with unexpected'
                        ' status code: %s.' % str_status)
                    return
                if (stream_id is not None) and (frame.stream_id != stream_id):
                    self.fail('Received RST_STREAM frame with unexpected'
                        ' stream id: %s.' % frame.stream_id)
                    return
                self.success('Received RST_STREAM frame'
                    '(status: %s, stream id: %s).' %
                    (str_status, frame.stream_id))
        return ('frame', catcher, handler)

#-------------------------------------------------------------------------------

class PingTestCase(SpdyTestCase):
    "Tests validating ping support."

    def test_ping_reply(self):
        "Check for replies to PING frames."
        ping_id = 2013 if self.runner.is_client else 2012
        frame = spdy_frames.PingFrame(ping_id)
        def ping_handler(frame):
            if frame.ping_id != ping_id:
                self.fail('Received PING frame with unexpected ping id: %s' %
                    frame.ping_id)
            else:
                self.success('Received correct PING reply.')
        self.format.test('Sending PING frame with id: %s.' % ping_id)
        self.send_and_catch([self.error_fail_event(),
            ('frame', frame_catcher([spdy_frames.FrameTypes.PING]), 
                ping_handler)], frame)

    def test_ping_invalid_id(self):
        "Check invalid ping ids are ignored."
        ping_id = 2012 if self.runner.is_client else 2013
        frame = spdy_frames.PingFrame(ping_id)
        def ping_handler(frame):
            self.fail('Received PING reply to an invalid ping id: %s' %  
                ping_id)
        self.format.test('Sending PING frame with id: %s.' % ping_id)
        self.send_and_catch([self.error_fail_event(),
            ('frame', frame_catcher([spdy_frames.FrameTypes.PING]), 
                ping_handler)], frame, fail_on_timeout=False)
    
    @classmethod
    def set_up_class(cls):
        valid_len = spdy_frames.MinFrameLen[spdy_frames.FrameTypes.PING]
        for size in range(valid_len * 2):
            if size == valid_len:
                continue
            def test_case(self, x_size=size):
                "Expect GOAWAY after invalid PING frame size."
                frame = MockFrame(spdy_frames.FrameTypes.PING, x_size)
                self.send_and_catch(
                    [self.goaway_event(), self.error_fail_event()], frame)
            name = 'test_ping_length_%s' % size
            test_case.__name__ = name
            setattr(cls, name, test_case)

#-------------------------------------------------------------------------------

COMMON_TEST_CASES = [
    PingTestCase
]

CLIENT_TEST_CASES = COMMON_TEST_CASES + [
]

SERVER_TEST_CASES = COMMON_TEST_CASES + [
]
 
#-------------------------------------------------------------------------------

class ClientTestRunner(SpdyRunner):
    _base_name = 'CLIENT-TEST'
    _instances = 0

    def __init__(self, settings, name=None):
        SpdyRunner.__init__(self, settings, name)
        self.tls_config = None
        self.is_client = True
        self.is_server = False
        self.wait_timeout = settings['client_test_timeout']
        
    def setup(self):
        self.format.status('ClientTestRunner PID: %s' % os.getpid())
        if self.settings['client_use_tls']:
            self.tls_config = setup_tls_config(self.settings)
        self.client = thor.SpdyClient(
            connect_timeout=self.settings['client_connect_timeout'],
            read_timeout=None,
            idle_timeout=None,
            tls_config=self.tls_config,
            loop=self.loop)
        self._curr_test_suite = None
        self._curr_test = None
        self._curr_session = None
        self._curr_conn_retry = 0
        self._max_conn_retry = 3
        self._remaining_tests = self._get_test_list()
        self._test_suite_instances = dict()
        self.next_test()
        
    def setup_session(self, session):
        session.removeListeners()
        SpdyRunner.setup_session(self, session)
        
        @thor.on(session, 'close')
        def on_close():
            # NOTE: connections closed by remote endpoint are preceded by
            #   'error' events with argument spdy_error.ConnectionClosedError.
            #   SpdyTestCases should use it to detect closed sessions. 
            pass
        
        @thor.on(session, 'error')
        def on_error(error):
            if isinstance(error, spdy_error.ConnectionFailedError):
                test_name = str_endpoint = ''
                if self._curr_test:
                    test_name = '%s.%s' % (
                        self._curr_test[1].__name__, self._curr_test[2])
                    str_endpoint = '[%s:%s]' % self._curr_test[0]
                if self._curr_conn_retry < self._max_conn_retry:
                    retry_left = self._max_conn_retry - self._curr_conn_retry
                    self._curr_conn_retry += 1
                    self.format.error('TEST %s Cancelling %s.'
                        ' Cannot connect to remote endpoint: %s.'
                        ' Retries left: %s.' %
                        (str_endpoint, test_name, error, retry_left))
                    session.connect()
                else:
                    self._curr_conn_retry = 0
                    self.format.error('TEST %s Cancelling %s.'
                        ' Cannot connect to remote endpoint: %s.'
                        ' Test will be skipped.' %
                        (str_endpoint, test_name, error))
                    self.next_test()
            else:
                if self._curr_test_suite:
                    self._curr_test_suite.emit('error', error)
                            
        @thor.on(session, 'bound')
        def on_bound(tcp_conn):
            self.run_test()
        
        @thor.on(session, 'frame')
        def on_frame(frame):
            if self._curr_test_suite:
                self._curr_test_suite.emit('frame', frame)

    def _get_test_suite_instance(self, cls, endpoint):
        try:
            suite = self._test_suite_instances[(cls, endpoint)]
        except KeyError:
            suite = cls(self, endpoint)
            self._test_suite_instances[(cls, endpoint)] = suite
        return suite
    
    def _get_test_list(self):
        tests = list()
        for entry in self.settings['client_test_endpoints']:
            if not entry['enabled']:
                continue
            origin = (entry['host'], entry['port'])
            for test_case_class in SERVER_TEST_CASES:
                if test_case_class.__name__ not in entry["skip_tests"]:
                    test_case_class.set_up_class()
                    test_names = test_case_class.get_test_names()
                    for name in test_names:
                        tests.append((origin, test_case_class, name))
        return tests
    
    def next_test(self):
        # traceback.print_stack()
        # self.format.test('TEST NEXT')
        if self._remaining_tests is None:
            return
        if len(self._remaining_tests) == 0:
            self.format.test('All tests done!')
            self._remaining_tests = None
            self._curr_test_suite = None
            self._curr_test = None
            self._curr_session = None
            return
        self._curr_test = self._remaining_tests[0]
        self._remaining_tests = self._remaining_tests[1:]
        self._curr_session = self.client.session(self._curr_test[0])
        if not self._curr_session.is_active:
            self._curr_session.frame_handlers.clear()
            self.setup_session(self._curr_session)
            self._curr_conn_retry = 0
            self._curr_session.connect()
        else:
            self.run_test()
            
    def run_test(self):
        if self._curr_test is None:
            return
        self._curr_test_suite = self._get_test_suite_instance(
            self._curr_test[1], self._curr_test[0])
        self._curr_test_suite.run_test(
            self._curr_session, self._curr_test[2])          
                         
#-------------------------------------------------------------------------------

class ServerTestRunner(SpdyRunner):
    _base_name = 'SERVER-TEST'
    _instances = 0

    def __init__(self, settings, name=None):
        SpdyRunner.__init__(self, settings, name)
        self.tls_config = None
        self.is_client = False
        self.is_server = True
        self.wait_timeout = settings['server_test_timeout']
        raise NotImplementedError

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        settings_file = sys.argv[1]
    except IndexError:
        print("""\
SPDY/3 Testing Tool (c) 2013 Alex Stefanescu <alex.stefa@gmail.com>

Usage:
    %s <settings-file>""" % sys.argv[0])
        sys.exit()
    with open(settings_file, 'r') as f:
        settings = json.load(f)
    if settings['log_file_level'] and settings['log_file_dir']:
        os.makedirs(settings['log_file_dir'], exist_ok=True)
    procs = list()
    if settings['server_enabled']:
        if settings['server_test_mode']:
            p = ServerTestRunner(settings, name='SERVER-TEST')
        else:
            p = ServerRunner(settings, name='SERVER')
        procs.append(p)
        p.start()
        time.sleep(2) # leave a little time to set up server socket
    if settings['client_enabled']:
        for i in range(settings['client_instances']):
            if settings['client_test_mode']:
                p = ClientTestRunner(settings, name='CLIENT-TEST-%d' % (i+1))
            else:
                p = ClientRunner(settings, name='CLIENT-%d' % (i+1))
            procs.append(p)
            p.start()
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        pass

        