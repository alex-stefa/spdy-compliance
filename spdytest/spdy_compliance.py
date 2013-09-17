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
import unittest
import urllib
import urllib.request
import urllib.parse

import thor
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
        test = functools.partial(_wrapper, logging.WARNING, Colors.CYAN))
        
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
        raise NotImplementedError
        
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
        # NOTE: this is a basic check; we expect quoted URLs in the settings file
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

def wait_for(session, event_map, timeout=None):
    t_event = threading.Event()
    result = list()
    listener_map = dict()
    
    for (event, predicate) in event_map.items():
        def on_event(*args):
            print('envent: %s, args: %s' % (event, args)) 
            if predicate(args): 
                print('is true')
                result.append((event, args))
                t_event.set()
        listener_map[event] = on_event
        session.on(event, on_event)

    t_event.wait(timeout)
    
    for event in event_map.keys():
        session.removeListener(event, listener_map[event])
        pass
        
    assert len(result) <= 1, 'More than one event has been matched'
    return None if len(result) == 0 else result[0]


#class SpdyTestCase(unittest.TestCase):
class SpdyTestCase():
    
    def __init__(self, runner, origin):
        #unittest.TestCase.__init__(self, methodName='runTest')
        self.runner = runner
        self.origin = origin
        self.session = None
        self.format = runner.format
    
    def send_and_wait_for_frame(self, out_frame, in_frame_types):
        self.session._queue_frame(out_frame, 0)
        if not in_frame_types:
            event_map = {'frame': (lambda frame: True)}
        else:
            sample = in_frame_types[0]
            if isinstance(sample, int):
                event_map = {'frame': 
                    (lambda frame: frame.type in in_frame_types)}
            else:
                event_map = {'frame': 
                    (lambda frame: type(frame) in in_frame_types)}
        return wait_for(self.session, event_map, self.runner.wait_timeout)
        
    def setUp(self):
        self.format.test('setUp')
        self.session = self.runner.get_session(self.origin)
        
    def tearDown(self):
        self.format.test('tearDown')
        pass

    
class PingTestCase(SpdyTestCase):

    def runTest(self):
        self.setUp()
        self.test_ping()
        self.tearDown()
    
    def test_ping(self):
        self.format.test('running test_ping')
        frame = spdy_frames.PingFrame(5)
        reply = self.send_and_wait_for_frame(frame, [spdy_frames.PingFrame])
        self.format.test('reply: %s' % reply)

    def run(self):
        self.runTest()
 
#-------------------------------------------------------------------------------

TEST_CASES = [
    PingTestCase
]

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

    #TODO: add auto test failer on 'error'
    
    def get_session(self, origin):
        session = self.client.session(origin, self.setup_session)
        self.format.session('SESSION NEW %s' % session)
        self.setup_session(session)
        session.connect()
        return session
    
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
        tester = TesterThread(self, settings['client_test_endpoints'])
        tester.start()
        #tester.run()
                    

class TesterThread(threading.Thread):
#class TesterThread():
    
    def __init__(self, runner, endpoints):
        threading.Thread.__init__(self)
        self.runner = runner
        self.endpoints = endpoints
        self.format = runner.format
        
    def run(self):
        for entry in self.endpoints:
            if not entry['enabled']:
                continue
            origin = (entry['host'], entry['port'])
            for test_case_class in TEST_CASES:
                if test_case_class.__name__ not in entry["skip_tests"]:
                    test_case = test_case_class(self.runner, origin)
                    test_case.run()
        
            
         
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

        