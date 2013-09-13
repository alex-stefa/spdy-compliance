#!/usr/bin/env python

import os
import sys
import json
import logging
import multiprocessing
import time
import functools
import socket
from urllib.parse import urlsplit, urlunsplit
from urllib.request import url2pathname

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
        status = functools.partial(_wrapper, logging.INFO, Colors.BOLD),
        notify = functools.partial(_wrapper, logging.INFO, Colors.BLUE))
        
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
    # TODO: directory listing?
    # TODO: implement LRU cache; limit total memory; etc.
    def __init__(self, rootdir='www'):
        self.rootdir = rootdir
    
    @functools.lru_cache(maxsize=64)
    def _get_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except OSError:
            return None
    
    @staticmethod
    def _get_err_page(status):
        return ('<html><body><h1>%s %s</h1></body></html>' % 
            (str(status[0]), str(status[1]))).encode()
                
    def handle_request(self, hdr_dict):
        if hdr_dict.method.lower() != 'get':
            status = (501, 'Not Implemented')
            return (status, self._get_err_page(status))
        path = url2pathname(hdr_dict.path_split[0])
        if path[0] != '/':
            status = (400, 'Bad Request') 
            return (status, self._get_err_page(status))
        path = path[1:]
        file_path = os.path.join(self.rootdir, path)
        if os.path.isdir(file_path):
            status = (403, 'Forbidden')
            return (status, self._get_err_page(status))
        data = self._get_file(file_path)
        if data is None:
            status = (404, 'Not Found')
            return (status, self._get_err_page(status))
        return ((200, 'OK'), data)

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
            port=self.settings['server_alternate_protocol'][0],
            loop=self.loop)
        adv_value = '%d:%s' % (
            self.settings['server_port'], 
            self.settings['server_alternate_protocol'][1])
        self.format.status('Alternate-Protocol: %s advertised on %s:%d' % (
            adv_value,
            self.settings['server_host'],
            self.settings['server_alternate_protocol'][0]))
        
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
        self.dns_host = settings['dns_host']
        self.dns_port = settings['dns_port']
        self.reply_ip = settings['dns_A_reply']
        
    def process_request(data):
        domain = b''
        type = (data[2] >> 3) & 15 # Opcode bits
        if type == 0: # Standard query
            start = 12
            size = data[ini]
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
                (domain, reply) = process_request(data)
                if reply:
                    self.format.notify('Replied to %s with %s for query %s.' % (
                        address, self.reply_ip, domain))
                    udps.sendto(reply, address)
        except KeyboardInterrupt:
            udps.close()

#-------------------------------------------------------------------------------
    
class TestRunner(multiprocessing.Process):
    def __init__(self, settings, name=None):
        multiprocessing.Process.__init__(self, name=name)
        self.settings = settings
        self.tls_config = None
        
    def _setup(self):
        self.format = setup_formatter(setup_logger(self.settings))
        self.loop = thor.loop.make()
        self.frame_buff = list()
        
    def setup(self): # to be implemented by inheriting classes
        pass
        
    def run(self):
        self._setup()
        self.setup()
        try:
            self.loop.run()
        except KeyboardInterrupt:
            pass
            
    def setup_session(self, session):
        session.frame_buff = list()
    
        @thor.on(session, 'frame')
        def on_frame(frame):  
            session.frame_buff.append(frame)
            self.format.frame('SESSION [%s] FRAME-IN %s' % 
                (session.origin, frame)) 
            
        @thor.on(session, 'output')
        def on_output(frame):  
            self.format.frame('SESSION [%s] FRAME-OUT %s' % 
                (session.origin, frame)) 

        @thor.on(session, 'error')
        def on_error(error):
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
    
    
class ServerTestRunner(TestRunner):
    def __init__(self, settings, name='SERVER'):
        TestRunner.__init__(self, settings, name)
        if self.settings['server_alternate_protocol'] is not None:
            self.padv = SpdyAdvertiser(self.settings)
            self.padv.start()   
        if self.settings['server_use_dns']:
            self.pdns = SimpleDNS(self.settings)
            self.pdns.start()
        
    def setup(self):
        self.format.status('ServerRunner PID: %s' % os.getpid())
        if self.settings['server_alternate_protocol'] is None:
            self.format.status('Alternate-Protocol disabled')
        if self.settings['server_use_tls']:
            self.tls_config = setup_tls_config(self.settings)
        if self.settings['server_proxy']:
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
            self.format.error('EXCHG [ID=%d] ERROR %s' % 
                (exchange.stream_id, error))
        
        @thor.on(exchange, 'request_start')
        def on_request_start(hdr_dict):
            self.format.exchange('EXCHG [ID=%d] REQ_START %s' % 
                (exchange.stream_id, hdr_dict))
            exchange.req_hdrs = hdr_dict
            exchange.req_body = b''
            exchange.is_local = hdr_dict.host[0] in [
                'localhost', '127.0.0.1', self.settings['server_host']]
        
        @thor.on(exchange, 'request_headers')
        def on_request_headers(hdr_dict):
            self.format.exchange('EXCHG [ID=%d] REQ_HDRS %s' % 
                (exchange.stream_id, hdr_dict))
            exchange.req_hdrs.update(hdr_dict)
        
        @thor.on(exchange, 'request_body')
        def on_request_body(chunk):
            self.format.exchange('EXCHG [ID=%d] REQ_BODY LEN=%d' % 
                (exchange.stream_id, len(chunk)))
            exchange.req_body += chunk
        
        @thor.on(exchange, 'request_done')
        def on_request_done():
            self.format.exchange('EXCHG [ID=%d] REQ_DONE' % 
                exchange.stream_id)
            if exchange.is_local:
                (res_status, res_body) = self.local_server.handle_request(
                    exchange.req_hdrs) 
                self.format.notify('RESPONSE %s %s' % 
                    (res_status, exchange.req_hdrs.uri))
                if res_body:
                    exchange.response_start(None, res_status)
                    exchange.response_body(res_body)
                    exchange.response_done()
                else:
                    exchange.response_start(None, res_status, done=True)
            else:
                if not self.settings['server_proxy']:
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
                        self.format.notify('Failed to fetch %s %s: %s' % (
                            exchange.req_hdrs.method, 
                            exchange.req_hdrs.uri, 
                            repr(error)))
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
            self.format.exchange('EXCHG [ID=%d] PAUSE %s' % 
                (exchange.stream_id, paused))
        
            
class ClientTestRunner(TestRunner):
    def __init__(self, settings, name='CLIENT'):
        TestRunner.__init__(self, settings, name)
        
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
            session = self.client.session((entry['host'], entry['port']))
            self.format.session('SESSION NEW %s' % session)
            self.setup_session(session)
            for url in  entry['urls']:
                self.do_request(session, url[0], url[1], url[2], url[3])
        
    def do_request(self, session, method, uri, headers, body):
        exchange = session.exchange()
        self.format.exchange('EXCHG NEW %s' % exchange)
        self.format.notify('REQUEST %s %s' % (method, uri))
        self.setup_exchange(exchange)
        exchange.request_start(method, uri, None, True)
        
    def setup_exchange(self, exchange):
        @thor.on(exchange, 'error')
        def on_error(error):
            self.format.error('EXCHG [ID=%d] ERROR %s' % 
                (exchange.stream_id, error))
        
        @thor.on(exchange, 'response_start')
        def on_response_start(hdr_dict):
            self.format.exchange('EXCHG [ID=%d] RES_START %s' % 
                (exchange.stream_id, hdr_dict))
        
        @thor.on(exchange, 'response_headers')
        def on_response_headers(hdr_dict):
            self.format.exchange('EXCHG [ID=%d] RES_HDRS %s' % 
                (exchange.stream_id, hdr_dict))
        
        @thor.on(exchange, 'response_body')
        def on_response_body(chunk):
            self.format.exchange('EXCHG [ID=%d] RES_BODY LEN=%d' % 
                (exchange.stream_id, len(chunk)))
        
        @thor.on(exchange, 'response_done')
        def on_response_done():
            self.format.exchange('EXCHG [ID=%d] RES_DONE' % 
                exchange.stream_id)
        
        @thor.on(exchange, 'pause')
        def on_pause(paused):
            self.format.exchange('EXCHG [ID=%d] PAUSE %s' % 
                (exchange.stream_id, paused))
        
        @thor.on(exchange, 'pushed_response')
        def on_pushed_response(pushed_exchange):
            self.format.exchange('EXCHG PUSHED %s' % 
                pushed_exchange)
            self.setup_exchange(pushed_exchange)
        
#-------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        settings_file = sys.argv[1]
    except IndexError:
        settings_file = 'settings.json'
    with open(settings_file, 'r') as f:
        settings = json.load(f)
    if settings['log_file_level'] and settings['log_file_dir']:
        os.makedirs(settings['log_file_dir'], exist_ok=True)
    procs = list()
    if settings['mode'] in ['server', 'mixed']:
        p = ServerTestRunner(settings)
        procs.append(p)
        p.start()
        time.sleep(2) # leave a little time to set up server socket
    if settings['mode'] in ['client', 'mixed']:
        for i in range(settings['client_count']):
            p = ClientTestRunner(settings, 'CLIENT-%d' % i)
            procs.append(p)
            p.start()
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        pass

        