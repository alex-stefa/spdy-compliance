#!/usr/bin/env python

import os
import sys
import json
import logging
import multiprocessing
import time
import functools

import thor
from thor.spdy import error
from thor.spdy import frames
from thor.spdy.frames import enum


# TerminalColorEscapes contains strings that, when printed to a terminal, will
# cause subsequent text to be displayed in the given manner.
Colors = enum(
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

def setup_logger():
    logger = multiprocessing.log_to_stderr()
    logger.setLevel(logging.DEBUG)
    return logger

def setup_formatter(use_colors, logger):
    def _wrapper(level, color, str):
        if use_colors:
            logger.log(level, color + str + Colors.NORMAL)
        else:
            logger.log(level, str)

    return enum(
        error = functools.partial(_wrapper, logging.ERROR, Colors.RED),
        frame = functools.partial(_wrapper, logging.DEBUG, Colors.DIM),
        exchange = functools.partial(_wrapper, logging.INFO, Colors.YELLOW),
        session = functools.partial(_wrapper, logging.INFO, Colors.GREEN),
        status = functools.partial(_wrapper, logging.INFO, Colors.BOLD),
        notify = functools.partial(_wrapper, logging.INFO, Colors.BLUE))
        
def setup_tls_config(settings):
    tls_config = settings['tls_config']
    return thor.TlsConfig(
        keyfile=tls_config['keyfile'],
        certfile=tls_config['certfile'],
        cafile=tls_config['cafile'],
        capath=tls_config['capath'],
        npn_prot=tls_config['npn_prot'])
    
#-------------------------------------------------------------------------------

class FileCache(object):
    """
    Very simple file cache. Avoids repeated reads of the same file.
    Should not be used for very large files.
    """
    # TODO: implement LRU cache; limit total memory; etc.
    # TODO: sanitize path (prevent dir traversal)
    def __init__(self, rootdir='www'):
        self.rootdir = rootdir
        self.cache = dict()
    
    def get_data(self, path):
        if path[0] == '/':
            path = path[1:]
        try:
            return self.cache[path]
        except KeyError:
            with open(os.path.join(self.rootdir, path), 'rb') as f:
                data = f.read()
                self.cache[path] = data
                return data

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
        self.format = setup_formatter(True, setup_logger())
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
            def advertise(method, uri, req_hdrs):
                self.format.notify('Alternate-Protocol announce: %s %s' % 
                    (method, uri))
                exchange.response_start(501, 'Not Implemented', [
                    ('Alternate-Protocol', adv_value), 
                    ('Content-Length', '0'),
                    ('Connection', 'close')])
                exchange.response_done([])
            
        self.adv_server.on('exchange', adv_handler)
    
    def run(self):
        self.setup()
        try:
            self.loop.run()
        except KeyboardInterrupt:
            self.adv_server.shutdown()

#-------------------------------------------------------------------------------
    
class TestRunner(multiprocessing.Process):
    def __init__(self, settings, name=None):
        multiprocessing.Process.__init__(self, name=name)
        self.settings = settings
        self.tls_config = None
        
    def _setup(self):
        self.format = setup_formatter(True, setup_logger())
        self.loop = thor.loop.make()
        self.frame_buff = list()
        
    def setup(self):
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
            self.format.frame('SESSION [%s] FRAME %s' % 
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
            self.format.session('SESSION [%s] GOAWAY %s LSID=%d' % 
                (session.origin, GoawayReasons.str[reason], last_stream_id))
        
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
        
    def setup(self):
        self.format.status('ServerRunner PID: %s' % os.getpid())
        if self.settings['server_alternate_protocol'] is None:
            self.format.status('Alternate-Protocol disabled')
        if self.settings['server_use_tls']:
            self.tls_config = setup_tls_config(self.settings)
        self.cache = FileCache(self.settings['server_webroot'])
        self.server = thor.SpdyServer(
            host=self.settings['server_host'],
            port=self.settings['server_port'],
            idle_timeout=self.settings['connection_idle_timeout'],
            tls_config=self.tls_config,
            loop=self.loop)
        self.format.status('LISTENING AT %s:%d' %
            (self.server._host, self.server._port))
        self.server.on('session', self.on_session)

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
            data = self.cache.get_data(hdr_dict.path)
            status = "200 OK"
            self.format.notify('RESPONSE %s %s' % 
                (status, hdr_dict.uri))
            exchange.response_start(None, status)
            exchange.response_body(data)
            exchange.response_done()
        
        @thor.on(exchange, 'request_headers')
        def on_request_headers(hdr_dict):
            self.format.exchange('EXCHG [ID=%d] REQ_HDRS %s' % 
                (exchange.stream_id, hdr_dict))
        
        @thor.on(exchange, 'request_body')
        def on_request_body(chunk):
            self.format.exchange('EXCHG [ID=%d] REQ_BODY LEN=%d' % 
                (exchange.stream_id, len(chunk)))
        
        @thor.on(exchange, 'request_done')
        def on_request_done():
            self.format.exchange('EXCHG [ID=%d] REQ_DONE' % 
                exchange.stream_id)
        
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
            idle_timeout=self.settings['connection_idle_timeout'],
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

        