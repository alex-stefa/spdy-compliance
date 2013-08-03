#!/usr/bin/env python2

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
    RED = r'[0;31m',
    GREEN = r'[0;32m',
    YELLOW = r'[0;33m',
    BOLD = r'[1m',
    NORMAL = r'[0m')

def setup_logging():
    log = multiprocessing.log_to_stderr()
    log.setLevel(logging.INFO)
    return log
    
def wrap(color, str):
    return color + str + Colors.NORMAL
    
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

class TestRunner(object):
    def __init__(self, settings_file='settings.json'):
        with open(settings_file, 'r') as f:
            self.settings = json.load(f)
        self.log = setup_logging()
        self.frame_buff = list()
        
    def setup_session(self, session):
        session.frame_buff = list()
    
        @thor.on(session, 'frame')
        def on_frame(frame):  
            session.frame_buff.append(frame)
            self.log.info(wrap(Colors.YELLOW, str(frame))) 
            
        @thor.on(session, 'error')
        def on_error(error):
            self.log.info(wrap(Colors.RED, str(error))) 
        
        @thor.on(session, 'bound')
        def on_bound(tcp_conn):
            self.log.info(wrap(Colors.BOLD, 'BOUND %s' % tcp_conn))
            
        @thor.on(session, 'goaway')
        def on_goaway(reason, last_stream_id):
            self.log.info(wrap(Colors.BOLD, 'GOAWAY %s LSID%d' % 
                (GoawayReasons.str[reason], last_stream_id)))
        
        @thor.on(session, 'pause')
        def on_pause(paused):
            self.log.info(wrap(Colors.BOLD, 'PAUSE %s' % paused))
            
        @thor.on(session, 'close')
        def on_close():
            self.log.info(wrap(Colors.BOLD, 'CLOSED'))
    
    
class ServerTestRunner(TestRunner):
    def __init__(self, settings_file):
        TestRunner.__init__(self, settings_file)
        self.log.info(wrap(Colors.RED, 'ServerRunner PID: %s' % os.getpid()))
        self.cache = FileCache(self.settings['server_webroot'])
        self.server = thor.SpdyServer(
            host=self.settings['server_host'],
            port=self.settings['server_port'],
            idle_timeout=self.settings['connection_idle_timeout'],
            loop=thor.loop.make())
        self.log.info(wrap(Colors.BOLD, 'LISTENING'))
        self.server.on('session', self.on_session)
        try:
            self.server._loop.run()
        except KeyboardInterrupt:
            pass
        
    def on_session(self, session):
        self.log.info(wrap(Colors.BOLD, 'SESSION %s' % session))
        self.setup_session(session)
        session.on('exchange', self.on_exchange)
    
    def on_exchange(self, exchange):
        self.log.info(wrap(Colors.GREEN, 'NEW EXCHG %s' % exchange))
        
        @thor.on(exchange, 'error')
        def on_error(error):
            self.log.info(wrap(Colors.RED, 
                '[ID=%d] %s' % (exchange.stream_id, error))) 
        
        @thor.on(exchange, 'request_start')
        def on_request_start(hdr_dict):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] REQ_START %s' % (exchange.stream_id, hdr_dict)))
            data = self.cache.get_data(hdr_dict.path)
            exchange.response_start(None, "200 OK")
            exchange.response_body(data)
            exchange.response_done()
        
        @thor.on(exchange, 'request_headers')
        def on_request_headers(hdr_dict):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] REQ_HDRS %s' % (exchange.stream_id, hdr_dict))) 
        
        @thor.on(exchange, 'request_body')
        def on_request_body(chunk):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] REQ_BODY LEN=%d' % (exchange.stream_id, len(chunk)))) 
        
        @thor.on(exchange, 'request_done')
        def on_request_done():
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] REQ_DONE' % exchange.stream_id)) 
        
        @thor.on(exchange, 'pause')
        def on_pause(paused):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] PAUSE %s' % (exchange.stream_id, paused))) 
        
            
class ClientTestRunner(TestRunner):
    def __init__(self, settings_file):
        TestRunner.__init__(self, settings_file)
        self.log.info(wrap(Colors.RED, 'ClientRunner PID: %s' % os.getpid()))
        self.client = thor.SpdyClient(
            connect_timeout=self.settings['client_connect_timeout'],
            read_timeout=self.settings['http_response_timeout'],
            idle_timeout=self.settings['connection_idle_timeout'],
            loop=thor.loop.make())
        for entry in self.settings['client_urls']:
            session = self.client.session((entry['host'], entry['port']))
            self.log.info(wrap(Colors.BOLD, 'SESSION %s' % session))
            self.setup_session(session)
            for url in  entry['urls']:
                self.do_request(session, url[0], url[1])
        try:
            self.client._loop.run()
        except KeyboardInterrupt:
            pass
        
    def do_request(self, session, method, uri):
        exchange = session.exchange()
        self.log.info(wrap(Colors.GREEN, 'NEW EXCHG %s' % exchange))
        self.setup_exchange(exchange)
        exchange.request_start(method, uri, None, True)
        
    def setup_exchange(self, exchange):
        @thor.on(exchange, 'error')
        def on_error(error):
            self.log.info(wrap(Colors.RED, 
                '[ID=%d] %s' % (exchange.stream_id, error))) 
        
        @thor.on(exchange, 'response_start')
        def on_response_start(hdr_dict):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] RES_START %s' % (exchange.stream_id, hdr_dict)))
        
        @thor.on(exchange, 'response_headers')
        def on_response_headers(hdr_dict):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] RES_HDRS %s' % (exchange.stream_id, hdr_dict))) 
        
        @thor.on(exchange, 'response_body')
        def on_response_body(chunk):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] RES_BODY LEN=%d' % (exchange.stream_id, len(chunk)))) 
        
        @thor.on(exchange, 'response_done')
        def on_response_done():
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] RES_DONE' % exchange.stream_id)) 
        
        @thor.on(exchange, 'pause')
        def on_pause(paused):
            self.log.info(wrap(Colors.NORMAL, 
                '[ID=%d] PAUSE %s' % (exchange.stream_id, paused))) 
        
        @thor.on(exchange, 'pushed_response')
        def on_pushed_response(pushed_exchange):
            self.log.info(wrap(Colors.GREEN, 'PUSHED EXCHG %s' % pushed_exchange))
            self.setup_exchange(pushed_exchange)
        
#-------------------------------------------------------------------------------

if __name__ == "__main__":
    ps = multiprocessing.Process(
        target=ServerTestRunner, 
        args=('settings.json',),
        name='SERVER')
    ps.start()
    time.sleep(2) # leave a little time to set up server socket
    pc = multiprocessing.Process(
        target=ClientTestRunner, 
        args=('settings.json',),
        name='CLIENT')
    pc.start()
    try:
        ps.join()
        pc.join()
    except KeyboardInterrupt:
        pass

        