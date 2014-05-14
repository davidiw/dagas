#!/usr/bin/env python3

import bottle

bottle.BaseRequest.MEMFILE_MAX = 2**40
class Server(bottle.ServerAdapter):
    def run(self, handler): # pragma: no cover
        from cherrypy import wsgiserver
        self.options['bind_addr'] = (self.host, self.port)
        self.options['wsgi_app'] = handler

        certfile = self.options.get('certfile')
        if certfile:
            del self.options['certfile']
        keyfile = self.options.get('keyfile')
        if keyfile:
            del self.options['keyfile']

        server = wsgiserver.CherryPyWSGIServer(**self.options)
        if certfile:
            server.ssl_certificate = certfile
        if keyfile:
            server.ssl_private_key = keyfile
        server.max_request_body_size = 2**40
        server.max_request_header_size = 2**40

        try:
            server.start()
        finally:
            server.stop()
