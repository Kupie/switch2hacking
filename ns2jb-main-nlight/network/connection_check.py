"""Offline response for the Switch 2 Wi-Fi connection check; no proxying."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = 'ctest.p01.ctest.srv.nintendo.net'

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Host', '').split(':')[0].lower() != HOST or self.path != '/':
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '2')
        self.send_header('X-Organization', 'Nintendo')
        self.send_header('Cache-Control', 'max-age=0, no-cache, no-store')
        self.send_header('Pragma', 'no-cache')
        self.end_headers()
        self.wfile.write(b'ok')

ThreadingHTTPServer(('192.168.77.1', 80), Handler).serve_forever()
