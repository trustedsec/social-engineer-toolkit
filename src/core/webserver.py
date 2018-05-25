import http.server
import http.server
import http.client
import os
import sys
from src.core.setcore import *

# specify the web port
web_port = check_config("WEB_PORT=")


class StoppableHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    """http request handler with QUIT stopping the server"""

    def do_QUIT(self):
        """send 200 OK response, and set server.stop to True"""
        self.send_response(200)
        self.end_headers()
        self.server.stop = True

    def do_POST(self):
        # We could also process paremeters here using something like below.
        self.do_GET()

    def send_head(self):
        # This is ripped directly from SimpleHTTPRequestHandler, only the
        # cookie part is added.
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        if ctype.startswith('text/'):
            mode = 'r'
        else:
            mode = 'rb'
        try:
            f = open(path, mode)
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f


class StoppableHttpServer(http.server.HTTPServer):
    """http server that reacts to self.stop flag"""

    def serve_forever(self):
        """Handle one request at a time until stopped."""
        self.stop = False
        while not self.stop:
            self.handle_request()

# stop the http server
def stop_server(web_port):
    try:
        web_port = int(web_port)
        """send QUIT request to http server running on localhost:<port>"""
        conn = http.client.HTTPConnection("localhost:%d" % web_port)
        conn.request("QUIT", "/")
        conn.getresponse()
    except: pass

# start the http server
def start_server(web_port, path):
    try:
        os.chdir(path)
        web_port = int(web_port)
        server = StoppableHttpServer(('', web_port), StoppableHttpRequestHandler)
        server.serve_forever()
    except: pass
