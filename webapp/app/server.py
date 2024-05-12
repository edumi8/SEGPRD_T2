import http.server
import ssl

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello, world!")

server_address = ('localhost', 8585)
httpd = http.server.HTTPServer(server_address, MyHandler)

# Create an SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="app.crt", keyfile="app.key")

# Require client certificate authentication
ssl_context.verify_mode = ssl.CERT_REQUIRED

httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

print("Server started at https://localhost:8585")
httpd.serve_forever()