from flask import Flask
from flask import request
from flask import jsonify
from flask import Response

from urllib.parse import urlparse

from OpenSSL import SSL

import requests

### Static
METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH"
    ]
URL = "http://scratchpads.org/"
PROXY = "https://127.0.0.1/"
## DEFAULT HEADERS
USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1"
ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
ACCEPT_LANGUAGE = "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3"
ACCEPT_ENCODING = "gzip, deflate, br"
CONNECTION = "keep-alive"
DOMAIN = urlparse(URL).netloc

set_headers = lambda request, string : request.headers[string] if string in list(request.headers.keys()) else globals()[string.upper().replace("-", "_")]

context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file("certs\\server.key")
context.use_certificate_file("certs\\server.crt")

app = Flask(__name__)

@app.route("/", defaults={"path": ""}, methods=METHODS)
@app.route("/<path:path>")
def main(path):
    # Get method for requests
    request_method = getattr(requests, request.method.lower())
    # Set headers
    headers = {
        "Host": DOMAIN,
        "User-Agent": set_headers(request, "User-Agent"),
        "Accept": set_headers(request, "Accept"),
        "Accept-Language": set_headers(request, "Accept-Language"),
        "Accept-Encoding": set_headers(request, "Accept-Encoding")
    }
    # Launch the Query
    response = request_method(URL + path, headers=headers)

    print(response.headers)

    # Make the response with content and header
    resp = Response(response.text.replace(URL, PROXY))
    resp.headers = {
        "Content-Type": response.headers["Content-Type"],
        "Content-Length": len(response.content)
        }

    return resp

    # 
    return f"<h1>You requests {path} with method {request.method}</h1>" + response.text.replace(URL, PROXY)
    
    #return Response(value, mimetype="text/html")
    headers = {"Content-Type": "text/html",
                "Content-Encoding": "gzip",
                "Vary": "Accept-Encoding"}
    value = gzip.compress(value.encode("iso-8859-1"))
    resp = app.make_response(value)
    #resp.mimetype = "text/html"
    resp.headers = headers
    return resp


if __name__ == "__main__":
    context = ("certs\\server.crt", "certs\\server.key")
    app.run(host="127.0.0.1", port=8083, debug=True, ssl_context=context)