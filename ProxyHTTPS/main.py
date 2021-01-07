#!/usr/local/bin/python3.8

from flask import Flask
from flask import request
from flask import Response

from urllib.parse import urlparse

import requests
import ssl
import os

# Static
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
## URL
URL = "http://scratchpads.org/"
PROXY = "https://127.0.0.1/"
DOMAIN = urlparse(URL).netloc
## Certs
PRIV_KEY = os.path.join("certs", "key.pem")
PUB_KEY = os.path.join("certs", "cert.pem")
## PID File
PID_FILE = "pid/pidhttps.ini"

set_args = lambda args : "&".join([f"{key}={value}" for key, value in args.items()])

app = Flask(__name__)

@app.route("/", defaults={"path": ""}, methods=METHODS)
@app.route("/<path:path>", methods=METHODS)
def main(path):
    # Make URL
    _url = URL + path + "?" + set_args(dict(request.args))

    # Get method for requests
    request_method = getattr(requests, request.method.lower())

    # Set headers
    client_headers = dict(request.headers)
    client_headers["Host"] = DOMAIN
    client_headers["Referer"] = URL

    # Set data
    client_data = dict(request.form)

    # Set files
    if len(dict(request.files)):
        # For each files
        for key, value in dict(request.files).items():
            # Check the filename
            if not len(value.filename):
                continue
            # Write into file
            with open(f"/tmp/{value.filename}", "wb") as f:
                f.write(value.read())
            # Add file to the client data
            client_data[key] = (value.filename, open(f"/tmp/{value.filename}", "rb"), value.content_type)

    # Launch the Query
    if "Content-Type" in list(client_headers.keys()) and client_headers["Content-Type"].startswith("multipart/form-data"):
            # Set info or if file set file
            files = tuple({(key, (None, value)) if not isinstance(value, tuple) else (key, (value)) for key, value in client_data.items()})
            # Delete Content-Type to let flask set the good multipart
            del client_headers["Content-Type"]
            response = request_method(_url, headers=client_headers, files=files, timeout=10)
    else:
        response = request_method(_url, headers=client_headers, data=client_data, timeout=10)

    # Make the response with content and header for the file type
    resp = Response(response.content)
    resp.headers = {
        "Content-Type": response.headers["Content-Type"],
        }

    # Attribution de cookie si le header est present
    if "Set-Cookie" in list(response.headers.keys()):
        resp.headers["Set-Cookie"] = response.headers["Set-Cookie"]

    return resp


if __name__ == "__main__":
    with open(PID_FILE, "w") as f:
        f.write(f"{os.getpid()}\n")
    # Mise en place d'un TLS v1.2 avec certificat HTTPS
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(PUB_KEY, PRIV_KEY)
    app.run(host="0.0.0.0", port=8083, debug=False, ssl_context=context)
