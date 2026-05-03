from flask import Flask, request
from honeypot.logger import log_request
from datetime import datetime

app = Flask(__name__)

# Fake endpoints
ROUTES = [
    "/",
    "/admin",
    "/login",
    "/wp-admin",
    "/dashboard",
    "/config",
]

def handle_request():
    log_request(request)
    return "OK", 200

# Register all routes dynamically
for route in ROUTES:
    app.add_url_rule(route, route, handle_request, methods = ["GET", "POST"])

@app.route("/<path:anything>", methods = ["GET", "POST"])
def catch_all(anything):
    log_request(request)
    return "Not Found", 404

if __name__ == "__main__":
    print("[*] Honeypot running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)