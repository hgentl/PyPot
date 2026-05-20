from flask import Flask, request, Response
from honeypot.logger import log_request, log_credentials, print_summary
import atexit

app = Flask(__name__)

atexit.register(print_summary)

@app.route("/")
def home():
    log_request(request)
    return "OK", 200

@app.route("/admin")
@app.route("/wp-admin")
@app.route("/dashboard")
@app.route("/config")
def trap_routes():
    log_request(request)
    return "Not Found", 404

@app.route("/login", methods=["GET", "POST"])
def login():
    log_request(request)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        log_credentials(username, password, request.remote_addr)
    
    return Response("""
        <html>
            <body>
                <h2>Login</h2>
                <form method="POST">
                    <input name="username" placeholder="Username"><br>
                    <input name="password" type="password" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>  
        """, mimetype="text/html")

@app.route("/<path:anything>", methods=["GET", "POST"])
def catch_all(anything):
    log_request(request)
    return "Not Found", 404

if __name__ == "__main__":
    print("[*] Honeypot running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
