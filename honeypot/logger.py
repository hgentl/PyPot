from datetime import datetime
from collections import defaultdict

LOG_FILE = "logs/requests.log"

# Track requests per IP
request_count = defaultdict(list)

# suspicious indicators
SUSPICIOUS_PATHS = ["admin", "wp-admin", "config", "login"]
SUSPICIOUS_AGENTS = ["curl", "python", "wget"]

TIME_WINDOW = 10
REQUST_LIMIT = 5

def is_suspicious(ip, path, user_agent):
    reasons = []

    # track timestamps
    now = datetime.now().timestamp()
    request_count[ip].append(now)

    # clear past entires
    request_count[ip] = [
        t for t in request_count[ip]
        if now - t <= TIME_WINDOW
    ]

    # Rule 1 too many requests
    if len(request_count[ip]) > REQUST_LIMIT:
        reasons.append("High request rate")
    
    # Rule 2 Suspicious paths 
    if any(p in path.lower() for p in SUSPICIOUS_PATHS):
        reasons.append("Sensitive endpoint probing")

    # Rule 3 Suspicios user agent
    if any(a in user_agent.lower() for a in SUSPICIOUS_AGENTS):
        reasons.append("Suspicious user agent")

    return reasons

def log_request(request):
    ip = request.remote_addr
    method = request.method
    path = request.path
    user_agent = request.headers.get("User-Agent", "Unknown")

    # check this
    timestamp = datetime.now().strftime("%d-%m-%y %H:%M:%S")

    reasons = is_suspicious(ip, path, user_agent)

    tag = "[SUSPICIOUS]" if reasons else "[INFO]"

    log_entry = (
        f"[{timestamp}] {ip} {method} {path} "
        f'User-Agent="{user_agent}"\n'
    )

    if reasons:
        log_entry += f" | Reasons: {', '.join(reasons)}"

    log_entry += "\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    
    print(log_entry.strip())