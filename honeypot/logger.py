from datetime import datetime
from collections import defaultdict

LOG_FILE = "logs/requests.log"
CRED_FILE = "logs/credentials.log"

# Track requests per IP
request_count = defaultdict(list)

ip_stats = defaultdict(lambda: {
    "count": 0,
    "paths": set(),
    "flags": set()
})


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

    timestamp = datetime.now().strftime("%d-%m-%y %H:%M:%S")

    reasons = is_suspicious(ip, path, user_agent)

    stats = ip_stats[ip]
    stats["count"] += 1
    stats["paths"].add(path)

    for reason in reasons:
        stats["flags"].add(reason)
    

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

def log_credentials(username, password, ip):
    entry = f"{ip} username={username} password={password}\n"

    with open(CRED_FILE, "a") as f:
        f.write(entry)
    
    print(f"[CREDENTIAS] {entry.strip()}")

def print_summary():
    print("\n--- Summary ---")

    if not ip_stats:
        print("No activity recorded.")
        return
    
    for ip, data in ip_stats.items():
        print(f"\nIP: {ip}")
        print(f"Requests: {data['count']}")
        print(f"Endpoints: {', '.join(data['paths'])}")

        if data["flags"]:
            print("Flags:")
            for f in data["flags"]:
                print(f"- {f}")