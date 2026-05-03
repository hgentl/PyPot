from datetime import datetime

LOG_FILE = "logs/requests.log"

def log_request(request):
    ip = request.remote_addr
    method = request.method
    path = request.path
    user_agent = request.headers.get("User-Agent", "Unknown")

    timestamp = datetime.now().strftime("%d-%m-%y %H:%M:%S")

    log_entry = (
        f"[{timestamp}] {ip} {method} {path} "
        f'User-Agent="{user_agent}"\n'
    )

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    
    print(log_entry.strip())