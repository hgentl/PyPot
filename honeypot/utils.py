def check_suspicious_path(path):
    suspicious = ["admin", "login", "config", "wp-dmin"]
    return any(word in path.lower() for word in suspicious)
