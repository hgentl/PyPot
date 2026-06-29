# PyPot

PyPot is a simple, lightweight web honeypot designed to simulate common attack targets and observe real-world probing behaviour on HTTP services.

---

## Overview

This project implements a minimal honeypot that exposes commonly targeted endpoints (e.g. `/admin`, `/login`, `/wp-admin`) and logs incoming requests. It extends beyond simple logging by identifying suspicious behaviour patterns and aggregating activity into per-IP summaries.

The goal is not to build a full intrusion detection system, but to explore how attackers interact with exposed web services and to extract meaningful insights from that behaviour.

---

## Motivation

Attackers frequently scan the internet for predictable paths and misconfigured services. Many of these interactions follow recognisable patterns:

* probing sensitive endpoints (`/admin`, `/wp-admin`)
* using automated tools (`curl`, `wget`, scripts)
* making repeated requests in short time windows

This project was built to better understand those behaviours by:

* simulating a target system
* capturing request data
* identifying suspicious patterns
* summarising attacker activity

---

## Features

### 1. Fake Attack Surface

* Exposes common endpoints:

  * `/admin`
  * `/login`
  * `/wp-admin`
  * `/config`
* Includes a simple login form to simulate credential harvesting targets

---

### 2. Behaviour-Based Detection

Each request is analysed using simple heuristics:

* Sensitive endpoint probing
* Suspicious user agents (e.g. `curl`, `wget`)
* High request rate from a single IP

Requests are flagged in real time with clear reasoning.

---

### 3. Credential Capture (Simulated)

The `/login` endpoint accepts POST requests and logs submitted credentials.

> This is for educational purposes only. No real authentication is implemented.

---

### 4. Attacker Summary

Rather than just logging individual requests, the honeypot aggregates behaviour per IP:

* total requests
* endpoints accessed
* triggered detection rules

This provides a clearer view of attacker intent and patterns.

---

## Example Output

### Real-time logs

```
[SUSPICIOUS] [2026-05-03 14:22:10] 192.168.1.10 GET /wp-admin User-Agent="curl/7.68.0" | Reasons: Sensitive endpoint probing, Suspicious user agent

[SUSPICIOUS] [2026-05-03 14:22:12] 192.168.1.10 GET /admin User-Agent="curl/7.68.0" | Reasons: High request rate, Sensitive endpoint probing, Suspicious user agent

[INFO] [2026-05-03 14:22:15] 127.0.0.1 GET / User-Agent="Mozilla/5.0"
```

---

### Captured credentials

```
[CREDENTIALS] 192.168.1.10 username=admin password=123456
```

---

### Attacker summary (on shutdown)

```
--- Attacker Summary ---

IP: 192.168.1.10
Requests: 8
Endpoints: /admin, /wp-admin, /login
Flags:
- High request rate
- Sensitive endpoint probing
- Suspicious user agent

IP: 127.0.0.1
Requests: 2
Endpoints: /
```

---

## Project Structure

```
honeypot/
├── app.py
├── honeypot/
│   └── logger.py
├── tests/
├── logs/              # runtime logs (gitignored)
└── README.md
```

---

## Running the Project

Install dependencies:

```
pip install -r requirements.txt
```

Run the server:

```
python app.py
```

Then visit:

```
http://localhost:5000/admin
http://localhost:5000/login
```

---

## Key Design Decisions

* **Simplicity over completeness**
  The system focuses on a few clear heuristics rather than attempting full detection coverage.

* **Explainable detection**
  Every flagged request includes explicit reasoning.

* **Separation of concerns**
  Request handling, logging, and detection logic are kept distinct for clarity and testability.

* **Stateful behaviour tracking**
  Detection considers patterns over time (e.g. repeated requests), not just individual events.

---

## What I Learned

* How attackers probe predictable web endpoints
* How simple heuristics can capture meaningful behaviour
* The importance of aggregating events into higher-level insights
* Designing systems that are both observable and explainable

---

## Disclaimer

This project is for educational purposes only. It is not intended to be deployed as a production security tool.

---

## Future Improvements

* persistent storage for logs
* IP reputation / enrichment
* more advanced behaviour correlation

---
