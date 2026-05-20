# Web Application Firewall

A Flask-based WAF that sits in front of a web application, inspecting every
incoming request for malicious content. Requests that match known attack
signatures are blocked and logged. IPs that repeatedly trigger rules are
automatically added to a persistent blocklist.

## How It Works

Every request passes through a middleware hook before reaching
any route. The middleware runs three checks in order:

**1. Blocklist Check**
The requesting IP is checked against a SQLite-backed blocklist. Blocked IPs
receive a 403 immediately with no further processing.

**2. Content Inspection**
The request path, query string, and body are scanned against a rule set covering
XSS (script tags, event handlers, javascript URIs), SQL injection (tautologies,
UNION SELECT, DROP TABLE, comment sequences), path traversal, and shell injection.
Any rule match results in a 403 with the matched rule names returned in the response.

**3. Dynamic IP Blocking**
Each time an IP triggers a rule, its violation count is incremented in the request
log. Once an IP reaches 5 violations it is automatically added to the blocklist,
blocking all future requests regardless of content.

All requests are written to a persistent SQLite log with
timestamp, IP, method, path, user agent, body, and matched rules.

## Project Structure

```
web-application-firewall/
├── waf/
│   ├── rules.py        # regex rule set for XSS, SQLi, traversal, shell injection
│   ├── middleware.py   # Flask before_request inspection hook
│   ├── blocklist.py    # dynamic IP blocklist backed by SQLite
│   └── database.py     # SQLite schema, logging, and query helpers
├── app.py              # Flask app with WAF and admin routes
├── main.py             # entrypoint with dotenv config
├── Dockerfile
├── requirements.txt
└── .env.example
```

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/web-application-firewall.git
cd web-application-firewall
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py
```

## Usage

Once running, all requests to the Flask app pass through the WAF automatically.

```bash
# Clean request — allowed
curl http://localhost:5000/

# XSS attempt — blocked
curl "http://localhost:5000/?q=<script>alert('xss')</script>"

# SQLi attempt — blocked
curl "http://localhost:5000/?id=' OR 1=1 --"

# View request log
curl http://localhost:5000/logs

# View blocklist
curl http://localhost:5000/blocklist

# Unblock an IP
curl -X DELETE http://localhost:5000/blocklist/127.0.0.1
```

## Docker

```bash
docker build -t web-application-firewall .
docker run -p 5000:5000 web-application-firewall
```

## Dependencies

- `flask` — web framework and request middleware
- `python-dotenv` — environment variable management
- Standard library: `sqlite3`, `re`, `json`

## Disclaimer

This is a demonstration WAF. It is not a replacement for production WAF solutions. 
Do not expose this directly to the internet without additional hardening.