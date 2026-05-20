from flask import request, jsonify
from waf.rules import inspect
from waf.blocklist import is_blocked, block_ip, get_violation_count
from waf.database import log_request

BLOCK_THRESHOLD = 5


def check_request():
    ip = request.remote_addr
    method = request.method
    path = request.path
    user_agent = request.headers.get("User-Agent", "")

    try:
        body = request.get_data(as_text=True)
    except Exception:
        body = ""

    if is_blocked(ip):
        log_request(ip, method, path, user_agent, body, True, ["IP blocklisted"])
        return jsonify({"error": "Forbidden", "reason": "IP blocklisted"}), 403

    full_input = f"{path} {body} {request.query_string.decode()}"
    rules_hit = inspect(full_input)

    if rules_hit:
        log_request(ip, method, path, user_agent, body, True, rules_hit)
        violations = get_violation_count(ip)
        if violations >= BLOCK_THRESHOLD:
            block_ip(ip, rules_hit[0]["name"])
        return jsonify({
            "error": "Forbidden",
            "reason": "Request blocked by WAF",
            "rules": [r["name"] for r in rules_hit],
    }), 403

    log_request(ip, method, path, user_agent, body, False, [])
    return None