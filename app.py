from flask import Flask, jsonify, request
from waf.database import init_db, get_recent_logs
from waf.blocklist import get_blocklist, unblock_ip
from waf.middleware import check_request

app = Flask(__name__)


@app.before_request
def firewall():
    return check_request()


@app.route("/")
def index():
    return jsonify({"status": "ok", "message": "WAF is running"})


@app.route("/logs")
def logs():
    return jsonify(get_recent_logs())


@app.route("/blocklist")
def blocklist():
    return jsonify(get_blocklist())


@app.route("/blocklist/<ip>", methods=["DELETE"])
def remove_block(ip):
    unblock_ip(ip)
    return jsonify({"status": "unblocked", "ip": ip})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)