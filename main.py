#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from waf.database import init_db
from app import app

load_dotenv()

if __name__ == "__main__":
    init_db()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[*] WAF running on {host}:{port}")
    app.run(host=host, port=port, debug=debug)