import re

RULES = [
    {
        "id": "xss-1",
        "name": "XSS Script Tag",
        "pattern": re.compile(r"<script.*?>", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "xss-2",
        "name": "XSS Event Handler",
        "pattern": re.compile(r"on\w+\s*=", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "xss-3",
        "name": "XSS Javascript URI",
        "pattern": re.compile(r"javascript\s*:", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "sqli-1",
        "name": "SQLi OR Tautology",
        "pattern": re.compile(r"(\bor\b|\band\b)\s+\d+=\d+", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "sqli-2",
        "name": "SQLi Comment Sequence",
        "pattern": re.compile(r"(--|#|\/\*)", re.IGNORECASE),
        "severity": "medium",
    },
    {
        "id": "sqli-3",
        "name": "SQLi UNION SELECT",
        "pattern": re.compile(r"\bunion\b.+\bselect\b", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "sqli-4",
        "name": "SQLi DROP TABLE",
        "pattern": re.compile(r"\bdrop\b.+\btable\b", re.IGNORECASE),
        "severity": "high",
    },
    {
        "id": "traversal-1",
        "name": "Path Traversal",
        "pattern": re.compile(r"\.\./|\.\.\\"),
        "severity": "high",
    },
    {
        "id": "shell-1",
        "name": "Shell Injection",
        "pattern": re.compile(r"(;|\|)\s*(ls|cat|wget|curl|bash|sh|nc)\b", re.IGNORECASE),
        "severity": "high",
    },
]


def inspect(text: str) -> list:
    return [
        {"id": rule["id"], "name": rule["name"], "severity": rule["severity"]}
        for rule in RULES
        if rule["pattern"].search(text)
    ]