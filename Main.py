import socket
import ssl
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

app = FastAPI(title="Security Auditor API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    url: str

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

COMMON_PORTS = [21, 22, 80, 443, 8080, 8443]

@app.post("/api/audit")
async def audit_target(data: AuditRequest):
    target_url = data.url
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname or parsed.path

    results = {
        "target": target_url,
        "hostname": hostname,
        "headers_score": 0,
        "headers_analysis": {},
        "open_ports": [],
        "ssl_valid": False
    }

    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
        missing_headers = []
        found_headers = []

        for header in SECURITY_HEADERS:
            if header in response.headers:
                found_headers.append(header)
            else:
                missing_headers.append(header)

        score = int((len(found_headers) / len(SECURITY_HEADERS)) * 100)
        results["headers_score"] = score
        results["headers_analysis"] = {
            "found": found_headers,
            "missing": missing_headers
        }
    except Exception as e:
        results["headers_analysis"] = {"error": f"Failed to reach target: {str(e)}"}

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        res = sock.connect_ex((hostname, port))
        if res == 0:
            results["open_ports"].append(port)
        sock.close()

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(2.0)
            s.connect((hostname, 443))
            results["ssl_valid"] = True
    except Exception:
        results["ssl_valid"] = False

    return results
