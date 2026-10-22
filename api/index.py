"""
api/index.py - Vercel Serverless Function entry point
Provides full DoH, RevenueCat & Firebase Remote Config mock API,
Locket Auth Proxy, and dynamic .mobileconfig generation on Vercel.
"""

import os
import sys
import json
import base64
import socket
import datetime
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler

# Add root directory to sys.path so it can import certs
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import certs

TARGET_SPOOF_DOMAINS = [
    "api.revenuecat.com",
    "firebaseremoteconfig.googleapis.com"
]


def extract_jwt_uid(token):
    try:
        parts = (token or "").split(".")
        if len(parts) >= 2:
            p = parts[1]
            pad = len(p) % 4
            if pad:
                p += "=" * (4 - pad)
            payload = json.loads(base64.urlsafe_b64decode(p.encode("ascii")))
            return payload.get("user_id") or payload.get("sub")
    except Exception:
        pass
    return None


def parse_dns_query_name(packet):
    if len(packet) < 12:
        return ""
    pos = 12
    labels = []
    while pos < len(packet):
        length = packet[pos]
        if length == 0:
            break
        pos += 1
        labels.append(packet[pos:pos + length].decode("ascii", errors="ignore"))
        pos += length
    return ".".join(labels).lower()


def build_spoofed_dns_response(query_packet, spoof_ip="127.0.0.1"):
    tx_id = query_packet[:2]
    flags = b"\x81\x80"
    qdcount = query_packet[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    pos = 12
    while pos < len(query_packet):
        l = query_packet[pos]
        if l == 0:
            pos += 5
            break
        pos += 1 + l
    question = query_packet[12:pos]

    answer = (
        b"\xc0\x0c"
        b"\x00\x01"
        b"\x00\x01"
        b"\x00\x00\x00\x3c"
        b"\x00\x04" + socket.inet_aton(spoof_ip)
    )
    return tx_id + flags + qdcount + ancount + nscount + arcount + question + answer


def forward_dns_upstream(query_packet, upstream_ip="1.1.1.1", upstream_port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        s.sendto(query_packet, (upstream_ip, upstream_port))
        resp, _ = s.recvfrom(4096)
        return resp
    except Exception:
        return None
    finally:
        s.close()


def handle_doh_packet(query_packet, host_ip="127.0.0.1"):
    qname = parse_dns_query_name(query_packet)
    for target in TARGET_SPOOF_DOMAINS:
        if qname == target or qname.endswith("." + target):
            return build_spoofed_dns_response(query_packet, host_ip)
    upstream = forward_dns_upstream(query_packet)
    if upstream:
        return upstream
    return build_spoofed_dns_response(query_packet, "0.0.0.0")


def build_mobileconfig_xml(username, token, base_url, ca_der_b64):
    display_tag = username or token or "VIP"
    doh_url = f"{base_url.rstrip('/')}/dns-query/{token or 'vip'}"

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Locket Gold VIP (@{display_tag})</string>
    <key>PayloadDescription</key>
    <string>Cau hinh Locket Gold VIP (Vinh vien 2099) - @{display_tag}</string>
    <key>PayloadIdentifier</key>
    <string>com.locketgold.profile.{token or 'vip'}</string>
    <key>PayloadOrganization</key>
    <string>Locket Gold VIP</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>9ddc879a-abb8-4bdb-9984-c53a273581e8</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.locketgold.rootca</string>
            <key>PayloadUUID</key>
            <string>bb0640e5-040b-4ecc-9f5c-53157883582a</string>
            <key>PayloadDisplayName</key>
            <string>Locket Gold Root CA</string>
            <key>PayloadDescription</key>
            <string>Chung chi goc Locket Gold Root CA</string>
            <key>PayloadContent</key>
            <data>{ca_der_b64}</data>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.locketgold.dns</string>
            <key>PayloadUUID</key>
            <string>2504b094-3aad-4998-a308-a23e7db9ffa4</string>
            <key>PayloadDisplayName</key>
            <string>Locket Gold VIP DNS</string>
            <key>PayloadDescription</key>
            <string>DNS-over-HTTPS Locket Gold VIP</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>{doh_url}</string>
                <key>SupplementalMatchDomains</key>
                <array>
                    <string>api.revenuecat.com</string>
                    <string>firebaseremoteconfig.googleapis.com</string>
                </array>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""


def get_revenuecat_gold_response(app_user_id="anonymous"):
    return {
        "request_date": "2026-10-23T00:00:00Z",
        "request_date_ms": 1792713600000,
        "subscriber": {
            "entitlements": {
                "Gold": {
                    "expires_date": "2099-12-31T23:59:59Z",
                    "grace_period_expires_date": None,
                    "product_identifier": "locket_gold_yearly_2099",
                    "purchase_date": "2024-01-01T00:00:00Z"
                },
                "gold": {
                    "expires_date": "2099-12-31T23:59:59Z",
                    "grace_period_expires_date": None,
                    "product_identifier": "locket_gold_yearly_2099",
                    "purchase_date": "2024-01-01T00:00:00Z"
                },
                "pro": {
                    "expires_date": "2099-12-31T23:59:59Z",
                    "grace_period_expires_date": None,
                    "product_identifier": "locket_gold_yearly_2099",
                    "purchase_date": "2024-01-01T00:00:00Z"
                }
            },
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2026-10-23T00:00:00Z",
            "management_url": "https://apps.apple.com/account/subscriptions",
            "non_subscriptions": {},
            "original_app_user_id": app_user_id,
            "original_application_version": "1.0",
            "original_purchase_date": "2024-01-01T00:00:00Z",
            "other_purchases": {},
            "subscriptions": {
                "locket_gold_yearly_2099": {
                    "auto_resume_date": None,
                    "billing_issues_detected_at": None,
                    "expires_date": "2099-12-31T23:59:59Z",
                    "grace_period_expires_date": None,
                    "is_sandbox": False,
                    "original_purchase_date": "2024-01-01T00:00:00Z",
                    "ownership_type": "PURCHASED",
                    "period_type": "normal",
                    "purchase_date": "2024-01-01T00:00:00Z",
                    "refunded_at": None,
                    "store": "app_store",
                    "store_transaction_id": "1000000000000000",
                    "unsubscribe_detected_at": None
                }
            }
        }
    }


def get_firebase_remote_config_response():
    return {
        "entries": {
            "is_gold_enabled": "true",
            "gold_video_length_seconds": "90",
            "max_video_size_mb": "100",
            "gold_themes_enabled": "true",
            "gold_captions_enabled": "true",
            "can_change_app_icon": "true"
        },
        "state": "UPDATE"
    }


class handler(BaseHTTPRequestHandler):

    def end_cors_headers(self, content_type="application/json"):
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_cors_headers("text/plain")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        host = (self.headers.get("Host") or "").lower()

        # DoH endpoint
        if path.startswith("/dns-query"):
            dns_b64 = query.get("dns", [""])[0]
            if dns_b64:
                pad = len(dns_b64) % 4
                if pad:
                    dns_b64 += "=" * (4 - pad)
                query_packet = base64.urlsafe_b64decode(dns_b64)
                dns_resp = handle_doh_packet(query_packet, "127.0.0.1")
                self.send_response(200)
                self.end_cors_headers("application/dns-message")
                self.wfile.write(dns_resp)
                return

        # RevenueCat Subscriber Mock
        if "revenuecat" in host or path.startswith("/v1/subscribers"):
            user_id = path.split("/")[-1] or "anonymous"
            resp_data = get_revenuecat_gold_response(user_id)
            self.send_response(200)
            self.end_cors_headers("application/json")
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        # Firebase Remote Config Mock
        if "firebaseremoteconfig" in host or "firebase:fetch" in path:
            resp_data = get_firebase_remote_config_response()
            self.send_response(200)
            self.end_cors_headers("application/json")
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        # MobileConfig Profile generator
        if path == "/locket_gold.mobileconfig":
            token = query.get("token", ["vip"])[0]
            username = query.get("username", ["VIP"])[0]
            base_url = f"https://{self.headers.get('Host') or 'locket-gold.vercel.app'}"
            ca_b64 = certs.get_ca_der_base64()
            xml = build_mobileconfig_xml(username, token, base_url, ca_b64)

            self.send_response(200)
            self.send_header("Content-Type", "application/x-apple-aspen-config")
            self.send_header("Content-Disposition", f'attachment; filename="LocketGold_{username}.mobileconfig"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(xml.encode("utf-8"))
            return

        # API /api/users
        if path == "/api/users":
            status_file = os.path.join(ROOT_DIR, "status.json")
            data = {"ok": True, "users": []}
            if os.path.exists(status_file):
                try:
                    with open(status_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass
            self.send_response(200)
            self.end_cors_headers("application/json")
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
            return

        self.send_response(404)
        self.end_cors_headers("text/plain")
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        host = (self.headers.get("Host") or "").lower()
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""

        # DoH POST
        if path.startswith("/dns-query"):
            dns_resp = handle_doh_packet(body, "127.0.0.1")
            self.send_response(200)
            self.end_cors_headers("application/dns-message")
            self.wfile.write(dns_resp)
            return

        # RevenueCat Subscriber Receipt Mock
        if "revenuecat" in host or path.startswith("/v1/subscribers") or "receipts" in path:
            resp_data = get_revenuecat_gold_response("app_store_verified")
            self.send_response(200)
            self.end_cors_headers("application/json")
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        # Firebase Remote Config Mock
        if "firebaseremoteconfig" in host or "firebase:fetch" in path:
            resp_data = get_firebase_remote_config_response()
            self.send_response(200)
            self.end_cors_headers("application/json")
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        # /api/locket/login Proxy
        if path == "/api/locket/login":
            try:
                payload = json.loads(body.decode("utf-8"))
                identifier = payload.get("identifier", "").strip()
                password = payload.get("password", "").strip()
                refresh_token = payload.get("refresh_token", "").strip()

                FIREBASE_API_KEY = "AIzaSyCQngaaXQIfJaH0aS2l7REgIjD7nL431So"
                ios_headers = {
                    "Content-Type": "application/json",
                    "X-Ios-Bundle-Identifier": "com.locket.Locket",
                    "User-Agent": "Locket/1.144.0 (iPhone; iOS 17.5.1; Scale/3.00)"
                }

                if refresh_token:
                    ref_url = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"
                    ref_body = json.dumps({"grant_type": "refresh_token", "refresh_token": refresh_token}).encode("utf-8")
                    req = urllib.request.Request(ref_url, data=ref_body, headers=ios_headers)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        d = json.loads(r.read().decode("utf-8"))
                        self.send_response(200)
                        self.end_cors_headers("application/json")
                        self.wfile.write(json.dumps({
                            "ok": True,
                            "id_token": d.get("id_token"),
                            "refresh_token": d.get("refresh_token", refresh_token),
                            "uid": d.get("user_id")
                        }).encode("utf-8"))
                        return

                if "@" in identifier:
                    sign_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
                    sign_body = json.dumps({"email": identifier, "password": password, "returnSecureToken": True}).encode("utf-8")
                    req = urllib.request.Request(sign_url, data=sign_body, headers=ios_headers)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        d = json.loads(r.read().decode("utf-8"))
                        self.send_response(200)
                        self.end_cors_headers("application/json")
                        self.wfile.write(json.dumps({
                            "ok": True,
                            "id_token": d.get("idToken"),
                            "refresh_token": d.get("refreshToken"),
                            "uid": d.get("localId"),
                            "username": identifier.split("@")[0],
                            "full_name": identifier.split("@")[0]
                        }).encode("utf-8"))
                        return
                else:
                    clean_phone = identifier.replace(" ", "").replace("-", "")
                    if clean_phone.startswith("0"):
                        clean_phone = "+84" + clean_phone[1:]
                    phone_req = urllib.request.Request(
                        "https://api.locketcamera.com/signInWithPhonePassword",
                        data=json.dumps({"data": {"phone": clean_phone, "password": password}}).encode("utf-8"),
                        headers={"Content-Type": "application/json"}
                    )
                    with urllib.request.urlopen(phone_req, timeout=10) as pr:
                        pd = json.loads(pr.read().decode("utf-8"))
                        custom_token = pd.get("result", {}).get("token")
                        custom_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={FIREBASE_API_KEY}"
                        custom_body = json.dumps({"token": custom_token, "returnSecureToken": True}).encode("utf-8")
                        req_c = urllib.request.Request(custom_url, data=custom_body, headers=ios_headers)
                        with urllib.request.urlopen(req_c, timeout=10) as cr:
                            cd = json.loads(cr.read().decode("utf-8"))
                            self.send_response(200)
                            self.end_cors_headers("application/json")
                            self.wfile.write(json.dumps({
                                "ok": True,
                                "id_token": cd.get("idToken"),
                                "refresh_token": cd.get("refreshToken"),
                                "uid": cd.get("localId")
                            }).encode("utf-8"))
                            return
            except Exception as e:
                self.send_response(400)
                self.end_cors_headers("application/json")
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))
                return

        # /api/locket/upload-storage
        if path == "/api/locket/upload-storage":
            try:
                parsed_query = urllib.parse.parse_qs(parsed.query)
                bucket = parsed_query.get("bucket", ["locket-img"])[0]
                raw_name = parsed_query.get("name", [""])[0]
                id_token = self.headers.get("X-Locket-Token") or ""
                upload_mime = self.headers.get("X-Upload-Content-Type") or "application/octet-stream"

                token_uid = extract_jwt_uid(id_token)
                target_name = raw_name
                if token_uid:
                    import re
                    target_name = re.sub(r"^users/[^/]+/", f"users/{token_uid}/", raw_name)

                encoded_name = urllib.parse.quote(target_name, safe="")
                gcs_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?name={encoded_name}"
                req = urllib.request.Request(
                    gcs_url,
                    data=body,
                    headers={
                        "Authorization": f"Bearer {id_token}",
                        "Content-Type": upload_mime,
                        "X-Ios-Bundle-Identifier": "com.locket.Locket",
                        "User-Agent": "Locket/1.144.0 (iPhone; iOS 17.5.1; Scale/3.00)"
                    }
                )
                with urllib.request.urlopen(req, timeout=30) as r:
                    gcs_resp = json.loads(r.read().decode("utf-8"))
                    tok = (gcs_resp.get("downloadTokens") or "").split(",")[0]
                    download_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{encoded_name}?alt=media"
                    if tok:
                        download_url += f"&token={tok}"
                    self.send_response(200)
                    self.end_cors_headers("application/json")
                    self.wfile.write(json.dumps({"ok": True, "download_url": download_url}).encode("utf-8"))
                    return
            except Exception as e:
                self.send_response(500)
                self.end_cors_headers("application/json")
                self.wfile.write(json.dumps({"ok": False, "error": f"Lỗi upload: {str(e)}"}).encode("utf-8"))
                return

        # /api/locket/post-moment
        if path == "/api/locket/post-moment":
            try:
                id_token = self.headers.get("X-Locket-Token") or ""
                req = urllib.request.Request(
                    "https://api.locketcamera.com/postMomentV2",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {id_token}",
                        "X-Ios-Bundle-Identifier": "com.locket.Locket",
                        "User-Agent": "Locket/1.144.0 (iPhone; iOS 17.5.1; Scale/3.00)"
                    }
                )
                with urllib.request.urlopen(req, timeout=15) as r:
                    resp_data = r.read()
                    self.send_response(200)
                    self.end_cors_headers("application/json")
                    self.wfile.write(resp_data)
                    return
            except Exception as e:
                self.send_response(500)
                self.end_cors_headers("application/json")
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))
                return

        self.send_response(404)
        self.end_cors_headers("text/plain")
        self.wfile.write(b"404 Not Found")
