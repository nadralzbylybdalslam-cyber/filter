from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import requests
import dns.resolver
import socket
import ssl
import re
import ipaddress
import sqlite3
import time

from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone


# =========================================================
# FILTER SECURITY SCANNER
# =========================================================

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["60 per minute"]
)

DB_FILE = "filter.db"

USER_AGENT = "Filter-SecurityScanner/3.0"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# HELPERS
# =========================================================

def normalize_phone(phone):
    return re.sub(r"\D", "", phone)


def valid_domain(domain):
    domain = domain.strip().lower().rstrip(".")

    if len(domain) > 253:
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(re.match(pattern, domain))


def dns_records(domain, record_type):
    values = []

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        for answer in answers:
            values.append(str(answer))

    except Exception:
        pass

    return values


def resolve_public_ips(hostname):
    ips = set()

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for result in results:
            ip = result[4][0]

            try:
                addr = ipaddress.ip_address(ip)

                if (
                    addr.is_private
                    or addr.is_loopback
                    or addr.is_link_local
                    or addr.is_reserved
                    or addr.is_multicast
                    or addr.is_unspecified
                ):
                    continue

                ips.add(ip)

            except ValueError:
                continue

    except Exception:
        pass

    return sorted(ips)


def safe_target(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, "يسمح فقط بروابط HTTP و HTTPS"

    hostname = parsed.hostname

    if not hostname:
        return False, "اسم النطاق غير صالح"

    hostname = hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback"
    }

    if hostname in blocked_names:
        return False, "العناوين المحلية غير مسموحة"

    try:
        addr = ipaddress.ip_address(hostname)

        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False, "العناوين الداخلية غير مسموحة"

        return True, None

    except ValueError:
        pass

    ips = resolve_public_ips(hostname)

    if not ips:
        return False, "النطاق لا يشير إلى IP عام"

    return True, None


# =========================================================
# URL RISK ASSESSMENT
# =========================================================

def calculate_url_verdict(
    status_code,
    https,
    tls_ok,
    missing_headers,
    redirect_count,
    certificate_error=False
):

    score = 50
    reasons = []

    if https:
        score += 20
    else:
        score -= 20
        reasons.append("الرابط لا يستخدم HTTPS")

    if tls_ok:
        score += 20
    elif https:
        score -= 25
        reasons.append("تعذر التحقق من اتصال TLS")

    if status_code:

        if 200 <= status_code < 400:
            score += 15

        elif status_code >= 400:
            score -= 10
            reasons.append(
                f"الخادم أعاد HTTP {status_code}"
            )

    if missing_headers:
        score -= min(
            len(missing_headers) * 3,
            15
        )

        reasons.append(
            f"ترويسات حماية غير موجودة: {len(missing_headers)}"
        )

    if redirect_count >= 3:
        score -= 10
        reasons.append("عدد التحويلات مرتفع")

    if certificate_error:
        score -= 30
        reasons.append("مشكلة في شهادة TLS")

    score = max(0, min(100, score))

    if score >= 75:
        verdict = "منخفض الخطورة"

    elif score >= 50:
        verdict = "يحتاج مراجعة"

    elif score >= 25:
        verdict = "مؤشرات خطورة"

    else:
        verdict = "غير حاسم"

    if not reasons:
        reasons.append(
            "لم تظهر مؤشرات تقنية واضحة ضمن الفحوصات الحالية"
        )

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons
    }


# =========================================================
# WEB PAGE
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


# =========================================================
# HEALTH
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({
        "name": "فِلتر",
        "english_name": "Filter",
        "version": "3.0",
        "status": "online",
        "time": datetime.now(timezone.utc).isoformat()
    })


# =========================================================
# PHONE
# =========================================================

@app.route("/api/phone")
@limiter.limit("20 per minute")
def check_phone():

    phone = request.args.get("q", "").strip()

    if not phone:
        return jsonify({
            "error": "أدخل رقم الهاتف"
        }), 400

    clean = normalize_phone(phone)

    if not re.fullmatch(r"[0-9]{7,15}", clean):
        return jsonify({
            "error": "صيغة الرقم غير صحيحة"
        }), 400

    result = {
        "input": phone,
        "normalized": clean,
        "country": "غير معروف",
        "type": "unknown",
        "prefix": None,
        "operator_hint": "غير معروف",
        "contact": None,
        "privacy": (
            "لا يتم كشف هوية صاحب الرقم. "
            "الاسم يظهر فقط إذا كان الرقم موجوداً في دفتر الأرقام الخاص بك."
        )
    }

    # Saudi international format
    if clean.startswith("966") and len(clean) == 12:

        result["country"] = "المملكة العربية السعودية"

        if clean[3] == "5":

            result["type"] = "جوال"
            result["prefix"] = clean[3:5]

            prefix = clean[3:5]

            if prefix in ["50", "53", "55"]:
                result["operator_hint"] = "STC — نطاق متوقع"

            elif prefix in ["54", "56"]:
                result["operator_hint"] = "Mobily — نطاق متوقع"

            elif prefix in ["58", "59"]:
                result["operator_hint"] = "Zain — نطاق متوقع"

            else:
                result["operator_hint"] = "نطاق جوال سعودي"

    # Saudi local format
    elif clean.startswith("05") and len(clean) == 10:

        result["country"] = "المملكة العربية السعودية"
        result["type"] = "جوال"
        result["prefix"] = clean[1:3]

        prefix = clean[1:3]

        if prefix in ["50", "53", "55"]:
            result["operator_hint"] = "STC — نطاق متوقع"

        elif prefix in ["54", "56"]:
            result["operator_hint"] = "Mobily — نطاق متوقع"

        elif prefix in ["58", "59"]:
            result["operator_hint"] = "Zain — نطاق متوقع"

        else:
            result["operator_hint"] = "نطاق جوال سعودي"

    # Private contact database
    conn = get_db()

    row = conn.execute(
        """
        SELECT name, note
        FROM contacts
        WHERE phone = ?
        """,
        (clean,)
    ).fetchone()

    conn.close()

    if row:

        result["contact"] = {
            "name": row["name"],
            "note": row["note"]
        }

    return jsonify(result)


# =========================================================
# CONTACTS
# =========================================================

@app.route("/api/contacts", methods=["POST"])
@limiter.limit("20 per minute")
def add_contact():

    data = request.get_json(silent=True) or {}

    phone = normalize_phone(
        str(data.get("phone", ""))
    )

    name = str(
        data.get("name", "")
    ).strip()

    note = str(
        data.get("note", "")
    ).strip()

    if not phone or not name:
        return jsonify({
            "error": "الرقم والاسم مطلوبان"
        }), 400

    if not re.fullmatch(
        r"[0-9]{7,15}",
        phone
    ):
        return jsonify({
            "error": "رقم الهاتف غير صالح"
        }), 400

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO contacts
            (phone, name, note, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                phone,
                name,
                note,
                datetime.now(
                    timezone.utc
                ).isoformat()
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error": "الرقم موجود مسبقاً"
        }), 409

    conn.close()

    return jsonify({
        "success": True,
        "message": "تمت إضافة جهة الاتصال"
    })


@app.route("/api/contacts")
@limiter.limit("20 per minute")
def list_contacts():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT id, phone, name, note, created_at
        FROM contacts
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return jsonify({
        "contacts": [
            dict(row)
            for row in rows
        ]
    })


@app.route("/api/contacts/<int:contact_id>", methods=["DELETE"])
@limiter.limit("20 per minute")
def delete_contact(contact_id):

    conn = get_db()

    cursor = conn.execute(
        """
        DELETE FROM contacts
        WHERE id = ?
        """,
        (contact_id,)
    )

    conn.commit()
    conn.close()

    if cursor.rowcount == 0:

        return jsonify({
            "error": "جهة الاتصال غير موجودة"
        }), 404

    return jsonify({
        "success": True
    })


# =========================================================
# EMAIL
# =========================================================

@app.route("/api/email")
@limiter.limit("20 per minute")
def check_email():

    email = request.args.get(
        "q",
        ""
    ).strip().lower()

    pattern = (
        r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
    )

    if not re.fullmatch(
        pattern,
        email
    ):
        return jsonify({
            "error": "البريد الإلكتروني غير صالح"
        }), 400

    domain = email.split("@", 1)[1]

    a = dns_records(domain, "A")
    aaaa = dns_records(domain, "AAAA")
    mx = dns_records(domain, "MX")
    ns = dns_records(domain, "NS")
    txt = dns_records(domain, "TXT")

    spf = [
        record
        for record in txt
        if "v=spf1" in record.lower()
    ]

    dmarc = dns_records(
        "_dmarc." + domain,
        "TXT"
    )

    return jsonify({

        "email": email,

        "domain": domain,

        "dns": {
            "A": a,
            "AAAA": aaaa,
            "MX": mx,
            "NS": ns,
            "TXT": txt
        },

        "email_security": {

            "SPF": {
                "present": bool(spf),
                "records": spf
            },

            "DMARC": {
                "present": bool(dmarc),
                "records": dmarc
            },

            "DKIM": {
                "status": "غير محدد",
                "note": "يتطلب معرفة DKIM selector"
            }
        },

        "summary": {

            "domain_resolves":
                bool(a or aaaa),

            "mail_server_exists":
                bool(mx),

            "spf_present":
                bool(spf),

            "dmarc_present":
                bool(dmarc)
        }
    })


# =========================================================
# DNS
# =========================================================

@app.route("/api/dns")
@limiter.limit("30 per minute")
def check_dns():

    domain = request.args.get(
        "q",
        ""
    ).strip().lower()

    if not valid_domain(domain):

        return jsonify({
            "error": "اسم النطاق غير صالح"
        }), 400

    records = {}

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "CAA"
    ]:

        records[record_type] = dns_records(
            domain,
            record_type
        )

    return jsonify({

        "domain": domain,

        "records": records,

        "status":
            "active"
            if any(records.values())
            else "not_found"
    })


# =========================================================
# URL
# =========================================================

@app.route("/api/url")
@limiter.limit("15 per minute")
def check_url():

    target = request.args.get(
        "q",
        ""
    ).strip()

    if not target:

        return jsonify({
            "error": "الرابط مطلوب"
        }), 400

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    allowed, reason = safe_target(target)

    if not allowed:

        return jsonify({
            "error": reason
        }), 400

    parsed = urlparse(target)

    hostname = parsed.hostname

    start = time.perf_counter()

    try:

        response = requests.get(
            target,
            headers={
                "User-Agent": USER_AGENT
            },
            timeout=(5, 8),
            allow_redirects=False,
            stream=True
        )

        elapsed = round(
            (
                time.perf_counter()
                - start
            ) * 1000,
            2
        )

        headers = dict(
            response.headers
        )

        security_headers = {}

        for header in SECURITY_HEADERS:

            security_headers[header] = (
                headers.get(header)
            )

        missing_headers = [
            header
            for header, value
            in security_headers.items()
            if not value
        ]

        redirect_count = 0
        redirect_location = None

        if response.is_redirect:

            location = headers.get(
                "Location"
            )

            if location:

                next_url = urljoin(
                    target,
                    location
                )

                next_allowed, next_reason = (
                    safe_target(next_url)
                )

                if next_allowed:

                    redirect_location = next_url
                    redirect_count = 1

                else:

                    redirect_location = {
                        "blocked": True,
                        "reason": next_reason
                    }

        https = (
            parsed.scheme == "https"
        )

        tls_ok = False

        if https:

            try:

                context = (
                    ssl.create_default_context()
                )

                with socket.create_connection(
                    (hostname, 443),
                    timeout=5
                ) as sock:

                    with context.wrap_socket(
                        sock,
                        server_hostname=hostname
                    ):

                        tls_ok = True

            except Exception:

                tls_ok = False

        assessment = calculate_url_verdict(
            status_code=response.status_code,
            https=https,
            tls_ok=tls_ok,
            missing_headers=missing_headers,
            redirect_count=redirect_count
        )

        result = {

            "url": target,

            "domain": hostname,

            "status_code":
                response.status_code,

            "response_time_ms":
                elapsed,

            "https":
                https,

            "tls": {
                "valid_connection":
                    tls_ok
            },

            "server":
                headers.get("Server"),

            "content_type":
                headers.get("Content-Type"),

            "content_length":
                headers.get("Content-Length"),

            "security_headers":
                security_headers,

            "missing_security_headers":
                missing_headers,

            "redirect":
                redirect_location,

            "assessment":
                assessment,

            "disclaimer":
                "التقييم تقني وليس ضماناً مطلقاً بأن الموقع آمن أو ضار."
        }

        response.close()

        return jsonify(result)

    except requests.exceptions.SSLError:

        return jsonify({

            "url": target,

            "assessment": {
                "verdict":
                    "مؤشرات خطورة",

                "score": 20,

                "reasons": [
                    "فشل اتصال TLS/SSL"
                ]
            },

            "error":
                "فشل اتصال TLS/SSL"

        }), 502

    except requests.exceptions.Timeout:

        return jsonify({

            "url": target,

            "assessment": {
                "verdict":
                    "غير حاسم",

                "score": 0,

                "reasons": [
                    "انتهت مهلة الاتصال"
                ]
            },

            "error":
                "انتهت مهلة الاتصال"

        }), 504

    except requests.exceptions.RequestException as e:

        return jsonify({

            "url": target,

            "assessment": {
                "verdict":
                    "غير حاسم",

                "score": 0,

                "reasons": [
                    "تعذر الاتصال بالموقع"
                ]
            },

            "error":
                "فشل الاتصال"

        }), 502


# =========================================================
# TLS
# =========================================================

@app.route("/api/tls")
@limiter.limit("15 per minute")
def check_tls():

    domain = request.args.get(
        "q",
        ""
    ).strip().lower()

    if not valid_domain(domain):

        return jsonify({
            "error": "النطاق غير صالح"
        }), 400

    ips = resolve_public_ips(domain)

    if not ips:

        return jsonify({
            "error":
                "النطاق لا يحل إلى IP عام"
        }), 400

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, 443),
            timeout=7
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as tls:

                cert = tls.getpeercert()

                issuer = dict(
                    x[0]
                    for x in cert.get(
                        "issuer",
                        []
                    )
                )

                subject = dict(
                    x[0]
                    for x in cert.get(
                        "subject",
                        []
                    )
                )

                cipher = tls.cipher()

                return jsonify({

                    "domain":
                        domain,

                    "ip":
                        ips[0],

                    "tls_version":
                        tls.version(),

                    "cipher":
                        cipher[0]
                        if cipher
                        else None,

                    "certificate": {

                        "subject":
                            subject,

                        "issuer":
                            issuer,

                        "valid_from":
                            cert.get(
                                "notBefore"
                            ),

                        "valid_until":
                            cert.get(
                                "notAfter"
                            ),

                        "serial_number":
                            cert.get(
                                "serialNumber"
                            ),

                        "san": [
                            item[1]
                            for item in
                            cert.get(
                                "subjectAltName",
                                []
                            )
                            if item[0] == "DNS"
                        ]
                    }
                })

    except Exception as e:

        return jsonify({

            "domain":
                domain,

            "error":
                "فشل فحص شهادة TLS",

            "details":
                str(e)

        }), 502


# =========================================================
# FULL SCAN
# =========================================================

@app.route("/api/scan")
@limiter.limit("5 per minute")
def full_scan():

    domain = request.args.get(
        "q",
        ""
    ).strip().lower()

    if not valid_domain(domain):

        return jsonify({
            "error": "النطاق غير صالح"
        }), 400

    ips = resolve_public_ips(domain)

    dns_result = {}

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CAA"
    ]:

        dns_result[record_type] = (
            dns_records(
                domain,
                record_type
            )
        )

    txt = dns_result["TXT"]

    spf = [
        x
        for x in txt
        if "v=spf1" in x.lower()
    ]

    dmarc = dns_records(
        "_dmarc." + domain,
        "TXT"
    )

    return jsonify({

        "name": "فِلتر",

        "target":
            domain,

        "scan_time":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "network": {
            "public_ips":
                ips
        },

        "dns":
            dns_result,

        "email_security": {

            "spf":
                spf,

            "dmarc":
                dmarc
        },

        "security_summary": {

            "dns_available":
                bool(
                    dns_result["A"]
                    or
                    dns_result["AAAA"]
                ),

            "mx_available":
                bool(
                    dns_result["MX"]
                ),

            "spf_available":
                bool(spf),

            "dmarc_available":
                bool(dmarc),

            "nameservers_available":
                bool(
                    dns_result["NS"]
                )
        }
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(429)
def rate_limit_error(error):

    return jsonify({
        "error":
            "تم تجاوز عدد الطلبات المسموح بها",
        "message":
            "انتظر قليلاً ثم حاول مرة أخرى."
    }), 429


@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "error":
            "المسار غير موجود"
    }), 404


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    init_db()

    print("")
    print("======================================")
    print("        فِلتر | FILTER")
    print("     Security Scanner v3.0")
    print("======================================")
    print("فتح المنصة:")
    print("http://127.0.0.1:5000")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )