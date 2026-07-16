#!/usr/bin/env python3
"""
Telegram Pentest Bot — Authorized Web Security Testing
For authorized penetration testing only.
"""

import os
import sys
import re
import json
import asyncio
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from dotenv import load_dotenv
from colorama import init, Fore, Style

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    filters, ContextTypes, CallbackQueryHandler
)

# -------------------- INIT --------------------
load_dotenv()
init(autoreset=True)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("8690012600:AAHMznNth0GhK8GBdDY8PQqyJ0O4odQNMh4")
ADMIN_USER_ID = int(os.getenv("7876578485", "0"))

if not BOT_TOKEN:
    logger.error("BOT_TOKEN not set in .env")
    sys.exit(1)

ua = UserAgent()
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": ua.random})

# -------------------- UTILITY --------------------
def is_url_valid(url: str) -> bool:
    """Basic URL validation and normalization."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return bool(parsed.netloc), url

async def send_typing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show typing indicator."""
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id,
        action="typing"
    )

def build_menu(buttons, n_cols=2):
    """Build inline keyboard menu."""
    menu = [buttons[i:i + n_cols] for i in range(0, len(buttons), n_cols)]
    return InlineKeyboardMarkup(menu)

# -------------------- ADMIN PANEL FINDER --------------------
ADMIN_PATHS = [
    # Common admin paths
    "admin", "administrator", "adminpanel", "admin-area", "admin_area",
    "admin/login", "admin/index.php", "admin/login.php", "admin/admin.php",
    "wp-admin", "wp-login.php", "administrator/index.php",
    "login", "login.php", "login.html", "log-in", "signin",
    "panel", "cpanel", "controlpanel", "control-panel",
    "dashboard", "user/login", "user/login.php",
    "backend", "backoffice", "admin/backup",
    "cp", "moderator", "webadmin", "sysadmin",
    "admin1", "admin2", "admin123",
    "manager", "management", "manager/html",
    "admin/login.asp", "admin/login.aspx", "admin/login.jsp",
    "bb-admin", "acceso", "accesos", "acceso.php",
    "adm", "adm.php", "admon", "admon.php",
    "siteadmin", "site/admin", "site/login",
    "sonata/admin", "secret", "private",
    ".env", ".git/config", "config.php.bak", "config.bak",
    "phpmyadmin", "phpMyAdmin", "pma", "mysql",
    "adminer.php", "adminer", "dbadmin",
]

async def find_admin_panels(url: str) -> list:
    """Brute-force discover admin panels on the target."""
    is_valid, normalized_url = is_url_valid(url)
    if not is_valid:
        return [("❌ Invalid URL", url)]

    parsed = urlparse(normalized_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    found = []

    logger.info(f"[Admin Finder] Scanning {base}")

    async def check_path(path):
        target_url = f"{base}/{path}"
        try:
            resp = await asyncio.to_thread(
                SESSION.get, target_url,
                timeout=5, allow_redirects=True
            )
            if resp.status_code in [200, 201, 202, 204, 301, 302, 303, 307, 308]:
                # Check if it actually looks like a login/admin page
                content = resp.text.lower()
                admin_keywords = [
                    "login", "password", "username", "admin", "sign in",
                    "signin", "log in", "dashboard", "control panel",
                    "administrator", "user name", "passwd"
                ]
                has_keywords = any(kw in content for kw in admin_keywords)
                # Always return 200 pages, flag keyword matches
                if resp.status_code == 200:
                    if has_keywords or len(content) > 500:
                        return (target_url, resp.status_code, "✅" if has_keywords else "ℹ️")
                else:  # Redirects often lead to login
                    return (target_url, resp.status_code, "🔀")
        except:
            pass
        return None

    # Check in batches to avoid overwhelming
    batch_size = 15
    for i in range(0, len(ADMIN_PATHS), batch_size):
        batch = ADMIN_PATHS[i:i + batch_size]
        tasks = [check_path(p) for p in batch]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)

    return found

# -------------------- SQLI SCANNER (Basic) --------------------
SQLI_PAYLOADS = [
    "'", "\"", "')", "\")", "';", "\";",
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
    "' AND SLEEP(5)--", "' AND 1=1--", "' AND 1=2--",
    "1' ORDER BY 1--", "1' ORDER BY 10--",
]

SQLI_ERRORS = [
    "sql", "mysql", "syntax error", "unclosed quotation mark",
    "you have an error in your sql", "warning: mysql",
    "odbc", "driver", "db2", "postgresql", "sqlite",
    "ora-", "oracle", "microsoft ole db",
]

async def scan_sqli(url: str) -> list:
    """Basic SQL injection detection via error-based and boolean techniques."""
    is_valid, normalized_url = is_url_valid(url)
    if not is_valid:
        return [("❌ Invalid URL", url)]

    parsed = urlparse(normalized_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parsed.query

    findings = []

    # If URL has query parameters, test them
    if params:
        param_pairs = params.split("&")
        for pair in param_pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                for payload in SQLI_PAYLOADS[:6]:  # Test first few
                    test_url = base + "?" + params.replace(
                        f"{key}={value}",
                        f"{key}={value}{requests.utils.quote(payload)}"
                    )
                    try:
                        resp = await asyncio.to_thread(
                            SESSION.get, test_url, timeout=8
                        )
                        body = resp.text.lower()
                        if any(err in body for err in SQLI_ERRORS):
                            findings.append((test_url, payload, "⚠️ Error-based SQLi detected"))
                            break  # Found for this param, move on
                    except:
                        continue

    # Test forms on the page
    try:
        resp = await asyncio.to_thread(SESSION.get, normalized_url, timeout=8)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            test_data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    test_data[name] = f"test{SQLI_PAYLOADS[0]}"
            if test_data and action:
                form_url = urljoin(normalized_url, action)
                if method == "post":
                    try:
                        resp2 = await asyncio.to_thread(
                            SESSION.post, form_url, data=test_data, timeout=8
                        )
                        body = resp2.text.lower()
                        if any(err in body for err in SQLI_ERRORS):
                            findings.append((form_url, str(test_data), "⚠️ Form-based SQLi detected"))
                    except:
                        pass
    except:
        pass

    return findings

# -------------------- XSS SCANNER --------------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "<ScRiPt>alert(1)</sCrIpT>",
]

async def scan_xss(url: str) -> list:
    """Reflected XSS detection on URL parameters."""
    is_valid, normalized_url = is_url_valid(url)
    if not is_valid:
        return [("❌ Invalid URL", url)]

    parsed = urlparse(normalized_url)
    params = parsed.query
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    findings = []

    if not params:
        return [("ℹ️ No query parameters to test", "")]

    param_pairs = params.split("&")
    for pair in param_pairs:
        if "=" in pair:
            key, value = pair.split("=", 1)
            for payload in XSS_PAYLOADS:
                encoded_payload = requests.utils.quote(payload)
                test_url = base + "?" + params.replace(
                    f"{key}={value}",
                    f"{key}={encoded_payload}"
                )
                try:
                    resp = await asyncio.to_thread(
                        SESSION.get, test_url, timeout=8
                    )
                    if payload in resp.text:
                        findings.append((test_url, payload, "⚠️ Reflected XSS detected"))
                        break
                except:
                    continue

    return findings

# -------------------- SUBDOMAIN ENUMERATION --------------------
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "shop", "api",
    "dev", "test", "staging", "beta", "demo", "app",
    "webmail", "cpanel", "whm", "server", "ns1", "ns2",
    "mx", "smtp", "pop3", "imap", "vpn", "remote",
    "portal", "secure", "ssl", "support", "help", "forum",
    "cdn", "static", "assets", "img", "css", "js",
    "backup", "intranet", "internal", "git", "jenkins",
    "jira", "confluence", "wiki", "dashboard", "adminer",
    "phpmyadmin", "pma", "monitor", "status", "statuspage",
    "cloud", "s3", "bucket", "uploads", "files", "download",
]

async def enumerate_subdomains(domain: str) -> list:
    """Brute-force common subdomains."""
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    found = []

    async def check_sub(sub):
        url = f"https://{sub}.{domain}"
        try:
            resp = await asyncio.to_thread(
                SESSION.get, url, timeout=5, allow_redirects=True
            )
            if resp.status_code < 400 or resp.status_code in [401, 403]:
                ip = ""
                try:
                    import socket
                    ip = socket.gethostbyname(f"{sub}.{domain}")
                except:
                    pass
                return (url, resp.status_code, ip)
        except:
            pass

        # Try HTTP if HTTPS fails
        try:
            url_http = f"http://{sub}.{domain}"
            resp = await asyncio.to_thread(
                SESSION.get, url_http, timeout=3, allow_redirects=True
            )
            if resp.status_code < 400 or resp.status_code in [401, 403]:
                ip = ""
                try:
                    import socket
                    ip = socket.gethostbyname(f"{sub}.{domain}")
                except:
                    pass
                return (url_http, resp.status_code, ip)
        except:
            pass
        return None

    batch_size = 10
    for i in range(0, len(COMMON_SUBDOMAINS), batch_size):
        batch = COMMON_SUBDOMAINS[i:i + batch_size]
        tasks = [check_sub(s) for s in batch]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)

    return found

# -------------------- PORT SCANNER --------------------
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    389, 443, 445, 465, 500, 587, 993, 995, 1433, 1521,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222,
    2375, 2376, 3000, 3128, 3306, 3389, 3690, 4333,
    4444, 4848, 5000, 5432, 5555, 5800, 5900, 5901,
    5984, 5985, 5986, 6379, 7001, 7002, 8000, 8001,
    8008, 8009, 8010, 8080, 8081, 8082, 8088, 8090,
    8181, 8443, 8834, 8888, 9000, 9001, 9042, 9060,
    9080, 9090, 9092, 9100, 9200, 9300, 9418, 10000,
    11211, 27017, 50070, 61616,
]

async def scan_ports(host: str) -> list:
    """TCP port scan using asyncio connection attempts."""
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    open_ports = []

    async def check_port(port):
        try:
            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=2)
            writer.close()
            await writer.wait_closed()
            service = PORT_SERVICES.get(port, "unknown")
            return (port, service)
        except:
            return None

    batch_size = 30
    for i in range(0, len(COMMON_PORTS), batch_size):
        batch = COMMON_PORTS[i:i + batch_size]
        tasks = [check_port(p) for p in batch]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                open_ports.append(r)

    return open_ports

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "SonarQube", 9092: "Kafka", 9200: "Elasticsearch", 27017: "MongoDB",
}

# -------------------- HEADER SCANNER --------------------
async def scan_headers(url: str) -> dict:
    """Analyze security headers."""
    is_valid, normalized_url = is_url_valid(url)
    if not is_valid:
        return {"error": "Invalid URL"}

    try:
        resp = await asyncio.to_thread(SESSION.get, normalized_url, timeout=10)
        headers = dict(resp.headers)
        security_headers = {
            "Strict-Transport-Security": ("HSTS", "high"),
            "Content-Security-Policy": ("CSP", "high"),
            "X-Content-Type-Options": ("XCTO", "medium"),
            "X-Frame-Options": ("XFO", "medium"),
            "X-XSS-Protection": ("X-XSS", "medium"),
            "Referrer-Policy": ("Referrer-Policy", "low"),
            "Permissions-Policy": ("Permissions-Policy", "low"),
        }
        results = {}
        for header, (name, severity) in security_headers.items():
            if header in headers:
                results[name] = f"✅ Present: {headers[header][:50]}"
            else:
                results[name] = f"❌ Missing ({severity})"

        results["Server"] = f"ℹ️ {headers.get('Server', 'Not disclosed')}"
        results["X-Powered-By"] = f"ℹ️ {headers.get('X-Powered-By', 'Not disclosed')}"

        return results
    except Exception as e:
        return {"error": str(e)}

# -------------------- BOT COMMANDS --------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    user = update.effective_user
    msg = (
        f"🔐 *Web Pentest Bot*\n"
        f"Welcome, {user.first_name}!\n\n"
        f"_For authorized penetration testing only._\n\n"
        f"📋 *Available Commands:*\n"
        f"/start — Show this menu\n"
        f"/help — Detailed help\n"
        f"/admin `<url>` — Find admin panels\n"
        f"/sqli `<url>` — Test for SQL injection\n"
        f"/xss `<url>` — Test for reflected XSS\n"
        f"/subs `<domain>` — Enumerate subdomains\n"
        f"/ports `<host>` — Scan common ports\n"
        f"/headers `<url>` — Check security headers\n"
        f"/recon `<url>` — Full recon (all of the above)\n\n"
        f"⚠️ *You must have explicit authorization to test the target.*"
    )
    await update.message.reply_markdown(msg)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    msg = (
        "🛠 *Usage Examples:*\n\n"
        "`/admin https://example.com` — Find admin login pages\n"
        "`/sqli https://example.com/page?id=1` — Test SQLi\n"
        "`/xss https://example.com/search?q=test` — Test XSS\n"
        "`/subs example.com` — Find subdomains\n"
        "`/ports example.com` — Scan open ports\n"
        "`/headers https://example.com` — Check security headers\n"
        "`/recon https://example.com` — Full recon scan\n\n"
        "⚡ Results are sent asynchronously. Large scans may take time."
    )
    await update.message.reply_markdown(msg)

async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Find admin panels."""
    if not context.args:
        await update.message.reply_text("Usage: /admin <url>\nExample: /admin https://example.com")
        return

    url = context.args[0]
    msg = await update.message.reply_text(f"🔍 Scanning for admin panels on {url}...")
    await send_typing(update, context)

    results = await find_admin_panels(url)

    if not results:
        await msg.edit_text(f"✅ No admin panels found on {url}")
        return

    lines = [f"📌 *Admin Panel Results for* `{url}`\n"]
    for target_url, status, indicator in results[:30]:  # Limit to 30
        lines.append(f"{indicator} `{target_url}` (HTTP {status})")

    if len(results) > 30:
        lines.append(f"\n... and {len(results) - 30} more")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_sqli(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan for SQL injection."""
    if not context.args:
        await update.message.reply_text("Usage: /sqli <url>\nExample: /sqli https://example.com/page?id=1")
        return

    url = context.args[0]
    msg = await update.message.reply_text(f"🔍 Testing SQL injection on {url}...")
    await send_typing(update, context)

    results = await scan_sqli(url)

    if not results:
        await msg.edit_text(f"✅ No obvious SQL injection found on {url}")
        return

    lines = [f"⚠️ *SQL Injection Results for* `{url}`\n"]
    for test_url, payload, description in results:
        lines.append(f"- {description}")
        lines.append(f"  Payload: `{payload}`")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_xss(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan for reflected XSS."""
    if not context.args:
        await update.message.reply_text("Usage: /xss <url>\nExample: /xss https://example.com/search?q=test")
        return

    url = context.args[0]
    msg = await update.message.reply_text(f"🔍 Testing XSS on {url}...")
    await send_typing(update, context)

    results = await scan_xss(url)

    if not results:
        await msg.edit_text(f"✅ No reflected XSS found on {url}")
        return

    lines = [f"⚠️ *XSS Results for* `{url}`\n"]
    for test_url, payload, description in results:
        lines.append(f"- {description}")
        lines.append(f"  Payload: `{payload}`")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_subs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enumerate subdomains."""
    if not context.args:
        await update.message.reply_text("Usage: /subs <domain>\nExample: /subs example.com")
        return

    domain = context.args[0]
    msg = await update.message.reply_text(f"🔍 Enumerating subdomains for {domain}...")
    await send_typing(update, context)

    results = await enumerate_subdomains(domain)

    if not results:
        await msg.edit_text(f"✅ No additional subdomains found for {domain}")
        return

    lines = [f"📌 *Subdomains for* `{domain}`\n"]
    for url, status, ip in sorted(results):
        ip_str = f" ({ip})" if ip else ""
        lines.append(f"- `{url}` HTTP {status}{ip_str}")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan ports."""
    if not context.args:
        await update.message.reply_text("Usage: /ports <host>\nExample: /ports example.com")
        return

    host = context.args[0]
    msg = await update.message.reply_text(f"🔍 Scanning ports on {host}...")
    await send_typing(update, context)

    results = await scan_ports(host)

    if not results:
        await msg.edit_text(f"✅ No open ports found on {host} (or host unreachable)")
        return

    lines = [f"📌 *Open Ports for* `{host}`\n"]
    for port, service in sorted(results):
        lines.append(f"- `{port}` — {service}")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_headers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check security headers."""
    if not context.args:
        await update.message.reply_text("Usage: /headers <url>\nExample: /headers https://example.com")
        return

    url = context.args[0]
    msg = await update.message.reply_text(f"🔍 Checking headers on {url}...")
    await send_typing(update, context)

    results = await scan_headers(url)

    if "error" in results:
        await msg.edit_text(f"❌ Error: {results['error']}")
        return

    lines = [f"📌 *Security Headers for* `{url}`\n"]
    for header, status in results.items():
        lines.append(f"- **{header}**: {status}")

    await msg.edit_text("\n".join(lines), parse_mode="Markdown")

async def cmd_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Full recon — run all scans sequentially."""
    if not context.args:
        await update.message.reply_text("Usage: /recon <url>\nExample: /recon https://example.com")
        return

    url = context.args[0]
    msg = await update.message.reply_text("🚀 Starting full reconnaissance... This may take a few minutes.")
    await send_typing(update, context)

    # Extract domain from URL
    parsed = urlparse(url if "://" in url else "https://" + url)
    domain = parsed.netloc

    report_lines = [f"📋 *Full Recon Report* — `{url}`\n"]

    # 1. Headers
    await msg.edit_text("📋 [1/5] Checking security headers...")
    headers = await scan_headers(url)
    report_lines.append("**🔐 Security Headers:**")
    if "error" not in headers:
        for h, s in headers.items():
            report_lines.append(f"  {h}: {s}")
    else:
        report_lines.append(f"  Error: {headers['error']}")
    report_lines.append("")

    # 2. Admin Panels
    await msg.edit_text("📋 [2/5] Scanning admin panels...")
    admin_results = await find_admin_panels(url)
    report_lines.append(f"**🔑 Admin Panels Found: {len(admin_results)}**")
    for target, status, indicator in admin_results[:15]:
        report_lines.append(f"  {indicator} `{target}` (HTTP {status})")
    report_lines.append("")

    # 3. Subdomains
    await msg.edit_text("📋 [3/5] Enumerating subdomains...")
    subs = await enumerate_subdomains(domain)
    report_lines.append(f"**🌐 Subdomains Found: {len(subs)}**")
    for sub_url, status, ip in subs[:15]:
        ip_str = f" ({ip})" if ip else ""
        report_lines.append(f"  - `{sub_url}` HTTP {status}{ip_str}")
    report_lines.append("")

    # 4. Ports
    await msg.edit_text("📋 [4/5] Scanning ports...")
    ports = await scan_ports(domain)
    report_lines.append(f"**🔌 Open Ports: {len(ports)}**")
    for port, service in sorted(ports):
        report_lines.append(f"  - `{port}` — {service}")
    report_lines.append("")

    # 5. SQLi + XSS
    await msg.edit_text("📋 [5/5] Testing for SQLi & XSS...")
    sqli = await scan_sqli(url)
    xss = await scan_xss(url)
    report_lines.append("**⚠️ Vulnerabilities:**")
    if sqli:
        for _, payload, desc in sqli:
            report_lines.append(f"  - {desc}: `{payload}`")
    else:
        report_lines.append("  - SQLi: ✅ No obvious issues")
    if xss:
        for _, payload, desc in xss:
            report_lines.append(f"  - {desc}: `{payload}`")
    else:
        report_lines.append("  - XSS: ✅ No obvious issues")

    # Send report in chunks if too long
    full_report = "\n".join(report_lines)
    if len(full_report) > 4000:
        chunks = [full_report[i:i + 4000] for i in range(0, len(full_report), 4000)]
        for i, chunk in enumerate(chunks):
            if i == 0:
                await msg.edit_text(chunk, parse_mode="Markdown")
            else:
                await update.message.reply_text(chunk, parse_mode="Markdown")
    else:
        await msg.edit_text(full_report, parse_mode="Markdown")

# -------------------- MAIN --------------------
def main():
    """Start the bot."""
    app = Application.builder().token(BOT_TOKEN).build()

    # Register commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CommandHandler("sqli", cmd_sqli))
    app.add_handler(CommandHandler("xss", cmd_xss))
    app.add_handler(CommandHandler("subs", cmd_subs))
    app.add_handler(CommandHandler("ports", cmd_ports))
    app.add_handler(CommandHandler("headers", cmd_headers))
    app.add_handler(CommandHandler("recon", cmd_recon))

    logger.info("🤖 Bot started. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
