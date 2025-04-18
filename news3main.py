import re
import subprocess
import concurrent.futures
import shutil
import os
import datetime
from tqdm import tqdm
from rich import print
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn  # Fixed this line

console = Console()

# Show banner
if shutil.which("figlet"):
    os.system('figlet "S3BucketMisconf" | lolcat')
else:
    print("[bold blue]S3BucketMisconf[/bold blue]")

print("[cyan]~ Made by LordofHeaven[/cyan]\n")

input_filename = input("[white][?] Enter the Dork-Eye results file:[/white] ").strip()
validated_output_filename = "validated_buckets.txt"
valid_urls_filename = "valid2.txt"
html_output_filename = "s3_validation_results.html"

print("\n[bold yellow][!] Make sure you have installed dork-eye!\n")

pattern = re.compile(r"https://([a-zA-Z0-9-]+\.)?s3\.amazonaws\.com(/[^/]+)?/")

try:
    with open(input_filename, "r", encoding="utf-8") as file:
        urls = [line.strip() for line in file if pattern.search(line)]
except FileNotFoundError:
    print("[red][!] File not found! Please check the filename and try again.[/red]")
    exit(1)

if not urls:
    print("[red][!] No valid S3 URLs found in the file![red]")
    exit(1)

# Deduplicate URLs based on bucket name before scanning
unique_urls = {}
for url in urls:
    match = pattern.search(url)
    if match:
        subdomain = match.group(1)
        next_directory = match.group(2)
        if subdomain:
            bucket_name = subdomain.rstrip('.')
        elif next_directory:
            bucket_name = next_directory.strip('/')
        if bucket_name not in unique_urls:
            unique_urls[bucket_name] = url

urls = list(unique_urls.values())
print(f"\n[bold green][✔] Found {len(urls)} unique S3 bucket URLs after deduplication![bold green]\n")

def check_bucket(url):
    match = pattern.search(url)
    if not match:
        return None, None, url

    subdomain = match.group(1)
    next_directory = match.group(2)

    if subdomain:
        bucket_name = subdomain.rstrip('.')
    elif next_directory:
        bucket_name = next_directory.strip('/')

    full_s3_url = f"https://s3.amazonaws.com/{bucket_name}/"
    command = f"aws s3 ls s3://{bucket_name} --no-sign-request"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        if "AccessDenied" in result.stderr or "NoSuchBucket" in result.stderr:
            return f"[❌] {bucket_name} - [bold red]INVALID[/bold red]", None, full_s3_url
        else:
            return f"[✅] {bucket_name} - [bold green]VALID[/bold green]\n{result.stdout}", url, full_s3_url
    except subprocess.TimeoutExpired:
        return f"[❌] {bucket_name} - [bold red]TIMEOUT[/bold red]", None, full_s3_url
    except Exception as e:
        return f"[❌] {bucket_name} - [bold red]ERROR[/bold red]\n{str(e)}", None, full_s3_url

print("\n[bold cyan][*] Validating Buckets...[bold cyan]\n")

validated_results = []
valid_urls = []

with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    transient=True
) as progress:
    task = progress.add_task("[bold green]Scanning S3 Buckets...[bold green]", total=len(urls))

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_bucket, url) for url in urls]

        for future in concurrent.futures.as_completed(futures):
            progress.update(task, advance=1)
            result, valid_url, full_url = future.result()
            if result:
                console.print(result)
                validated_results.append((result, bool(valid_url), full_url))
            if valid_url:
                valid_urls.append(valid_url)

with open(validated_output_filename, "w", encoding="utf-8") as output_file:
    output_file.write("\n".join([r[0] for r in validated_results]) + "\n")

with open(valid_urls_filename, "w", encoding="utf-8") as valid_file:
    valid_file.write("\n".join(valid_urls) + "\n")

html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>S3BucketMisconf Results - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: linear-gradient(135deg, #1a1a1a, #2a2a2a); color: #fff; padding: 20px; }}
        h1 {{ text-align: center; color: #00ffcc; text-shadow: 0 0 10px #00ffcc; }}
        table {{ width: 90%; margin: 20px auto; border-collapse: collapse; box-shadow: 0 0 20px rgba(0,255,204,0.2); }}
        th, td {{ padding: 15px; border: 1px solid #444; text-align: left; }}
        th {{ background: #333; color: #00ffcc; text-transform: uppercase; }}
        .valid {{ background: rgba(0,255,0,0.1); color: #00ff00; transition: all 0.3s; }}
        .valid:hover {{ background: rgba(0,255,0,0.2); }}
        .invalid {{ background: rgba(255,0,0,0.1); color: #ff3333; }}
        .footer {{ text-align: center; color: #00ffcc; font-style: italic; }}
        .footer a {{ color: #00ffcc; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>S3 Bucket Validation Results</h1>
    <table>
        <tr><th>Bucket URL</th><th>Status</th><th>Details</th></tr>
"""

for result, status, full_url in validated_results:
    details = " - ".join(result.split(" - ")[1:]) if " - " in result else ""
    status_text = "VALID" if status else "Access denied or not accessible"
    row_class = "valid" if status else "invalid"
    html_content += f"""<tr class="{row_class}"><td>{full_url}</td><td>{status_text}</td><td>{details.replace('\n', '<br>')}</td></tr>"""

html_content += """
    </table>
    <div class="footer">Crafted with 💖 by <a href="https://github.com/Atharv834/S3BucketMisconf" target="_blank">LordofHeaven</a></div>
</body></html>
"""

with open(html_output_filename, "w", encoding="utf-8") as html_file:
    html_file.write(html_content)

print(f"\n[bold green][✔] HTML results saved to {html_output_filename}[bold green]")
