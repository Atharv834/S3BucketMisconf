import re
import subprocess
import concurrent.futures
import shutil
import os
import datetime
from rich import print
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from rich.layout import Layout

custom_theme = Theme({
    "info": "bright_cyan",
    "warning": "bright_yellow",
    "success": "bright_green",
    "error": "bright_red",
    "highlight": "bold magenta",
    "title": "bold cyan",
    "subtle": "dim white"
})
console = Console(theme=custom_theme)


def show_banner():
    if shutil.which("figlet") and shutil.which("lolcat"):
        os.system('figlet "S3BucketMisconf" | lolcat -f')
    else:
        console.print(Panel.fit(
            "[highlight]S3BucketMisconf[/highlight]", 
            style="title", 
            border_style="bright_green",
            title="S3 Scanner",
            subtitle="v1.0 by LordofHeaven",
            padding=(1, 5)
        ))


layout = Layout()
layout.split_column(
    Layout(name="header", size=5),
    Layout(name="main"),
    Layout(name="progress", size=3),
    Layout(name="footer", size=3)
)


def update_header():
    with console.capture() as capture:
        show_banner()
    layout["header"].update(capture.get())


def update_footer(message="Ready to scan..."):
    layout["footer"].update(Panel(
        message, 
        style="subtle", 
        border_style="bright_magenta"
    ))


pattern = re.compile(r"(?:http[s]?://)?((?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+)(?:\.?s3(?:[-.](?:external-1|dualstack\.[a-z]{2}-[a-z]+-\d))?\.amazonaws\.com)(?:/.*)?(?:\?.*)?$")


def extract_bucket_info(input_str):
    input_str = str(input_str).strip() 
    match = pattern.search(input_str)
    if not match:
        console.print(f"[warning][!] No S3 pattern match for: {input_str}[/warning]")
        return None, None
    
    bucket_name = match.group(1)  
    bucket_url = f"https://{bucket_name}.s3.amazonaws.com"  
    if bucket_name:
        console.print(f"[info][+] Extracted bucket: {bucket_name} ({bucket_url}) from {input_str}[/info]")
        return bucket_name, bucket_url
    
    console.print(f"[warning][!] No bucket name extracted from: {input_str}[/warning]")
    return None, None


def process_urls_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            lines = [line.strip() for line in file if line.strip()]  
            
        if not lines:
            console.print("[error][!] No URLs found in the file![/error]")
            return []
        

        urls = []
        for line in lines:
            if line.startswith('(') and ',' in line:  
                try:
                    index, url = eval(line)  
                    urls.append(url)
                except Exception as e:
                    console.print(f"[warning][!] Failed to parse tuple {line}: {e}, treating as plain string[/warning]")
                    urls.append(line)
            else:
                urls.append(line)  
        

        bucket_url_map = {}
        for url in sorted(urls):  
            bucket_name, bucket_url = extract_bucket_info(url)
            if bucket_name:
                bucket_url_map[bucket_name] = bucket_url  
        

        unique_buckets = sorted(bucket_url_map.keys())
        console.print(f"[success][✔] Discovered {len(unique_buckets)} unique S3 buckets from {len(urls)} URLs![/success]\n")
        return [(bucket, bucket_url_map[bucket]) for bucket in unique_buckets]
    
    except FileNotFoundError:
        console.print("[error][!] File not found! Check the filename and try again.[/error]")
        return []
    except Exception as e:
        console.print(f"[error][!] Error reading file: {str(e)}[/error]")
        return []


def check_bucket(bucket_url_tuple):
    bucket_name, bucket_url = bucket_url_tuple
    command = f"aws s3 ls s3://{bucket_name} --no-sign-request"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        if "AccessDenied" in result.stderr:
            return f"[❌] {bucket_url} - INVALID (Access Denied)", None
        elif "NoSuchBucket" in result.stderr:
            return f"[❌] {bucket_url} - INVALID (Bucket Not Found)", None
        elif result.stdout:
            return f"[✅] {bucket_url} - VALID\n{result.stdout}", bucket_url
        else:
            return f"[❌] {bucket_url} - INVALID (Empty Response)", None
    except subprocess.TimeoutExpired:
        return f"[❌] {bucket_url} - ERROR (Timeout)", None
    except Exception as e:
        return f"[❌] {bucket_url} - ERROR\n{str(e)}", None

# Main scanning function
def scan_buckets(bucket_list, validated_output_filename="validated_buckets.html", valid_urls_filename="valid_s3_urls.txt"):
    validated_results = []
    valid_urls = []
    table = Table(title="S3 Bucket Validation Results", style="title", border_style="bright_cyan")
    table.add_column("Bucket URL", style="white", no_wrap=False)
    table.add_column("Status", justify="center", style="bold")
    table.add_column("Details", style="subtle", no_wrap=False)
    
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    )
    task = progress.add_task("[highlight]Scanning S3 Buckets...[/highlight]", total=len(bucket_list))

    update_header()
    update_footer("Scanning in progress...")
    layout["main"].update(Panel(table, border_style="bright_blue"))
    layout["progress"].update(progress)
    console.print(layout)

    with progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(check_bucket, bucket_url): bucket_url for bucket_url in bucket_list}
            for future in concurrent.futures.as_completed(futures):
                progress.update(task, advance=1)
                result, valid_url = future.result()
                if result:
                    status = "VALID" if "[✅]" in result else "INVALID"
                    bucket_url = result.split(" - ")[0][4:] 
                    details = " - ".join(result.split(" - ")[1:]) if " - " in result else ""
                    table.add_row(
                        bucket_url,
                        "[success]VALID[/success]" if status == "VALID" else "[error]INVALID[/error]",
                        details,
                        style="success" if status == "VALID" else "error"
                    )
                    validated_results.append((result, status == "VALID"))
                if valid_url:
                    valid_urls.append(valid_url)
                layout["main"].update(Panel(table, border_style="bright_blue"))
                console.print(layout)


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
    for result, status in validated_results:
        bucket_url = result.split(" - ")[0][4:]  
        details = " - ".join(result.split(" - ")[1:]) if " - " in result else ""
        status_text = "VALID" if status else "INVALID"
        row_class = "valid" if status else "invalid"
        html_content += f"""<tr class="{row_class}"><td>{bucket_url}</td><td>{status_text}</td><td>{details.replace('\n', '<br>')}</td></tr>"""
    
    html_content += f"""
        </table>
        <div class="footer">Crafted with 💖 by <a href="https://github.com/Atharv834/S3BucketMisconf" target="_blank">LordofHeaven</a></div>
    </body></html>
    """

    with open(validated_output_filename, "w", encoding="utf-8") as output_file:
        output_file.write(html_content)
    with open(valid_urls_filename, "w", encoding="utf-8") as valid_file:
        valid_file.write("\n".join(valid_urls) + "\n")

    layout["progress"].update("")
    update_footer(f"[success]Scan complete! Results saved to {validated_output_filename} and {valid_urls_filename}[/success]")
    console.print(layout)

    console.print(Panel(
        "[warning]⚡ Use these valid S3 links responsibly! Happy Hacking![/warning]", 
        style="warning", 
        border_style="bright_yellow",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    console.rule("[title]S3 Bucket Misconfiguration Scanner[/title]", style="bright_cyan")
    input_filename = console.input("[info][?] Enter the file containing S3 URLs (e.g., nasa.txt): [/info]").strip()
    unique_bucket_list = process_urls_from_file(input_filename)
    if unique_bucket_list:
        scan_buckets(unique_bucket_list)
