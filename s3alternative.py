import re
import subprocess
import concurrent.futures
import shutil
import os
from tqdm import tqdm
from rich import print
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Show banner
if shutil.which("figlet"):
    os.system('figlet "S3BucketMisconf" | lolcat')
else:
    print("[bold blue]S3BucketMisconf[/bold blue]")

print("[cyan]~ Made by LordofHeaven[/cyan]\n")

# Ask for input file with white-colored prompt
input_filename = input("[white][?] Enter the Dork-Eye results file:[/white] ").strip()
validated_output_filename = "validated_buckets.txt"
valid_urls_filename = "valid.txt"

# Tell users to install dork-eye (but don't check for it)
print("\n[bold yellow][!] Make sure you have installed dork-eye! Install it using:[/bold yellow] [bold]pip install dork-eye[/bold]\n")

# Regex for extracting S3 URLs
pattern = re.compile(r"https://([a-zA-Z0-9-]+\.)?s3\.amazonaws\.com(/[^/]+)?/")

# Read URLs from file
try:
    with open(input_filename, "r", encoding="utf-8") as file:
        urls = [line.strip() for line in file if pattern.search(line)]
except FileNotFoundError:
    print("[red][!] File not found! Please check the filename and try again.[/red]")
    exit(1)

if not urls:
    print("[red][!] No valid S3 URLs found in the file![/red]")
    exit(1)

print(f"\n[bold green][✔] Found {len(urls)} potential S3 bucket URLs![/bold green]\n")

# Function to extract bucket name & validate it
def check_bucket(url):
    match = pattern.search(url)
    if not match:
        return None, None  # Skip invalid lines

    subdomain = match.group(1)  # Anything before "s3."
    next_directory = match.group(2)  # First directory after "s3.amazonaws.com"

    if subdomain:
        bucket_name = subdomain.rstrip('.')  # Case 1: Before "s3"
    elif next_directory:
        bucket_name = next_directory.strip('/')  # Case 2: After ".com/"

    command = f"aws s3 ls s3://{bucket_name} --no-sign-request"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if "AccessDenied" in result.stderr or "NoSuchBucket" in result.stderr:
            return f"[❌] {bucket_name} - [bold red]INVALID[/bold red]", None
        else:
            return f"[✅] {bucket_name} - [bold green]VALID[/bold green]\n{result.stdout}", url
    except Exception as e:
        return f"[❌] {bucket_name} - [bold red]ERROR[/bold red]\n{str(e)}", None

# Start Progress Bar
print("\n[bold cyan][*] Validating Buckets...[/bold cyan]\n")

validated_results = []
valid_urls = []

with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    transient=True
) as progress:
    task = progress.add_task("[bold green]Scanning S3 Buckets...[/bold green]", total=len(urls))

    # Use ThreadPoolExecutor for efficiency
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:  # Dynamic thread scaling
        futures = {executor.submit(check_bucket, url): url for url in urls}

        for future in concurrent.futures.as_completed(futures):
            progress.update(task, advance=1)  # Update progress bar
            result, valid_url = future.result()
            if result:
                console.print(result)  # Show result live
                validated_results.append(result)
            if valid_url:
                valid_urls.append(valid_url)  # Store valid URLs

# Save all validation results
with open(validated_output_filename, "w", encoding="utf-8") as output_file:
    output_file.write("\n".join(validated_results) + "\n")

# Save only valid URLs
with open(valid_urls_filename, "w", encoding="utf-8") as valid_file:
    valid_file.write("\n".join(valid_urls) + "\n")

print(f"\n[bold green][✔] Validation results saved to {validated_output_filename}[/bold green]")
print(f"[bold cyan][✔] Valid URLs saved to {valid_urls_filename}[/bold cyan]\n")

print("[yellow][!] Use these valid S3 links for further testing! Happy Hacking! ⚡[/yellow]")

