#!/bin/bash

# --- FUNCTIONS ---

check_dependencies() {
    for cmd in katana subfinder httpx-toolkit curl aws python3 gum; do
        command -v $cmd >/dev/null 2>&1 || { echo >&2 "$cmd is required but not installed."; exit 1; }
    done
}

prompt_inputs() {
    echo -e "\nEnter domain (e.g., example.com):"
    read DOMAIN
    [[ -z "$DOMAIN" ]] && echo "❌ Domain not provided. Exiting." && exit 1

    echo -e "\nEnter number of threads [Default: 30]:"
    read THREADS
    THREADS=${THREADS:-30}
    echo -e "⚙️ Using $THREADS threads.\n"
}

extract_buckets_from_js() {
    echo "🔍 Crawling $DOMAIN for JS files..."
    katana -u "https://$DOMAIN" -d 5 -jc -silent | grep '\.js$' > alljs.txt

    echo "🔍 Extracting S3 URLs from JS files..."
    cat alljs.txt | xargs -P "$THREADS" -I {} curl -s {} \
    | grep -oP '([a-zA-Z0-9.-]+\.s3(\.dualstack)?\.[a-z0-9-]+\.amazonaws\.com)' \
    | sort -u > js_s3.txt
}

extract_buckets_from_subdomains() {
    echo "🔍 Extracting subdomains and checking S3 from them..."
    subfinder -d "$DOMAIN" -silent -all \
    | httpx-toolkit -silent \
    | sed -E 's|https?://||' \
    | python3 /home/darklord/Tools/S3BucketMisconf/java2s3/java2s3.py /dev/stdin "$DOMAIN" /dev/stdout \
    | grep -oP '([a-zA-Z0-9.-]+\.s3(\.dualstack)?\.[a-z0-9-]+\.amazonaws\.com)' \
    | sort -u > subdomain_s3.txt
}

check_bucket_access() {
    echo "🔐 Checking access level for all discovered S3 buckets..."
    mkdir -p results
    : > results/final_buckets.txt

    cat js_s3.txt subdomain_s3.txt 2>/dev/null | sort -u | while read bucket_url; do
        bucket_name=$(echo "$bucket_url" | cut -d'.' -f1)
        ACCESS_LEVEL=""

        # Check for public read access
        aws s3 ls "s3://$bucket_name" --no-sign > /dev/null 2>&1 && ACCESS_LEVEL="[PUBLIC-READ] "

        # Check for public write access
        touch temp_upload_check.txt
        aws s3 mv temp_upload_check.txt "s3://$bucket_name/" --no-sign > /dev/null 2>&1 && ACCESS_LEVEL="$ACCESS_LEVEL[PUBLIC-WRITE] "

        if [[ -n "$ACCESS_LEVEL" ]]; then
            echo -e "$bucket_url $ACCESS_LEVEL" >> results/final_buckets.txt
        else
            echo -e "$bucket_url [NO PUBLIC ACCESS]" >> results/final_buckets.txt
        fi
    done

    echo -e "\n✅ Results saved to: results/final_buckets.txt"
}

display_results() {
    echo -e "\n📜 Displaying S3 bucket results in terminal..."
    
    if [[ -f results/final_buckets.txt ]]; then
        cat results/final_buckets.txt | while read line; do
            # Show results in a nice format
            gum style --foreground 220 "📦 Bucket URL: $line"
        done
    else
        echo "⚠️ No results found."
    fi
}

run_tui() {
    CHOICE=$(gum choose "🌐 Start Full Scan" "📁 Show Results" "❌ Exit")
    case "$CHOICE" in
        "🌐 Start Full Scan")
            prompt_inputs
            extract_buckets_from_js &  # JS-based
            extract_buckets_from_subdomains &  # Subdomain based
            wait
            check_bucket_access
            display_results  # Immediately show results in terminal after scan
            ;;
        "📁 Show Results")
            display_results  # Show saved results from previous scans
            ;;
        "❌ Exit")
            echo "Exiting."
            exit 0
            ;;
    esac
}

# --- RUN SCRIPT ---

check_dependencies
run_tui

