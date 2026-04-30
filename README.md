![S3BucketMisconf](https://github.com/Atharv834/S3BucketMisconf/blob/main/Images/s3.png)
![S3BucketMisconf](https://github.com/Atharv834/S3BucketMisconf/blob/main/Images/s31.png)


# S3BucketMisconf - AWS S3 Bucket Misconfiguration Finder

**S3BucketMisconf** is a tool designed to help you identify misconfigured **AWS S3 buckets** that might be publicly accessible. It checks if the S3 bucket is **valid** ✅ or **invalid** ❌, and gives feedback about the security status of each bucket. The tool uses **Dork-Eye** results and interacts with **AWS CLI** to validate the buckets.

## Features

- **Bucket Validation:** Checks if the S3 bucket exists and whether it's publicly accessible. 🌐
- **Real-Time Progress Bar:** Displays a dynamic progress bar during validation. ⏳
- **Output Files:** Saves results to text files for further analysis. 💾
- **Multi-Threaded:** Uses multiple threads to make the validation process faster. ⚡
- **Easy-to-Use Interface:** Interactive UI with colorful and clean prompts. 🎨

## Requirements

1. **Python 3.x** 🐍
2. **AWS CLI:** Make sure AWS CLI is installed and configured with the correct permissions for bucket validation. 🔑
   - Install AWS CLI: [AWS CLI Installation](https://aws.amazon.com/cli/) 📥
   - Configure AWS CLI: Run `aws configure` and input your credentials. ✨
3. **Dork-Eye:** A Python library used to extract potential S3 URLs from **Dork-Eye** results. 🔎
   - Install Dork-Eye: `git clone https://github.com/BullsEye0/dorks-eye` 🛠️
4. **figlet** : Used to generate a fun ASCII banner for the tool. 🎉
   - Install figlet:
     - **Linux (Ubuntu/Debian):**
       ```bash
       sudo apt-get install figlet
       ```
     - **MacOS:**
       ```bash
       brew install figlet
       ```
     - **Windows:** You can use [Cygwin](https://www.cygwin.com/) to install figlet. 💻

5. **lolcat** : Used to add funny "lolcat" messages for a fun experience. 😹
   - Install lolcat:
     - **Linux (Ubuntu/Debian):**
       ```bash
       sudo apt-get install lolcat
       ```
     - **MacOS:**
       ```bash
       brew install lolcat
       ```
     - **Windows:** You can use [Cygwin](https://www.cygwin.com/) to install lolcat or find an equivalent package for Windows. 🐱

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Atharv834/S3BucketMisconf.git
   cd S3BucketMisconf
   ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure **AWS CLI** is configured and that you have valid **permissions** to access AWS S3 resources. 🚀

4. **Dork-Eye** should be installed using `git clone https://github.com/BullsEye0/dorks-eye`. 📚

5. **Install figlet** and **lolcat**  🌟

## Usage

### Step 1: Provide Dork-Eye Results File

Run the script:

```bash
python news3main.py
```

It will ask you to **enter the Dork-Eye results file**:

```bash
[?] Enter the Dork-Eye results file:
```

Provide the file path where Dork-Eye has saved the **results**. 🗂️

### Step 2: Script Workflow

- The script will **validate** all potential S3 URLs extracted from the provided file. 🔒
- It will display results for each S3 bucket, showing whether the bucket is **valid** ✅ or **invalid** ❌.
- It also checks if the bucket is publicly accessible and gives feedback based on the result. 🌍

### Step 3: View Output

- **Validation results** will be saved to `s3_validation_results.html`. 📝
- Only **valid URLs** will be saved to `valid.txt`. 📂

```bash
[✔] Validation results saved to validated_buckets.txt
[✔] Valid URLs saved to valid.txt
```

### Example Output:


![Output Image](https://github.com/Atharv834/S3BucketMisconf/blob/main/Images/output.png)

![Output Image](https://github.com/Atharv834/S3BucketMisconf/blob/main/Images/output2.png)

### Step 4: Next Steps

After running the script:
- You can **review** the **valid URLs** in `valid.txt` for further testing. 🔍
- Use these buckets to **check for sensitive data leaks** or misconfigurations. 💡

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 📄

## Credits

- Uses **AWS CLI**, **Dork-Eye**, **figlet**, and **lolcat** (for fun ASCII banners). 🎨
- Inspired by security research and misconfiguration detection. 🔐



[S3BucketMisconf - Demo Video](https://github.com/Atharv834/S3BucketMisconf/blob/main/s3scan.mp4)


![](https://komarev.com/ghpvc/?username=Atharv834&style=the-for-badge&color=orange)
