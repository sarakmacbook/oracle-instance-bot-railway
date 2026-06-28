# OCI Always Free Provisioner

> ⚠️ **DISCLAIMER: USE AT YOUR OWN RISK — READ CAREFULLY**
> 
> This tool is provided for **educational and personal use only**. By downloading, installing, or using this software, you agree to the following:
> 
> 1. **Terms of Service Compliance**: Automated interaction with Oracle Cloud Infrastructure (OCI) APIs may violate [Oracle's Cloud Services Agreement](https://www.oracle.com/legal/terms.html) and/or Acceptable Use Policy. You are solely responsible for ensuring your use complies with all applicable Oracle policies.
> 
> 2. **No Liability**: The authors, contributors, and distributors of this tool assume **absolutely no liability** for any consequences arising from its use, including but not limited to: account suspension, account termination, data loss, unexpected charges, or legal action by Oracle or third parties.
> 
> 3. **No Warranty**: This software is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
> 
> 4. **Responsible Use**: This tool is designed to automate legitimate provisioning workflows. Do not use it to abuse, overwhelm, or circumvent OCI's fair use mechanisms. Excessive or abusive automation may result in IP bans, account suspension, or legal consequences.
> 
> 5. **Credential Security**: You are responsible for safeguarding your OCI API credentials. Never commit private keys to version control, never share them publicly, and rotate them regularly. The authors are not responsible for credential leaks or unauthorized access resulting from your negligence.
> 
> **By using this tool, you acknowledge that you have read, understood, and agree to this disclaimer in its entirety.**

---

## What This Tool Does

A web-based automation tool that provisions OCI Always Free instances with intelligent retry logic. When OCI reports "Out of capacity," the tool automatically retries after a configurable delay until an instance is successfully created or manually stopped.

## Features

| Feature | Description |
|---------|-------------|
| **Auto-Retry Loop** | Continuously retries instance creation until success |
| **Dynamic Retry** | Randomized 25-60s delays to avoid rate limits |
| **Free Tier Protection** | Pre-launch quota checks (storage, micro, ARM) |
| **All-OS-Mode** | Toggle between Ubuntu-only or all operating systems |
| **Telegram Alerts** | Get notified on your phone when instances are created |
| **Username Detection** | Auto-detects OCI username via Identity API |
| **Live Log Stream** | Real-time terminal output of all attempts |
| **SSH Key Upload** | Upload `.pub` files directly |

## Quick Start

### Requirements
- Python 3.11+
- OCI account with Always Free eligibility
- OCI API key pair (config + private key)

### Installation

```bash
# Clone or download the repository
git clone <your-repo-url>
cd oci-provisioner

# Install dependencies
pip install -r requirements.txt

# Set authentication password (optional but recommended)
export APP_PASSWORD=your_secure_password

# Start the server
python app.py
```

Then open `http://localhost:5000` in your browser.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_PASSWORD` | No | *(none)* | Enables Basic Auth. **Strongly recommended for public deployments.** |
| `PORT` | No | `5000` | Server port |

## How to Use — Step by Step

### Step 1: Prepare Your OCI Credentials

Before starting, you need:
- Your OCI `~/.oci/config` file (contains user OCID, tenancy OCID, fingerprint, region)
- Your OCI private key file (usually `~/.oci/oci_api_key.pem`)
- An SSH public key (usually `~/.ssh/id_rsa.pub` or `~/.ssh/id_ed25519.pub`)

> ⚠️ **Never share your private key (.pem) with anyone.**

### Step 2: Open the App

Navigate to your deployed URL (e.g., `https://your-app.railway.app`) or `http://localhost:5000` if running locally.

### Step 3: Enter Credentials

| Field | What to Do |
|-------|-----------|
| **Paste raw config** | Copy contents of `~/.oci/config` and paste into the dark text box. The app auto-extracts user, tenancy, fingerprint, and region. |
| **Upload private key** | Click "Choose File" and select your `.pem` file. The key loads automatically. |

### Step 4: Check Your Quota

Click **"Check Free Tier Usage"** to see:
- Storage used / 200 GB limit
- Micro instances used / 2 limit
- ARM OCPUs and RAM usage

If any bar is at 100%, you cannot create more of that resource type.

### Step 5: Select Operating System

| Mode | How to Use |
|------|-----------|
| **Ubuntu Only** (default) | Click **"Ubuntu-Only OS"** — scans for Ubuntu 18+ images |
| **All OS** | Click **"All-OS-Mode"** toggle first, then scan — shows Oracle Linux, CentOS, Windows, etc. |

Select your desired image from the dropdown.

### Step 6: Configure Instance

| Setting | Recommendation |
|---------|-----------------|
| **Retry Delay** | 60s default. Use "Dynamic" (25-60s random) only if you understand rate limit risks. |
| **Shape** | `VM.Standard.A1.Flex` (ARM, flexible) or `VM.Standard.E2.1.Micro` (AMD, fixed 1 OCPU / 1 GB) |
| **OCPUs / RAM** | For ARM: max 2 OCPUs / 12 GB RAM (free tier limit). For Micro: fixed at 1/1. |
| **Boot Volume** | 50 GB default. Click "Max" to use remaining free storage. |
| **VM Name** | Any name you want (e.g., `AlwaysFree-Bot`) |
| **SSH Key** | Paste your public key or click "📁 Upload .pub" to select your `.pub` file. |

### Step 7: (Optional) Telegram Alerts

Want a phone notification when your instance is ready?

1. Click **"💬 Telegram Alert"**
2. Enter your **Bot Token** (get from [@BotFather](https://t.me/BotFather))
3. Enter your **Chat ID** (get from [@userinfobot](https://t.me/userinfobot))
4. Click **"🔗 Send Connected Message"** to test
5. If test passes, the button turns blue and shows "(ON)"

To disable: Click **"🚫 Turn Off Alerts"**

### Step 8: Start the Loop

Click **"Start Continuous Provisioning Loop"**.

The terminal will show live output:
```
[12:30:15] OCI username detected: your-name (your@email.com)
[12:30:16] Initializing infrastructure scan inside: us-ashburn-1...
[12:30:17] Setup Verified -> Subnet: ocid1.subnet... | Image: ocid1.image... | Zone: AD-1
[12:30:17] Launching provisioning loop for 'AlwaysFree-Bot'...
[12:30:17] Attempt 1: sending instance launch request...
[12:30:18] Capacity busy in 'us-ashburn-1'. [user: your-name] Retrying...
[12:30:18] Dynamic retry: waiting 45s (randomized 25-60s)
...
[14:22:05] Attempt 187: sending instance launch request...
[14:22:06] SUCCESS! Instance created and running.
[14:22:06] Telegram success alert sent.
```

### Step 9: Stop (If Needed)

Click **"Stop Provisioning Loop"** at any time. The loop also stops automatically on:
- ✅ Instance created successfully
- 🛑 Free tier limit would be exceeded (checked at startup)
- 🛑 Non-capacity API error (e.g., invalid credentials, no VCN)

### Step 10: Verify in OCI Console

Once successful:
1. Go to [OCI Console](https://cloud.oracle.com) → Compute → Instances
2. Find your instance (name from Step 6)
3. Copy the public IP
4. SSH in: `ssh -i ~/.ssh/id_rsa opc@<public-ip>` (Oracle Linux) or `ubuntu@<public-ip>` (Ubuntu)

## Security Notes

| Concern | Mitigation |
|---------|-----------|
| Credentials in request body | **Always use HTTPS** in production |
| Private key in memory | Cleared on server restart; never logged |
| No session management | Use `APP_PASSWORD` for Basic Auth |
| Telegram tokens in browser | Stored in JS memory only; cleared on refresh |
| Server info exposure | Endpoint requires auth if `APP_PASSWORD` is set |

## Important Warnings

### Rate Limiting & Fair Use
- OCI may rate-limit or flag accounts making frequent API calls
- Default retry delay is **60 seconds minimum**
- Dynamic retry randomizes between 25-60s — use responsibly
- Consider increasing delays if you experience throttling

### Free Tier Quotas
The tool enforces these limits before launching:

| Resource | Limit | What Counts |
|----------|-------|-------------|
| Storage | 200 GB | All boot volumes across all ADs |
| Micro Instances | 2 max | All non-TERMINATED (including STOPPED) |
| ARM OCPUs | 2 max | All non-TERMINATED (including STOPPED) |
| ARM Memory | 12 GB max | All non-TERMINATED (including STOPPED) |

### Account Safety
- **Do not share your OCI private key**
- **Do not commit credentials to Git**
- **Rotate API keys regularly**
- **Monitor OCI Console for unexpected usage**

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | Optional | Main UI |
| `/api/list-images` | POST | Required* | Scan OS images |
| `/api/free-tier-status` | POST | Required* | Get quota usage |
| `/api/auto-launch-loop` | POST | Required* | Start provisioning |
| `/api/stop-loop` | POST | Required* | Stop provisioning |
| `/api/logs` | GET | Required* | Fetch live logs |
| `/api/status` | GET | Required* | Check loop status |
| `/api/test-telegram` | POST | Required* | Test Telegram config |
| `/api/send-telegram` | POST | Required* | Send custom alert |
| `/api/server-info` | GET | Required* | Server IP/domain info |

\* Required only if `APP_PASSWORD` is set.

## Troubleshooting

### "APP_PASSWORD environment variable must be set"
Set the env var: `export APP_PASSWORD=yourpassword`

### "Capacity busy" forever
OCI free tier capacity is limited and varies by region/time. Try:
- Different regions
- Different availability domains
- Off-peak hours (early morning UTC)

### "Invalid OCI config"
Verify your config file has all required fields: `user`, `fingerprint`, `tenancy`, `region`, `key_content`

### Connection errors / "Remote end closed connection"
The tool now handles these as retryable network issues. If persistent, check:
- Your internet connection
- OCI service status
- Firewall/proxy settings

## License

MIT License — see LICENSE file.

## Contributing

Issues and PRs welcome. Please ensure:
- Code follows existing style
- Security implications are considered
- Disclaimers are updated if behavior changes

---

**Last Updated:** 2026-06-28
