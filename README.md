OCI Always Free Provisioner

A web-based tool for automating OCI Always Free instance provisioning with retry logic.
Features

Ubuntu-Only Mode: Scans and filters for Ubuntu images only (default)
All-OS-Mode: Toggle to scan ALL available operating system images
Live Status Indicator: Real-time loop status in the header
Free Tier Quota Monitor: Visual progress bars for storage, micro instances, and ARM resources
Dynamic Retry: Randomized delay between 25-60s to avoid rate limits
SSH Key Validation: Validates SSH public key format before launch
Security Headers: X-Frame-Options, X-Content-Type-Options, HSTS
Bug Fixes

Fixed missing import random that crashed dynamic retry mode
Fixed Micro instance limit display (now correctly shows 2, not 1)
Fixed MAX_ATTEMPTS being ignored (now properly enforced in the loop)
Fixed race condition on automation_running state
Fixed fingerprint regex to accept 32-47 character fingerprints
Added /api/status endpoint for automation status polling
Environment Variables

Table


Variable	Required	Default	Description
APP_PASSWORD	Yes	-	Basic auth password for the portal
MAX_ATTEMPTS	No	100	Maximum retry attempts per provisioning loop
PORT	No	5000	Server port
Quick Start

bash

pip install -r requirements.txt
export APP_PASSWORD=your_secure_password
python app.py
Then open http://localhost:5000 in your browser.