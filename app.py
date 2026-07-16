import os
import re
import time
import random
import secrets
import threading
import datetime
import functools
import requests
from flask import Flask, render_template, request, jsonify, Response
import oci

# ---- Timezone Configuration (Phnom Penh - ICT, UTC+7) ----
from zoneinfo import ZoneInfo
PHNOM_PENH_TZ = ZoneInfo("Asia/Phnom_Penh")

def get_phnom_penh_time():
    """Return current time in Phnom Penh timezone (ICT, UTC+7)."""
    return datetime.datetime.now(PHNOM_PENH_TZ)

def format_phnom_penh_time(dt=None):
    """Format datetime as string in Phnom Penh timezone."""
    if dt is None:
        dt = get_phnom_penh_time()
    return dt.strftime('%Y-%m-%d %H:%M:%S')

app = Flask(__name__)

# ---- Security Headers ----
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ---- Config ----
ADMIN_PASSWORD = os.environ.get('APP_PASSWORD')
if not ADMIN_PASSWORD:
    print("WARNING: APP_PASSWORD not set. Running WITHOUT authentication. Set APP_PASSWORD to enable Basic Auth.")

MAX_ATTEMPTS = int(os.environ.get('MAX_ATTEMPTS', 100))

# ---- Shared state ----
global_logs = []
logs_lock = threading.Lock()

automation_lock = threading.Lock()
automation_running = False
automation_shape = None  # Track which shape is currently running
stop_event = threading.Event()


def add_log(message):
    timestamp = format_phnom_penh_time()  # FIXED: Use Phnom Penh timezone
    line = f"[{timestamp}] {message}"
    print(line)
    with logs_lock:
        global_logs.append(line)
        if len(global_logs) > 200:
            global_logs.pop(0)


def build_config(data):
    return {
        "user": data.get('user'),
        "fingerprint": data.get('fingerprint'),
        "tenancy": data.get('tenancy'),
        "region": data.get('region'),
        "key_content": data.get('private_key')
    }


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not ADMIN_PASSWORD:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or auth.password != ADMIN_PASSWORD:
            return Response(
                'Authentication required',
                401,
                {'WWW-Authenticate': 'Basic realm="OCI Provisioner"'}
            )
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Flask Template Error: {str(e)}", 500


@app.route('/api/test-config', methods=['POST'])
@require_auth
def test_oci_config():
    """Pre-flight test: validates OCI config and attempts a real API call.

    This endpoint catches the common 401 'Failed to verify HTTP(S) Signature'
    error early, with a human-readable explanation of what's wrong.
    """
    data = request.json or {}
    config = build_config(data)

    # Step 1: Check required fields
    required_fields = ['user', 'fingerprint', 'tenancy', 'region', 'key_content']
    missing = [f for f in required_fields if not config.get(f)]
    if missing:
        return jsonify({
            'success': False,
            'error': f"Missing required fields: {', '.join(missing)}"
        })

    # Step 2: Format validation
    try:
        oci.config.validate_config(config)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Config format invalid: {e}",
            'hint': "Check that user/fingerprint/tenancy are valid OCIDs (ocid1...) and region is a valid OCI region identifier."
        })

    # Step 3: Verify private key loads
    try:
        import oci.signer
        signer = oci.signer.Signer(
            tenancy=config['tenancy'],
            user=config['user'],
            fingerprint=config['fingerprint'],
            private_key_file_location=None,
            pass_phrase=None,
            private_key_content=config.get('key_content')
        )
    except Exception as e:
        err_msg = str(e).lower()
        if 'passphrase' in err_msg or 'password' in err_msg:
            return jsonify({
                'success': False,
                'error': f"Private key requires a passphrase: {e}",
                'hint': "Your private key is encrypted with a passphrase. This app does not support passphrase-protected keys. Regenerate the key without a passphrase."
            })
        return jsonify({
            'success': False,
            'error': f"Private key could not be loaded: {e}",
            'hint': "Make sure you pasted the FULL private key including BEGIN/END lines. Format: -----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----"
        })

    # Step 4: Real API call — this is where 401 "Failed to verify HTTP(S) Signature" happens
    try:
        identity_client = oci.identity.IdentityClient(config)
        ads = identity_client.list_availability_domains(
            compartment_id=config['tenancy']
        ).data

        # If we got here, auth works!
        ad_names = [ad.name for ad in ads]
        return jsonify({
            'success': True,
            'message': 'OCI config verified and authenticated successfully!',
            'region': config['region'],
            'availability_domains': ad_names
        })

    except oci.exceptions.ServiceError as e:
        if e.status == 401 and 'Failed to verify' in str(e.message):
            return jsonify({
                'success': False,
                'error': '401 NotAuthenticated: Failed to verify the HTTP(S) Signature',
                'hint': 'The API key signature does not match. This means one of these is wrong:\n'
                        '1. The private key you pasted does NOT match the public key registered in OCI Console.\n'
                        '2. The fingerprint is from a DIFFERENT API key.\n'
                        '3. The User OCID does not match the user who owns this API key.\n\n'
                        'FIX: Go to OCI Console → Identity → Users → your user → API Keys.\n'
                        '   - Click "Add API Key" → generate a NEW key pair.\n'
                        '   - Copy the NEW private key and paste it here.\n'
                        '   - Copy the NEW fingerprint and config snippet from the dialog.'
            })
        elif e.status == 401:
            return jsonify({
                'success': False,
                'error': f'401: {e.message}',
                'hint': 'Authentication failed. Your tenancy or user OCID may be wrong.'
            })
        elif e.status == 404:
            return jsonify({
                'success': False,
                'error': f'404: {e.message}',
                'hint': 'Not found. The tenancy OCID may be wrong, or the user does not exist in this region.'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'OCI API error (HTTP {e.status}): {e.message}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Unexpected error: {type(e).__name__}: {e}'
        })


@app.route('/api/list-images', methods=['POST'])
@require_auth
def list_available_images():
    data = request.json or {}
    config = build_config(data)
    shape = data.get('shape')
    all_os_mode = data.get('all_os_mode', False)

    try:
        oci.config.validate_config(config)
        compute = oci.core.ComputeClient(config)

        kwargs = {'compartment_id': config['tenancy']}
        if shape:
            kwargs['shape'] = shape

        images = compute.list_images(**kwargs).data

        # FIXED: Use Phnom Penh timezone for image sorting
        min_dt = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc).astimezone(PHNOM_PENH_TZ)
        images = sorted(
            images,
            key=lambda i: i.time_created.astimezone(PHNOM_PENH_TZ) if i.time_created else min_dt,
            reverse=True
        )

        valid = []
        for img in images:
            if getattr(img, 'lifecycle_state', '') != 'AVAILABLE':
                continue

            os_name = (getattr(img, 'operating_system', '') or '').lower()
            version = (getattr(img, 'operating_system_version', '') or '').strip()
            display_name = (img.display_name or '').lower()

            # Filter by OS if not in All-OS-Mode
            if not all_os_mode:
                if 'ubuntu' not in os_name:
                    continue
                major = 0
                if version:
                    try:
                        major = int(str(version).split('.')[0])
                    except (ValueError, IndexError):
                        major = 0
                else:
                    m = re.search(r'ubuntu[-_\s]?(\d+)', display_name)
                    if m:
                        major = int(m.group(1))
                if major < 18:
                    continue

            valid.append({
                'id': img.id,
                'name': img.display_name or f"{getattr(img, 'operating_system', 'Unknown')} {version}",
                'version': version,
                'os': getattr(img, 'operating_system', 'Unknown'),
                'os_version': version
            })

        return jsonify({'success': True, 'images': valid[:50]})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def check_free_tier_limits(config, account_config, compute_client, block_client, identity_client):
    tenancy = config['tenancy']
    requested_shape = account_config.get('shape')
    requested_boot_gb = int(account_config.get('boot_volume_gb', 50))
    if requested_boot_gb < 50:
        requested_boot_gb = 50

    ads = identity_client.list_availability_domains(compartment_id=tenancy).data
    total_storage = 0
    for ad in ads:
        boot_volumes = block_client.list_boot_volumes(
            compartment_id=tenancy,
            availability_domain=ad.name
        ).data
        total_storage += sum(
            int(v.size_in_gbs) for v in boot_volumes
            if v.lifecycle_state != 'TERMINATED'
        )

    if total_storage + requested_boot_gb > 200:
        return False, (
            f"Storage would exceed 200 GB free tier limit "
            f"(used {total_storage} GB + requested {requested_boot_gb} GB)"
        )

    instances = compute_client.list_instances(compartment_id=tenancy).data
    active_states = {'RUNNING', 'PROVISIONING', 'STARTING'}

    if requested_shape == 'VM.Standard.E2.1.Micro':
        micro_count = sum(
            1 for inst in instances
            if inst.shape == 'VM.Standard.E2.1.Micro'
            and inst.lifecycle_state != 'TERMINATED'
        )
        if micro_count >= 2:
            return False, f"Free tier allows only 2 Micro instances (found {micro_count})"
        return True, ""

    if requested_shape == 'VM.Standard.A1.Flex':
        requested_ocpus = int(account_config.get('ocpus', 4))
        requested_memory = int(account_config.get('memory', 24))

        total_ocpus = 0
        total_memory = 0
        for inst in instances:
            # Count ALL non-TERMINATED ARM instances (including STOPPED)
            # Free tier quota counts stopped instances too
            if inst.shape == 'VM.Standard.A1.Flex' and inst.lifecycle_state != 'TERMINATED':
                cfg = inst.shape_config
                if cfg:
                    total_ocpus += int(cfg.ocpus or 0)
                    total_memory += int(cfg.memory_in_gbs or 0)

        if total_ocpus + requested_ocpus > 2:
            return False, (
                f"A1 OCPUs would exceed 2 (used {total_ocpus} + requested {requested_ocpus})"
            )
        if total_memory + requested_memory > 12:
            return False, (
                f"A1 memory would exceed 12 GB (used {total_memory} + requested {requested_memory})"
            )
        return True, ""

    return True, ""



def get_free_tier_usage(config, compute_client, block_client, identity_client):
    """Returns current free tier usage without blocking."""
    tenancy = config['tenancy']

    ads = identity_client.list_availability_domains(compartment_id=tenancy).data

    # Storage usage
    total_storage = 0
    for ad in ads:
        boot_volumes = block_client.list_boot_volumes(
            compartment_id=tenancy,
            availability_domain=ad.name
        ).data
        total_storage += sum(
            int(v.size_in_gbs) for v in boot_volumes
            if v.lifecycle_state != 'TERMINATED'
        )
    storage_remaining = max(0, 200 - total_storage)

    # Instance usage
    instances = compute_client.list_instances(compartment_id=tenancy).data
    active_states = {'RUNNING', 'PROVISIONING', 'STARTING'}

    # Micro instances
    micro_count = sum(
        1 for inst in instances
        if inst.shape == 'VM.Standard.E2.1.Micro'
        and inst.lifecycle_state != 'TERMINATED'
    )
    micro_remaining = max(0, 2 - micro_count)

    # ARM (A1.Flex) usage - count ALL non-TERMINATED (including STOPPED)
    total_ocpus = 0
    total_memory = 0
    arm_instances = []
    for inst in instances:
        if inst.shape == 'VM.Standard.A1.Flex' and inst.lifecycle_state != 'TERMINATED':
            cfg = inst.shape_config
            if cfg:
                ocpus = int(cfg.ocpus or 0)
                memory = int(cfg.memory_in_gbs or 0)
                total_ocpus += ocpus
                total_memory += memory
                arm_instances.append({
                    'name': inst.display_name,
                    'ocpus': ocpus,
                    'memory': memory,
                    'state': inst.lifecycle_state
                })

    ocpus_remaining = max(0, 2 - total_ocpus)
    memory_remaining = max(0, 12 - total_memory)

    return {
        'storage': {
            'used_gb': total_storage,
            'limit_gb': 200,
            'remaining_gb': storage_remaining,
            'percent': round((total_storage / 200) * 100, 1) if total_storage > 0 else 0
        },
        'micro': {
            'used': micro_count,
            'limit': 2,
            'remaining': micro_remaining,
            'percent': round((micro_count / 2) * 100, 1) if micro_count > 0 else 0
        },
        'arm': {
            'used_ocpus': total_ocpus,
            'limit_ocpus': 2,
            'remaining_ocpus': ocpus_remaining,
            'used_memory_gb': total_memory,
            'limit_memory_gb': 12,
            'remaining_memory_gb': memory_remaining,
            'instances': arm_instances,
            'ocpu_percent': round((total_ocpus / 2) * 100, 1) if total_ocpus > 0 else 0,
            'memory_percent': round((total_memory / 12) * 100, 1) if total_memory > 0 else 0
        }
    }




def send_telegram_message(bot_token, chat_id, message):
    """Send a message via Telegram Bot API."""
    if not bot_token or not chat_id:
        return False, "Missing bot token or chat ID"
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        data = response.json()
        if data.get("ok"):
            return True, "Message sent"
        else:
            return False, data.get("description", "Unknown Telegram error")
    except Exception as e:
        return False, str(e)




def get_oci_username(config, identity_client):
    """Fetch the username from OCI Identity API using user OCID.

    OCI User model attributes (from docs):
    - name: login username (required, unique)
    - description: user description (required)
    - email: email address (optional)
    - db_user_name: DB username (optional)
    """
    try:
        user_ocid = config.get('user')
        if not user_ocid:
            add_log("Username detection skipped: no user OCID in config")
            return None

        add_log(f"Fetching user info from Identity API...")
        user = identity_client.get_user(user_id=user_ocid).data

        # name = Console login username (most useful)
        # email = Email if set
        # description = Description field
        name = getattr(user, 'name', None)
        email = getattr(user, 'email', None)
        desc = getattr(user, 'description', None)

        # Build a readable identifier: prefer name, then email, then description
        if name and email:
            result = f"{name} ({email})"
        elif name:
            result = name
        elif email:
            result = email
        elif desc and desc != user_ocid:
            result = desc
        else:
            result = user_ocid

        add_log(f"Detected OCI user: {result}")
        return result

    except oci.exceptions.ServiceError as e:
        add_log(f"Identity API error (status {e.status}): {e.message}")
        return None
    except Exception as e:
        add_log(f"Error fetching user info: {str(e)}")
        return None


import random

...

def run_automated_creation(config, account_config, compute_client, network_client, identity_client,
                    retry_delay=60, randomize_delay=False, random_min=25, random_max=60,
                    telegram_bot_token=None, telegram_chat_id=None):
    global automation_running
    
    # Initialize retry parameters
    attempts = 0
    base_delay = retry_delay
    max_attempts = int(os.environ.get('MAX_ATTEMPTS', 100))
    
    while attempts < max_attempts:
        try:
            # Add progress logging
            add_log(f"Attempt {attempts + 1}/{max_attempts} - Checking free tier limits...")
            
            # Enhanced free tier check allowing existing resources
            can_proceed, limit_message = check_free_tier_limits(config, compute_client, block_client, identity_client)
            if not can_proceed:
                if account_config.get('use_existing', False):
                    add_log("Proceeding with existing resources despite limit")
                else:
                    add_log(f"Quota limit reached: {limit_message}")
                    return False, "quota_exceeded"
            
            # Core instance creation logic
            if create_instance(...):  # Assuming this function exists
                return True, "success"

            # Calculated delay with exponential backoff and jitter
            delay = base_delay * (2 ** attempts)
            if randomize_delay:
                delay += random.uniform(random_min, random_max)
            
            add_log(f"Attempt {attempts + 1} failed, retrying in {delay} seconds...")
            time.sleep(delay)
            attempts += 1

        except oci.exceptions.ServiceError as e:
            if "RateLimit" in str(e):
                # Special handling for rate limits
                delay = 600  # 10 minutes for rate limit recovery
                add_log(f"Rate limited. Waiting {delay} seconds...")
                time.sleep(delay)
                continue
            
        except Exception as e:
            add_log(f"Error: {str(e)}")
            if attempts >= max_attempts:
                return False, "max_retries_exceeded"

    return False, "loop_completed_without_success"

# Ensure the function is properly called
if __name__ == '__main__':
    # Example usage
    run_automated_creation(...)

                           retry_delay=60, randomize_delay=False, random_min=25, random_max=60,
                           telegram_bot_token=None, telegram_chat_id=None):
    global automation_running

    # Initialize oci_username early so it exists even if exceptions occur
    oci_username = None
    target_region = config.get('region', 'unknown')
    target_name = account_config.get('display_name', 'AlwaysFree-Bot')

    # Try to detect username before anything else
    try:
        oci_username = get_oci_username(config, identity_client)
        if oci_username:
            add_log(f"OCI username detected: {oci_username}")
    except Exception as e:
        add_log(f"Could not detect OCI username: {str(e)}")

    try:
        block_client = oci.core.BlockstorageClient(config)
        ok, err = check_free_tier_limits(
            config, account_config, compute_client, block_client, identity_client
        )
        if not ok:
            add_log(f"Free tier limit check failed: {err}")
            return

        add_log(f"Initializing infrastructure scan inside: {target_region}...")

        ads = identity_client.list_availability_domains(
            compartment_id=config['tenancy']
        ).data
        ad_name = ads[0].name if ads else ''

        vcns = network_client.list_vcns(compartment_id=config['tenancy']).data
        if not vcns:
            add_log("Error: No VCN found.")
            return

        subnets = network_client.list_subnets(
            compartment_id=config['tenancy'],
            vcn_id=vcns[0].id
        ).data
        if not subnets:
            add_log("Error: No subnet found.")
            return
        subnet_id = subnets[0].id

        image_id = account_config.get('image_id')
        if not image_id:
            add_log("Error: No OS image selected.")
            return

        ssh_key = account_config.get('ssh_key', '').strip()
        if not ssh_key:
            add_log("Error: SSH public key is required.")
            return

        # Validate SSH key format
        valid_prefixes = ('ssh-rsa', 'ssh-ed25519', 'ssh-dss', 'ecdsa-sha2-nistp256',
                          'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519')
        if not any(ssh_key.startswith(p) for p in valid_prefixes):
            add_log("Error: SSH key does not appear to be a valid public key.")
            return

        boot_gb = int(account_config.get('boot_volume_gb', 50))
        if boot_gb < 50:
            add_log("Boot volume raised to minimum 50 GB.")
            boot_gb = 50

        add_log(f"Setup Verified -> Subnet: {subnet_id[:15]}... | "
                f"Image: {image_id[:15]}... | Zone: {ad_name}")

        is_arm = account_config.get('shape') == "VM.Standard.A1.Flex"
        shape_config = None
        if is_arm:
            ocpus = int(account_config.get('ocpus', 2))
            memory = int(account_config.get('memory', 12))
            shape_config = oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=ocpus, memory_in_gbs=memory
            )

        instance_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=config['tenancy'],
            availability_domain=ad_name,
            shape=account_config['shape'],
            shape_config=shape_config,
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_id,
                boot_volume_size_in_gbs=boot_gb
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=subnet_id,
                assign_public_ip=True
            ),
            metadata={"ssh_authorized_keys": ssh_key},
            display_name=target_name
        )

        add_log(f"Launching provisioning loop for '{target_name}'...")

        attempts = 0
        success = False

        while True:
            attempts += 1

            if stop_event.is_set():
                add_log("Provisioning loop stopped by user.")
                break

            try:
                add_log(f"Attempt {attempts}: sending instance launch request...")
                compute_client.launch_instance(instance_details)
                add_log("SUCCESS! Instance created and running.")
                success = True
                # Send Telegram alert if configured
                if telegram_bot_token and telegram_chat_id:
                    instance_name = account_config.get('display_name', 'AlwaysFree-Bot')
                    shape = account_config.get('shape', 'Unknown')
                    region = config.get('region', 'unknown')
                    # FIXED: Use Phnom Penh time in Telegram message
                    pp_time = format_phnom_penh_time()
                    user_line = f"<b>User:</b> {oci_username}\n" if oci_username else ""
                    tg_msg = (
                        f"&#9989; <b>OCI Provisioner Success!</b>\n\n"
                        f"<b>Instance:</b> {instance_name}\n"
                        f"<b>Shape:</b> {shape}\n"
                        f"<b>Region:</b> {region}\n"
                        f"{user_line}"
                        f"<b>Time:</b> {pp_time} (Phnom Penh)\n"
                        f"<b>Status:</b> Running\n\n"
                        f"Your Always Free instance has been successfully provisioned!"
                    )
                    tg_ok, tg_err = send_telegram_message(telegram_bot_token, telegram_chat_id, tg_msg)
                    if tg_ok:
                        add_log("Telegram success alert sent.")
                    else:
                        add_log(f"Telegram alert failed: {tg_err}")
                break

            except oci.exceptions.ServiceError as e:
                msg = str(e)
                if "Out of capacity" in msg or e.status in (500, 429, 503, 504):
                    user_info = f" [user: {oci_username}]" if oci_username else ""
                    add_log(f"Capacity busy in '{target_region}'.{user_info} Retrying...")
                else:
                    add_log(f"OCI API error: {e.message}")
                    break
            except (ConnectionError, OSError) as e:
                # Handle connection drops, timeouts, DNS failures as retryable
                user_info = f" [user: {oci_username}]" if oci_username else ""
                add_log(f"Connection issue in '{target_region}': {type(e).__name__}.{user_info} Retrying...")
            except Exception as e:
                msg = str(e)
                if "Remote end closed connection" in msg or "Connection aborted" in msg or "timeout" in msg.lower():
                    user_info = f" [user: {oci_username}]" if oci_username else ""
                    add_log(f"Network hiccup in '{target_region}': connection dropped.{user_info} Retrying...")
                else:
                    add_log(f"Automation engine failure: {msg}")
                    break

            actual_delay = retry_delay
            if randomize_delay:
                actual_delay = random.randint(random_min, random_max)
                add_log(f"Dynamic retry: waiting {actual_delay}s (randomized {random_min}-{random_max}s)")

            if stop_event.wait(actual_delay):
                add_log("Provisioning loop stopped while waiting.")
                break

        if not success:
            add_log(f"Provisioning loop ended after {attempts} attempts.")
            if telegram_bot_token and telegram_chat_id:
                user_line = f"<b>User:</b> {oci_username}\n" if oci_username else ""
                # FIXED: Use Phnom Penh time in Telegram message
                pp_time = format_phnom_penh_time()
                tg_msg = (
                    f"&#10060; <b>OCI Provisioner Stopped</b>\n\n"
                    f"{user_line}"
                    f"Loop stopped after {attempts} attempts.\n"
                    f"<b>Region:</b> {config.get('region', 'unknown')}\n"
                    f"<b>Time:</b> {pp_time} (Phnom Penh)"
                )
                send_telegram_message(telegram_bot_token, telegram_chat_id, tg_msg)

    except Exception as e:
        msg = str(e)
        if "Remote end closed connection" in msg or "Connection aborted" in msg:
            add_log(f"Network connection lost. Loop ended.")
        else:
            add_log(f"Automation engine failure: {msg}")
        if telegram_bot_token and telegram_chat_id:
            user_line = f"<b>User:</b> {oci_username}\n" if oci_username else ""
            # FIXED: Use Phnom Penh time in Telegram message
            pp_time = format_phnom_penh_time()
            tg_msg = (
                f"&#10060; <b>OCI Provisioner Error</b>\n\n"
                f"{user_line}"
                f"Automation engine failure:\n{msg[:200]}\n"
                f"<b>Time:</b> {pp_time} (Phnom Penh)"
            )
            send_telegram_message(telegram_bot_token, telegram_chat_id, tg_msg)

    finally:
        with automation_lock:
            automation_running = False
            automation_shape = None


@app.route('/api/free-tier-status', methods=['POST'])
@require_auth
def free_tier_status():
    data = request.json or {}
    config = build_config(data)

    try:
        oci.config.validate_config(config)
        compute_client = oci.core.ComputeClient(config)
        block_client = oci.core.BlockstorageClient(config)
        identity_client = oci.identity.IdentityClient(config)

        usage = get_free_tier_usage(config, compute_client, block_client, identity_client)

        return jsonify({
            'success': True,
            'usage': usage
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/status', methods=['GET'])
@require_auth
def get_status():
    """Return current automation status."""
    with automation_lock:
        return jsonify({
            'success': True,
            'running': automation_running,
            'shape': automation_shape
        })


@app.route('/api/auto-launch-loop', methods=['POST'])
@require_auth
def auto_launch():
    global automation_running
    data = request.json or {}
    config = build_config(data)

    # Validate that all required fields are present
    required_fields = ['user', 'fingerprint', 'tenancy', 'region', 'key_content']
    missing = [f for f in required_fields if not config.get(f)]
    if missing:
        return jsonify({'success': False, 'error': f"Missing required OCI fields: {', '.join(missing)}. Please paste your full OCI config text and upload your private key."})

    try:
        oci.config.validate_config(config)
    except Exception as e:
        return jsonify({'success': False, 'error': f"Invalid OCI config: {e}"})

    requested_shape = data.get('shape', '')

    with automation_lock:
        if automation_running:
            if automation_shape and automation_shape != requested_shape:
                return jsonify({
                    'success': False,
                    'error': f"A provisioning loop is already running for shape '{automation_shape}'. Stop it first before starting '{requested_shape}'."
                })
            return jsonify({
                'success': False,
                'error': 'A provisioning loop is already running.'
            })
        automation_running = True
        automation_shape = requested_shape
        stop_event.clear()

    try:
        compute_client = oci.core.ComputeClient(config)
        network_client = oci.core.VirtualNetworkClient(config)
        identity_client = oci.identity.IdentityClient(config)

        retry_delay = int(data.get('retry_delay', 60))
        if retry_delay < 10:
            retry_delay = 10

        randomize_delay = data.get('randomize_delay', False)
        random_min = int(data.get('random_min', 25))
        random_max = int(data.get('random_max', 60))

        thread = threading.Thread(
            target=run_automated_creation,
            args=(config, data, compute_client, network_client, identity_client,
                  retry_delay, randomize_delay, random_min, random_max,
                  data.get('telegram_bot_token'), data.get('telegram_chat_id')),
            daemon=True
        )
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Provisioning loop started.'
        })

    except Exception as e:
        with automation_lock:
            automation_running = False
            automation_shape = None
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/stop-loop', methods=['POST'])
@require_auth
def stop_loop():
    stop_event.set()
    return jsonify({'success': True, 'message': 'Stop signal sent.'})


@app.route('/api/logs', methods=['GET'])
@require_auth
def fetch_live_logs():
    offset = int(request.args.get('offset', 0))
    with logs_lock:
        batch = global_logs[offset:]
        total = len(global_logs)
    return jsonify({'logs': batch, 'next_offset': total})


@app.route('/api/test-telegram', methods=['POST'])
@require_auth
def test_telegram():
    data = request.json or {}
    bot_token = data.get('bot_token', '').strip()
    chat_id = data.get('chat_id', '').strip()
    if not bot_token or not chat_id:
        return jsonify({'success': False, 'error': 'Bot token and chat ID are required'})
    # FIXED: Use Phnom Penh time in test message
    pp_time = format_phnom_penh_time()
    ok, err = send_telegram_message(
        bot_token, chat_id,
        f"&#9989; <b>OCI Instance loop Connected</b>\n\n"
        f"Your Telegram alerts are now active.\n"
        f"<b>Server Time:</b> {pp_time} (Phnom Penh, ICT)\n\n"
        f"You will receive notifications when provisioning succeeds or fails."
    )
    if ok:
        return jsonify({'success': True, 'message': 'Test message sent successfully'})
    return jsonify({'success': False, 'error': err})


# ---- Telegram Connect-via-Link ----
# Stores pending connect sessions: { connect_code: { 'bot_token': ..., 'expires': timestamp } }
connect_sessions = {}
connect_sessions_lock = threading.Lock()


def _tg_api_call(bot_token, method, payload=None):
    """Helper: call Telegram Bot API and return (success, data_or_error)."""
    url = f"https://api.telegram.org/bot{bot_token}/{method}"
    try:
        resp = requests.post(url, json=payload or {}, timeout=10)
        data = resp.json()
        if data.get("ok"):
            return True, data.get("result", [])
        return False, data.get("description", "Unknown Telegram error")
    except Exception as e:
        return False, str(e)


@app.route('/api/tg-connect/start', methods=['POST'])
@require_auth
def tg_connect_start():
    """Start the link-connect flow.

    Input:  { bot_token: "..." }
    Output: { success, connect_code, bot_username, connect_url }

    The connect_url is t.me/<bot>?start=<code>. When the user opens it and
    hits Start, the bot receives a /start message containing the code.
    The frontend then polls /api/tg-connect/poll to find the chat_id.
    """
    data = request.json or {}
    bot_token = data.get('bot_token', '').strip()
    if not bot_token:
        return jsonify({'success': False, 'error': 'Bot token is required'})

    # Verify the bot token is valid by calling getMe
    ok, result = _tg_api_call(bot_token, 'getMe')
    if not ok:
        return jsonify({'success': False, 'error': f'Invalid bot token: {result}'})

    bot_info = result if isinstance(result, dict) else {}
    bot_username = bot_info.get('username', '')
    if not bot_username:
        return jsonify({'success': False, 'error': 'Could not determine bot username'})

    # Generate a short unique connect code
    connect_code = secrets.token_hex(4)  # 8-char hex
    expires = time.time() + 300  # 5-minute expiry

    with connect_sessions_lock:
        # Clean up expired sessions
        expired = [k for k, v in connect_sessions.items() if v['expires'] < time.time()]
        for k in expired:
            del connect_sessions[k]
        connect_sessions[connect_code] = {
            'bot_token': bot_token,
            'bot_username': bot_username,
            'expires': expires
        }

    connect_url = f"https://t.me/{bot_username}?start={connect_code}"

    return jsonify({
        'success': True,
        'connect_code': connect_code,
        'bot_username': bot_username,
        'connect_url': connect_url,
        'expires_in': 300
    })


@app.route('/api/tg-connect/poll', methods=['POST'])
@require_auth
def tg_connect_poll():
    """Poll for the user's chat_id after they open the connect link.

    Input:  { bot_token: "...", connect_code: "..." }
    Output: { success, chat_id, chat_first_name, chat_username } or
            { success: false, waiting: true } if not found yet
    """
    data = request.json or {}
    bot_token = data.get('bot_token', '').strip()
    connect_code = data.get('connect_code', '').strip()
    if not bot_token or not connect_code:
        return jsonify({'success': False, 'error': 'Bot token and connect_code required'})

    # Check session validity
    with connect_sessions_lock:
        session = connect_sessions.get(connect_code)
        if not session:
            return jsonify({'success': False, 'error': 'Invalid or expired connect code'})
        if session['expires'] < time.time():
            del connect_sessions[connect_code]
            return jsonify({'success': False, 'error': 'Connect code expired. Please try again.'})
        if session['bot_token'] != bot_token:
            return jsonify({'success': False, 'error': 'Bot token mismatch' })

    # Fetch recent updates from Telegram, look for /start <connect_code>
    ok, result = _tg_api_call(bot_token, 'getUpdates', {'timeout': 0})
    if not ok:
        return jsonify({'success': False, 'error': f'Failed to get updates: {result}'})

    for update in result:
        message = update.get('message') or update.get('edited_message')
        if not message:
            continue
        text = message.get('text', '')
        chat = message.get('chat', {})
        chat_id = chat.get('id')

        # Match: "/start <connect_code>"
        if text.startswith('/start ') and connect_code in text:
            chat_first_name = chat.get('first_name', '')
            chat_username = chat.get('username', '')
            chat_type = chat.get('type', '')

            # Send a confirmation message to the user via the bot
            pp_time = format_phnom_penh_time()
            send_telegram_message(
                bot_token, str(chat_id),
                f"&#9989; <b>OCI Provisioner Connected!</b>\n\n"
                f"Hi {chat_first_name}! Your chat ID <code>{chat_id}</code> has been linked.\n\n"
                f"You will receive alerts here when your instance is provisioned.\n"
                f"<b>Server Time:</b> {pp_time} (Phnom Penh)"
            )

            # Clean up the session
            with connect_sessions_lock:
                connect_sessions.pop(connect_code, None)

            return jsonify({
                'success': True,
                'chat_id': str(chat_id),
                'chat_first_name': chat_first_name,
                'chat_username': chat_username,
                'chat_type': chat_type
            })

    # Not found yet — keep waiting
    return jsonify({'success': False, 'waiting': True, 'message': 'Waiting for user to open link...'})


@app.route('/api/send-telegram', methods=['POST'])
@require_auth
def send_telegram():
    data = request.json or {}
    ok, err = send_telegram_message(
        data.get('bot_token'), data.get('chat_id'), data.get('message', '')
    )
    return jsonify({'success': ok, 'error': err})


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)