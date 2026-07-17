import os
import re
import time
import random
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


def get_compartment_id(config, data):
    """Return compartment_id from payload, or fall back to tenancy root."""
    comp = data.get('compartment_id', '').strip()
    if comp and comp.startswith('ocid1.compartment.'):
        return comp
    return config['tenancy']


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
        compartment_id = get_compartment_id(config, data)

        kwargs = {'compartment_id': compartment_id}
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
    compartment_id = get_compartment_id(config, account_config)
    requested_shape = account_config.get('shape')
    requested_boot_gb = int(account_config.get('boot_volume_gb', 50))
    if requested_boot_gb < 50:
        requested_boot_gb = 50

    ads = identity_client.list_availability_domains(compartment_id=tenancy).data
    total_storage = 0
    for ad in ads:
        boot_volumes = block_client.list_boot_volumes(
            compartment_id=compartment_id,
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

    instances = compute_client.list_instances(compartment_id=compartment_id).data
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



def get_free_tier_usage(config, account_config, compute_client, block_client, identity_client):
    """Returns current free tier usage without blocking."""
    tenancy = config['tenancy']
    compartment_id = get_compartment_id(config, account_config)

    ads = identity_client.list_availability_domains(compartment_id=tenancy).data

    # Storage usage
    total_storage = 0
    for ad in ads:
        boot_volumes = block_client.list_boot_volumes(
            compartment_id=compartment_id,
            availability_domain=ad.name
        ).data
        total_storage += sum(
            int(v.size_in_gbs) for v in boot_volumes
            if v.lifecycle_state != 'TERMINATED'
        )
    storage_remaining = max(0, 200 - total_storage)

    # Instance usage
    instances = compute_client.list_instances(compartment_id=compartment_id).data
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


def run_automated_creation(config, account_config, compute_client, network_client, identity_client,
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

    compartment_id = get_compartment_id(config, account_config)

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

        vcns = network_client.list_vcns(compartment_id=compartment_id).data
        if not vcns:
            add_log("Error: No VCN found.")
            return

        subnets = network_client.list_subnets(
            compartment_id=compartment_id,
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
            compartment_id=compartment_id,
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
                elif e.status == 404:
                    add_log(f"ERROR 404: Resource not found. Check: (1) Compartment OCID is correct, (2) VCN/Subnet exist in this compartment, (3) Image ID is valid for this region.")
                    break
                elif e.status == 401:
                    add_log(f"ERROR 401: Authorization failed. Check: (1) IAM policies allow 'manage instances' + 'manage virtual-network-family' + 'manage volumes' in compartment '{compartment_id[:30]}...', (2) API key is active and not expired, (3) User has correct permissions.")
                    break
                elif e.status == 400:
                    add_log(f"ERROR 400: Bad request - {e.message[:120]}. Check shape config, image compatibility, and free tier limits.")
                    break
                else:
                    add_log(f"OCI API error ({e.status}): {e.message}")
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
            add_log("Provisioning loop ended without success.")
            if telegram_bot_token and telegram_chat_id:
                user_line = f"<b>User:</b> {oci_username}\n" if oci_username else ""
                # FIXED: Use Phnom Penh time in Telegram message
                pp_time = format_phnom_penh_time()
                tg_msg = (
                    f"&#10060; <b>OCI Provisioner Stopped</b>\n\n"
                    f"{user_line}"
                    f"Loop stopped after {attempts} attempts without success.\n"
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

        usage = get_free_tier_usage(config, data, compute_client, block_client, identity_client)

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
