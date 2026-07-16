def run_automated_creation(config, account_config, compute_client, network_client, identity_client, telegram_bot_token=None, telegram_chat_id=None):
    """Automated instance creation with unlimited retries until instance found or free tier exceeded."""
    global automation_running, automation_lock, stop_event
    
    with automation_lock:
        if automation_running:
            add_log("Automation already running - exiting")
            return None, "automation_already_running"
        automation_running = True
        automation_shape = account_config.get('shape', 'VM.Standard.A1.Flex')
    
    try:
        while True:
            # Check free tier limits at each iteration
            can_proceed, limit_message = check_free_tier_limits(
                config, compute_client, block_client, identity_client
            )
            if not can_proceed:
                if account_config.get('use_existing', False):
                    add_log("Proceeding with existing resources despite limit")
                else:
                    add_log(f"Free tier limit exceeded: {limit_message}")
                    return None, "quota_exceeded"
            
            if stop_event.is_set():
                add_log("Provisioning loop stopped by user.")
                return None, "user_stopped"
            
            try:
                instance = find_available_instance(account_config)
                if instance:
                    add_log(f"Found available instance: {instance.id}")
                    return instance, "success"
                else:
                    add_log("No instances found. Checking free tier limits...")
            except Exception as e:
                add_log(f"Error finding instances: {str(e)}")
                continue
            
            # Random delay with exponential backoff and jitter
            attempt = 0  # New line
            while True:  # Exponential backoff with random jitter
                delay = 60 + random.uniform(25, 60)
                add_log(f"No instance found. Retrying in {int(delay)}s...")
                time.sleep(delay)
                attempt += 1
                # Option to reset delay after a long time
                if random.random() < 0.05:  # 5% chance to reset delay
                    delay = 60
                # Exit retry loop if instance found in next attempt
                if can_proceed:  # Recheck free tier
                    break
    except Exception as e:
        add_log(f"Critical error in automation: {str(e)}")
    finally:
        with automation_lock:
            automation_running = False
            automation_shape = None