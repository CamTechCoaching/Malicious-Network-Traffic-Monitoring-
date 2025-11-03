# This script monitors network traffic on the system, detects unusual spikes in connections, and logs
# the findings for security analysis

import psutil
import json
import logging
import time
from datetime import datetime

# For demonstration purposes I have put tryhackme.com and hackthebox.com hosting IP in the blacklist array
# Run the script, nothing will happen, navigate to http://tryhackme.com and see the output
# in the terminal and in json file.

# Configuration
blacklisted_ips = {"109.176.239.69", "104.22.55.228"}  # Example bad IPs
connection_limit = 20  # Threshold for excessive connections
log_file = "network_alerts.log"
json_file = "network_alerts.json"
scan_interval = 10  # Scan interval in seconds

# Setup logging
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_message(message, level="info"):
    """Helper function to log messages and print them."""
    print(message)
    if level == "warning":
        logging.warning(message)
    else:
        logging.info(message)

def get_active_connections():
    """Fetches current active network connections."""
    detected = []
    counted_processes = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        log_message(f"Error retrieving network connections: {e}", "warning")
        return detected

    for conn in connections:
        try:
            if conn.raddr:
                process_id = conn.pid
                remote_ip = conn.raddr.ip

                # Count connections per process
                if process_id in counted_processes:
                    counted_processes[process_id] += 1
                else:
                    counted_processes[process_id] = 1

                # Check against blacklisted IPs
                if remote_ip in blacklisted_ips:
                    entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "pid": process_id,
                        "local_ip": conn.laddr.ip,
                        "local_port": conn.laddr.port,
                        "remote_ip": remote_ip,
                        "remote_port": conn.raddr.port,
                        "reason": "Blacklisted IP"
                    }
                    detected.append(entry)
                    log_message(f"Suspicious connection: {entry}", "warning")
        except Exception:
            continue

    # Identify excessive connections
    for process_id, count in counted_processes.items():
        if count > connection_limit:
            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "pid": process_id,
                "connections": count,
                "reason": "Excessive connections"
            }
            detected.append(entry)
            log_message(f"Excessive connections detected: {entry}", "warning")

    return detected

def save_json(data):
    """Saves detected alerts to JSON."""
    if data:
        try:
            with open(json_file, "a") as file:
                json.dump(data, file, indent=4)
                file.write("\n")
            log_message("Suspicious activity saved to JSON.")
        except Exception as e:
            log_message(f"Error saving JSON: {e}", "warning")

def scan_loop():
    """Runs continuous scanning without using `__main__`."""
    log_message("Starting network monitoring...")
    
    while True:
        results = get_active_connections()
        if results:
            save_json(results)
        else:
            log_message("No anomalies detected.")
        time.sleep(scan_interval)

# Direct function call to start the process without __main__
scan_loop()
