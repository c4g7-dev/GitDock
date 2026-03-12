#!/usr/bin/env python3
"""Deploy GitDock to remote server via SSH."""

import paramiko
import os
import sys
import time

HOST = "10.27.27.226"
PORT = 22
USER = "root"
PASS = "59464115"
LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = "/opt/gitdock"
SERVICE_PORT = 3099

def ssh_exec(client, cmd, label=""):
    """Execute command and print output."""
    if label:
        print(f"  → {label}")
    stdin, stdout, stderr = client.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        print(f"    {out[:300]}")
    if err and exit_code != 0:
        print(f"    [err] {err[:300]}")
    return out, err, exit_code

def main():
    print(f"[1] Connecting to {USER}@{HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10,
                       look_for_keys=False, allow_agent=False)
    except paramiko.ssh_exception.AuthenticationException:
        # Try keyboard-interactive
        try:
            transport = paramiko.Transport((HOST, PORT))
            transport.connect(username=USER, password=PASS)
            client._transport = transport
        except Exception as e2:
            print(f"  Connection failed: {e2}")
            sys.exit(1)
    except Exception as e:
        print(f"  Connection failed: {e}")
        sys.exit(1)
    print("  Connected.\n")

    # Check OS / package manager
    print("[2] Detecting OS...")
    out, _, _ = ssh_exec(client, "cat /etc/os-release 2>/dev/null | head -3")
    
    # Detect package manager
    out_pm, _, _ = ssh_exec(client, "which apt-get 2>/dev/null || which dnf 2>/dev/null || which yum 2>/dev/null || which pacman 2>/dev/null || echo none")
    pm = out_pm.strip().split("/")[-1] if out_pm.strip() != "none" else None
    print(f"  Package manager: {pm}\n")

    # Install Node.js if needed
    print("[3] Checking Node.js...")
    out_node, _, rc = ssh_exec(client, "node --version 2>/dev/null")
    if rc != 0 or not out_node:
        print("  Node.js not found, installing...")
        if pm == "apt-get":
            ssh_exec(client, "apt-get update -qq && apt-get install -y -qq nodejs npm git", "Installing node/npm/git via apt")
        elif pm == "dnf":
            ssh_exec(client, "dnf install -y nodejs npm git", "Installing via dnf")
        elif pm == "yum":
            ssh_exec(client, "curl -fsSL https://rpm.nodesource.com/setup_22.x | bash - && yum install -y nodejs git", "Installing via nodesource + yum")
        elif pm == "pacman":
            ssh_exec(client, "pacman -Sy --noconfirm nodejs npm git", "Installing via pacman")
        else:
            print("  Unknown package manager. Trying curl-based install...")
            ssh_exec(client, "curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs git", "nodesource fallback")
        out_node, _, rc = ssh_exec(client, "node --version 2>/dev/null")
        if rc != 0:
            print("  ERROR: Failed to install Node.js")
            sys.exit(1)
    print(f"  Node.js: {out_node}\n")

    # Check git
    ssh_exec(client, "which git >/dev/null 2>&1 || (apt-get install -y -qq git 2>/dev/null || dnf install -y git 2>/dev/null || pacman -S --noconfirm git 2>/dev/null)", "Ensuring git is installed")

    # Create remote directory
    print("[4] Setting up remote directory...")
    ssh_exec(client, f"mkdir -p {REMOTE_DIR}")

    # Upload files via SFTP
    print("[5] Uploading application files...")
    sftp = client.open_sftp()
    
    files_to_upload = ["server.js", "package.json"]
    for fname in files_to_upload:
        local_path = os.path.join(LOCAL_DIR, fname)
        remote_path = f"{REMOTE_DIR}/{fname}"
        if os.path.isfile(local_path):
            print(f"  → {fname}")
            sftp.put(local_path, remote_path)
    
    # Create storage dirs
    ssh_exec(client, f"mkdir -p {REMOTE_DIR}/storage/repos {REMOTE_DIR}/storage/files {REMOTE_DIR}/storage/tmp")
    sftp.close()
    print()

    # Install npm dependencies
    print("[6] Installing npm dependencies...")
    ssh_exec(client, f"cd {REMOTE_DIR} && npm install --production 2>&1 | tail -5", "npm install")
    print()

    # Stop existing service if running
    print("[7] Creating systemd service...")
    ssh_exec(client, "systemctl stop gitdock 2>/dev/null", "Stopping existing service (if any)")

    service_unit = f"""[Unit]
Description=GitDock - Self-hosted Git + File vault
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={REMOTE_DIR}
Environment=PORT={SERVICE_PORT}
Environment=STORAGE_DIR={REMOTE_DIR}/storage
ExecStart=/usr/bin/env node {REMOTE_DIR}/server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    
    # Write service file
    stdin, stdout, stderr = client.exec_command(f"cat > /etc/systemd/system/gitdock.service << 'SERVICEEOF'\n{service_unit}SERVICEEOF")
    stdout.channel.recv_exit_status()
    
    ssh_exec(client, "systemctl daemon-reload", "Reloading systemd")
    ssh_exec(client, "systemctl enable gitdock", "Enabling gitdock service")
    ssh_exec(client, "systemctl start gitdock", "Starting gitdock service")
    print()

    # Verify
    print("[8] Verifying deployment...")
    time.sleep(2)
    out_status, _, _ = ssh_exec(client, "systemctl is-active gitdock")
    if "active" in out_status:
        print(f"  ✓ GitDock is running on port {SERVICE_PORT}")
    else:
        ssh_exec(client, "journalctl -u gitdock --no-pager -n 20", "Service logs")
        print("  ✗ Service may have failed. Check logs above.")

    # Show listening port
    ssh_exec(client, f"ss -tlnp | grep {SERVICE_PORT} || netstat -tlnp 2>/dev/null | grep {SERVICE_PORT}", "Checking port binding")
    
    client.close()
    print(f"\n{'='*50}")
    print(f"  Deployment complete!")
    print(f"  Service: gitdock.service (systemd)")
    print(f"  Port: {SERVICE_PORT}")
    print(f"  Set your reverse proxy to: http://10.27.27.226:{SERVICE_PORT}")
    print(f"  Login: c4g7 / admin")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
