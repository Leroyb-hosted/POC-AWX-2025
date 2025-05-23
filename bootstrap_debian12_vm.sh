#!/usr/bin/env bash
#===============================================================================
# Bootstrap Script: Debian 12 VM for GitHub Public Repo (Single User)
#===============================================================================
# This script will:
#  - Ensure it's run with root privileges (prompts for sudo password if not root)
#  - Create a non-root user + group for Ansible/automation
#  - Fetch and install SSH public key from your GitHub repo (public access)
#  - Harden sudo and SSH access to only AWX & GitLab controllers
#  - Disable password-based SSH for the automation user and root login
#  - Logs all sudo actions based on group, including local sudo elevation!
#  - This script is safe to run multiple times (idempotent).
#
# Requirements:
#  - VM must reach your GitLab URL (internal 10.0.0.13)
#  - Run as root or via sudo
#
# Usage:
# 1. Download script locally:
#     wget -O bootstrap_debian12_vm_github.sh https://raw.githubusercontent.com/Leroyb-hosted/POC-AWX-2025/main/bootstrap_debian12_vm_github.sh
# 2. Execute with sudo:
#     sudo bash bootstrap_debian12_vm_github.sh
#
# Oneliner: wget -N -O ./bootstrap_debian12_vm_github.sh https://raw.githubusercontent.com/Leroyb-hosted/POC-AWX-2025/main/bootstrap_debian12_vm_github.sh && sudo bash ./bootstrap_debian12_vm_github.sh
# TIP: you can specify the USERNAME var by "sudo bash bootstrap_debian12_vm_gitlab.sh <TOKENKEY> <USERNAME>"
# Defaults to ansible-managed-hosted atm
#===============================================================================
# DEBUG TOOLS
#===============================================================================
# - Check if public key is present:
#     sudo cat /home/ansible-managed-hosted/.ssh/authorized_keys
#
# - Test downloading public key manually:
#     wget -O awx_key.pub https://raw.githubusercontent.com/Leroyb-hosted/POC-AWX-2025/main/awx_service_deploy_key_eddsa_key_20250513.pub
# 
# - check what users are on system currently:
#     cat /etc/passwd | grep ansible-managed-hosted or cat /etc/passwd  #list of all users.
#===============================================================================

### TODO ###
# Right now the SSHD service always reloads, instead of checking if file is diff and then decide!

#===============================================================================
# VARIABLES (customize before running)
#===============================================================================
USERNAME="${1:-ansible-managed-hosted}"  # Uses first argument, else defaults to service user. Change here if needed.
GROUPNAME="service-account" # group to create
GITHUB_USER=Leroyb-hosted
GITHUB_REPO=POC-AWX-2025
BRANCH=main
KEY_FILE=awx_service_deploy_key_eddsa_key_20250513.pub

REPO_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${BRANCH}/${KEY_FILE}"  # raw.githubusercontent URL for your pubkey

# Hostname should work too.
# SSH restrictions: allow IPs to connect to service account via SSH
AWX_CONTROLLER_IP="10.0.0.15" 
GITLAB_CONTROLLER_IP="10.0.0.13"

# Optional: Logging file (persistent logs)
# LOGFILE="/var/log/bootstrap_${USERNAME}_$(date +%F_%H-%M-%S).log"
# exec > >(tee -a "$LOGFILE") 2>&1

# Secure umask applied to new files
# owner RWX perms, read and execute for group, others no perms
umask 027 

#===============================================================================
# FUNCTIONS
#===============================================================================
log()   { echo "[BOOTSTRAP] $*"; }
error_exit() { echo "[ERROR] $*" >&2; exit 1; }

#===============================================================================
# Ensure root privileges
#===============================================================================
if [ "$EUID" -ne 0 ]; then
  echo "This script requires root. Prompting for sudo..."
  exec sudo bash "$0" "$@"
fi

#===============================================================================
# MAIN
#===============================================================================
set -euo pipefail
log "Starting Guthub based bootstrap..."
reload_sshd=0

# Make sure /etc/ssh/sshd_config.d exists (fix for minimal Debian image)
mkdir -p /etc/ssh/sshd_config.d

# Create group if missing
log "=== Group: ${GROUPNAME} setup ==="
if ! getent group "${GROUPNAME}" >/dev/null; then
  log "Creating group '${GROUPNAME}'"
  groupadd --system "${GROUPNAME}" || error_exit "groupadd failed"
  log "Group '${GROUPNAME}' created"
else
  log "Group exists"
fi

# Fix home dir, user and group ownership if it exists
if [ -d "/home/${USERNAME}" ]; then
  chown -R "${USERNAME}:${GROUPNAME}" "/home/${USERNAME}"
fi

# Create user if missing
log "=== User: ${USERNAME} setup ==="
if ! id -u "${USERNAME}" >/dev/null 2>&1; then
  log "Creating user '${USERNAME}'"
  useradd --system --create-home --gid "${GROUPNAME}" --shell /bin/bash "${USERNAME}" || error_exit "useradd failed"
  log "User '${USERNAME}' created"
else
  log "User exists"
fi

# Create SSH directory
SSH_DIR="/home/$USERNAME/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

log "=== SSH directory for ${USERNAME} ==="
if [ ! -d "${SSH_DIR}" ]; then
  log "Creating .ssh directory"
  install -d -m 700 -o "${USERNAME}" -g "${GROUPNAME}" "${SSH_DIR}" || error_exit "failed to create .ssh dir"
  log ".ssh directory created for ${USERNAME}"
else
  log ".ssh directory exists for ${USERNAME}"
fi

# Fetch public key
log "=== Downloading public key ==="
log "Downloading public key from ${REPO_URL}"
wget -q -O "${AUTH_KEYS}" "${REPO_URL}" || error_exit "wget public key failed"
log "Public key downloaded and written to ${AUTH_KEYS}"

# Setting permissions for authorized_keys
log "=== Setting permissions on authorized_keys ==="
chown "${USERNAME}:${GROUPNAME}" "${AUTH_KEYS}" && chmod 600 "${AUTH_KEYS}"
log "Permissions set on ${AUTH_KEYS}"

# Sudoers hardening + logging (GROUP-BASED)
SUDO_LOG_DIR=/var/log/sudo-ansible
SUDOERS_FILE=/etc/sudoers.d/${GROUPNAME}

log "=== Sudoers hardening & logging for group ${GROUPNAME} ==="
mkdir -p "$SUDO_LOG_DIR" && chown root:root "$SUDO_LOG_DIR" && chmod 750 "$SUDO_LOG_DIR" || error_exit "mkdir/chown/chmod $SUDO_LOG_DIR failed"
cat <<EOF > "${SUDOERS_FILE}"
# Allow group ${GROUPNAME} to sudo as root (must authenticate with root’s password)
Defaults:%${GROUPNAME}    rootpw,log_input,log_output,iolog_dir=${SUDO_LOG_DIR}
%${GROUPNAME}    ALL=(root) ALL
EOF
chmod 440 "${SUDOERS_FILE}" || error_exit "chmod sudoers failed"
log "sudoers updated: members of ${GROUPNAME} require root password to sudo"

# Restrict SSH to AWX/GitLab Controllers IP
SSH_CONFIG="/etc/ssh/sshd_config.d/99-awx-restrict.conf"
log "=== Restricting SSH to allowed IP/controllers (${AWX_CONTROLLER_IP},${GITLAB_CONTROLLER_IP}) ==="

cat <<EOF > "${SSH_CONFIG}"
# Only allow SSH from defined IP/controllers
Match Address $AWX_CONTROLLER_IP,$GITLAB_CONTROLLER_IP
  AllowUsers ${USERNAME}
EOF
chmod 644 "${SSH_CONFIG}" || error_exit "chmod sshd config failed"
log "SSH restriction config updated at ${SSH_CONFIG}"
reload_sshd=1

# Disable SSH password‐based login for Ansible service user (only 1 user at a time atm)
SSHD_CONF="/etc/ssh/sshd_config.d/90-${USERNAME}-passwd.conf"
log "=== Disabling password authentication for ${USERNAME} ==="
cat <<EOF > "${SSHD_CONF}"
Match User ${USERNAME}
  PasswordAuthentication no
EOF
chmod 644 "${SSHD_CONF}" || error_exit "chmod passwd config failed"
log "Password authentication disabled for ${USERNAME}"
reload_sshd=1

# Disable SSH login for root
ROOT_CONF="/etc/ssh/sshd_config.d/91-disable-root-account.conf"
log "=== Disabling SSH login for root ==="
cat <<EOF > "${ROOT_CONF}"
# Disable SSH access for root
PermitRootLogin no
EOF
chmod 644 "${ROOT_CONF}" || error_exit "chmod root config failed"
log "SSH login for root disabled"
reload_sshd=1

# Verify sudoers file syntax and entry
log "=== Verifying sudoers file syntax for ${GROUPNAME} ==="
if visudo -cf "/etc/sudoers.d/${GROUPNAME}"; then
  log "✔ sudoers syntax OK for ${GROUPNAME}"
else
  error_exit "✖ sudoers syntax error in /etc/sudoers.d/${GROUPNAME}"
fi

#priv check
log "=== Verifying sudo privileges for ${USERNAME} ==="
sudo -l -U "${USERNAME}" >/dev/null 2>&1 \
&& log "✔ sudo privileges OK for ${USERNAME}" || error_exit "✖ sudo privileges misconfigured for ${USERNAME}"

# Reload sshd once if needed
log "=== Reloading sshd ==="
if [ "$reload_sshd" -eq 1 ]; then
  systemctl reload sshd || error_exit "reload sshd failed"
  log "sshd reloaded"
fi

log "Bootstrap script completed for ${USERNAME}."
log "You can now SSH as '${USERNAME}' from ${AWX_CONTROLLER_IP}, ${GITLAB_CONTROLLER_IP} (public key only)."
log "Review sudo activity in $SUDO_LOG_DIR. If troubleshooting SSH, see /var/log/auth.log."
log "To verify SSH config, try: sudo -u ${USERNAME} ssh -T localhost"
exit 0
