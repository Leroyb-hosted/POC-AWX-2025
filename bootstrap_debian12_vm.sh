#!/usr/bin/env bash
#-------------------------------------------------------------------------------

############### GITHUB ONLY!!! ############### 
# Bootstrap script for Debian 12 VM
# - Creates a non-root user & group (ansible-managed-hosted)
# - Adds SSH public key from GitHub
# - Configures sudoers (logging, requires password)
# - Hardens SSH and access from IP
# Usage:
#  sudo wget -O /home/leroyadmin-hosted/bootstrap_debian12_vm.sh https://raw.githubusercontent.com/Leroyb-hosted/POC-AWX-2025/main/bootstrap_debian12_vm.sh && sudo bash /home/leroyadmin-hosted/bootstrap_debian12_vm.sh
# Note: Run as root. Exits on error.
#-------------------------------------------------------------------------------

#===============================================================================
# VARIABLES (customize before running)
#===============================================================================
USERNAME=ansible-managed-hosted
GROUPNAME=service-account
GITHUB_USER=Leroyb-hosted
GITHUB_REPO=POC-AWX-2025
BRANCH=main
KEY_FILE=awx_service_deploy_key_eddsa_key_20250513.pub

REPO_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${BRANCH}/${KEY_FILE}"  # raw.githubusercontent URL for your pubkey

AWX_CONTROLLER_IP="10.0.0.15" # AWX controller IP for SSH restriction # this is int-auto-1 AWXtower

#===============================================================================
# FUNCTIONS
#===============================================================================
log()   { echo "[BOOTSTRAP] $*"; }
error_exit() { echo "[ERROR] $*" >&2; exit 1; }

#===============================================================================
# MAIN
#===============================================================================
set -e
log "Starting bootstrap..."

# 1) Create group
if ! getent group "${GROUPNAME}" >/dev/null; then
  log "Creating group '${GROUPNAME}'"
  groupadd --system "${GROUPNAME}" || error_exit "groupadd failed"
else
  log "Group exists"
fi

# 2) Create user
if ! id -u "${USERNAME}" >/dev/null 2>&1; then
  log "Creating user '${USERNAME}'"
  useradd --system --create-home --gid "${GROUPNAME}" \
    --shell /bin/bash "${USERNAME}" || error_exit "useradd failed"
else
  log "User exists"
fi

# 3) SSH directory
SSH_DIR="/home/${USERNAME}/.ssh"
if [ ! -d "${SSH_DIR}" ]; then
  log "Creating .ssh directory"
  install -d -m 700 -o "${USERNAME}" -g "${GROUPNAME}" "${SSH_DIR}" \
    || error_exit "mkdir .ssh failed"
fi

# 4) Fetch public key
AUTH_KEYS="${SSH_DIR}/authorized_keys"
log "Downloading public key from ${REPO_URL}"
wget -q -O "${AUTH_KEYS}" "${REPO_URL}" || error_exit "wget public key failed"

# 5) Permissions
log "Setting permissions on authorized_keys"
chown "${USERNAME}:${GROUPNAME}" "${AUTH_KEYS}" && chmod 600 "${AUTH_KEYS}"

# 6) Sudoers hardening + logging
SUDO_LOG_DIR=/var/log/sudo-ansible
SUDOERS_FILE=/etc/sudoers.d/${USERNAME}
log "Configuring sudoers"
mkdir -p "${SUDO_LOG_DIR}" || error_exit "mkdir sudo log dir failed"
chown root:root "${SUDO_LOG_DIR}" && chmod 750 "${SUDO_LOG_DIR}"
cat <<EOF > "${SUDOERS_FILE}"
# Allow ${USERNAME} to sudo to root (password required)
Defaults:${USERNAME} log_input, log_output, iolog_dir=${SUDO_LOG_DIR}
${USERNAME} ALL=(ALL) ALL
EOF
chmod 440 "${SUDOERS_FILE}" || error_exit "chmod sudoers failed"

# 7) Restrict SSH to AWX controller IP
SSH_CONFIG="/etc/ssh/sshd_config.d/99-awx-restrict.conf"
log "Restricting SSH to AWX controller (${AWX_CONTROLLER_IP})"
cat <<EOF > "${SSH_CONFIG}"
# Only allow SSH from AWX controller
Match Address ${AWX_CONTROLLER_IP}
  AllowUsers ${USERNAME}
EOF
chmod 644 "${SSH_CONFIG}" || error_exit "chmod sshd config failed"
systemctl reload sshd || error_exit "reload sshd failed"

# 8) Disable password‐based login for Ansible user
log "Disabling password authentication for ${USERNAME}"
SSHD_CONF="/etc/ssh/sshd_config.d/90-${USERNAME}-passwd.conf"
cat <<EOF > "${SSHD_CONF}"
Match User ${USERNAME}
  PasswordAuthentication no
EOF
chmod 644 "${SSHD_CONF}" || error_exit "chmod passwd config failed"
systemctl reload sshd || error_exit "reload sshd failed"

# 9) Disable SSH login for root
log "Disabling SSH login for root"
ROOT_CONF="/etc/ssh/sshd_config.d/91-disable-root.conf"
cat <<EOF > "${ROOT_CONF}"
# Disable SSH access for root
PermitRootLogin no
EOF
chmod 644 "${ROOT_CONF}" || error_exit "chmod root config failed"
systemctl reload sshd || error_exit "reload sshd failed"

# 10) Test sudo escalation
log "Testing sudo escalation for ${USERNAME}"
su - "${USERNAME}" -c "sudo -l" || error_exit "sudo -l failed"
su - "${USERNAME}" -c "sudo whoami" || error_exit "sudo whoami failed"

log "Bootstrap complete for ${USERNAME}"
exit 0
