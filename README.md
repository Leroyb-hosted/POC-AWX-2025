# PoC AWX - Testrepository

Deze repository bevat scripts, configuraties en handleidingen voor het testen en uitrollen van een Proof of Concept (PoC) rondom **AWX automatisering** op Debian 12 servers.

---

## Inhoud van de repository

- **Mini Knowledge Base**  
  Verzameling van links naar best practices, code style sheets, cursussen en beheer-taken.

- **Public Key AWX Automatiseringssysteem**  
  Public SSH-key bestand voor AWX:  
  `public_keys/awx_service_deploy_key_eddsa_key_20250513.pub`

- **Bootstrap Script (GitHub)**  
  `bootstrap_debian12_vm_github.sh`  
  Script voor het aanmaken van een service-user, installeren van de SSH-key (uit GitHub) en het hardenen van SSH op Debian 12.

- **Bootstrap Script (GitLab)**  
  `bootstrap_debian12_vm_gitlab.sh`  
  Vergelijkbaar script, maar haalt de SSH-key op via de GitLab API (met Private-Token argument).

- **Static IP Configuratie Script**  
  `script-set_static_IP_systemd.sh`  
  Bash script om een statisch IP-adres in te stellen via systemd-networkd.

- **IaC voor AWX Tower**  
  Ansible playbooks, rollen en configuratievoorbeelden voor het provisionen en beheren van AWX Tower.

---

## Gebruik

### 1. Repository clonen

```bash
git clone <repository-url>
cd <repository-folder>
