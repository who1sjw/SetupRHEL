# SetupRHEL with Ansible

This repository provides an automated way to bootstrap and harden **RHEL7/CentOS7** servers using a shell script executed via Ansible.

## Contents

- `setupRHEL.sh`  
  The main script that configures baseline security, users, services, sysctl parameters, and other OS-level settings.  
  It includes support for **change/reboot markers** so Ansible can reliably detect if changes occurred and if a reboot is required.

- `setup.yml`  
  Ansible playbook that:
  1. Copies the script to the target host.
  2. Clears any previous state markers.
  3. Runs the script in non-interactive mode (`yes` argument).
  4. Detects changes using the script’s `CHANGED=1` output or marker files.
  5. Triggers a reboot if required.
  6. Optionally cleans markers after successful execution.

## How It Works

- The script writes marker files:
  - `/var/run/setupRHEL.changed` → Indicates the system state was modified.
  - `/var/run/setupRHEL.reboot` → Indicates a reboot is required for changes to take effect.

- Ansible uses these markers and the script’s `CHANGED=1` output to provide **idempotent runs**.

## Usage

1. Edit your `inventory.ini`:

   ```ini
   [servers]
   myserver ansible_host=192.168.1.100 ansible_user=myuser ansible_become=true
   ```

2. Run the playbook:

   ansible-playbook -i inventory.ini setup.yml

3. Ansible will:
   - Apply the script.
   - Report changed status correctly.
   - Reboot automatically if required.

Notes

- Designed for RHEL7/CentOS7 only.
- Some settings (e.g., SELinux, GRUB options) require a reboot.
- Always test on a staging host before applying to production.
- You can extend the playbook or script for additional OS versions or roles.

License

MIT License