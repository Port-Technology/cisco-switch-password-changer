
# Cisco Local User Audit & Password Update

Automate auditing of **locally configured users** and optionally **rotate a local user's password** across many Cisco switches.

Supports:
- **Cisco IOS / IOS-XE**
- **Cisco NX-OS (Nexus)**
- **CatOS** (best-effort; per-user accounts often not present)

Uses [Netmiko](https://github.com/ktbyers/netmiko) for robust SSH CLI automation.

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Hosts file format

Create a `hosts.txt` (or any filename) with one device per line. Optionally hint the OS after a comma.

```
10.1.1.10
10.1.1.11,ios
10.1.1.12,nxos
10.1.1.13,catos
```

Supported hints: `ios`, `nxos`, `catos`

If no hint is provided, the script attempts to auto-detect via `show version` / `show config` heuristics.

## Usage

Audit only (list local users on each device):

```bash
python3 cisco_local_users_audit_and_password_update.py   --hosts hosts.txt   --login-user admin   --login-pass 'SuperSecret'   --audit
```

Change a specific local user's password on each device (and still print discovered users):

```bash
python3 cisco_local_users_audit_and_password_update.py   --hosts hosts.txt   --login-user admin   --login-pass 'SuperSecret'   --target-user netops   --new-pass 'NewP@ssw0rd!'   --commit
```

Include enable secret when required:

```bash
python3 cisco_local_users_audit_and_password_update.py   --hosts hosts.txt   --login-user admin   --login-pass 'pw'   --enable-secret 'enablepw'   --audit
```

### What it does

- **IOS/IOS-XE**: prefers `username <u> secret <pw>` (secure hash), falls back to `password` if needed.
- **NX-OS**: uses `username <u> password <pw>`.
- **CatOS**: best-effort. Attempts `set username <u> password <pw>` if supported, and surfaces shared password constructs (e.g., `set enablepass`, line/vty passwords).

Changes are **not saved** unless you pass `--commit` (then it tries `write memory` / `copy run start`).

## Security & Safety Notes

- Run from a secured admin host. Avoid putting real passwords in shell history; omit `--login-pass` to be prompted.
- Consider using a PAM or secrets manager and/or per-device creds.
- Test on a small subset (or a lab pair) before broad rollout.
- The script targets **existing** users. If you need _create-if-missing_ behavior with roles/privilege (e.g., NX-OS roles), open the script and extend `change_password()` accordingly—or ask for an extended version.

## Requirements

See `requirements.txt` for Python dependencies.

Python 3.8+ recommended.

## Exit codes

- `0`: Success (overall run completed; individual devices may still show per-host failures)
- `2`: Invalid arguments

## License

MIT (or adapt to your internal policy).
