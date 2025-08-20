#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cisco_local_users_audit_and_password_update.py
#
# Usage examples:
# 1) Audit only (list local users on each device):
#    python3 script.py --hosts hosts.txt --login-user admin --login-pass 'SuperSecret' --audit
#
# 2) Change a specific user's password across all devices (and still print users found):
#    python3 script.py --hosts hosts.txt --login-user admin --login-pass 'SuperSecret' \
#                      --target-user netops --new-pass 'NewP@ssw0rd!' --commit
#
# 3) Provide enable secret if your devices require it:
#    python3 script.py --hosts hosts.txt --login-user admin --login-pass 'pw' --enable-secret 'enablepw' --audit
#
# hosts.txt format:
# - One host per line. Optional second field to hint OS type:
#   10.1.1.10
#   10.1.1.11,ios
#   10.1.1.12,nxos
#   10.1.1.13,catos
#
# Supported types (hint or autodetect): ios, nxos, catos
#
# Notes:
# - NX-OS uses 'username <u> password <pw>' (no 'secret').
# - IOS/IOS-XE uses 'username <u> secret <pw>' (preferred over 'password').
# - CatOS is legacy and inconsistent; this script tries common patterns and will report if it can't apply.

import argparse
import re
import sys
from getpass import getpass
from typing import List, Tuple, Optional

from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException

# ---------- Helpers ----------

def parse_hosts_file(path: str) -> List[Tuple[str, Optional[str]]]:
    hosts = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            if ',' in s:
                ip, hint = [x.strip() for x in s.split(',', 1)]
                hosts.append((ip, hint.lower()))
            else:
                hosts.append((s, None))
    return hosts

def detect_platform(conn) -> str:
    """
    Return one of: 'ios', 'nxos', 'catos', or 'unknown'
    """
    try:
        out = conn.send_command("show version", use_textfsm=False)
    except Exception:
        out = ""

    text = out.lower()

    if "nx-os" in text or "nexus" in text:
        return "nxos"
    if "ios" in text or "ios-xe" in text or "cisco ios software" in text:
        return "ios"

    # CatOS is very old; some boxes don't support 'show version' as IOS does.
    # Try a CatOS-ish command to see if it's accepted.
    try:
        cat = conn.send_command("show config", use_textfsm=False)
        if "catalyst operating system" in cat.lower() or "set " in cat.lower():
            return "catos"
    except Exception:
        pass

    return "unknown"

def enter_enable(conn, enable_secret: Optional[str]) -> None:
    if not conn.check_enable_mode():
        try:
            conn.enable()
        except Exception:
            # If enable fails, proceed in user mode when possible
            pass

def get_local_users(conn, platform: str) -> List[str]:
    """
    Returns a list of usernames configured locally.
    """
    users = set()

    # Try a few ways per platform
    cmds_by_platform = {
        "ios": [
            "show running-config | include ^username",
            "show run | i ^username",
            "show running-config | section username",
        ],
        "nxos": [
            "show running-config | include ^username",
            "show run | i ^username",
            "show run username",
        ],
        "catos": [
            # CatOS typically doesn't use 'username' as in IOS;
            # Instead, it relies on 'set' commands for enable/console/vty.
            "show config",
        ],
        "unknown": [
            "show running-config | include ^username",
            "show run | i ^username",
            "show config",
        ],
    }

    for cmd in cmds_by_platform.get(platform, cmds_by_platform["unknown"]):
        try:
            out = conn.send_command(cmd, use_textfsm=False)
        except Exception:
            continue
        if not out:
            continue

        if platform == "catos":
            # Look for common CatOS constructs (best-effort)
            for line in out.splitlines():
                l = line.strip()
                if re.search(r"\bset\s+username\s+(\S+)\s+password\b", l, re.IGNORECASE):
                    m = re.search(r"\bset\s+username\s+(\S+)\s+password\b", l, re.IGNORECASE)
                    if m:
                        users.add(m.group(1))
                # Also surface console/vty/enable shared passwords
                if re.search(r"\bset\s+(enablepass|password)\b", l, re.IGNORECASE):
                    users.add("(catos: shared password found; no per-user accounts)")
        else:
            for line in out.splitlines():
                l = line.strip()
                # IOS/NX-OS typically: username <user> ...
                m = re.match(r"^username\s+([A-Za-z0-9._\-]+)\b", l)
                if m:
                    users.add(m.group(1))

        if users:
            break

    return sorted(users)

def change_password(conn, platform: str, user: str, new_password: str):
    """
    Attempt to change the given user's password based on platform.
    Returns (success, message).
    """
    try:
        if platform == "nxos":
            cfg = [f"username {user} password {new_password}"]
            conn.send_config_set(cfg)
            return True, "NX-OS password updated (username password)."

        elif platform == "ios":
            cfg = [f"username {user} secret {new_password}"]
            result = conn.send_config_set(cfg)
            if "Invalid input" in result or "% Invalid" in result:
                cfg = [f"username {user} password {new_password}"]
                conn.send_config_set(cfg)
                return True, "IOS password updated (username password)."
            return True, "IOS password updated (username secret)."

        elif platform == "catos":
            try:
                result = conn.send_config_set([f"set username {user} password {new_password}"])
                if "Incomplete" in result or "Invalid" in result or "% " in result:
                    return False, "CatOS: 'set username' not accepted on this device."
                return True, "CatOS password updated (best-effort)."
            except Exception as e:
                return False, f"CatOS update failed: {e}"

        else:
            try:
                result = conn.send_config_set([f"username {user} secret {new_password}"])
                if "Invalid input" in result or "% Invalid" in result:
                    result = conn.send_config_set([f"username {user} password {new_password}"])
                return True, "Password updated (generic path)."
            except Exception as e:
                return False, f"Unknown platform update failed: {e}"

    except Exception as e:
        return False, f"Error sending config: {e}"

def save_config(conn, platform: str) -> None:
    try:
        conn.save_config()
        return
    except Exception:
        pass
    for cmd in ["write memory", "copy running-config startup-config", "copy run start"]:
        try:
            out = conn.send_command_timing(cmd)
            if "Destination filename" in out or "confirm" in out.lower() or out.strip().endswith("]") or out.strip().endswith("?"):
                conn.send_command_timing("\n")
            return
        except Exception:
            continue

def connect_device(ip: str, username: str, password: str, enable_secret: Optional[str], os_hint: Optional[str]):
    device_type_map = {
        "ios": "cisco_ios",
        "nxos": "cisco_nxos",
        "catos": "cisco_ios",
    }
    device_type = device_type_map.get(os_hint or "ios", "cisco_ios")

    return ConnectHandler(
        device_type=device_type,
        host=ip,
        username=username,
        password=password,
        secret=enable_secret or password,
        fast_cli=False,
    )

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Audit and update local users on Cisco IOS/NX-OS/CatOS switches.")
    parser.add_argument("--hosts", required=True, help="Path to hosts file (one IP per line, optional ',<os_hint>').")
    parser.add_argument("--login-user", required=True, help="Username for device login.")
    parser.add_argument("--login-pass", help="Password for device login. If omitted, will prompt.")
    parser.add_argument("--enable-secret", help="Enable secret (optional).")
    parser.add_argument("--audit", action="store_true", help="Audit local users (printed to stdout).")
    parser.add_argument("--target-user", help="Local username to change password for (existing user).")
    parser.add_argument("--new-pass", help="New password for --target-user.")
    parser.add_argument("--commit", action="store_true", help="Save config after changes.")
    args = parser.parse_args()

    if not args.audit and not args.target_user:
        print("Nothing to do: specify --audit and/or --target-user with --new-pass.", file=sys.stderr)
        sys.exit(2)

    if args.target_user and not args.new_pass:
        print("Error: --target-user requires --new-pass.", file=sys.stderr)
        sys.exit(2)

    login_pass = args.login_pass or getpass("Device login password: ")
    enable_secret = args.enable_secret

    hosts = parse_hosts_file(args.hosts)

    print("\n=== Cisco Local User Audit / Password Update ===\n")
    for ip, os_hint in hosts:
        print(f"--- {ip} ---")
        try:
            conn = connect_device(ip, args.login_user, login_pass, enable_secret, os_hint)
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            print(f"  CONNECT FAILED: {e}")
            continue
        except Exception as e:
            print(f"  CONNECT ERROR: {e}")
            continue

        try:
            enter_enable(conn, enable_secret)
        except Exception:
            pass

        platform = os_hint or detect_platform(conn)
        if platform == "unknown":
            print("  Platform: unknown (proceeding with generic commands)")
        else:
            print(f"  Platform: {platform}")

        users = []
        try:
            users = get_local_users(conn, platform)
            if users:
                print("  Local users found:")
                for u in users:
                    print(f"    - {u}")
            else:
                print("  No local users discovered (or not detectable).")
        except Exception as e:
            print(f"  AUDIT ERROR: {e}")

        if args.target_user and args.new_pass:
            if users and args.target_user not in users and platform != "catos":
                print(f"  WARNING: target user '{args.target_user}' not observed in config (still attempting).")
            ok, msg = change_password(conn, platform, args.target_user, args.new_pass)
            if ok:
                print(f"  PASSWORD CHANGE: success -> {msg}")
                if args.commit:
                    try:
                        save_config(conn, platform)
                        print("  SAVE CONFIG: success")
                    except Exception as e:
                        print(f"  SAVE CONFIG: failed ({e})")
            else:
                print(f"  PASSWORD CHANGE: FAILED -> {msg}")

        try:
            conn.disconnect()
        except Exception:
            pass

        print("")

    print("=== Done ===")

if __name__ == "__main__":
    main()
