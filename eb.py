#!/usr/bin/env python3
import sys
import re
import urllib.parse
import argparse
import textwrap
import os

# The Buddy Registry
REPOS = {
    "landscape-client": "canonical/landscape-client",
    "landscape-server": "canonical/landscape-server",
    "maas": "canonical/maas",
    "lxd": "canonical/lxd",
    "juju": "juju/juju",
    "cloud-init": "canonical/cloud-init",
    "curtin": "canonical/curtin",
    "subiquity": "canonical/subiquity",
    "microk8s": "canonical/microk8s",
    "microstack": "canonical/microstack",
    "charmed-kubernetes": "charmed-kubernetes/bundle",
    "ubuntu-desktop-installer": "canonical/ubuntu-desktop-installer",
    "snapd": "canonical/snapd",
    "snapcraft": "canonical/snapcraft",
    "charmcraft": "canonical/charmcraft",
    "rockcraft": "canonical/rockcraft",
    "cos-lite": "canonical/cos-lite-bundle",
    "netplan": "canonical/netplan",
    "autoinstall": "canonical/autoinstall"
}

def get_url(repo, msg):
    """Generates fuzzy GitHub link for deep searches."""
    clean = re.sub(r'\[.*?\]|\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|0x[0-9a-fA-F]+|[0-9a-f\-]{36}', '', msg)
    clean = re.sub(r'[^\w\s\']', ' ', clean)
    clean_terms = " ".join(clean.split())[:80]
    query = f'repo:{repo} {clean_terms}'
    params = urllib.parse.urlencode({'q': query, 'type': 'code'})
    return f"https://github.com/search?{params}"

def print_table_header():
    """Prints the ASCII table header."""
    print(f"\n+ {'-'*25} + {'-'*70} +")
    print(f"| {'SOURCE LOG FILE':<25} | {'ERROR MESSAGE':<70} |")
    print(f"+ {'-'*25} + {'-'*70} +")

def print_table_row(filename, error_msg):
    """Prints a wrapped table row."""
    fname = (filename[:22] + '...') if len(filename) > 25 else filename
    clean_msg = error_msg.replace('\n', ' ').replace(' | ', ' ')
    wrapped_err = textwrap.wrap(clean_msg, width=70)
    if not wrapped_err: return

    print(f"| {fname:<25} | {wrapped_err[0]:<70} |")
    for line in wrapped_err[1:]:
        print(f"| {' ':<25} | {line:<70} |")
    print(f"+ {'-'*25} + {'-'*70} +")

def parse_log_to_table(path):
    """Scans log file for errors and groups Tracebacks/Multi-line failures."""
    trigger_pattern = re.compile(r'(?:FATAL|ERROR|CRITICAL|CRIT|WARNING|FAIL|Failure)', re.IGNORECASE)
    continuation_pattern = re.compile(r'^(\s+|Traceback|File\s"|[\w\.]+: )')
    
    seen = set()
    filename = os.path.basename(path)
    
    try:
        with open(path, 'r', errors='ignore') as f:
            lines = f.readlines()
            i = 0
            while i < len(lines):
                line_content = lines[i].strip()
                match = trigger_pattern.search(line_content)
                if match:
                    # Capture from the trigger word onwards to avoid losing context like 'KeyError'
                    parts = line_content.split()
                    full_error = ""
                    for idx, word in enumerate(parts):
                        if trigger_pattern.search(word):
                            full_error = " ".join(parts[idx:])
                            break
                    
                    if not full_error:
                        full_error = line_content

                    j = i + 1
                    # Peek ahead to capture stack traces
                    while j < len(lines) and j < i + 8:
                        next_line = lines[j].strip()
                        if not next_line:
                            j += 1
                            continue
                        if continuation_pattern.search(next_line) or "TRACEBACK" in next_line.upper():
                            full_error += f" | {next_line}"
                            j += 1
                        else:
                            break
                    
                    if full_error not in seen:
                        print_table_row(filename, full_error)
                        seen.add(full_error)
                    i = j
                else:
                    i += 1
    except Exception: pass

def main():
    parser = argparse.ArgumentParser(
        prog="error-buddy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Error Buddy: Audit logs or find source code."
    )
    parser.add_argument("product_or_path", nargs="?", help="Nickname, repo, or file/dir path")
    parser.add_argument("input", nargs="?", help="Error string (triggers GitHub search)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    target = args.product_or_path
    expanded_path = os.path.abspath(os.path.expanduser(target)) if target else None

    # MODE: DEEP SEARCH
    if args.product_or_path and args.product_or_path.lower() in REPOS and args.input:
        repo = REPOS[args.product_or_path.lower()]
        print(f"\n🔍 Buddy Deep Search Hit ({repo}):")
        print(f"🔗 \033[4;34m{get_url(repo, args.input)}\033[0m\n")
        sys.exit(0)

    # MODE: AUDIT (Path exists)
    if expanded_path and os.path.exists(expanded_path):
        print_table_header()
        if os.path.isdir(expanded_path):
            for root, _, files in os.walk(expanded_path):
                for file in files:
                    if (file.lower().endswith(('.log', '.txt', '.out', '.err')) or 
                        re.search(r'\.\d+$', file) or 
                        file in ['syslog', 'dmesg', 'kern.log', 'auth.log']):
                        parse_log_to_table(os.path.join(root, file))
        else:
            parse_log_to_table(expanded_path)
        print()
        sys.exit(0)

    print(f"Buddy Error: Could not find '{target}' and no valid search string provided.")

if __name__ == "__main__":
    main()
