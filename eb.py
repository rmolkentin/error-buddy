#!/usr/bin/env python3
import argparse
import collections
import fnmatch
import json
import os
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import zipfile

# ANSI Color Codes
RED = "\033[1;31m"
PURPLE = "\033[1;35m"
BLUE = "\033[4;34m"
BOLD_BLUE = "\033[1;34m"
GREEN = "\033[1;32m"  # Bold Green
RESET = "\033[0m"

# Normalized keys for section titles in sosreport analysis and product/generic error-mode AI output.
SOS_SECTION_HEADING_SPECS = {
    "1) most likely root causes": (1, "MOST LIKELY ROOT CAUSES"),
    "2) most relevant error messages and logs": (2, "MOST RELEVANT ERROR MESSAGES AND LOGS"),
    "3) relevant documentation links": (3, "RELEVANT DOCUMENTATION LINKS"),
    "4) possible next steps": (4, "POSSIBLE NEXT STEPS"),
    "5) additional things to check": (5, "ADDITIONAL THINGS TO CHECK"),
    "most likely root causes": (1, "MOST LIKELY ROOT CAUSES"),
    "most likely root cause": (1, "MOST LIKELY ROOT CAUSES"),
    "most relevant error messages and logs": (2, "MOST RELEVANT ERROR MESSAGES AND LOGS"),
    "most relevant errors and logs": (2, "MOST RELEVANT ERROR MESSAGES AND LOGS"),
    "relevant documentation links": (3, "RELEVANT DOCUMENTATION LINKS"),
    "relevant documentation": (3, "RELEVANT DOCUMENTATION LINKS"),
    "documentation links": (3, "RELEVANT DOCUMENTATION LINKS"),
    "possible next steps": (4, "POSSIBLE NEXT STEPS"),
    "additional things to check": (5, "ADDITIONAL THINGS TO CHECK"),
}

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
    "autoinstall": "canonical/autoinstall",
    "openstack": "openstack",
    "charm": "openstack-charmers",
}

CONFIG_PATH = os.path.expanduser("~/.error-buddy")
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_TIMEOUT = 120
DEFAULT_OLLAMA_RETRIES = 2
DEFAULT_OLLAMA_NUM_PREDICT = 1000
DEFAULT_MULTI_PASS_ANALYSIS = False
MAX_PROMPT_CHARS = 4000
MAX_CONTEXT_SNIPPETS = 80
MAX_DOC_LINKS = 8
SOS_PROGRESS_EVERY_FILES = 250
SOS_PROGRESS_EVERY_SECONDS = 5
SOS_INVENTORY_FILE_SAMPLE = 120
SOS_TARGET_MAX_FILES = 19
SOS_TARGET_MAX_SNIPPETS = 32
SOS_TARGET_MAX_CHARS = 9000
SOS_TRIAGE_TIMEOUT_SECONDS = 90
SOS_ANALYSIS_TIMEOUT_SECONDS = 900
SOS_CANDIDATE_FILE_LIMIT = 150
SOS_MAX_LINES_PER_FILE = 1500
SOS_MAX_SNIPPETS_PER_FILE = 9
SOS_SYSLOG_MAX_SNIPPETS = 23
SOS_SYSLOG_MAX_LINES_PER_FILE = 3000
SOS_JOURNALCTL_MAX_LINES = 600
JOURNAL_REVIEW_PATTERN = re.compile(r"\b(error|critical|crit)\b", re.IGNORECASE)
SOS_TRIAGE_MAX_PATTERNS = 12
SOS_TRIAGE_MAX_KEYWORDS = 12
SOS_FORCE_INCLUDE_FAILED_UNITS_SNIPPETS = 6
SOS_FORCE_INCLUDE_SYSTEMCTL_STATUS_SNIPPETS = 3

DOC_HINTS = [
    ("maas", "https://maas.io/docs"),
    ("juju", "https://juju.is/docs"),
    ("lxd", "https://documentation.ubuntu.com/lxd"),
    ("cloud-init", "https://cloudinit.readthedocs.io/en/latest/"),
    ("netplan", "https://netplan.readthedocs.io/en/stable/"),
    ("snapd", "https://snapcraft.io/docs"),
    ("dns", "https://ubuntu.com/server/docs/domain-name-service-dns"),
    ("certificate", "https://ubuntu.com/server/docs/security-certificates"),
    ("ssl", "https://ubuntu.com/server/docs/security-certificates"),
    ("disk", "https://ubuntu.com/server/docs/storage"),
]

def save_config(ollama_url, ollama_model):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(
                {
                    "ollama_url": ollama_url,
                    "ollama_model": ollama_model,
                },
                f,
            )
        print(f"Configuration saved to {CONFIG_PATH}")
    except (PermissionError, OSError):
        print(f"\nERROR: Access Denied. Run: {GREEN}sudo snap connect error-buddy:dot-error-buddy{RESET}\n")

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f) or {}
            return {
                "ollama_url": config.get("ollama_url", DEFAULT_OLLAMA_URL),
                "ollama_model": config.get("ollama_model", DEFAULT_OLLAMA_MODEL),
            }
    except (PermissionError, OSError):
        return "PLUG_REQUIRED"
    except Exception:
        return None

def get_timeout():
    value = os.getenv("ERROR_BUDDY_OLLAMA_TIMEOUT")
    if not value:
        return DEFAULT_OLLAMA_TIMEOUT
    try:
        parsed = int(value)
        if parsed > 0:
            return parsed
    except ValueError:
        pass
    return DEFAULT_OLLAMA_TIMEOUT

def get_num_predict():
    value = os.getenv("ERROR_BUDDY_OLLAMA_NUM_PREDICT")
    if not value:
        return DEFAULT_OLLAMA_NUM_PREDICT
    try:
        parsed = int(value)
        if parsed > 0:
            return parsed
    except ValueError:
        pass
    return DEFAULT_OLLAMA_NUM_PREDICT

def is_multi_pass_enabled():
    value = os.getenv("ERROR_BUDDY_MULTI_PASS")
    if value is None:
        return DEFAULT_MULTI_PASS_ANALYSIS
    return value.strip().lower() in ("1", "true", "yes", "on")

def get_sos_context_limits():
    return {
        "target_max_files": SOS_TARGET_MAX_FILES,
        "target_max_snippets": SOS_TARGET_MAX_SNIPPETS,
        "target_max_chars": SOS_TARGET_MAX_CHARS,
        "candidate_file_limit": SOS_CANDIDATE_FILE_LIMIT,
        "max_lines_per_file": SOS_MAX_LINES_PER_FILE,
        "max_snippets_per_file": SOS_MAX_SNIPPETS_PER_FILE,
        "syslog_max_snippets": SOS_SYSLOG_MAX_SNIPPETS,
        "syslog_max_lines_per_file": SOS_SYSLOG_MAX_LINES_PER_FILE,
        "journalctl_max_lines": SOS_JOURNALCTL_MAX_LINES,
    }

def should_run_refinement_pass(first_pass_text):
    text = (first_pass_text or "").strip()
    if not text:
        return True
    if len(text) < 450:
        return True
    lowered = text.lower()
    weak_markers = [
        "no obvious cause identified",
        "insufficient evidence",
        "not enough evidence",
        "unable to determine",
        "cannot determine",
        "need more information",
    ]
    return any(marker in lowered for marker in weak_markers)

def normalize_ollama_url(url):
    candidate = (url or DEFAULT_OLLAMA_URL).strip()
    if not candidate:
        candidate = DEFAULT_OLLAMA_URL
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    path = parsed.path or "/api/generate"
    if path == "/":
        path = "/api/generate"
    if path == "/api":
        path = "/api/generate"
    return urllib.parse.urlunparse(parsed._replace(path=path, query="", fragment=""))

def alternate_loopback_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if host == "localhost":
        alt_host = "127.0.0.1"
    elif host == "127.0.0.1":
        alt_host = "localhost"
    else:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        auth += "@"
    netloc = f"{auth}{alt_host}{port}"
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))

def get_ollama_endpoints(config_url):
    primary = normalize_ollama_url(config_url)
    endpoints = [primary]
    alternate = alternate_loopback_url(primary)
    if alternate and alternate != primary:
        endpoints.append(alternate)
    return endpoints

def post_json(url, payload, timeout):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))

def get_tags_url(generate_url):
    parsed = urllib.parse.urlparse(generate_url)
    return urllib.parse.urlunparse(parsed._replace(path="/api/tags", query="", fragment=""))

def get_available_models(generate_url, timeout):
    tags_url = get_tags_url(generate_url)
    req = urllib.request.Request(tags_url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
        models = body.get("models", [])
        return {item.get("name", "") for item in models if item.get("name")}

def is_probably_text(path):
    try:
        with open(path, "rb") as f:
            sample = f.read(4096)
            if not sample:
                return True
            return b"\x00" not in sample
    except Exception:
        return False

def safe_extract_tar(tar, dest_dir):
    abs_dest = os.path.abspath(dest_dir)
    for member in tar.getmembers():
        member_path = os.path.abspath(os.path.join(dest_dir, member.name))
        if not member_path.startswith(abs_dest + os.sep) and member_path != abs_dest:
            continue
        tar.extract(member, path=dest_dir)

def prepare_sosreport_root(path):
    expanded = os.path.abspath(os.path.expanduser(path))
    cleanup_dir = None
    if os.path.isdir(expanded):
        return expanded, cleanup_dir
    if not os.path.isfile(expanded):
        raise FileNotFoundError(f"Sosreport path not found: {expanded}")
    if tarfile.is_tarfile(expanded):
        print(f"{PURPLE}Preparing sosreport archive:{RESET} extracting {expanded}")
        cleanup_dir = tempfile.mkdtemp(prefix="error-buddy-sos-")
        with tarfile.open(expanded, "r:*") as tar:
            safe_extract_tar(tar, cleanup_dir)
        return cleanup_dir, cleanup_dir
    if zipfile.is_zipfile(expanded):
        print(f"{PURPLE}Preparing sosreport archive:{RESET} extracting {expanded}")
        cleanup_dir = tempfile.mkdtemp(prefix="error-buddy-sos-")
        with zipfile.ZipFile(expanded, "r") as zf:
            zf.extractall(cleanup_dir)
        return cleanup_dir, cleanup_dir
    raise ValueError("Unsupported sosreport format. Provide a directory, tar/tar.gz/tar.xz, or zip file.")

def normalize_line_for_signature(line):
    scrubbed = re.sub(r"\d{4}-\d{2}-\d{2}", "", line)
    scrubbed = re.sub(r"\d{2}:\d{2}:\d{2}", "", scrubbed)
    scrubbed = re.sub(r"\b[0-9a-f]{8,}\b", "", scrubbed, flags=re.IGNORECASE)
    scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
    return scrubbed[:200]

def collect_sosreport_findings(root_dir):
    trigger = re.compile(
        r"(fatal|error|critical|crit|warning|failed|exception|traceback|timeout|denied|refused|unavailable|panic)",
        re.IGNORECASE,
    )
    file_count = 0
    text_file_count = 0
    unreadable = 0
    total_trigger_hits = 0
    snippets = []
    signatures = collections.Counter()
    keyword_hits = collections.Counter()
    product_hints = collections.Counter()
    high_signal_files = []
    per_file_hits = collections.Counter()
    started_at = time.time()
    last_progress_at = started_at

    for walk_root, _, files in os.walk(root_dir):
        for name in files:
            file_count += 1
            now = time.time()
            should_log = (
                file_count % SOS_PROGRESS_EVERY_FILES == 0
                or (now - last_progress_at) >= SOS_PROGRESS_EVERY_SECONDS
            )
            if should_log:
                elapsed = int(now - started_at)
                print(
                    f"  progress: scanned {file_count} files "
                    f"(text: {text_file_count}, hits: {total_trigger_hits}, elapsed: {elapsed}s)"
                )
                last_progress_at = now
            full_path = os.path.join(walk_root, name)
            rel_path = os.path.relpath(full_path, root_dir)
            if not is_probably_text(full_path):
                continue
            text_file_count += 1
            try:
                with open(full_path, "r", errors="ignore") as f:
                    for idx, raw_line in enumerate(f, start=1):
                        line = raw_line.strip()
                        if not line:
                            continue
                        if trigger.search(line):
                            total_trigger_hits += 1
                            per_file_hits[rel_path] += 1
                            signatures[normalize_line_for_signature(line)] += 1
                            lowered = line.lower()
                            for key, _ in DOC_HINTS:
                                if key in lowered:
                                    keyword_hits[key] += 1
                            if "maas" in rel_path.lower() or "maas" in lowered:
                                product_hints["maas"] += 1
                            if "juju" in rel_path.lower() or "juju" in lowered:
                                product_hints["juju"] += 1
                            if "lxd" in rel_path.lower() or "lxd" in lowered:
                                product_hints["lxd"] += 1
                            if len(snippets) < MAX_CONTEXT_SNIPPETS:
                                snippets.append(f"{rel_path}:{idx}: {line[:320]}")
            except Exception:
                unreadable += 1

    for rel_path, count in per_file_hits.most_common(10):
        high_signal_files.append(f"{rel_path} ({count} hits)")

    top_signatures = [f"{sig} ({count})" for sig, count in signatures.most_common(15) if sig]
    return {
        "root_dir": root_dir,
        "file_count": file_count,
        "text_file_count": text_file_count,
        "unreadable": unreadable,
        "total_trigger_hits": total_trigger_hits,
        "snippets": snippets,
        "top_signatures": top_signatures,
        "keyword_hits": keyword_hits,
        "product_hints": product_hints,
        "high_signal_files": high_signal_files,
    }

def suggest_docs(findings):
    links = []
    seen = set()
    for key, url in DOC_HINTS:
        if findings["keyword_hits"].get(key, 0) > 0 or findings["product_hints"].get(key, 0) > 0:
            if url not in seen:
                seen.add(url)
                links.append(url)
    if findings["product_hints"].get("maas", 0) > 0 and "https://maas.io/docs" not in seen:
        links.append("https://maas.io/docs")
    if not links:
        links = [
            "https://maas.io/docs",
            "https://juju.is/docs",
            "https://documentation.ubuntu.com/lxd",
            "https://cloudinit.readthedocs.io/en/latest/",
            "https://snapcraft.io/docs",
        ]
    return links[:MAX_DOC_LINKS]

def build_next_steps(findings):
    steps = [
        "Run 'error-buddy doctor' to validate Ollama endpoint/model connectivity from the snap.",
        "Prioritize the top high-signal files and signatures shown below for manual confirmation.",
    ]
    sig_blob = " ".join(findings["top_signatures"]).lower()
    if "timeout" in sig_blob:
        steps.append("Check network reachability, DNS resolution, and service response latency around timeout events.")
    if "denied" in sig_blob or "permission" in sig_blob:
        steps.append("Audit permissions, ownership, AppArmor/SELinux policy, and snap interface connections.")
    if "refused" in sig_blob or "unavailable" in sig_blob:
        steps.append("Verify target services are listening on expected ports and dependencies are healthy.")
    if "disk" in sig_blob or "no space" in sig_blob:
        steps.append("Check filesystem capacity and inode usage; clear space and rotate logs as needed.")
    return steps[:6]

def build_sosreport_prompt(findings):
    header = [
        "You are Error Buddy, a Canonical support engineer assistant.",
        "Analyze this sosreport-derived summary and produce:",
        "1) evidence-based root-cause assessment, 2) likely affected components, 3) possible checks and next steps.",
        "Prioritize accuracy: tie conclusions to the snippets/signatures shown; say explicitly if there is not enough evidence or you cannot tell.",
        "Treat root causes as hypotheses unless the evidence clearly rules out alternatives; avoid definitive fixes unless the failure is unambiguous in the logs.",
        "Phrase remediation as things to verify or try next (consider, check, may) rather than commands, unless you are highly confident from the evidence.",
        "",
        f"Scanned files: {findings['file_count']}",
        f"Text files read: {findings['text_file_count']}",
        f"Unreadable files: {findings['unreadable']}",
        f"Error-like hits: {findings['total_trigger_hits']}",
        "",
        "Top signatures:",
    ]
    header.extend(f"- {item}" for item in findings["top_signatures"][:10])
    header.append("")
    header.append("Top files by hit count:")
    header.extend(f"- {item}" for item in findings["high_signal_files"][:10])
    header.append("")
    header.append("Evidence snippets:")
    header.extend(f"- {item}" for item in findings["snippets"][:MAX_CONTEXT_SNIPPETS])
    prompt = "\n".join(header)
    return prompt[:20000]

def parse_json_object_from_text(text):
    if not text:
        return None
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            return None
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None

def extract_model_triage_or_none(raw_text):
    triage_obj = parse_json_object_from_text(raw_text) or {}
    if not isinstance(triage_obj, dict):
        return None

    patterns = triage_obj.get("file_patterns", [])
    keywords = triage_obj.get("keywords", [])
    rationale = triage_obj.get("rationale", "")

    if not isinstance(patterns, list) or not isinstance(keywords, list):
        return None
    if not isinstance(rationale, str) or not rationale.strip():
        return None

    clean_patterns = [p for p in patterns if isinstance(p, str) and p.strip()][:SOS_TRIAGE_MAX_PATTERNS]
    clean_keywords = [k for k in keywords if isinstance(k, str) and k.strip()][:SOS_TRIAGE_MAX_KEYWORDS]
    return {
        "file_patterns": clean_patterns,
        "keywords": clean_keywords,
        "rationale": rationale.strip(),
    }

def get_effective_ollama_model(model_override=None):
    if model_override:
        return model_override
    config = load_config()
    if isinstance(config, dict):
        return config.get("ollama_model", DEFAULT_OLLAMA_MODEL)
    return DEFAULT_OLLAMA_MODEL


def normalize_ai_markdown(text):
    if not text:
        return text
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    # If model returns markdown as one long line, split common markers.
    out = re.sub(r"\s+(#{1,6}\s+)", r"\n\1", out)
    out = re.sub(r"\s+(```)", r"\n\1", out)
    out = re.sub(r"(```)\s+", r"\1\n", out)
    out = re.sub(r"```([a-zA-Z0-9_-]+)\s{2,}", r"```\1\n", out)
    out = re.sub(r"\s{2,}```", r"\n```", out)
    out = re.sub(r"\s+(\d+\.\s+)", r"\n\1", out)
    out = re.sub(r"\s+(\d+\)\s+)", r"\n\1", out)
    out = re.sub(r"\s+(-\s+\*\*)", r"\n\1", out)
    out = re.sub(r"\s+(-\s+)", r"\n\1", out)
    # Do not inject newlines around section title phrases: that breaks prose like
    # "The MOST LIKELY ROOT CAUSES are ..." and creates false heading lines.
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def _canonicalize_sos_heading_match_key(stripped_line):
    """Normalize a single line so we can match section headers despite markdown / unicode noise."""
    if not stripped_line:
        return ""
    s = stripped_line.replace("\u00a0", " ")
    s = re.sub(r"[\u200b\ufeff\u200c\u200d\u2060]", "", s)
    s = s.strip().lower().rstrip(":").strip()
    s = re.sub(r"^#+\s*", "", s)
    s = re.sub(r"^[*_`]+|[*_`]+$", "", s).strip()
    s = re.sub(r"[*_`]+", "", s)
    s = s.strip()
    s = re.sub(r"^[-*]\s+", "", s)
    s = re.sub(r"^(section|part)\s*\d+\s*[:.\)]\s*", "", s)
    s = re.sub(r"^(\d+)[\.\)]\s*", r"\1) ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _line_is_sos_section_heading_only(stripped_line):
    """
    True only when the line is (almost) exactly a known section title, not a sentence that
    mentions that phrase.
    """
    key = _canonicalize_sos_heading_match_key(stripped_line)
    if not key or key not in SOS_SECTION_HEADING_SPECS:
        return False
    # Reject long lines: real headers are short; prose that matched after aggressive stripping is rare.
    if len(stripped_line) > 120:
        return False
    return True


def _match_sos_section_heading(stripped_line):
    """Return (section_num, canonical_title) if line is a known sosreport analysis section header."""
    if not _line_is_sos_section_heading_only(stripped_line):
        return None
    return SOS_SECTION_HEADING_SPECS[_canonicalize_sos_heading_match_key(stripped_line)]


# Lines like "2)" or "3." on their own (models split these from section titles); limit to 1–4
# so we do not eat arbitrary numbered list markers.
_ORPHAN_SECTION_ENUM_RE = re.compile(r"^[1-4][\.\)]\s*$")


def _strip_orphan_section_enumerators(text):
    """Remove lone 1)…4) lines (models emit these as section markers then repeat the title)."""
    if not text:
        return text
    lines = text.splitlines()
    return "\n".join(
        ln for ln in lines
        if not _ORPHAN_SECTION_ENUM_RE.fullmatch(ln.strip())
    )


def _light_normalize_sos_cli_text(text):
    """Line endings + at most one consecutive blank line in the source (models emit runs of empties)."""
    if not text:
        return text
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    collapsed = []
    prev_empty = False
    for ln in out.splitlines():
        empty = not ln.strip()
        if empty:
            if not prev_empty:
                collapsed.append("")
            prev_empty = True
        else:
            collapsed.append(ln.rstrip())
            prev_empty = False
    return "\n".join(collapsed).strip()


def _format_sos_analysis_for_cli(text):
    """Prepare interactive sosreport model output for the CLI printer."""
    return _strip_orphan_section_enumerators(_light_normalize_sos_cli_text(text or ""))


def _print_sos_section_heading_line(section_num, title, indent, emit_leading_break=None):
    """Blank line before sections 2–4 (unless caller suppresses), blue title, one blank after title."""
    if section_num >= 2:
        if emit_leading_break is None or emit_leading_break:
            print()
    print(f"{indent}{BOLD_BLUE}{title}{RESET}")
    print()


def print_pretty_ai_output(text, width=100, indent="  "):
    if not text:
        print(f"{indent}(no output)")
        return

    text = normalize_ai_markdown(text)
    in_code_block = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            in_code_block = not in_code_block
            print(f"{indent}{stripped}")
            continue

        if in_code_block:
            print(f"{indent}{line}")
            continue

        if not stripped:
            print()
            continue

        heading_match = _match_sos_section_heading(stripped)
        if heading_match:
            _print_sos_section_heading_line(heading_match[0], heading_match[1], indent)
            continue

        bullet = re.match(r"^([-*])\s+(.+)$", stripped)
        number = re.match(r"^(\d+[\.\)])\s+(.+)$", stripped)
        heading = stripped.startswith("#")

        if heading:
            print(f"{indent}{stripped}")
            continue

        if bullet:
            wrapped = textwrap.wrap(
                bullet.group(2),
                width=max(30, width - len(indent) - 4),
                initial_indent=f"{indent}{bullet.group(1)} ",
                subsequent_indent=f"{indent}  ",
            )
            for w in wrapped:
                print(w)
            continue

        if number:
            prefix = f"{number.group(1)} "
            wrapped = textwrap.wrap(
                number.group(2),
                width=max(30, width - len(indent) - len(prefix)),
                initial_indent=f"{indent}{prefix}",
                subsequent_indent=f"{indent}{' ' * len(prefix)}",
            )
            for w in wrapped:
                print(w)
            continue

        wrapped = textwrap.wrap(
            stripped,
            width=max(30, width - len(indent)),
            initial_indent=indent,
            subsequent_indent=indent,
        )
        for w in wrapped:
            print(w)


def print_cli_sosreport_analysis(text, width=100, indent="  "):
    text = _format_sos_analysis_for_cli(text)
    if not text:
        print(f"{indent}(no output)")
        return

    in_code_block = False
    last_out_blank = False
    skip_blank_after_heading = False

    for raw in text.splitlines():
        stripped = raw.strip()

        if stripped.startswith("```"):
            in_code_block = not in_code_block
            # Omit fence lines; content is printed as indented text below.
            last_out_blank = False
            skip_blank_after_heading = False
            continue

        if in_code_block:
            inner = raw.rstrip()
            if not inner.strip():
                if not last_out_blank:
                    print()
                    last_out_blank = True
                continue
            last_out_blank = False
            print(f"{indent}  {inner.lstrip()}")
            skip_blank_after_heading = False
            continue

        line = stripped
        if not line:
            if skip_blank_after_heading:
                skip_blank_after_heading = False
                continue
            if last_out_blank:
                continue
            print()
            last_out_blank = True
            continue

        if skip_blank_after_heading:
            skip_blank_after_heading = False

        heading_match = _match_sos_section_heading(line)
        if heading_match:
            section_num, title = heading_match
            emit_leading = None
            if section_num >= 2:
                emit_leading = not last_out_blank
            _print_sos_section_heading_line(
                section_num, title, indent, emit_leading_break=emit_leading
            )
            skip_blank_after_heading = True
            last_out_blank = True
            continue

        last_out_blank = False

        # Remove markdown markers for cleaner CLI output.
        line = re.sub(r"[*_`#]+", "", line).strip()
        line = re.sub(r"\s{2,}", " ", line)

        bullet = re.match(r"^([-*])\s+(.+)$", line)
        number = re.match(r"^(\d+[\.\)])\s+(.+)$", line)
        if bullet:
            wrapped = textwrap.wrap(
                bullet.group(2),
                width=max(30, width - len(indent) - 4),
                initial_indent=f"{indent}- ",
                subsequent_indent=f"{indent}  ",
            )
            for w in wrapped:
                print(w)
            continue
        if number:
            prefix = f"{number.group(1)} "
            wrapped = textwrap.wrap(
                number.group(2),
                width=max(30, width - len(indent) - len(prefix)),
                initial_indent=f"{indent}{prefix}",
                subsequent_indent=f"{indent}{' ' * len(prefix)}",
            )
            for w in wrapped:
                print(w)
            continue

        wrapped = textwrap.wrap(
            line,
            width=max(30, width - len(indent)),
            initial_indent=indent,
            subsequent_indent=indent,
        )
        for w in wrapped:
            print(w)


def build_sosreport_inventory(root_dir):
    file_paths = []
    dir_counter = collections.Counter()
    total_files = 0
    for walk_root, _, files in os.walk(root_dir):
        rel_dir = os.path.relpath(walk_root, root_dir)
        for name in files:
            total_files += 1
            rel_path = os.path.normpath(os.path.join(rel_dir, name))
            if rel_path.startswith("."):
                rel_path = rel_path[2:] if rel_path.startswith("./") else rel_path
            file_paths.append(rel_path)
            top_dir = rel_path.split(os.sep)[0] if os.sep in rel_path else rel_path
            dir_counter[top_dir] += 1
            if len(file_paths) >= SOS_INVENTORY_FILE_SAMPLE:
                break
        if len(file_paths) >= SOS_INVENTORY_FILE_SAMPLE:
            break
    return {
        "total_files": total_files,
        "sample_paths": file_paths,
        "top_dirs": dir_counter.most_common(20),
    }

def build_triage_prompt(issue_question, inventory):
    lines = [
        "You are selecting the most relevant sosreport files for investigation.",
        "Return JSON only with keys:",
        "file_patterns (array of glob-like patterns),",
        "keywords (array of strings),",
        "rationale (short string).",
        "Keep file_patterns to <= 12 entries and keywords to <= 12 entries.",
        "Use Linux sosreport-style paths only. No prose outside JSON.",
        "",
        f"Issue question: {issue_question}",
        f"Total files discovered: {inventory['total_files']}",
        "Top directories:",
    ]
    for d, count in inventory["top_dirs"][:15]:
        lines.append(f"- {d}: {count}")
    lines.append("Sample file paths:")
    for path in inventory["sample_paths"][:70]:
        lines.append(f"- {path}")
    return "\n".join(lines)[:6000]

def guess_triage_from_issue(issue_question):
    issue = (issue_question or "").lower()
    patterns = ["var/log/*", "etc/*", "*syslog*", "*dmesg*", "*journal*"]
    keywords = []
    keyword_to_patterns = {
        "maas": ["*maas*", "var/log/maas/*", "etc/maas/*"],
        "juju": ["*juju*", "var/log/juju/*", "etc/juju/*"],
        "lxd": ["*lxd*", "var/log/lxd/*"],
        "network": ["*netplan*", "etc/netplan/*", "*network*", "*resolv*"],
        "dns": ["*resolv*", "*named*", "*dns*"],
        "dhcp": ["*dhcp*", "*dnsmasq*"],
        "kubernetes": ["*kube*", "*containerd*", "*microk8s*"],
        "microk8s": ["*microk8s*", "*containerd*"],
        "cloud-init": ["*cloud-init*", "var/log/cloud-init*"],
        "disk": ["*fstab*", "*mount*", "*lsblk*", "*df*"],
        "certificate": ["*ssl*", "*cert*", "*tls*"],
        "auth": ["*auth.log*", "*pam*"],
        "snap": ["*snap*", "var/log/snap*"],
    }
    for key, pats in keyword_to_patterns.items():
        if key in issue:
            keywords.append(key)
            for pat in pats:
                if pat not in patterns:
                    patterns.append(pat)
    for token in ["error", "failed", "timeout", "denied", "refused", "traceback", "exception"]:
        if token not in keywords:
            keywords.append(token)
    return {
        "file_patterns": patterns[:20],
        "keywords": keywords[:20],
        "rationale": "Fast heuristic triage from issue keywords.",
    }

def path_matches_pattern(rel_path, pattern):
    rel = rel_path.lower()
    pat = (pattern or "").strip().lower()
    if not pat:
        return False
    if any(ch in pat for ch in ["*", "?", "["]):
        return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat)
    return pat in rel

def read_journal_file_with_journalctl(
    journal_file,
    rel_path,
    normalized_keywords,
    max_snippets,
    max_lines=SOS_JOURNALCTL_MAX_LINES,
):
    snippets = []
    cmd = [
        "journalctl",
        "--file",
        journal_file,
        "--no-pager",
        "--output=short-iso",
        "--priority=debug",
        "--lines",
        str(max_lines),
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return snippets
    except Exception:
        return snippets

    if proc.returncode != 0 or not proc.stdout:
        return snippets

    for idx, raw_line in enumerate(proc.stdout.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        # Keep journal review focused on error/critical messages.
        if not JOURNAL_REVIEW_PATTERN.search(line):
            continue
        lowered = line.lower()
        if normalized_keywords and not any(k in lowered for k in normalized_keywords):
            continue
        snippets.append(f"{rel_path}:journalctl:{idx}: {line[:320]}")
        if len(snippets) >= max_snippets:
            break
    return snippets

def collect_targeted_sos_context(root_dir, patterns, keywords):
    trigger = re.compile(
        r"(fatal|error|critical|crit|warning|failed|exception|traceback|timeout|denied|refused|unavailable|panic)",
        re.IGNORECASE,
    )
    syslog_trigger = re.compile(
        r"(error|err\b|critical|crit\b|failed|failure|panic|segfault|traceback|denied|refused|timed?\s*out)",
        re.IGNORECASE,
    )
    normalized_patterns = [p for p in patterns if isinstance(p, str) and p.strip()]
    normalized_keywords = [k.lower() for k in keywords if isinstance(k, str) and k.strip()]
    limits = get_sos_context_limits()
    target_max_files = limits["target_max_files"]
    target_max_snippets = limits["target_max_snippets"]
    candidate_file_limit = limits["candidate_file_limit"]
    max_lines_per_file = limits["max_lines_per_file"]
    max_snippets_per_file = limits["max_snippets_per_file"]
    syslog_max_snippets = limits["syslog_max_snippets"]
    syslog_max_lines_per_file = limits["syslog_max_lines_per_file"]
    journalctl_max_lines = limits["journalctl_max_lines"]
    selected_files = []
    snippets = []
    scanned_files = 0
    candidate_files = []
    syslog_candidate_files = []
    seen_paths = set()
    candidate_map = {}

    def is_syslog_or_journal_path(rel_path):
        lower = rel_path.lower()
        base = os.path.basename(lower)
        if "journal" in lower:
            return True
        return base in ("syslog", "messages", "kern.log", "auth.log", "dmesg") or "syslog" in lower

    def is_binary_journal_file(rel_path):
        return rel_path.lower().endswith(".journal")

    def is_failed_units_capture(rel_path):
        rel_lower = rel_path.lower()
        list_units = "list-units" in rel_lower or "list_units" in rel_lower
        return list_units and "failed" in rel_lower

    def is_systemctl_status_capture(rel_path):
        rel_lower = rel_path.lower()
        return "systemctl_status" in rel_lower or ("systemctl" in rel_lower and "status" in rel_lower)

    def classify_category(rel_path):
        rel_lower = rel_path.lower()
        if is_failed_units_capture(rel_path):
            return "failed_units"
        if is_systemctl_status_capture(rel_path):
            return "systemctl_status"
        if "journal" in rel_lower:
            return "journal"
        if any(token in rel_lower for token in ("syslog", "messages", "kern.log", "auth.log", "dmesg")):
            return "syslog"
        if rel_lower.startswith("etc/"):
            return "config"
        if "network" in rel_lower or "resolv" in rel_lower or "route" in rel_lower:
            return "network"
        if any(token in rel_lower for token in ("df", "lsblk", "mount", "fstab", "filesystem", "storage")):
            return "storage"
        if rel_lower.startswith("var/log/"):
            return "app_log"
        return "other"

    def format_line_for_snippet(rel_path, line):
        # Normalize systemd/systemctl table-like rows so they are easier to read in prompts.
        if is_failed_units_capture(rel_path) or is_systemctl_status_capture(rel_path):
            return re.sub(r"\s+", " ", line).strip()
        return line

    def score_snippet(rel_path, line):
        lowered = line.lower()
        score = 0
        category = classify_category(rel_path)
        if trigger.search(line):
            score += 3
        if syslog_trigger.search(line):
            score += 2
        keyword_hits = sum(1 for k in normalized_keywords if k and k in lowered)
        score += min(keyword_hits, 3) * 3
        if "traceback" in lowered or "exception" in lowered:
            score += 3
        if "failed" in lowered or "denied" in lowered or "refused" in lowered:
            score += 2
        rel_lower = rel_path.lower()
        if any(k in rel_lower for k in normalized_keywords):
            score += 2
        if is_syslog_or_journal_path(rel_path):
            score += 1
        if category == "failed_units":
            score += 8
        elif category == "systemctl_status":
            score += 5
        elif category in ("syslog", "journal"):
            score += 2
        return score

    def add_candidate(rel_path, idx, line):
        formatted_line = format_line_for_snippet(rel_path, line)
        snippet = f"{rel_path}:{idx}: {formatted_line[:320]}"
        dedupe_key = f"{rel_path}|{normalize_line_for_signature(formatted_line)}"
        if dedupe_key in candidate_map:
            existing = candidate_map[dedupe_key]
            existing["freq"] += 1
            existing["score"] = max(existing["score"], score_snippet(rel_path, formatted_line))
            return
        candidate_map[dedupe_key] = {
            "path": rel_path,
            "snippet": snippet,
            "score": score_snippet(rel_path, formatted_line),
            "category": classify_category(rel_path),
            "freq": 1,
        }

    # Phase 1: fast candidate selection by filename/path pattern.
    for walk_root, _, files in os.walk(root_dir):
        for name in files:
            full_path = os.path.join(walk_root, name)
            rel_path = os.path.relpath(full_path, root_dir)
            scanned_files += 1
            if is_syslog_or_journal_path(rel_path):
                syslog_candidate_files.append((rel_path, full_path))
            if normalized_patterns and not any(path_matches_pattern(rel_path, p) for p in normalized_patterns):
                continue
            if rel_path not in seen_paths:
                candidate_files.append((rel_path, full_path))
                seen_paths.add(rel_path)
            if len(candidate_files) >= candidate_file_limit:
                break
        if len(candidate_files) >= candidate_file_limit:
            break

    # Always include systemd `list-units --failed` command output files. They often live under
    # sos_commands/systemd/ but can be skipped when candidate_file_limit is reached earlier
    # in os.walk order (many other paths match *syslog* / var/log/* first).
    systemd_cmd_dir = os.path.join(root_dir, "sos_commands", "systemd")
    if os.path.isdir(systemd_cmd_dir):
        for sd_root, _, sd_names in os.walk(systemd_cmd_dir):
            for name in sd_names:
                full_path = os.path.join(sd_root, name)
                rel_path = os.path.relpath(full_path, root_dir)
                if not is_failed_units_capture(rel_path):
                    continue
                if rel_path not in seen_paths:
                    candidate_files.append((rel_path, full_path))
                    seen_paths.add(rel_path)

    # If triage did not give patterns, fall back to broad candidate selection.
    if not candidate_files and not normalized_patterns:
        for walk_root, _, files in os.walk(root_dir):
            for name in files:
                full_path = os.path.join(walk_root, name)
                rel_path = os.path.relpath(full_path, root_dir)
                scanned_files += 1
                if rel_path not in seen_paths:
                    candidate_files.append((rel_path, full_path))
                    seen_paths.add(rel_path)
                if len(candidate_files) >= candidate_file_limit:
                    break
            if len(candidate_files) >= candidate_file_limit:
                break

    # Always prioritize syslog/journal style files for grep-like error extraction.
    prioritized = []
    for rel_path, full_path in syslog_candidate_files:
        if rel_path in seen_paths:
            continue
        prioritized.append((rel_path, full_path))
        seen_paths.add(rel_path)
    candidate_files = prioritized + candidate_files

    def score_candidate_path(rel_path):
        rel_lower = rel_path.lower()
        score = 0
        if is_syslog_or_journal_path(rel_path):
            score += 4
        score += sum(2 for k in normalized_keywords if k and k in rel_lower)
        score += sum(1 for p in normalized_patterns if p and path_matches_pattern(rel_path, p))
        if any(token in rel_lower for token in ("error", "fail", "trace", "exception", "panic", "critical")):
            score += 2
        return score

    candidate_files = sorted(candidate_files, key=lambda item: score_candidate_path(item[0]), reverse=True)
    failed_unit_files = [item for item in candidate_files if is_failed_units_capture(item[0])]
    systemctl_status_files = [
        item for item in candidate_files
        if is_systemctl_status_capture(item[0]) and not is_failed_units_capture(item[0])
    ]
    other_files = [
        item for item in candidate_files
        if not is_failed_units_capture(item[0]) and not is_systemctl_status_capture(item[0])
    ]
    candidate_files = failed_unit_files + systemctl_status_files + other_files

    syslog_snippets = 0
    collection_per_file_cap = max(max_snippets_per_file * 3, max_snippets_per_file + 4)
    collection_pool_limit = target_max_snippets * 12
    # Phase 2: read only candidate files with bounded per-file effort.
    for rel_path, full_path in candidate_files:
        if len(candidate_map) >= collection_pool_limit:
            break
        if not is_probably_text(full_path):
            if is_binary_journal_file(rel_path):
                journal_snippets = read_journal_file_with_journalctl(
                    full_path,
                    rel_path,
                    normalized_keywords,
                    max_snippets=min(max_snippets_per_file, max(1, syslog_max_snippets - syslog_snippets)),
                    max_lines=journalctl_max_lines,
                )
                if journal_snippets:
                    for item in journal_snippets:
                        rel_path_only, _, rest = item.partition(":journalctl:")
                        line_no = rest.split(":", 1)[0] if rest else "0"
                        text_part = rest.split(":", 1)[1].strip() if ":" in rest else item
                        try:
                            parsed_line_no = int(line_no)
                        except Exception:
                            parsed_line_no = 0
                        add_candidate(rel_path_only or rel_path, parsed_line_no, text_part)
                        if len(candidate_map) >= collection_pool_limit:
                            break
                    syslog_snippets += len(journal_snippets)
            continue
        per_file_snippets = 0
        is_priority_syslog = is_syslog_or_journal_path(rel_path)
        max_lines_this_file = syslog_max_lines_per_file if is_priority_syslog else max_lines_per_file
        try:
            with open(full_path, "r", errors="ignore") as f:
                for idx, raw_line in enumerate(f, start=1):
                    if idx > max_lines_this_file:
                        break
                    line = raw_line.strip()
                    if not line:
                        continue
                    if is_failed_units_capture(rel_path):
                        failed_units_line = line.lower()
                        # Keep table headers and failed unit rows even if they do not match generic triggers.
                        if not (
                            "failed" in failed_units_line
                            or failed_units_line.startswith("unit ")
                            or failed_units_line.startswith("legend:")
                            or ".service" in failed_units_line
                            or ".mount" in failed_units_line
                            or ".socket" in failed_units_line
                        ):
                            continue
                    lowered = line.lower()
                    if normalized_keywords and not any(k in lowered for k in normalized_keywords):
                        if not trigger.search(line) and not (is_priority_syslog and syslog_trigger.search(line)):
                            if not is_failed_units_capture(rel_path):
                                continue
                            # For failed-unit captures, still retain relevant table lines.
                            if "failed" not in lowered and ".service" not in lowered:
                                continue
                    elif not normalized_keywords and not trigger.search(line) and not (
                        is_priority_syslog and syslog_trigger.search(line)
                    ):
                        if not is_failed_units_capture(rel_path):
                            continue
                    add_candidate(rel_path, idx, line)
                    per_file_snippets += 1
                    if is_priority_syslog:
                        syslog_snippets += 1
                    if (
                        per_file_snippets >= collection_per_file_cap
                        or syslog_snippets >= syslog_max_snippets
                        or len(candidate_map) >= collection_pool_limit
                    ):
                        break
        except Exception:
            continue

    candidates = list(candidate_map.values())
    candidates.sort(key=lambda item: (item["score"], item["freq"]), reverse=True)

    required_quotas = {
        "failed_units": SOS_FORCE_INCLUDE_FAILED_UNITS_SNIPPETS,
        "systemctl_status": SOS_FORCE_INCLUDE_SYSTEMCTL_STATUS_SNIPPETS,
    }
    soft_category_caps = {
        "syslog": max(6, target_max_snippets // 3),
        "journal": max(4, target_max_snippets // 4),
        "config": max(4, target_max_snippets // 5),
        "network": max(3, target_max_snippets // 6),
        "storage": max(3, target_max_snippets // 6),
    }
    max_per_file_final = 4

    selected = []
    seen_selected = set()
    file_counts = collections.Counter()
    category_counts = collections.Counter()

    def try_add(candidate):
        snippet = candidate["snippet"]
        path = candidate["path"]
        category = candidate["category"]
        if snippet in seen_selected:
            return False
        if len(selected) >= target_max_snippets:
            return False
        if file_counts[path] >= max_per_file_final:
            return False
        selected.append(snippet)
        seen_selected.add(snippet)
        file_counts[path] += 1
        category_counts[category] += 1
        return True

    for category, quota in required_quotas.items():
        if quota <= 0:
            continue
        for candidate in candidates:
            if candidate["category"] != category:
                continue
            if category_counts[category] >= quota:
                break
            try_add(candidate)

    for candidate in candidates:
        category = candidate["category"]
        cap = soft_category_caps.get(category, target_max_snippets)
        if category_counts[category] >= cap:
            continue
        try_add(candidate)
        if len(selected) >= target_max_snippets:
            break

    snippets = selected
    selected_files = list(file_counts.keys())[:target_max_files]
    selected_syslog = category_counts.get("syslog", 0) + category_counts.get("journal", 0)

    return {
        "scanned_files": scanned_files,
        "selected_files": selected_files,
        "snippets": snippets,
        "patterns": normalized_patterns,
        "keywords": normalized_keywords,
        "syslog_snippets": selected_syslog,
    }

def build_targeted_analysis_prompt(
    issue_question,
    triage,
    context,
    max_files=SOS_TARGET_MAX_FILES,
    max_snippets=SOS_TARGET_MAX_SNIPPETS,
    max_chars=SOS_TARGET_MAX_CHARS,
):
    lines = [
        "You are Error Buddy, a Canonical support engineer assistant.",
        "Analyze the targeted sosreport evidence and return plain text only.",
        "Do not use markdown formatting.",
        "Accuracy: prefer being correct over sounding confident. Tie each root-cause claim to specific evidence (file/log lines).",
        "If evidence is missing, weak, or contradictory, say so plainly (e.g. insufficient evidence, cannot determine from provided logs).",
        "Section 1: rank hypotheses by evidence; state one definitive root cause only when the cited evidence leaves little room for alternatives.",
        "Section 4: list things to check or verify next; use hedging (consider, verify, may) unless the failure mode is unambiguous in the evidence.",
        "Use exactly these sections and order:",
        "1) MOST LIKELY ROOT CAUSES",
        "2) MOST RELEVANT ERROR MESSAGES AND LOGS",
        "3) RELEVANT DOCUMENTATION LINKS",
        "4) POSSIBLE NEXT STEPS",
    ]
    lines.extend(
        [
            "For section 2, include 5-10 concise items and include source log/file for each item.",
            "For section 3 RELEVANT DOCUMENTATION LINKS: include 3-5 links when they clearly relate to the issue (use fewer only if fewer are genuinely relevant).",
            "Prioritize official Canonical and Ubuntu documentation where applicable (e.g. documentation.ubuntu.com, Ubuntu Server guides, snapcraft.io/docs, and product docs such as MAAS, Juju, or LXD when those products appear in the evidence).",
            "Include authoritative upstream or project documentation for implicated components (e.g. PostgreSQL, Apache httpd, systemd, cloud-init, RabbitMQ, OpenStack projects).",
            "Each link line: a brief label, then the full https URL; only use URLs you are confident exist; do not invent links.",
            "If there is no obvious cause or not enough evidence, say so explicitly (e.g. 'No obvious cause identified from available evidence' or 'Insufficient evidence to determine').",
            "Do not invent a root cause to fill space. Do not include a separate confidence section.",
            "",
            f"Issue question: {issue_question}",
            f"Triage rationale: {triage.get('rationale', 'n/a')}",
            f"Files matched: {len(context['selected_files'])}",
            "Selected patterns:",
        ]
    )
    lines.extend(f"- {p}" for p in context["patterns"][:20])
    lines.append("Selected keywords:")
    lines.extend(f"- {k}" for k in context["keywords"][:20])
    lines.append("Selected files:")
    lines.extend(f"- {path}" for path in context["selected_files"][:max_files])
    lines.append("Evidence snippets:")
    lines.extend(f"- {s}" for s in context["snippets"][:max_snippets])
    return "\n".join(lines)[:max_chars]

def run_sosreport_interactive():
    print(f"\n{PURPLE}SOSREPORT AI Analysis Interactive Mode{RESET}")
    sos_path = input("Enter sosreport file/directory path: ").strip()
    if not sos_path:
        print(f"{RED}SOSREPORT ERROR:{RESET} No sosreport path provided.")
        sys.exit(1)
    issue_question = input("Describe the main issue to investigate: ").strip()
    if not issue_question:
        print(f"{RED}SOSREPORT ERROR:{RESET} No issue/question provided.")
        sys.exit(1)

    extracted_temp = None
    try:
        started_at = time.time()
        root_dir, extracted_temp = prepare_sosreport_root(sos_path)
        limits = get_sos_context_limits()
        ollama_model = get_effective_ollama_model()
        print(f"{PURPLE}Building sosreport inventory...{RESET}")
        inventory = build_sosreport_inventory(root_dir)
        triage_prompt = build_triage_prompt(issue_question, inventory)
        debug_prompts = os.getenv("ERROR_BUDDY_DEBUG_PROMPTS", "").strip().lower() in ("1", "true", "yes")
        print(
            f"{PURPLE}Step 1/2:{RESET} Asking Ollama "
            f"(model: {ollama_model}) what to search for..."
        )
        if debug_prompts:
            print(f"\n{PURPLE}TRIAGE PROMPT SENT TO OLLAMA:{RESET}\n{triage_prompt}\n")
        triage_raw = generate_ollama_text(
            triage_prompt,
            model=ollama_model,
            timeout_override=SOS_TRIAGE_TIMEOUT_SECONDS,
        )
        triage = extract_model_triage_or_none(triage_raw)
        if not triage:
            repair_prompt = (
                "Convert the following content into strict JSON only with keys "
                "file_patterns (array of strings), keywords (array of strings), and rationale (string). "
                "Do not include markdown fences or extra prose.\n\n"
                f"Content to convert:\n{triage_raw[:4000]}"
            )
            repaired_raw = generate_ollama_text(
                repair_prompt,
                model=ollama_model,
                timeout_override=SOS_TRIAGE_TIMEOUT_SECONDS,
            )
            triage = extract_model_triage_or_none(repaired_raw)

        if not triage:
            raise RuntimeError(
                "Step 1 triage did not return valid Ollama JSON. "
                "Increase ERROR_BUDDY_OLLAMA_TIMEOUT or retry with a faster model."
            )

        raw_patterns = triage.get("file_patterns", [])
        keywords = triage.get("keywords", [])
        if not isinstance(raw_patterns, list):
            raw_patterns = []
        if not isinstance(keywords, list):
            keywords = []

        model_patterns = [p.strip() for p in raw_patterns if isinstance(p, str) and p.strip()]
        # Baselines first so they are never dropped when trimming to SOS_TRIAGE_MAX_PATTERNS.
        baselines = [
            "sos_commands/systemd/*",
            "*list-units*failed*",
            "sos_commands/systemd/systemctl*failed*",
            "*syslog*",
            "*journal*",
            "var/log/*",
            "*messages*",
            "*kern.log*",
            "*auth.log*",
        ]
        patterns = []
        for b in baselines:
            if b not in patterns:
                patterns.append(b)
        for p in model_patterns:
            if p not in patterns and len(patterns) < SOS_TRIAGE_MAX_PATTERNS:
                patterns.append(p)

        for baseline_kw in ["error", "critical", "crit", "failed", "systemctl"]:
            if baseline_kw not in keywords:
                keywords.append(baseline_kw)
        keywords = keywords[:SOS_TRIAGE_MAX_KEYWORDS]

        print(f"{PURPLE}Collecting targeted evidence from sosreport...{RESET}")
        context = collect_targeted_sos_context(
            root_dir,
            patterns,
            keywords,
        )
        if not context["snippets"]:
            print(f"{PURPLE}No targeted matches found; falling back to broad scan snippets...{RESET}")
            broad = collect_sosreport_findings(root_dir)
            context["snippets"] = broad["snippets"][: limits["target_max_snippets"]]
            context["selected_files"] = broad["high_signal_files"][: limits["target_max_files"]]

        print(
            f"{PURPLE}Step 2/2:{RESET} Sending focused evidence to Ollama "
            f"(model: {ollama_model}) for final analysis..."
        )
        analysis_prompt = build_targeted_analysis_prompt(
            issue_question,
            triage,
            context,
            max_files=limits["target_max_files"],
            max_snippets=limits["target_max_snippets"],
            max_chars=limits["target_max_chars"],
        )
        print(
            f"  step-2 payload: {len(context['selected_files'])} files, "
            f"{len(context['snippets'])} snippets, {len(analysis_prompt)} chars"
        )
        ai_result = run_multi_pass_analysis(
            analysis_prompt,
            model=ollama_model,
            timeout_override=SOS_ANALYSIS_TIMEOUT_SECONDS,
            extra_refinement_passes=0,
        )
        total_elapsed = int(time.time() - started_at)

        print(f"\n{'-'*70}")
        print(f"{RED}Final AI Analysis:{RESET}")
        print()
        print_cli_sosreport_analysis(ai_result, width=100, indent="  ")
        print(f"{'-'*70}")
        print(f"Input root: {root_dir}")
        print(f"Files searched: {inventory['total_files']}")
        print(f"Files selected for targeted read: {len(context['selected_files'])}")
        print(f"Evidence snippets sent: {len(context['snippets'])}")
        print(f"Syslog/journal snippets: {context.get('syslog_snippets', 0)}")
        print(f"Elapsed: {total_elapsed}s")
        print(f"{PURPLE}Ollama triage rationale:{RESET} {triage.get('rationale', 'n/a')}")
        if context["patterns"]:
            print(f"{PURPLE}Selected patterns:{RESET}")
            for p in context["patterns"][:12]:
                print(f"  - {p}")
        if context["keywords"]:
            print(f"{PURPLE}Selected keywords:{RESET}")
            for k in context["keywords"][:12]:
                print(f"  - {k}")
        print()
    except KeyboardInterrupt:
        print(f"\n{RED}SOSREPORT CANCELLED:{RESET} Interrupted by user (Ctrl+C).")
        sys.exit(130)
    except (FileNotFoundError, ValueError) as e:
        print(f"{RED}SOSREPORT ERROR:{RESET} {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}SOSREPORT ERROR:{RESET} Analysis failed: {e}")
        sys.exit(1)
    finally:
        if extracted_temp and os.path.isdir(extracted_temp):
            try:
                for walk_root, dirs, files in os.walk(extracted_temp, topdown=False):
                    for name in files:
                        os.remove(os.path.join(walk_root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(walk_root, name))
                os.rmdir(extracted_temp)
            except Exception:
                pass

def generate_ollama_text(prompt, model=None, timeout_override=None, extra_options=None):
    config = load_config()
    if config == "PLUG_REQUIRED":
        return f"Permission Denied: Run '{GREEN}sudo snap connect error-buddy:dot-error-buddy{RESET}'"
    if not config:
        return "Ollama configuration not found. Run 'error-buddy init' first."
    timeout = timeout_override or get_timeout()
    ollama_url = normalize_ollama_url(config.get("ollama_url", DEFAULT_OLLAMA_URL))
    ollama_model = model or config.get("ollama_model", DEFAULT_OLLAMA_MODEL)
    ollama_options = {"num_predict": get_num_predict()}
    if isinstance(extra_options, dict):
        for key, value in extra_options.items():
            if value is not None:
                ollama_options[key] = value
    data = {"model": ollama_model, "prompt": prompt, "stream": False, "options": ollama_options}
    endpoints = get_ollama_endpoints(ollama_url)
    last_error = None
    for endpoint in endpoints:
        for _ in range(DEFAULT_OLLAMA_RETRIES + 1):
            try:
                result = post_json(endpoint, data, timeout=timeout)
                return result.get("response", "").strip() or "No response returned from Ollama."
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    last_error = "Ollama is busy. Try again in a moment."
                    time.sleep(1)
                    continue
                return f"Ollama API Error {e.code}"
            except socket.timeout:
                last_error = f"Ollama request timed out after {timeout}s."
                time.sleep(1)
                continue
            except urllib.error.URLError as e:
                last_error = f"Could not reach Ollama at {endpoint} ({getattr(e, 'reason', 'connection failed')})."
                break
            except Exception as e:
                return f"Analysis failed: {str(e)}"
    return last_error or "Could not reach Ollama."

def run_multi_pass_analysis(prompt, model=None, timeout_override=None, extra_refinement_passes=0):
    # Pass 1: generate a complete first draft analysis.
    first_pass = generate_ollama_text(
        prompt,
        model=model,
        timeout_override=timeout_override,
    )
    run_refinement = (
        is_multi_pass_enabled()
        or should_run_refinement_pass(first_pass)
        or extra_refinement_passes > 0
    )
    if not first_pass or not run_refinement:
        return first_pass

    def make_refinement_prompt(previous_text):
        clipped_previous = (previous_text or "")[:6000]
        return (
            f"{prompt}\n\n"
            "Initial draft analysis:\n"
            f"{clipped_previous}\n\n"
            "Task: Re-evaluate the draft against the evidence above and provide an improved final answer. "
            "Correct mistakes, remove weak speculation, and keep the same requested output format. "
            "Do not upgrade uncertain guesses to facts; keep next steps as verification suggestions unless the evidence is conclusive."
        )

    current = generate_ollama_text(
        make_refinement_prompt(first_pass),
        model=model,
        timeout_override=timeout_override,
    )
    for _ in range(max(0, extra_refinement_passes)):
        current = generate_ollama_text(
            make_refinement_prompt(current),
            model=model,
            timeout_override=timeout_override,
        )
    return current

def run_sosreport_analysis(path):
    extracted_temp = None
    try:
        started_at = time.time()
        root_dir, extracted_temp = prepare_sosreport_root(path)
        active_model = get_effective_ollama_model()
        print(f"{PURPLE}Scanning sosreport:{RESET} {root_dir}")
        findings = collect_sosreport_findings(root_dir)
        print(
            f"{PURPLE}Generating AI summary from findings with Ollama "
            f"(model: {active_model})...{RESET}"
        )
        docs = suggest_docs(findings)
        next_steps = build_next_steps(findings)
        prompt = build_sosreport_prompt(findings)
        ai_result = run_multi_pass_analysis(
            prompt,
            timeout_override=SOS_ANALYSIS_TIMEOUT_SECONDS,
        )
        total_elapsed = int(time.time() - started_at)

        print(f"\n{'-'*70}")
        print(f"{RED}AI Analysis:{RESET}")
        print_pretty_ai_output(ai_result, width=100, indent="  ")
        print(f"{'-'*70}")
        print(f"Input root: {root_dir}")
        print(f"Files scanned: {findings['file_count']} (text files: {findings['text_file_count']})")
        print(f"Error-like hits: {findings['total_trigger_hits']}")
        print(f"Elapsed: {total_elapsed}s")
        print(f"\n{PURPLE}Relevant Documentation:{RESET}")
        for link in docs:
            print(f"  - {link}")
        print(f"\n{PURPLE}Possible Next Steps:{RESET}")
        for idx, step in enumerate(next_steps, start=1):
            print(f"  {idx}. {step}")
        print(f"\n{PURPLE}Top Signatures:{RESET}")
        for line in findings["top_signatures"][:10]:
            print(f"  - {line}")
        print(f"\n{PURPLE}Top Files By Hit Count:{RESET}")
        for line in findings["high_signal_files"][:10]:
            print(f"  - {line}")
        print()
    except KeyboardInterrupt:
        print(f"\n{RED}SOSREPORT CANCELLED:{RESET} Interrupted by user (Ctrl+C).")
        sys.exit(130)
    except (FileNotFoundError, ValueError) as e:
        print(f"{RED}SOSREPORT ERROR:{RESET} {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}SOSREPORT ERROR:{RESET} Analysis failed: {e}")
        sys.exit(1)
    finally:
        if extracted_temp and os.path.isdir(extracted_temp):
            try:
                for walk_root, dirs, files in os.walk(extracted_temp, topdown=False):
                    for name in files:
                        os.remove(os.path.join(walk_root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(walk_root, name))
                os.rmdir(extracted_temp)
            except Exception:
                pass

def get_ollama_analysis(product, error_msg):
    clipped_error = error_msg[:MAX_PROMPT_CHARS]
    prompt = (
        f"You are Error Buddy (Canonical support engineer assistant) helping with product or stack: {product}.\n"
        "Respond in plain text only. Do not use markdown (no **, no ``` fences, no # headings).\n\n"
        "Start with a concise summary (about 2-6 sentences): prioritize accuracy; if unsure, say so; "
        "suggest possible causes or checks rather than one definitive fix unless the error clearly implies one.\n\n"
        "Then output exactly these two section titles as their own lines, in this order, below the summary:\n"
        "ADDITIONAL THINGS TO CHECK\n"
        "RELEVANT DOCUMENTATION LINKS\n\n"
        "Under ADDITIONAL THINGS TO CHECK: only include content if it is relevant. When relevant, list concrete items "
        "(e.g. specific systemctl services to check, log file paths to inspect, configuration files or settings). "
        "Use bullet lines starting with '- '. If nothing specific applies, write exactly: Not applicable.\n\n"
        "Under RELEVANT DOCUMENTATION LINKS: include 3-5 links when they relate to the error (fewer only if fewer are genuinely relevant). "
        "Prioritize official Canonical and Ubuntu documentation where applicable (e.g. documentation.ubuntu.com, Ubuntu Server guides, "
        "snapcraft.io/docs, and product docs such as MAAS, Juju, LXD when relevant to the product). "
        "Include authoritative upstream documentation for implicated components (e.g. PostgreSQL, Apache, systemd, cloud-init, Kubernetes). "
        "Each item: a short label, then the full https URL on the same line; do not invent URLs.\n\n"
        f"Error or context:\n{clipped_error}"
    )
    return run_multi_pass_analysis(prompt)

def run_doctor():
    print(f"\n{PURPLE}Error Buddy Doctor{RESET}")
    config = load_config()
    if config == "PLUG_REQUIRED":
        print(f"- Config access: {RED}FAILED{RESET} (run sudo snap connect error-buddy:dot-error-buddy)")
        return
    if not config:
        print(f"- Config file: {RED}MISSING{RESET} (run error-buddy init)")
        return

    timeout = get_timeout()
    ollama_model = config.get("ollama_model", DEFAULT_OLLAMA_MODEL)
    endpoints = get_ollama_endpoints(config.get("ollama_url", DEFAULT_OLLAMA_URL))
    print(f"- Config file: {GREEN}OK{RESET} ({CONFIG_PATH})")
    print(f"- Model: {ollama_model}")
    print(f"- Timeout: {timeout}s (set ERROR_BUDDY_OLLAMA_TIMEOUT to override)")
    print(f"- num_predict: {get_num_predict()} (set ERROR_BUDDY_OLLAMA_NUM_PREDICT to override)")
    print(f"- Multi-pass analysis: {'enabled' if is_multi_pass_enabled() else 'disabled'} (set ERROR_BUDDY_MULTI_PASS)")

    for endpoint in endpoints:
        print(f"- Endpoint check: {endpoint}")
        try:
            models = get_available_models(endpoint, timeout=min(timeout, 15))
            print(f"  {GREEN}reachable{RESET}")
            if ollama_model in models:
                print(f"  {GREEN}model present{RESET}")
            else:
                print(f"  {RED}model missing{RESET}: run 'ollama run {ollama_model}'")
            return
        except Exception as e:
            print(f"  {RED}failed{RESET}: {e}")
    print("  No reachable Ollama endpoint found.")

def get_search_urls(repo, msg):
    clean = re.sub(r'\[.*?\]|\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|0x[0-9a-fA-F]+|[0-9a-f\-]{36}', '', msg)
    clean = re.sub(r'[^\w\s\']', ' ', clean)
    clean_terms = " ".join(clean.split())

    if repo in ["openstack", "openstack-charmers"]:
        repo_filter = "^openstack/" if repo == "openstack" else "^openstack-charmers/"
        source_params = urllib.parse.urlencode({"q": clean_terms, "i": "nope", "repos": repo_filter})
        source_url = f"https://codesearch.openstack.org/?{source_params}"
    else:
        query = f"repo:{repo} {clean_terms}"
        source_params = urllib.parse.urlencode({"q": query, "type": "code"})
        source_url = f"https://github.com/search?{source_params}"

    bug_params = urllib.parse.urlencode({"field.searchtext": clean_terms, "search": "Search Bug Reports", "field.scope": "all"})
    bug_url = f"https://bugs.launchpad.net/bugs/+bugs?{bug_params}"

    return source_url, bug_url

def get_launchpad_bug_url(msg):
    clean = re.sub(r'\[.*?\]|\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|0x[0-9a-fA-F]+|[0-9a-f\-]{36}', '', msg)
    clean = re.sub(r'[^\w\s\']', ' ', clean)
    clean_terms = " ".join(clean.split())
    bug_params = urllib.parse.urlencode(
        {
            "field.searchtext": clean_terms,
            "search": "Search Bug Reports",
            "field.scope": "all",
        }
    )
    return f"https://bugs.launchpad.net/bugs/+bugs?{bug_params}"

def run_with_spinner(message, func, *args, **kwargs):
    # Keep output simple when not attached to a terminal.
    if not sys.stdout.isatty():
        print(message)
        return func(*args, **kwargs)

    done = threading.Event()
    result = {"value": None, "error": None}
    frames = ["|", "/", "-", "\\"]

    def worker():
        try:
            result["value"] = func(*args, **kwargs)
        except Exception as e:
            result["error"] = e
        finally:
            done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    idx = 0
    while not done.is_set():
        frame = frames[idx % len(frames)]
        sys.stdout.write(f"\r{message} {frame}")
        sys.stdout.flush()
        idx += 1
        done.wait(0.12)

    # Clear spinner line.
    sys.stdout.write("\r" + (" " * (len(message) + 4)) + "\r")
    sys.stdout.flush()

    if result["error"] is not None:
        raise result["error"]
    return result["value"]

def print_table_header():
    print(f"\n+ {'-'*25} + {'-'*70} +")
    print(f"| {'SOURCE LOG FILE':<25} | {'ERROR MESSAGE':<70} |")
    print(f"+ {'-'*25} + {'-'*70} +")

def print_table_row(filename, error_msg):
    fname = (filename[:22] + '...') if len(filename) > 25 else filename
    clean_msg = error_msg.replace('\n', ' ').replace(' | ', ' ')
    wrapped_err = textwrap.wrap(clean_msg, width=70)
    if not wrapped_err: return
    print(f"| {fname:<25} | {wrapped_err[0]:<70} |")
    for line in wrapped_err[1:]:
        print(f"| {' ':<25} | {line:<70} |")
    print(f"+ {'-'*25} + {'-'*70} +")

def parse_log_to_table(path):
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
                if trigger_pattern.search(line_content):
                    parts = line_content.split()
                    full_error = ""
                    for idx, word in enumerate(parts):
                        if trigger_pattern.search(word):
                            full_error = " ".join(parts[idx:])
                            break
                    if not full_error: full_error = line_content
                    j = i + 1
                    while j < len(lines) and j < i + 8:
                        next_line = lines[j].strip()
                        if not next_line: j += 1; continue
                        if continuation_pattern.search(next_line) or "TRACEBACK" in next_line.upper():
                            full_error += f" | {next_line}"
                            j += 1
                        else: break
                    if full_error not in seen:
                        print_table_row(filename, full_error)
                        seen.add(full_error)
                    i = j
                else: i += 1
    except Exception: pass

def main():
    parser = argparse.ArgumentParser(
        prog="error-buddy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""
            Analyze local logs, sosreports, or Canonical product errors with optional
            local Ollama AI assistance.

            Modes:
              - init: configure Ollama endpoint/model
              - doctor: validate config + Ollama connectivity
              - sosreport: interactive two-step sosreport investigation
              - <error>: generic error analysis (+ AI + Launchpad bugs)
              - <product> <error>: product error-search (source + bugs + AI summary)
              - <path>: local file/directory log audit
        """),
        epilog=textwrap.dedent(f"""
            {PURPLE}Usage Examples:{RESET}
              {BLUE}# Configure local Ollama integration{RESET}
              error-buddy init
              
              {BLUE}# Validate configuration and endpoint health{RESET}
              error-buddy doctor
              
              {BLUE}# Audit a local directory or SOS report{RESET}
              error-buddy ./var/log/syslog
              
              {BLUE}# Product error-search (Source + Bugs + AI){RESET}
              error-buddy maas "failed to power on"

              {BLUE}# Generic error analysis without product{RESET}
              error-buddy "camera failed to initialize"

              {BLUE}# List all supported product nicknames{RESET}
              error-buddy --list-products
              
              {BLUE}# Search without AI analysis{RESET}
              error-buddy juju "agent initialization" --no-ai
              
              {BLUE}# Diagnose local Ollama connectivity{RESET}
              error-buddy doctor
              
              {BLUE}# Interactive sosreport investigation{RESET}
              error-buddy sosreport
        """)
    )
    
    parser.add_argument(
        "product_or_path",
        nargs="?",
        help=(
            "Mode selector or target. Use: "
            "'init', 'doctor', 'sosreport', a product nickname (for deep search), "
            "or a local file/directory path (for log audit)."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Error text used with product error-search mode.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable Ollama AI analysis for product error-search mode.",
    )
    parser.add_argument(
        "--list-products",
        action="store_true",
        help="List supported product nicknames for product error-search mode.",
    )

    args = parser.parse_args()

    if args.list_products:
        print(f"\n{PURPLE}Supported Products:{RESET}")
        for name in sorted(REPOS.keys()):
            print(f"  - {name}")
        print()
        sys.exit(0)

    if args.product_or_path == "init":
        print(f"\n{PURPLE}Initialization Steps:{RESET}")
        print(f"1. Connect storage plug: {GREEN}sudo snap connect error-buddy:dot-error-buddy{RESET}")
        print(f"2. Start Ollama locally and run a model (example: {GREEN}ollama run qwen2.5-coder:7b{RESET})")
        print(f"3. Run {BLUE}error-buddy init{RESET} again to set Ollama config.")
        
        try:
            with open(CONFIG_PATH, "a"): pass
            url = input(
                f"\n{PURPLE}Step 4: Ollama API URL [{DEFAULT_OLLAMA_URL}] (or press Enter for default): {RESET}"
            ).strip()
            model = input(
                f"{PURPLE}Step 5: Ollama model [{DEFAULT_OLLAMA_MODEL}] (or press Enter for default): {RESET}"
            ).strip()
            save_config(url or DEFAULT_OLLAMA_URL, model or DEFAULT_OLLAMA_MODEL)
        except (PermissionError, OSError):
            print(f"\n{RED}Error: Write access denied.{RESET} Please perform Step 1 above.")
        sys.exit(0)

    if args.product_or_path == "doctor":
        run_doctor()
        sys.exit(0)

    if args.product_or_path == "sosreport":
        run_sosreport_interactive()
        sys.exit(0)

    if not args.product_or_path:
        parser.print_help()
        sys.exit(0)

    target = args.product_or_path
    expanded_path = os.path.abspath(os.path.expanduser(target))

    # Generic error mode: one argument that is not a known mode/product/path.
    if args.input is None and target.lower() not in REPOS and not os.path.exists(expanded_path):
        bug_url = get_launchpad_bug_url(target)
        if not args.no_ai:
            active_model = get_effective_ollama_model()
            print(f"\n{RED}AI Analysis:{RESET}")
            analysis = run_with_spinner(
                f"Running AI analysis with {active_model}",
                get_ollama_analysis,
                "generic",
                target,
            )
            print_pretty_ai_output(analysis, width=80, indent="  ")
        print(f"\nGeneric Error Search Results:")
        print(f"{'-'*60}")
        print(f"{PURPLE}Launchpad Bugs:{RESET} {BLUE}{bug_url}{RESET}")
        print(f"{'-'*60}\n")
        sys.exit(0)

    if target.lower() in REPOS and args.input:
        repo = REPOS[target.lower()]
        source_url, bug_url = get_search_urls(repo, args.input)
        
        if not args.no_ai:
            active_model = get_effective_ollama_model()
            print(f"\n{RED}AI Analysis for {target}:{RESET}")
            analysis = run_with_spinner(
                f"Running AI analysis with {active_model}",
                get_ollama_analysis,
                target,
                args.input,
            )
            print_pretty_ai_output(analysis, width=80, indent="  ")
        
        print(f"\nDeep Search Results:")
        print(f"{'-'*60}")
        print(f"{PURPLE}Source Code:{RESET} {BLUE}{source_url}{RESET}")
        print(f"{PURPLE}Launchpad Bugs:{RESET} {BLUE}{bug_url}{RESET}")
        print(f"{'-'*60}\n")
        sys.exit(0)

    if os.path.exists(expanded_path):
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

    print(f"Buddy Error: Could not find '{target}'.")

if __name__ == "__main__":
    main()
