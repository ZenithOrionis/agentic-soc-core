from __future__ import annotations

import argparse
import json
import os
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request

try:
    import pwd
except ImportError:  # pragma: no cover - only hit on non-Unix development hosts
    pwd = None


AUDIT_MSG_RE = re.compile(r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
AUDIT_TYPE_RE = re.compile(r"^type=(?P<record_type>[A-Z_]+)")
AUDIT_KV_RE = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"(?:[^\"\\]|\\.)*\"|[^ ]+)")

ENCODED_PATTERNS = ("base64 -d", "base64 --decode", "frombase64string", "openssl enc", "python3 -c", "python -c")
DOWNLOAD_PATTERNS = ("curl ", "wget ", "fetch ", "invoke-webrequest")
DOWNLOAD_EXEC_PATTERNS = ("| sh", "| bash", "bash -c", "sh -c", "chmod +x", "/tmp/", "/var/tmp/")
REVERSE_SHELL_PATTERNS = ("/dev/tcp/", "nc -e", "netcat -e", "socat tcp", "mkfifo /tmp/", "bash -i", "sh -i")
PERSISTENCE_PATTERNS = ("crontab ", "/etc/cron", "systemctl enable", "rc.local", "at now")
INTERPRETER_PATTERNS = ("python -c", "python3 -c", "perl -e", "ruby -e", "php -r", "node -e", "bash -c", "sh -c")


@dataclass
class AuditRecord:
    record_type: str
    event_id: str
    epoch: float
    fields: dict[str, str]
    raw: str


@dataclass
class PendingEvent:
    event_id: str
    epoch: float
    records: list[AuditRecord] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)


def log(event: str, **fields: Any) -> None:
    payload = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
    print(json.dumps(payload), flush=True)


def parse_audit_line(line: str) -> AuditRecord | None:
    msg_match = AUDIT_MSG_RE.search(line)
    type_match = AUDIT_TYPE_RE.search(line)
    if not msg_match or not type_match:
        return None
    fields: dict[str, str] = {}
    for match in AUDIT_KV_RE.finditer(line):
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[match.group("key")] = value
    return AuditRecord(
        record_type=type_match.group("record_type"),
        event_id=f"{msg_match.group('epoch')}:{msg_match.group('serial')}",
        epoch=float(msg_match.group("epoch")),
        fields=fields,
        raw=line.rstrip(),
    )


def command_from_records(records: list[AuditRecord]) -> str:
    execve = next((record for record in records if record.record_type == "EXECVE"), None)
    if not execve:
        return ""
    args = []
    for key, value in execve.fields.items():
        if key.startswith("a") and key[1:].isdigit():
            args.append((int(key[1:]), value))
    return " ".join(value for _, value in sorted(args))


def field_from_records(records: list[AuditRecord], key: str) -> str:
    for record in records:
        if key in record.fields:
            return record.fields[key]
    return ""


def username_from_uid(value: str) -> str:
    if not value or value in {"4294967295", "-1"}:
        return "unknown"
    if pwd is None:
        return value
    try:
        return pwd.getpwuid(int(value)).pw_name
    except Exception:  # noqa: BLE001
        return value


def detect_asset_ip() -> str:
    try:
        host = socket.gethostname()
        addresses = socket.getaddrinfo(host, None, family=socket.AF_INET)
        for address in addresses:
            ip = address[4][0]
            if not ip.startswith(("127.", "169.254.")):
                return ip
    except Exception:  # noqa: BLE001
        pass
    return "127.0.0.1"


def classify_command(command: str, exe: str, comm: str) -> tuple[int, int, str, list[str], str] | None:
    haystack = " ".join(filter(None, [command, exe, comm])).lower()
    if not haystack:
        return None

    has_encoded = any(pattern in haystack for pattern in ENCODED_PATTERNS) and ("base64" in haystack or "-c" in haystack)
    has_download = any(pattern in haystack for pattern in DOWNLOAD_PATTERNS)
    has_download_exec = any(pattern in haystack for pattern in DOWNLOAD_EXEC_PATTERNS)
    has_reverse_shell = any(pattern in haystack for pattern in REVERSE_SHELL_PATTERNS)
    has_persistence = any(pattern in haystack for pattern in PERSISTENCE_PATTERNS)
    has_interpreter = any(pattern in haystack for pattern in INTERPRETER_PATTERNS)

    if has_persistence:
        return (
            100400,
            10,
            "Kali auditd persistence-like command execution detected by Agentic SOC bridge",
            ["persistence", "auditd-bridge"],
            "persistence-like command",
        )
    if has_reverse_shell:
        return (
            100202,
            13,
            "Kali auditd reverse-shell-like command detected by Agentic SOC bridge",
            ["suspicious-script", "reverse-shell", "execution", "command-and-control", "auditd-bridge"],
            "reverse-shell-like command chain",
        )
    if has_download and has_download_exec:
        return (
            100201,
            12,
            "Kali auditd suspicious download-and-execute pattern detected by Agentic SOC bridge",
            ["suspicious-script", "download", "execution", "auditd-bridge"],
            "download-and-execute pattern",
        )
    if has_encoded or has_interpreter:
        return (
            100200,
            11,
            "Kali auditd suspicious encoded or inline shell command detected by Agentic SOC bridge",
            ["suspicious-script", "execution", "auditd-bridge"],
            "inline interpreter or encoded command",
        )
    return None


def build_wazuh_payload(records: list[AuditRecord], hostname: str, asset_ip: str) -> dict[str, Any] | None:
    if not records:
        return None
    command = command_from_records(records)
    exe = field_from_records(records, "exe")
    comm = field_from_records(records, "comm")
    syscall_record = next((record for record in records if record.record_type == "SYSCALL"), None)
    success = syscall_record.fields.get("success", "yes").lower() if syscall_record else "yes"
    if success not in {"1", "yes"}:
        return None

    classification = classify_command(command, exe, comm)
    if not classification:
        return None

    rule_id, level, description, tags, reason = classification
    username = username_from_uid(field_from_records(records, "auid") or field_from_records(records, "uid"))
    cwd = field_from_records(records, "cwd")
    timestamp = datetime.fromtimestamp(records[0].epoch, UTC).isoformat()
    return {
        "timestamp": timestamp,
        "agent": {"name": hostname, "id": hostname},
        "rule": {"id": rule_id, "level": level, "description": description, "groups": tags},
        "data": {
            "username": username,
            "process": comm or Path(exe).name or "unknown",
            "command": command[:400],
            "hostname": hostname,
            "asset_ip": asset_ip,
            "cwd": cwd,
            "exe": exe,
            "reason": reason,
            "audit_event_id": records[0].event_id,
            "audit_key": field_from_records(records, "key") or "agentic_exec",
        },
        "raw_event": {
            "records": [{"type": record.record_type, "fields": record.fields, "raw": record.raw} for record in records]
        },
    }


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")


def post_payload(url: str, api_key: str, payload: dict[str, Any]) -> None:
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-SOC-API-Key": api_key},
        method="POST",
    )
    with request.urlopen(req, timeout=10) as response:  # noqa: S310
        response.read()


def process_pending(
    pending: dict[str, PendingEvent],
    *,
    flush_all: bool,
    settle_seconds: float,
    hostname: str,
    asset_ip: str,
    normalizer_url: str,
    api_key: str,
    emitted: set[str],
) -> None:
    now = time.time()
    ready = [
        event_id
        for event_id, event in pending.items()
        if flush_all or now - event.last_updated >= settle_seconds
    ]
    for event_id in ready:
        event = pending.pop(event_id)
        if event_id in emitted:
            continue
        payload = build_wazuh_payload(event.records, hostname=hostname, asset_ip=asset_ip)
        if not payload:
            continue
        try:
            post_payload(f"{normalizer_url.rstrip('/')}/ingest/wazuh", api_key, payload)
            log(
                "audit_event_forwarded",
                rule_id=payload["rule"]["id"],
                description=payload["rule"]["description"],
                command=payload["data"]["command"],
                audit_event_id=event_id,
            )
            emitted.add(event_id)
        except error.HTTPError as exc:
            log("normalizer_http_error", status=exc.code, reason=exc.reason, audit_event_id=event_id)
        except Exception as exc:  # noqa: BLE001
            log("normalizer_post_failed", error=str(exc), audit_event_id=event_id)


def watch(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).expanduser()
    load_env_file(env_file)
    api_key = args.api_key or os.environ.get("SOC_API_KEY", "")
    if not api_key:
        raise SystemExit("Missing SOC API key. Pass --api-key or point --env-file at .env.production.")

    audit_log = Path(args.audit_log)
    state_path = Path(args.state_file).expanduser()
    hostname = args.hostname or socket.gethostname()
    asset_ip = args.asset_ip if args.asset_ip != "auto" else detect_asset_ip()
    normalizer_url = args.normalizer_url

    emitted: set[str] = set()
    pending: dict[str, PendingEvent] = {}
    state = load_state(state_path)

    while True:
        if not audit_log.exists():
            log("audit_log_missing", path=str(audit_log))
            time.sleep(args.poll_seconds)
            continue

        stat = audit_log.stat()
        inode = getattr(stat, "st_ino", 0)
        file_size = stat.st_size
        offset = int(state.get("offset", 0))
        if not state:
            offset = 0 if args.from_start or args.once else file_size
        if state.get("inode") != inode or offset > file_size:
            offset = 0 if args.from_start else file_size

        with audit_log.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for line in handle:
                parsed = parse_audit_line(line)
                if not parsed:
                    continue
                event = pending.setdefault(
                    parsed.event_id,
                    PendingEvent(event_id=parsed.event_id, epoch=parsed.epoch),
                )
                event.records.append(parsed)
                event.last_updated = time.time()
            state = {"inode": inode, "offset": handle.tell()}
            save_state(state_path, state)

        process_pending(
            pending,
            flush_all=args.once,
            settle_seconds=args.settle_seconds,
            hostname=hostname,
            asset_ip=asset_ip,
            normalizer_url=normalizer_url,
            api_key=api_key,
            emitted=emitted,
        )

        if args.once:
            break
        time.sleep(args.poll_seconds)

    process_pending(
        pending,
        flush_all=True,
        settle_seconds=args.settle_seconds,
        hostname=hostname,
        asset_ip=asset_ip,
        normalizer_url=normalizer_url,
        api_key=api_key,
        emitted=emitted,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Tail Kali auditd exec events and post suspicious ones to AegisCore.")
    parser.add_argument("--normalizer-url", default=os.getenv("NORMALIZER_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--api-key", default="")
    parser.add_argument("--env-file", default=".env.production")
    parser.add_argument("--audit-log", default="/var/log/audit/audit.log")
    parser.add_argument("--state-file", default="~/.local/state/agentic-soc-core/auditd-bridge-state.json")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--asset-ip", default="auto")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--settle-seconds", type=float, default=0.6)
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return watch(args)


if __name__ == "__main__":
    raise SystemExit(main())
