from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import random
import uuid


HOSTNAMES = [
    "web01",
    "web02",
    "db01",
    "db02",
    "fw01",
    "win10-lab",
    "win11-lab",
    "k8s-node1",
    "k8s-node2",
    "app01",
    "app02",
    "esxi01",
    "router1",
    "switch1",
]

USERNAMES = ["admin", "root", "jdoe", "svc_app", "alice", "bob", "svc_backup"]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
URL_PATHS = ["/", "/login", "/api/v1/items", "/admin", "/health", "/static/app.js"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyntheticLog",
    "curl/7.88.1 SyntheticLog",
    "python-requests/2.31 SyntheticLog",
]

SERVICES = ["sshd", "nginx", "apache2", "mysql", "docker", "kubelet", "cron"]

LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


@dataclass(frozen=True)
class TimeRange:
    start: datetime
    end: datetime


def get_timerange(timeframe_days: int) -> TimeRange:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=timeframe_days)
    return TimeRange(start=start, end=end)


def generate_timestamps(count: int, timeframe_days: int, rnd: random.Random) -> list[datetime]:
    if count <= 0:
        return []
    tr = get_timerange(timeframe_days)
    total_seconds = int((tr.end - tr.start).total_seconds())
    if total_seconds >= count - 1:
        points = rnd.sample(range(total_seconds + 1), count)
    else:
        points = [rnd.randint(0, total_seconds) for _ in range(count)]
    points.sort()
    return [tr.start + timedelta(seconds=sec) for sec in points]


def fmt_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def fmt_syslog(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%b %d %H:%M:%S")


def fmt_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def fmt_date_ms(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def choose(rnd: random.Random, items: list[str]) -> str:
    return rnd.choice(items)


def random_hostname(rnd: random.Random) -> str:
    return choose(rnd, HOSTNAMES)


def random_username(rnd: random.Random) -> str:
    return choose(rnd, USERNAMES)


def random_private_ip(rnd: random.Random) -> str:
    block = rnd.choice(["10", "172", "192"])
    if block == "10":
        return f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
    if block == "172":
        return f"172.{rnd.randint(16, 31)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
    return f"192.168.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


def random_doc_ip(rnd: random.Random) -> str:
    base = rnd.choice(["198.51.100", "203.0.113"])
    return f"{base}.{rnd.randint(1, 254)}"


def random_ip(rnd: random.Random) -> str:
    return random_private_ip(rnd) if rnd.random() < 0.8 else random_doc_ip(rnd)


def random_port(rnd: random.Random) -> int:
    common = [22, 53, 80, 443, 3389, 3306, 1433, 8080, 8443]
    return rnd.choice(common + [rnd.randint(1024, 65535)])


def random_protocol(rnd: random.Random) -> str:
    return rnd.choice(["TCP", "UDP", "ICMP"])


def random_hex(rnd: random.Random, length: int = 8) -> str:
    return "".join(rnd.choice("0123456789abcdef") for _ in range(length))


def random_uuid(rnd: random.Random) -> str:
    if hasattr(rnd, "randbytes"):
        return str(uuid.UUID(bytes=rnd.randbytes(16)))
    return str(uuid.UUID(int=rnd.getrandbits(128)))


def synthetic_tag(message: str) -> str:
    return f"[SYNTHETIC] {message}"
