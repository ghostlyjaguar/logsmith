from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable
import json
import random

from formats import (
    LEVELS,
    REGIONS,
    SERVICES,
    HTTP_METHODS,
    URL_PATHS,
    USER_AGENTS,
    fmt_date,
    fmt_date_ms,
    fmt_iso,
    fmt_syslog,
    generate_timestamps,
    random_hex,
    random_hostname,
    random_ip,
    random_port,
    random_private_ip,
    random_protocol,
    random_username,
    random_uuid,
    synthetic_tag,
)


GeneratorFn = Callable[[int, random.Random, int], list[str]]


@dataclass(frozen=True)
class LogType:
    name: str
    description: str
    extension: str
    generator: GeneratorFn


def _syslog_line(ts: str, host: str, proc: str, pid: int, msg: str) -> str:
    return f"{ts} {host} {proc}[{pid}]: {msg}"


def generate_windows_system(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    sources = ["Service Control Manager", "Kernel-General", "DriverFrameworks-UserMode"]
    events = [
        (7036, "Information", "The {svc} service entered the running state."),
        (12, "Information", "The operating system started at system time {time}."),
        (6008, "Warning", "The previous system shutdown was unexpected."),
    ]
    lines = []
    for dt in timestamps:
        event_id, level, msg_t = rnd.choice(events)
        svc = rnd.choice(SERVICES)
        msg = msg_t.format(svc=svc, time=fmt_date(dt))
        line = (
            f"{fmt_date(dt)} EventID={event_id} Level={level} "
            f"Source={rnd.choice(sources)} Computer={random_hostname(rnd)} "
            f"Message={synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_windows_security(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    events = [
        (4624, "Audit Success", "An account was successfully logged on."),
        (4625, "Audit Failure", "An account failed to log on."),
        (4634, "Audit Success", "An account was logged off."),
    ]
    lines = []
    for dt in timestamps:
        event_id, level, msg = rnd.choice(events)
        user = random_username(rnd)
        ip = random_ip(rnd)
        line = (
            f"{fmt_date(dt)} EventID={event_id} Level={level} "
            "Source=Microsoft-Windows-Security-Auditing "
            f"Computer={random_hostname(rnd)} Account={user} LogonType=3 "
            f"IpAddress={ip} Message={synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_windows_application(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    sources = ["Application Error", "MyApp", "Updater"]
    messages = [
        "Application {app} crashed with exception 0x{code}.",
        "Application {app} started successfully.",
        "Update check completed for {app}.",
    ]
    lines = []
    for dt in timestamps:
        msg = rnd.choice(messages).format(app=rnd.choice(["AcmeApp", "TelemetrySvc"]), code=rnd.randint(1000, 9999))
        line = (
            f"{fmt_date(dt)} EventID={rnd.randint(1000, 5000)} Level={rnd.choice(['Information','Error','Warning'])} "
            f"Source={rnd.choice(sources)} Computer={random_hostname(rnd)} "
            f"Message={synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_linux_syslog(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        host = random_hostname(rnd)
        proc = rnd.choice(SERVICES)
        pid = rnd.randint(100, 9999)
        msg = synthetic_tag(rnd.choice([
            "Accepted publickey for {user} from {ip} port {port}",
            "Failed password for {user} from {ip} port {port}",
            "Started {svc} service",
            "Stopped {svc} service",
        ])).format(user=random_username(rnd), ip=random_ip(rnd), port=random_port(rnd), svc=proc)
        lines.append(_syslog_line(fmt_syslog(dt), host, proc, pid, msg))
    return lines


def generate_apache_access(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        ip = random_ip(rnd)
        user = random_username(rnd)
        method = rnd.choice(HTTP_METHODS)
        path = rnd.choice(URL_PATHS)
        status = rnd.choice([200, 201, 302, 400, 401, 403, 404, 500])
        size = rnd.randint(128, 8192)
        agent = rnd.choice(USER_AGENTS)
        ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = (
            f"{ip} - {user} [{ts}] \"{method} {path} HTTP/1.1\" "
            f"{status} {size} \"-\" \"{agent}\" {synthetic_tag('access log')}"
        )
        lines.append(line)
    return lines


def generate_apache_error(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    levels = ["notice", "warn", "error"]
    lines = []
    for dt in timestamps:
        ip = random_ip(rnd)
        msg = synthetic_tag(rnd.choice([
            "File does not exist: /var/www/html/favicon.ico",
            "client denied by server configuration: /var/www/html/admin",
            "AH00036: access to / forbidden (filesystem path '/var/www/html')",
        ]))
        line = f"[{dt.strftime('%a %b %d %H:%M:%S %Y')}] [{rnd.choice(levels)}] [pid {rnd.randint(1000,9999)}] [client {ip}] {msg}"
        lines.append(line)
    return lines


def generate_nginx_access(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        ip = random_ip(rnd)
        user = random_username(rnd)
        method = rnd.choice(HTTP_METHODS)
        path = rnd.choice(URL_PATHS)
        status = rnd.choice([200, 204, 301, 404, 499, 500, 502])
        size = rnd.randint(128, 8192)
        agent = rnd.choice(USER_AGENTS)
        line = (
            f"{ip} - {user} [{dt.strftime('%d/%b/%Y:%H:%M:%S +0000')}] "
            f"\"{method} {path} HTTP/1.1\" {status} {size} \"-\" \"{agent}\" "
            f"rt={rnd.random():.3f} {synthetic_tag('access log')}"
        )
        lines.append(line)
    return lines


def generate_nginx_error(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    levels = ["error", "warn", "notice"]
    lines = []
    for dt in timestamps:
        ip = random_ip(rnd)
        msg = synthetic_tag(rnd.choice([
            "upstream timed out (110: Connection timed out)",
            "connect() failed (111: Connection refused)",
            "client intended to send too large body",
        ]))
        line = (
            f"{dt.strftime('%Y/%m/%d %H:%M:%S')} [{rnd.choice(levels)}] "
            f"{rnd.randint(1000,9999)}#0: *{rnd.randint(1,999)} {msg}, "
            f"client: {ip}, server: example.com, request: \"GET / HTTP/1.1\", host: \"example.com\""
        )
        lines.append(line)
    return lines


def generate_java_app(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    classes = ["com.example.Auth", "com.example.Api", "com.example.Worker"]
    messages = [
        "User {user} logged in from {ip}",
        "Processed request {id} in {ms}ms",
        "Connection to {svc} established",
    ]
    lines = []
    for dt in timestamps:
        msg = rnd.choice(messages).format(
            user=random_username(rnd),
            ip=random_ip(rnd),
            id=random_uuid(rnd)[:8],
            ms=rnd.randint(5, 500),
            svc=rnd.choice(["db", "cache", "queue"]),
        )
        line = (
            f"{fmt_date_ms(dt)} {rnd.choice(LEVELS)} [{rnd.choice(['main','http-nio-8080-exec-1','worker-1'])}] "
            f"{rnd.choice(classes)} - {synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_dotnet_app(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        payload = {
            "timestamp": fmt_iso(dt),
            "level": rnd.choice(["Information", "Warning", "Error"]),
            "eventId": rnd.randint(1000, 2000),
            "message": synthetic_tag(
                rnd.choice([
                    "User {user} authenticated",
                    "Order {id} processed",
                    "Dependency call to {svc} succeeded",
                ])
            ).format(user=random_username(rnd), id=random_uuid(rnd)[:8], svc=rnd.choice(["db", "cache", "payments"])),
            "host": random_hostname(rnd),
            "user": random_username(rnd),
            "synthetic": True,
        }
        lines.append(json.dumps(payload, separators=(",", ":")))
    return lines


def generate_mysql(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        line = (
            f"{fmt_iso(dt)} {rnd.randint(1000,9999)} [Note] "
            f"{synthetic_tag('Aborted connection to db from ' + random_ip(rnd))}"
        )
        lines.append(line)
    return lines


def generate_mssql(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        msg = synthetic_tag(
            rnd.choice([
                "Login failed for user '{user}'.",
                "Database 'Sales' was backed up successfully.",
                "I/O is frozen on database 'Inventory'.",
            ])
        ).format(user=random_username(rnd))
        line = (
            f"{fmt_date_ms(dt)} Server      Error: {rnd.randint(1000, 20000)}, "
            f"Severity: {rnd.randint(10, 20)}, State: {rnd.randint(1, 10)}. {msg}"
        )
        lines.append(line)
    return lines


def generate_firewall(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    actions = ["ALLOW", "DENY"]
    lines = []
    for dt in timestamps:
        src = random_ip(rnd)
        dst = random_ip(rnd)
        line = (
            f"{fmt_date(dt)} {random_hostname(rnd)} action={rnd.choice(actions)} "
            f"src={src} dst={dst} spt={random_port(rnd)} dpt={random_port(rnd)} "
            f"proto={random_protocol(rnd)} msg=\"{synthetic_tag('Firewall policy match')}\""
        )
        lines.append(line)
    return lines


def generate_cisco_ios(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        src = random_ip(rnd)
        dst = random_ip(rnd)
        line = (
            f"{dt.strftime('%b %d %H:%M:%S')} {random_hostname(rnd)} %SEC-6-IPACCESSLOGP: "
            f"list 100 permit tcp {src}({random_port(rnd)}) -> {dst}({random_port(rnd)}), 1 packet "
            f"{synthetic_tag('ACL match')}"
        )
        lines.append(line)
    return lines


def generate_ids(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        payload = {
            "timestamp": fmt_iso(dt),
            "event_type": "alert",
            "src_ip": random_ip(rnd),
            "dest_ip": random_ip(rnd),
            "proto": rnd.choice(["TCP", "UDP"]),
            "src_port": random_port(rnd),
            "dest_port": random_port(rnd),
            "alert": {
                "signature": rnd.choice([
                    "ET SCAN Possible Nmap Scripting Engine User-Agent Detected",
                    "ET POLICY Suspicious inbound to MSSQL port",
                    "ET MALWARE Possible Evil User-Agent",
                ]),
                "category": rnd.choice(["Attempted Information Leak", "Potentially Bad Traffic", "Not Suspicious Traffic"]),
                "severity": rnd.randint(1, 3),
            },
            "app_proto": rnd.choice(["http", "dns", "ssh", "tls"]),
            "flow_id": rnd.randint(100000, 999999),
            "synthetic": True,
            "message": "SYNTHETIC IDS event",
        }
        lines.append(json.dumps(payload, separators=(",", ":")))
    return lines


def generate_antivirus(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    threats = ["EICAR-Test-File", "Trojan.Generic", "PUA.Optional"]
    actions = ["quarantine", "delete", "block"]
    lines = []
    for dt in timestamps:
        line = (
            f"{fmt_date(dt)} host={random_hostname(rnd)} product=GenericAV action={rnd.choice(actions)} "
            f"threat={rnd.choice(threats)} user={random_username(rnd)} "
            f"path=C:\\Users\\{random_username(rnd)}\\Downloads\\sample.bin result=success "
            f"{synthetic_tag('AV detection event')}"
        )
        lines.append(line)
    return lines


def generate_aws_cloudtrail(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    events = [
        ("ec2.amazonaws.com", "StartInstances"),
        ("iam.amazonaws.com", "CreateUser"),
        ("s3.amazonaws.com", "PutObject"),
    ]
    lines = []
    for dt in timestamps:
        source, name = rnd.choice(events)
        payload = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "userName": random_username(rnd),
            },
            "eventTime": fmt_iso(dt),
            "eventSource": source,
            "eventName": name,
            "awsRegion": rnd.choice(REGIONS),
            "sourceIPAddress": random_ip(rnd),
            "userAgent": "aws-cli/2.15 SyntheticLog",
            "requestParameters": {"instanceId": f"i-{random_uuid(rnd)[:8]}"},
            "responseElements": None,
            "eventID": random_uuid(rnd),
            "eventType": "AwsApiCall",
            "recipientAccountId": str(rnd.randint(100000000000, 999999999999)),
            "synthetic": True,
        }
        lines.append(json.dumps(payload, separators=(",", ":")))
    return lines


def generate_vmware_esxi(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        if rnd.random() < 0.5:
            line = f"{fmt_iso(dt)} cpu0:{rnd.randint(1000,9999)})VMkernel: {synthetic_tag('Device queue depth set to 32')}"
        else:
            line = f"{fmt_iso(dt)} vpxa: {synthetic_tag('Hostd connection established')}"
        lines.append(line)
    return lines


def generate_docker(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        if rnd.random() < 0.3:
            payload = {
                "log": synthetic_tag("Container started successfully") + "\n",
                "stream": rnd.choice(["stdout", "stderr"]),
                "time": fmt_iso(dt),
            }
            lines.append(json.dumps(payload, separators=(",", ":")))
        else:
            line = f"{fmt_iso(dt)} {random_hex(rnd,12)} {rnd.choice(['stdout','stderr'])} {synthetic_tag('Service heartbeat')}"
            lines.append(line)
    return lines


def generate_kubernetes(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        pod = f"web-{random_hex(rnd, 8)}"
        ns = rnd.choice(["default", "prod", "dev"])
        container = rnd.choice(["nginx", "app", "sidecar"])
        line = (
            f"{fmt_iso(dt)} pod={pod} ns={ns} container={container} host={random_hostname(rnd)} "
            f"{synthetic_tag('Handled request with status ' + str(rnd.choice([200, 404, 500])))}"
        )
        lines.append(line)
    return lines


def generate_snmp_traps(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    oids = [
        "1.3.6.1.6.3.1.1.5.3",  # linkDown
        "1.3.6.1.6.3.1.1.5.4",  # linkUp
        "1.3.6.1.6.3.1.1.5.2",  # coldStart
    ]
    severities = ["minor", "major", "critical"]
    lines = []
    for dt in timestamps:
        line = (
            f"{fmt_date(dt)} host={random_hostname(rnd)} trap={rnd.choice(['linkDown','linkUp','coldStart'])} "
            f"oid={rnd.choice(oids)} severity={rnd.choice(severities)} interface=Gi0/{rnd.randint(1,48)} "
            f"{synthetic_tag('SNMP trap')}"
        )
        lines.append(line)
    return lines


def generate_performance_metrics(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = ["timestamp,metric,value,host,tags"]
    metrics = ["cpu_pct", "mem_pct", "disk_iops", "latency_ms"]
    for dt in timestamps:
        metric = rnd.choice(metrics)
        if metric.endswith("pct"):
            value = f"{rnd.uniform(1, 99):.2f}"
        elif metric == "latency_ms":
            value = f"{rnd.uniform(1, 500):.2f}"
        else:
            value = str(rnd.randint(10, 5000))
        host = random_hostname(rnd)
        tags = f"service={rnd.choice(['web','db','cache'])};synthetic=true"
        lines.append(f"{fmt_iso(dt)},{metric},{value},{host},{tags}")
    return lines


def get_log_types() -> dict[str, LogType]:
    return {
        "windows_system": LogType(
            "windows_system",
            "Windows System Event Log style",
            "log",
            generate_windows_system,
        ),
        "windows_security": LogType(
            "windows_security",
            "Windows Security Event Log style",
            "log",
            generate_windows_security,
        ),
        "windows_application": LogType(
            "windows_application",
            "Windows Application Event Log style",
            "log",
            generate_windows_application,
        ),
        "linux_syslog": LogType(
            "linux_syslog",
            "Unix/Linux syslog style",
            "log",
            generate_linux_syslog,
        ),
        "apache_access": LogType(
            "apache_access",
            "Apache access log",
            "log",
            generate_apache_access,
        ),
        "apache_error": LogType(
            "apache_error",
            "Apache error log",
            "log",
            generate_apache_error,
        ),
        "nginx_access": LogType(
            "nginx_access",
            "Nginx access log",
            "log",
            generate_nginx_access,
        ),
        "nginx_error": LogType(
            "nginx_error",
            "Nginx error log",
            "log",
            generate_nginx_error,
        ),
        "java_app": LogType(
            "java_app",
            "Java Log4j/SLF4J style",
            "log",
            generate_java_app,
        ),
        "dotnet_app": LogType(
            "dotnet_app",
            ".NET structured app log style",
            "log",
            generate_dotnet_app,
        ),
        "mysql": LogType(
            "mysql",
            "MySQL error log style",
            "log",
            generate_mysql,
        ),
        "mssql": LogType(
            "mssql",
            "Microsoft SQL Server error log style",
            "log",
            generate_mssql,
        ),
        "firewall": LogType(
            "firewall",
            "Firewall traffic log",
            "log",
            generate_firewall,
        ),
        "cisco_ios": LogType(
            "cisco_ios",
            "Cisco IOS syslog style",
            "log",
            generate_cisco_ios,
        ),
        "ids": LogType(
            "ids",
            "Snort/Suricata style (JSONL, Suricata-like eve)",
            "ids_eve.jsonl",
            generate_ids,
        ),
        "antivirus": LogType(
            "antivirus",
            "Generic AV detection/action logs",
            "log",
            generate_antivirus,
        ),
        "aws_cloudtrail": LogType(
            "aws_cloudtrail",
            "AWS CloudTrail JSONL",
            "jsonl",
            generate_aws_cloudtrail,
        ),
        "vmware_esxi": LogType(
            "vmware_esxi",
            "VMware ESXi vmkernel/vpxa style",
            "log",
            generate_vmware_esxi,
        ),
        "docker": LogType(
            "docker",
            "Docker stdout/stderr or json-file style",
            "log",
            generate_docker,
        ),
        "kubernetes": LogType(
            "kubernetes",
            "Kubernetes pod logs with metadata",
            "log",
            generate_kubernetes,
        ),
        "snmp_traps": LogType(
            "snmp_traps",
            "SNMP trap notifications",
            "log",
            generate_snmp_traps,
        ),
        "performance_metrics": LogType(
            "performance_metrics",
            "Time-series metrics CSV",
            "csv",
            generate_performance_metrics,
        ),
    }
