from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable
import json
import random

from formats import (
    LEVELS,
    REGIONS,
    SERVICES,
    WINDOWS_SERVICES,
    HTTP_METHODS,
    URL_PATHS,
    USER_AGENTS,
    fmt_date,
    fmt_date_ms,
    fmt_iso,
    fmt_syslog,
    generate_timestamps,
    random_hex,
    random_ip,
    random_port,
    random_protocol,
    random_uuid,
    random_app_host,
    random_app_user,
    random_ephemeral_port,
    random_k8s_host,
    random_linux_host,
    random_linux_user,
    random_metric_host,
    random_mssql_host,
    random_mysql_host,
    random_network_host,
    random_service_port,
    random_web_host,
    random_windows_host,
    random_windows_user,
    random_esxi_host,
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
    events = [
        (7036, "Information", "Service Control Manager", "The {svc} service entered the running state."),
        (12, "Information", "Kernel-General", "The operating system started at system time {time}."),
        (6008, "Warning", "EventLog", "The previous system shutdown was unexpected."),
    ]
    lines = []
    for dt in timestamps:
        event_id, level, source, msg_t = rnd.choice(events)
        svc = rnd.choice(WINDOWS_SERVICES)
        msg = msg_t.format(svc=svc, time=fmt_date(dt))
        line = (
            f"{fmt_date(dt)} EventID={event_id} Level={level} "
            f"Source={source} Computer={random_windows_host(rnd)} "
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
        user = random_windows_user(rnd)
        base = (
            f"{fmt_date(dt)} EventID={event_id} Level={level} "
            "Source=Microsoft-Windows-Security-Auditing "
            f"Computer={random_windows_host(rnd)} Account={user} LogonType=3 "
        )
        if event_id in (4624, 4625):
            ip = random_ip(rnd)
            line = f"{base}IpAddress={ip} Message={synthetic_tag(msg)}"
        else:
            line = f"{base}Message={synthetic_tag(msg)}"
        lines.append(line)
    return lines


def generate_windows_application(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    events = [
        ("Application Error", "Error", "Application {app} crashed with exception 0x{code}."),
        ("MyApp", "Information", "Application {app} started successfully."),
        ("Updater", "Information", "Update check completed for {app}."),
        ("MyApp", "Warning", "Application {app} encountered a recoverable error."),
    ]
    lines = []
    for dt in timestamps:
        source, level, msg_t = rnd.choice(events)
        msg = msg_t.format(app=rnd.choice(["AcmeApp", "TelemetrySvc"]), code=rnd.randint(1000, 9999))
        line = (
            f"{fmt_date(dt)} EventID={rnd.randint(1000, 5000)} Level={level} "
            f"Source={source} Computer={random_windows_host(rnd)} "
            f"Message={synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_linux_syslog(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        proc = rnd.choice(SERVICES)
        if proc == "kubelet":
            host = random_k8s_host(rnd)
        else:
            host = random_linux_host(rnd)
        pid = rnd.randint(100, 9999)
        if proc == "sshd":
            msg_t = rnd.choice([
                "Accepted publickey for {user} from {ip} port {port}",
                "Failed password for {user} from {ip} port {port}",
            ])
        elif proc == "cron":
            msg_t = rnd.choice([
                "pam_unix(cron:session): session opened for user {user}",
                "pam_unix(cron:session): session closed for user {user}",
            ])
        elif proc in ("nginx", "apache2"):
            msg_t = rnd.choice([
                "Started {svc} service",
                "Stopped {svc} service",
                "{svc} reloaded configuration",
            ])
        elif proc == "mysql":
            msg_t = rnd.choice([
                "Aborted connection for user {user} from {ip}",
                "Access denied for user {user} from {ip}",
            ])
        elif proc == "docker":
            msg_t = rnd.choice([
                "Container started: {id}",
                "Container stopped: {id}",
            ])
        else:
            msg_t = rnd.choice([
                "Started {svc} service",
                "Stopped {svc} service",
            ])
        msg = synthetic_tag(msg_t).format(
            user=random_linux_user(rnd),
            ip=random_ip(rnd),
            port=random_port(rnd),
            svc=proc,
            id=random_hex(rnd, 12),
        )
        lines.append(_syslog_line(fmt_syslog(dt), host, proc, pid, msg))
    return lines


def generate_apache_access(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    status_by_method = {
        "GET": [200, 304, 401, 403, 404, 500],
        "POST": [200, 201, 400, 401, 403, 409, 500],
        "PUT": [200, 204, 400, 401, 403, 409, 500],
        "DELETE": [204, 401, 403, 404, 500],
    }
    for dt in timestamps:
        ip = random_ip(rnd)
        user = random_app_user(rnd)
        method = rnd.choice(HTTP_METHODS)
        path = rnd.choice(URL_PATHS)
        status = rnd.choice(status_by_method[method])
        size = rnd.randint(128, 8192)
        agent = rnd.choice(USER_AGENTS)
        ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = (
            f"{ip} - {user} [{ts}] \"{method} {path} HTTP/1.1\" "
            f"{status} {size} \"-\" \"{agent}\""
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
    status_by_method = {
        "GET": [200, 304, 401, 403, 404, 500, 502, 499],
        "POST": [200, 201, 400, 401, 403, 409, 500, 502, 499],
        "PUT": [200, 204, 400, 401, 403, 409, 500, 502, 499],
        "DELETE": [204, 401, 403, 404, 500, 502, 499],
    }
    for dt in timestamps:
        ip = random_ip(rnd)
        user = random_app_user(rnd)
        method = rnd.choice(HTTP_METHODS)
        path = rnd.choice(URL_PATHS)
        status = rnd.choice(status_by_method[method])
        size = rnd.randint(128, 8192)
        agent = rnd.choice(USER_AGENTS)
        line = (
            f"{ip} - {user} [{dt.strftime('%d/%b/%Y:%H:%M:%S +0000')}] "
            f"\"{method} {path} HTTP/1.1\" {status} {size} \"-\" \"{agent}\" "
            f"rt={rnd.random():.3f}"
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
    events = [
        ("INFO", "User {user} logged in from {ip}"),
        ("INFO", "Processed request {id} in {ms}ms"),
        ("INFO", "Connection to {svc} established"),
        ("WARN", "Slow request {id} took {ms}ms"),
        ("ERROR", "Failed to reach {svc}: timeout"),
    ]
    lines = []
    for dt in timestamps:
        level, msg_t = rnd.choice(events)
        msg = msg_t.format(
            user=random_app_user(rnd),
            ip=random_ip(rnd),
            id=random_uuid(rnd)[:8],
            ms=rnd.randint(200, 2000),
            svc=rnd.choice(["db", "cache", "queue"]),
        )
        line = (
            f"{fmt_date_ms(dt)} {level} [{rnd.choice(['main','http-nio-8080-exec-1','worker-1'])}] "
            f"{rnd.choice(classes)} - {synthetic_tag(msg)}"
        )
        lines.append(line)
    return lines


def generate_dotnet_app(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        level = rnd.choice(["Information", "Warning", "Error"])
        user = random_app_user(rnd)
        if level == "Error":
            msg_t = rnd.choice([
                "Dependency call to {svc} failed",
                "Order {id} failed",
            ])
        elif level == "Warning":
            msg_t = rnd.choice([
                "Dependency call to {svc} degraded",
                "Order {id} processed with retry",
            ])
        else:
            msg_t = rnd.choice([
                "User {user} authenticated",
                "Order {id} processed",
                "Dependency call to {svc} succeeded",
            ])
        payload = {
            "timestamp": fmt_iso(dt),
            "level": level,
            "eventId": rnd.randint(1000, 2000),
            "message": synthetic_tag(
                msg_t
            ).format(user=user, id=random_uuid(rnd)[:8], svc=rnd.choice(["db", "cache", "payments"])),
            "host": random_app_host(rnd),
            "user": user,
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
        event = rnd.choice([
            ("Error", 18456, 14, "Login failed for user '{user}'."),
            ("Message", 18264, 0, "Database 'Sales' was backed up successfully."),
            ("Error", 9002, 16, "I/O is frozen on database 'Inventory'."),
        ])
        kind, code, severity, msg_t = event
        msg = synthetic_tag(msg_t).format(user=random_app_user(rnd))
        line = (
            f"{fmt_date_ms(dt)} Server      {kind}: {code}, "
            f"Severity: {severity}, State: {rnd.randint(1, 10)}. {msg}"
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
        proto = random_protocol(rnd)
        host = random_network_host(rnd)
        base = (
            f"{fmt_date(dt)} {host} action={rnd.choice(actions)} "
            f"src={src} dst={dst} proto={proto} msg=\"{synthetic_tag('Firewall policy match')}\""
        )
        if proto == "ICMP":
            line = base
        else:
            line = (
                f"{fmt_date(dt)} {host} action={rnd.choice(actions)} "
                f"src={src} dst={dst} spt={random_ephemeral_port(rnd)} "
                f"dpt={random_service_port(rnd, proto)} proto={proto} "
                f"msg=\"{synthetic_tag('Firewall policy match')}\""
            )
        lines.append(line)
    return lines


def generate_cisco_ios(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        src = random_ip(rnd)
        dst = random_ip(rnd)
        dpt = random_service_port(rnd, "TCP")
        spt = random_ephemeral_port(rnd)
        line = (
            f"{dt.strftime('%b %d %H:%M:%S')} {random_network_host(rnd)} %SEC-6-IPACCESSLOGP: "
            f"list 100 permit tcp {src}({spt}) -> {dst}({dpt}), 1 packet "
            f"{synthetic_tag('ACL match')}"
        )
        lines.append(line)
    return lines


def generate_ids(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    alerts = [
        {
            "signature": "ET SCAN Possible Nmap Scripting Engine User-Agent Detected",
            "category": "Attempted Information Leak",
            "severity": 2,
            "proto": "TCP",
            "app_proto": "http",
            "dest_port": 80,
        },
        {
            "signature": "ET POLICY Suspicious inbound to MSSQL port",
            "category": "Potentially Bad Traffic",
            "severity": 2,
            "proto": "TCP",
            "app_proto": "mssql",
            "dest_port": 1433,
        },
        {
            "signature": "ET MALWARE Possible Evil User-Agent",
            "category": "A Network Trojan was detected",
            "severity": 3,
            "proto": "TCP",
            "app_proto": "http",
            "dest_port": 8080,
        },
        {
            "signature": "ET POLICY DNS Query to Suspicious TLD",
            "category": "Potentially Bad Traffic",
            "severity": 1,
            "proto": "UDP",
            "app_proto": "dns",
            "dest_port": 53,
        },
    ]
    lines = []
    for dt in timestamps:
        alert = rnd.choice(alerts)
        payload = {
            "timestamp": fmt_iso(dt),
            "event_type": "alert",
            "src_ip": random_ip(rnd),
            "dest_ip": random_ip(rnd),
            "proto": alert["proto"],
            "src_port": random_ephemeral_port(rnd),
            "dest_port": alert["dest_port"],
            "alert": {
                "signature": alert["signature"],
                "category": alert["category"],
                "severity": alert["severity"],
            },
            "app_proto": alert["app_proto"],
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
        user = random_windows_user(rnd)
        line = (
            f"{fmt_date(dt)} host={random_windows_host(rnd)} product=GenericAV action={rnd.choice(actions)} "
            f"threat={rnd.choice(threats)} user={user} "
            f"path=C:\\Users\\{user}\\Downloads\\sample.bin result=success "
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
        account_id = str(rnd.randint(100000000000, 999999999999))
        user = random_app_user(rnd)
        access_key = f"AKIA{random_hex(rnd, 16).upper()}"
        user_arn = f"arn:aws:iam::{account_id}:user/{user}"
        request_parameters = {}
        response_elements = None
        if name == "StartInstances":
            instance_id = f"i-{random_hex(rnd, 8)}"
            request_parameters = {"instancesSet": {"items": [{"instanceId": instance_id}]}}
            response_elements = {
                "instancesSet": {
                    "items": [
                        {
                            "instanceId": instance_id,
                            "currentState": {"code": 16, "name": "running"},
                            "previousState": {"code": 80, "name": "stopped"},
                        }
                    ]
                }
            }
        elif name == "CreateUser":
            created_user = random_app_user(rnd)
            if created_user == user:
                created_user = random_app_user(rnd)
                if created_user == user:
                    created_user = f"{user}_svc"
            created_user_arn = f"arn:aws:iam::{account_id}:user/{created_user}"
            request_parameters = {"userName": created_user}
            response_elements = {
                "user": {
                    "userName": created_user,
                    "arn": created_user_arn,
                    "createDate": fmt_iso(dt),
                }
            }
        elif name == "PutObject":
            bucket = rnd.choice(["logs-bucket", "app-data", "backups"])
            key = f"uploads/{random_hex(rnd, 6)}.txt"
            request_parameters = {"bucketName": bucket, "key": key}
            response_elements = {
                "x-amz-request-id": random_hex(rnd, 16),
                "x-amz-id-2": random_hex(rnd, 32),
            }
        payload = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": random_hex(rnd, 16).upper(),
                "arn": user_arn,
                "accountId": account_id,
                "accessKeyId": access_key,
                "userName": user,
            },
            "eventTime": fmt_iso(dt),
            "eventSource": source,
            "eventName": name,
            "awsRegion": rnd.choice(REGIONS),
            "sourceIPAddress": random_ip(rnd),
            "userAgent": "aws-cli/2.15 SyntheticLog",
            "requestParameters": request_parameters,
            "responseElements": response_elements,
            "eventID": random_uuid(rnd),
            "eventType": "AwsApiCall",
            "recipientAccountId": account_id,
            "eventCategory": "Management",
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
        payload = {
            "log": synthetic_tag(rnd.choice([
                "Container started successfully",
                "Service heartbeat",
                "Healthcheck passed",
            ])) + "\n",
            "stream": rnd.choice(["stdout", "stderr"]),
            "time": fmt_iso(dt),
        }
        lines.append(json.dumps(payload, separators=(",", ":")))
    return lines


def generate_kubernetes(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    lines = []
    for dt in timestamps:
        pod = f"web-{random_hex(rnd, 8)}"
        ns = rnd.choice(["default", "prod", "dev"])
        container = rnd.choice(["nginx", "app", "sidecar"])
        line = (
            f"{fmt_iso(dt)} pod={pod} ns={ns} container={container} host={random_k8s_host(rnd)} "
            f"{synthetic_tag('Handled request with status ' + str(rnd.choice([200, 404, 500])))}"
        )
        lines.append(line)
    return lines


def generate_snmp_traps(count: int, rnd: random.Random, timeframe_days: int) -> list[str]:
    timestamps = generate_timestamps(count, timeframe_days, rnd)
    oids = {
        "linkDown": "1.3.6.1.6.3.1.1.5.3",
        "linkUp": "1.3.6.1.6.3.1.1.5.4",
        "coldStart": "1.3.6.1.6.3.1.1.5.1",
    }
    severities = ["minor", "major", "critical"]
    lines = []
    for dt in timestamps:
        trap = rnd.choice(list(oids.keys()))
        if rnd.random() < 0.2:
            host = random_esxi_host(rnd)
            iface = f"vmnic{rnd.randint(0, 3)}"
        else:
            host = random_network_host(rnd)
            iface = f"Gi0/{rnd.randint(1,48)}"
        line = (
            f"{fmt_date(dt)} host={host} trap={trap} "
            f"oid={oids[trap]} severity={rnd.choice(severities)} interface={iface} "
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
        if metric in ("cpu_pct", "mem_pct", "disk_iops"):
            host = random_k8s_host(rnd)
        else:
            host = random_app_host(rnd)
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
