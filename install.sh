#!/usr/bin/env bash
set -euo pipefail

APP_NAME="outbound-logger"
INSTALL_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
ENV_FILE="${CONFIG_DIR}/${APP_NAME}.env"
PY_FILE="${INSTALL_DIR}/logger.py"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
RSYSLOG_FILE="/etc/rsyslog.d/30-${APP_NAME}.conf"
RSYSLOG_TEMPLATE_FILE="/etc/rsyslog.d/29-${APP_NAME}-template.conf"

OUTPUT_MODE=""
LOG_FORMAT="json"
LOG_DIR="/var/log/${APP_NAME}"
SYSLOG_TARGET=""
SYSLOG_PORT="514"
SYSLOG_PROTO="udp"

IGNORE_LOOPBACK="yes"
IGNORE_PRIVATE="no"
IGNORE_ROOT="no"
ENABLE_HOST_ENRICHMENT="yes"

if [[ $EUID -ne 0 ]]; then
  echo "Bu script root olarak çalıştırılmalıdır."
  exit 1
fi

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_pkg_manager() {
  if command_exists apt; then
    PKG_MGR="apt"
  elif command_exists dnf; then
    PKG_MGR="dnf"
  elif command_exists yum; then
    PKG_MGR="yum"
  else
    echo "Desteklenmeyen paket yöneticisi."
    exit 1
  fi
}

install_packages() {
  echo "Gerekli paketler kontrol edilip kuruluyor..."

  if [[ "$PKG_MGR" == "apt" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y \
      python3 python3-pip python3-bpfcc bpfcc-tools rsyslog \
      "linux-headers-$(uname -r)" || true
  elif [[ "$PKG_MGR" == "dnf" ]]; then
    dnf install -y epel-release || true
    dnf install -y \
      python3 python3-pip rsyslog \
      bcc bcc-tools python3-bcc kernel-devel kernel-headers || true
  elif [[ "$PKG_MGR" == "yum" ]]; then
    yum install -y epel-release || true
    yum install -y \
      python3 python3-pip rsyslog \
      bcc bcc-tools python3-bcc kernel-devel kernel-headers || true
  fi
}

ask_install_questions() {
  echo
  echo "Çıktı modu seçin:"
  echo "  1) file"
  echo "  2) syslog"
  echo "  3) both"
  read -rp "Seçim [1-3]: " OUTPUT_MODE_CHOICE

  case "$OUTPUT_MODE_CHOICE" in
    1) OUTPUT_MODE="file" ;;
    2) OUTPUT_MODE="syslog" ;;
    3) OUTPUT_MODE="both" ;;
    *) echo "Geçersiz seçim"; exit 1 ;;
  esac

  echo
  echo "Log formatı seçin:"
  echo "  1) json"
  echo "  2) csv"
  read -rp "Seçim [1-2] (önerilen json): " FORMAT_CHOICE

  case "$FORMAT_CHOICE" in
    1|"") LOG_FORMAT="json" ;;
    2) LOG_FORMAT="csv" ;;
    *) echo "Geçersiz seçim"; exit 1 ;;
  esac

  if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
    read -rp "Dosya log dizini [${LOG_DIR}]: " INPUT_LOG_DIR || true
    LOG_DIR="${INPUT_LOG_DIR:-$LOG_DIR}"
    mkdir -p "$LOG_DIR"
  fi

  if [[ "$OUTPUT_MODE" == "syslog" || "$OUTPUT_MODE" == "both" ]]; then
    read -rp "Uzak syslog sunucusu IP/FQDN: " SYSLOG_TARGET
    read -rp "Port [514]: " SYSLOG_PORT_INPUT || true
    SYSLOG_PORT="${SYSLOG_PORT_INPUT:-514}"

    echo
    echo "Uzak syslog protokolü:"
    echo "  1) tcp"
    echo "  2) udp"
    read -rp "Seçim [1-2]: " SYSLOG_PROTO_CHOICE

    case "$SYSLOG_PROTO_CHOICE" in
      1) SYSLOG_PROTO="tcp" ;;
      2) SYSLOG_PROTO="udp" ;;
      *) echo "Geçersiz seçim"; exit 1 ;;
    esac
  fi

  echo
  read -rp "127.0.0.1 -> 127.0.0.1 gibi loopback bağlantılar loglansın mı? [y/N]: " ANSWER_LOOP || true
  case "${ANSWER_LOOP,,}" in
    y|yes) IGNORE_LOOPBACK="no" ;;
    *) IGNORE_LOOPBACK="yes" ;;
  esac

  read -rp "Private IP (10.x, 172.16/12, 192.168.x, fc00::/7 vb.) bağlantılar ignore edilsin mi? [y/N]: " ANSWER_PRIVATE || true
  case "${ANSWER_PRIVATE,,}" in
    y|yes) IGNORE_PRIVATE="yes" ;;
    *) IGNORE_PRIVATE="no" ;;
  esac

  read -rp "root kullanıcısının bağlantıları ignore edilsin mi? [y/N]: " ANSWER_ROOT || true
  case "${ANSWER_ROOT,,}" in
    y|yes) IGNORE_ROOT="yes" ;;
    *) IGNORE_ROOT="no" ;;
  esac

  read -rp "Hostname/domain enrichment (DNS/SNI best-effort) aktif olsun mu? [Y/n]: " ANSWER_HOST || true
  case "${ANSWER_HOST,,}" in
    n|no) ENABLE_HOST_ENRICHMENT="no" ;;
    *) ENABLE_HOST_ENRICHMENT="yes" ;;
  esac
}

write_env() {
  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

  cat > "$ENV_FILE" <<EOF
OUTPUT_MODE="${OUTPUT_MODE}"
LOG_FORMAT="${LOG_FORMAT}"
IGNORE_LOOPBACK="${IGNORE_LOOPBACK}"
IGNORE_PRIVATE="${IGNORE_PRIVATE}"
IGNORE_ROOT="${IGNORE_ROOT}"
ENABLE_HOST_ENRICHMENT="${ENABLE_HOST_ENRICHMENT}"
EOF

  chmod 600 "$ENV_FILE"
}

write_python_logger() {
  cat > "$PY_FILE" <<'PYEOF'
#!/usr/bin/env python3
import os
import sys
import pwd
import json
import time
import socket
import ipaddress
import ctypes as ct
import subprocess
from datetime import datetime, timezone

try:
    from bcc import BPF
except Exception as e:
    print(f"BCC import hatası: {e}", file=sys.stderr)
    sys.exit(1)

APP_NAME = "outbound-logger"
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json").strip().lower()
IGNORE_LOOPBACK = os.environ.get("IGNORE_LOOPBACK", "yes").strip().lower() == "yes"
IGNORE_PRIVATE = os.environ.get("IGNORE_PRIVATE", "no").strip().lower() == "yes"
IGNORE_ROOT = os.environ.get("IGNORE_ROOT", "no").strip().lower() == "yes"
ENABLE_HOST_ENRICHMENT = os.environ.get("ENABLE_HOST_ENRICHMENT", "yes").strip().lower() == "yes"
HOSTNAME = socket.gethostname()

HOST_CACHE = {}
HOST_TTL = 20

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define HOST_LEN 256

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

struct host_event_t {
    u32 pid;
    u32 uid;
    u8 source;   // 1=dns(getaddrinfo), 2=sni(openssl)
    char host[HOST_LEN];
};

BPF_HASH(currsock, u64, struct sock *);
BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);
BPF_PERF_OUTPUT(host_events);

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sk);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    if (ret != 0) {
        currsock.delete(&pid_tgid);
        return 0;
    }

    struct sock *sk = *skpp;
    u16 dport = 0, sport = 0;
    u32 saddr = 0, daddr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    struct ipv4_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = ntohs(dport);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    ipv4_events.perf_submit(ctx, &evt, sizeof(evt));
    currsock.delete(&pid_tgid);
    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sk);
    return 0;
}

int trace_connect_v6_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    if (ret != 0) {
        currsock.delete(&pid_tgid);
        return 0;
    }

    struct sock *sk = *skpp;
    u16 dport = 0, sport = 0;
    unsigned __int128 saddr = 0, daddr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    struct ipv6_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = ntohs(dport);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    ipv6_events.perf_submit(ctx, &evt, sizeof(evt));
    currsock.delete(&pid_tgid);
    return 0;
}

int trace_getaddrinfo(struct pt_regs *ctx, const char __user *node) {
    if (node == NULL) {
        return 0;
    }

    struct host_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 1;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), node);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_ssl_set_tlsext_host_name(struct pt_regs *ctx, void *ssl, const char __user *name) {
    if (name == NULL) {
        return 0;
    }

    struct host_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 2;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), name);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

class HostEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("source", ct.c_ubyte),
        ("host", ct.c_char * 256),
    ]

def ip4_to_str(addr):
    return socket.inet_ntop(socket.AF_INET, addr.to_bytes(4, byteorder="little"))

def ip6_to_str(raw):
    try:
        if isinstance(raw, (bytes, bytearray)):
            buf = bytes(raw)
        else:
            try:
                buf = bytes(raw)
            except Exception:
                buf = int(raw).to_bytes(16, byteorder="big", signed=False)

        if len(buf) != 16:
            buf = buf[:16].ljust(16, b"\x00")

        return socket.inet_ntop(socket.AF_INET6, buf)
    except Exception:
        return ""

def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)

def get_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            data = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
            return data if data else ""
    except Exception:
        return ""

def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return False

def is_private(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_link_local
    except Exception:
        return False

def cleanup_host_cache():
    now = time.time()
    expired = [pid for pid, value in HOST_CACHE.items() if now - value["ts"] > HOST_TTL]
    for pid in expired:
        HOST_CACHE.pop(pid, None)

def valid_host(host):
    if not host:
        return False
    host = host.strip()
    if len(host) < 2:
        return False
    if " " in host:
        return False
    if host.startswith("/"):
        return False
    return True

def remember_host(pid, host, source):
    if not ENABLE_HOST_ENRICHMENT:
        return
    if not valid_host(host):
        return
    HOST_CACHE[pid] = {
        "host": host,
        "source": source,
        "ts": time.time(),
    }

def get_host_for_pid(pid):
    cleanup_host_cache()
    item = HOST_CACHE.get(pid)
    if not item:
        return None, None
    return item["host"], item["source"]

def should_skip(rec):
    if IGNORE_ROOT and rec["uid"] == 0:
        return True

    if IGNORE_LOOPBACK and is_loopback(rec["src_ip"]) and is_loopback(rec["dst_ip"]):
        return True

    if IGNORE_PRIVATE and is_private(rec["dst_ip"]):
        return True

    return False

def emit_record(rec):
    if should_skip(rec):
        return

    if LOG_FORMAT == "csv":
        fields = [
            rec["timestamp"],
            rec["hostname"],
            str(rec["uid"]),
            rec["user"],
            str(rec["pid"]),
            rec["comm"],
            rec["cmdline"],
            rec["family"],
            rec["src_ip"],
            str(rec["src_port"]),
            rec["dst_ip"],
            str(rec["dst_port"]),
            rec.get("dst_host", ""),
            rec.get("dst_host_source", ""),
        ]
        line = ",".join('"' + str(x).replace('"', '""') + '"' for x in fields)
    else:
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))

    print(line, flush=True)

def handle_host(cpu, data, size):
    event = ct.cast(data, ct.POINTER(HostEvent)).contents
    pid = int(event.pid)
    source = "dns" if int(event.source) == 1 else "sni"
    host = bytes(event.host).split(b"\x00", 1)[0].decode(errors="replace").strip()
    remember_host(pid, host, source)

def handle_ipv4(cpu, data, size):
    try:
        event = b["ipv4_events"].event(data)
        uid = int(event.uid)
        pid = int(event.pid)

        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": HOSTNAME,
            "uid": uid,
            "user": get_username(uid),
            "pid": pid,
            "comm": event.comm.decode(errors="replace").rstrip("\x00"),
            "cmdline": get_cmdline(pid),
            "family": "ipv4",
            "src_ip": ip4_to_str(event.saddr),
            "src_port": int(event.sport),
            "dst_ip": ip4_to_str(event.daddr),
            "dst_port": int(event.dport),
        }

        dst_host, dst_host_source = get_host_for_pid(pid)
        if dst_host:
            rec["dst_host"] = dst_host
            rec["dst_host_source"] = dst_host_source

        emit_record(rec)
    except Exception as e:
        print(json.dumps({
            "logger_error": "handle_ipv4_failed",
            "error": str(e)
        }), flush=True)

def handle_ipv6(cpu, data, size):
    try:
        event = b["ipv6_events"].event(data)
        uid = int(event.uid)
        pid = int(event.pid)

        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": HOSTNAME,
            "uid": uid,
            "user": get_username(uid),
            "pid": pid,
            "comm": event.comm.decode(errors="replace").rstrip("\x00"),
            "cmdline": get_cmdline(pid),
            "family": "ipv6",
            "src_ip": ip6_to_str(event.saddr),
            "src_port": int(event.sport),
            "dst_ip": ip6_to_str(event.daddr),
            "dst_port": int(event.dport),
        }

        dst_host, dst_host_source = get_host_for_pid(pid)
        if dst_host:
            rec["dst_host"] = dst_host
            rec["dst_host_source"] = dst_host_source

        emit_record(rec)
    except Exception as e:
        print(json.dumps({
            "logger_error": "handle_ipv6_failed",
            "error": str(e)
        }), flush=True)

def find_libssl():
    candidates = [
        "/lib64/libssl.so.3",
        "/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    try:
        out = subprocess.check_output(
            ["sh", "-c", "ldconfig -p | grep 'libssl.so' | head -n1 | awk '{print $NF}'"],
            text=True
        ).strip()
        if out and os.path.exists(out):
            return out
    except Exception:
        pass
    return None

b = BPF(text=BPF_PROGRAM)

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_entry")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

if ENABLE_HOST_ENRICHMENT:
    try:
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo")
    except Exception:
        pass

    libssl_path = find_libssl()
    if libssl_path:
        try:
            b.attach_uprobe(name=libssl_path, sym="SSL_set_tlsext_host_name", fn_name="trace_ssl_set_tlsext_host_name")
        except Exception:
            pass

b["ipv4_events"].open_perf_buffer(handle_ipv4)
b["ipv6_events"].open_perf_buffer(handle_ipv6)
b["host_events"].open_perf_buffer(handle_host)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
PYEOF

  chmod +x "$PY_FILE"
}

write_rsyslog_config() {
  local file_ext="jsonl"
  [[ "$LOG_FORMAT" == "csv" ]] && file_ext="csv"

  if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
    printf 'template(name="OutboundDynFile" type="string" string="%s/%%$YEAR%%-%%$MONTH%%-%%$DAY%%.%s")\n' \
      "$LOG_DIR" "$file_ext" > "$RSYSLOG_TEMPLATE_FILE"
  else
    rm -f "$RSYSLOG_TEMPLATE_FILE"
  fi

  {
    echo "# ${APP_NAME} rsyslog config"
    echo 'if ('
    echo '    $msg contains "\"src_ip\"" and'
    echo '    $msg contains "\"dst_ip\"" and'
    echo '    $msg contains "\"cmdline\""'
    echo ') then {'

    if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
      echo '    action(type="omfile" dynaFile="OutboundDynFile")'
    fi

    if [[ "$OUTPUT_MODE" == "syslog" || "$OUTPUT_MODE" == "both" ]]; then
      if [[ "$SYSLOG_PROTO" == "tcp" ]]; then
        echo "    action(type=\"omfwd\" target=\"${SYSLOG_TARGET}\" port=\"${SYSLOG_PORT}\" protocol=\"tcp\" TCP_Framing=\"octet-counted\")"
      else
        echo "    action(type=\"omfwd\" target=\"${SYSLOG_TARGET}\" port=\"${SYSLOG_PORT}\" protocol=\"udp\")"
      fi
    fi

    echo '    stop'
    echo '}'
  } > "$RSYSLOG_FILE"
}

write_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Outbound Logger eBPF Logger
After=network-online.target rsyslog.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 ${PY_FILE}
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
}

validate_rsyslog() {
  echo
  echo "rsyslog config doğrulanıyor..."
  if ! rsyslogd -N1; then
    echo
    echo "rsyslog config doğrulaması başarısız oldu."
    echo "Kontrol edin:"
    echo "  ${RSYSLOG_FILE}"
    [[ -f "$RSYSLOG_TEMPLATE_FILE" ]] && echo "  ${RSYSLOG_TEMPLATE_FILE}"
    exit 1
  fi
}

enable_services() {
  systemctl enable rsyslog >/dev/null 2>&1 || true
  systemctl restart rsyslog

  systemctl daemon-reload
  systemctl enable "${APP_NAME}"
  systemctl restart "${APP_NAME}"
}

show_install_result() {
  local today_file=""
  local ext="jsonl"
  [[ "$LOG_FORMAT" == "csv" ]] && ext="csv"

  if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
    today_file="${LOG_DIR}/$(date +%Y-%m-%d).${ext}"
  fi

  echo
  echo "Kurulum tamamlandı."
  echo
  echo "Servis durumu:"
  systemctl --no-pager --full status "${APP_NAME}" || true
  echo
  echo "=== Test / Debug Komutları ==="
  echo "journalctl -u ${APP_NAME} -f"
  echo "curl -k https://google.com >/dev/null 2>&1"
  echo "php -r '\$fp=stream_socket_client(\"ssl://google.com:443\",\$e,\$s,10); if(\$fp){ fwrite(\$fp, \"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n\"); fclose(\$fp);} '"
  echo "/usr/share/bcc/tools/tcpconnect"

  if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
    echo "tail -f ${today_file}"
  fi

  if [[ "$OUTPUT_MODE" == "syslog" || "$OUTPUT_MODE" == "both" ]]; then
    echo "tcpdump -ni any host ${SYSLOG_TARGET} and port ${SYSLOG_PORT}"
  fi

  echo "rsyslogd -N1"
  echo "systemctl restart ${APP_NAME}"
  echo "systemctl restart rsyslog"
  echo "systemctl stop ${APP_NAME}"
  echo "source ${ENV_FILE}"
  echo "LOG_FORMAT=\$LOG_FORMAT IGNORE_LOOPBACK=\$IGNORE_LOOPBACK IGNORE_PRIVATE=\$IGNORE_PRIVATE IGNORE_ROOT=\$IGNORE_ROOT ENABLE_HOST_ENRICHMENT=\$ENABLE_HOST_ENRICHMENT /usr/bin/python3 ${PY_FILE}"
  echo
  echo "=== Kurulum Özeti ==="
  echo "Çıktı modu       : ${OUTPUT_MODE}"
  echo "Log formatı      : ${LOG_FORMAT}"
  echo "Loopback ignore  : ${IGNORE_LOOPBACK}"
  echo "Private ignore   : ${IGNORE_PRIVATE}"
  echo "Root ignore      : ${IGNORE_ROOT}"
  echo "Host enrichment  : ${ENABLE_HOST_ENRICHMENT}"

  if [[ "$OUTPUT_MODE" == "file" || "$OUTPUT_MODE" == "both" ]]; then
    echo "Log dizini       : ${LOG_DIR}"
    echo "Bugünkü dosya    : ${today_file}"
  fi

  if [[ "$OUTPUT_MODE" == "syslog" || "$OUTPUT_MODE" == "both" ]]; then
    echo "Syslog hedefi    : ${SYSLOG_TARGET}:${SYSLOG_PORT}/${SYSLOG_PROTO}"
  fi

  echo
  echo "Kaldırmak için:"
  echo "bash $0 uninstall"
}

uninstall_app() {
  echo "Uninstall başlatılıyor..."

  echo "- Servis durduruluyor"
  systemctl stop "${APP_NAME}.service" 2>/dev/null || true
  systemctl disable "${APP_NAME}.service" 2>/dev/null || true

  echo "- Kalan process kontrolü"
  pkill -f "/opt/${APP_NAME}/logger.py" 2>/dev/null || true

  echo "- Dosyalar kaldırılıyor"
  rm -f "$SERVICE_FILE"
  rm -f "$RSYSLOG_FILE"
  rm -f "$RSYSLOG_TEMPLATE_FILE"
  rm -f "$PY_FILE"
  rm -f "$ENV_FILE"

  if [[ -d "$CONFIG_DIR" ]]; then
    rmdir "$CONFIG_DIR" 2>/dev/null || true
  fi

  if [[ -d "$INSTALL_DIR" ]]; then
    rmdir "$INSTALL_DIR" 2>/dev/null || true
  fi

  echo
  read -rp "Log dizini de silinsin mi? [/var/log/${APP_NAME}] [y/N]: " REMOVE_LOGS || true
  case "${REMOVE_LOGS,,}" in
    y|yes)
      rm -rf "/var/log/${APP_NAME}" 2>/dev/null || true
      echo "- Log dizini silindi: /var/log/${APP_NAME}"
      ;;
    *)
      echo "- Log dizini bırakıldı"
      ;;
  esac

  echo "- systemd cache temizleniyor"
  systemctl daemon-reload
  systemctl reset-failed || true

  echo "- rsyslog restart"
  systemctl restart rsyslog || true

  echo
  echo "Uninstall tamamlandı."
  echo
  echo "Kontrol komutları:"
  echo "systemctl status ${APP_NAME}.service"
  echo "systemctl list-unit-files | grep ${APP_NAME}"
  echo "ps aux | grep ${APP_NAME}"
}

ask_main_action() {
  echo "Ne yapmak istiyorsunuz?"
  echo "  1) install"
  echo "  2) uninstall"
  read -rp "Seçim [1-2]: " MAIN_ACTION
  case "$MAIN_ACTION" in
    1) ACTION="install" ;;
    2) ACTION="uninstall" ;;
    *) echo "Geçersiz seçim"; exit 1 ;;
  esac
}

main() {
  ACTION="${1:-}"

  if [[ -z "$ACTION" ]]; then
    ask_main_action
  fi

  case "$ACTION" in
    install)
      detect_pkg_manager
      install_packages
      ask_install_questions
      write_env
      write_python_logger
      write_rsyslog_config
      write_service
      validate_rsyslog
      enable_services
      show_install_result
      ;;
    uninstall)
      uninstall_app
      ;;
    *)
      echo "Kullanım:"
      echo "  bash $0 install"
      echo "  bash $0 uninstall"
      exit 1
      ;;
  esac
}

main "${1:-}"
