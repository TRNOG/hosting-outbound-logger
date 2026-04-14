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
WHITELIST_FILE="${CONFIG_DIR}/process_whitelist.txt"
PORT_FILTER_FILE="${CONFIG_DIR}/port_filter.txt"
GEOIP_DB_PATH="/usr/share/GeoIP/GeoLite2-Country.mmdb"
THREAT_INTEL_FILE="${CONFIG_DIR}/threat_intel.txt"
DOCKER_SOCKET="/var/run/docker.sock"

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
LOG_UDP="yes"
LOG_DNS_QUERIES="yes"
ENABLE_PROCESS_WHITELIST="no"
ENABLE_PORT_FILTER="no"
ENABLE_GEOIP="no"
ENABLE_THREAT_INTEL="no"
ENABLE_CONTAINER_DETECTION="no"

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
      "linux-headers-$(uname -r)" geoip-bin python3-geoip2 \
      python3-docker || true
    pip3 install docker --break-system-packages || true
  elif [[ "$PKG_MGR" == "dnf" ]]; then
    dnf install -y epel-release || true
    dnf install -y \
      python3 python3-pip rsyslog \
      bcc bcc-tools python3-bcc kernel-devel kernel-headers \
      GeoIP geoipupdate python3-geoip2 python3-docker || true
    pip3 install docker --break-system-packages || true
  elif [[ "$PKG_MGR" == "yum" ]]; then
    yum install -y epel-release || true
    yum install -y \
      python3 python3-pip rsyslog \
      bcc bcc-tools python3-bcc kernel-devel kernel-headers \
      GeoIP geoipupdate python3-geoip2 python3-docker || true
    pip3 install docker --break-system-packages || true
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

  read -rp "UDP bağlantılar loglansın mı? [Y/n]: " ANSWER_UDP || true
  case "${ANSWER_UDP,,}" in
    n|no) LOG_UDP="no" ;;
    *) LOG_UDP="yes" ;;
  esac

  read -rp "DNS query loglama aktif olsun mu? [Y/n]: " ANSWER_DNS || true
  case "${ANSWER_DNS,,}" in
    n|no) LOG_DNS_QUERIES="no" ;;
    *) LOG_DNS_QUERIES="yes" ;;
  esac

  read -rp "Process whitelist kullanılsın mı? (belirli process'ler ignore edilecek) [y/N]: " ANSWER_WHITELIST || true
  case "${ANSWER_WHITELIST,,}" in
    y|yes) ENABLE_PROCESS_WHITELIST="yes" ;;
    *) ENABLE_PROCESS_WHITELIST="no" ;;
  esac

  if [[ "$ENABLE_PROCESS_WHITELIST" == "yes" ]]; then
    read -rp "Whitelist process isimleri (virgülle ayrılmış, ör: nginx,apache,mysql): " WHITELIST_PROCESS_INPUT || true
    if [[ -n "$WHITELIST_PROCESS_INPUT" ]]; then
      echo "$WHITELIST_PROCESS_INPUT" | tr ',' '\n' | sed 's/^ *//;s/ *$//' > "$WHITELIST_FILE"
    else
      touch "$WHITELIST_FILE"
    fi
  fi

  read -rp "Port filter kullanılsın mı? (belirli portlar ignore/filter edilecek) [y/N]: " ANSWER_PORT || true
  case "${ANSWER_PORT,,}" in
    y|yes) ENABLE_PORT_FILTER="yes" ;;
    *) ENABLE_PORT_FILTER="no" ;;
  esac

  if [[ "$ENABLE_PORT_FILTER" == "yes" ]]; then
    echo
    echo "Port filter modu:"
    echo "  1) whitelist (sadece bu portlar loglanır)"
    echo "  2) blacklist (bu portlar ignore edilir)"
    read -rp "Seçim [1-2]: " PORT_FILTER_MODE || true
    case "$PORT_FILTER_MODE" in
      1) PORT_FILTER_MODE_VAL="whitelist" ;;
      2) PORT_FILTER_MODE_VAL="blacklist" ;;
      *) PORT_FILTER_MODE_VAL="blacklist" ;;
    esac

    read -rp "Port listesi (virgülle ayrılmış, ör: 80,443,22): " PORT_FILTER_INPUT || true
    if [[ -n "$PORT_FILTER_INPUT" ]]; then
      echo "# mode=${PORT_FILTER_MODE_VAL}" > "$PORT_FILTER_FILE"
      echo "$PORT_FILTER_INPUT" | tr ',' '\n' | sed 's/^ *//;s/ *$//' >> "$PORT_FILTER_FILE"
    else
      echo "# mode=blacklist" > "$PORT_FILTER_FILE"
    fi
  fi

  read -rp "GeoIP enrichment aktif olsun mu? (IP'lerin ülke bilgisi eklenecek) [y/N]: " ANSWER_GEOIP || true
  case "${ANSWER_GEOIP,,}" in
    y|yes) ENABLE_GEOIP="yes" ;;
    *) ENABLE_GEOIP="no" ;;
  esac

  if [[ "$ENABLE_GEOIP" == "yes" ]]; then
    read -rp "GeoIP database path [/usr/share/GeoIP/GeoLite2-Country.mmdb]: " GEOIP_PATH_INPUT || true
    GEOIP_DB_PATH="${GEOIP_PATH_INPUT:-$GEOIP_DB_PATH}"
  fi

  read -rp "Threat Intel enrichment aktif olsun mu? (IP'ler threat intel listesine karşı kontrol edilecek) [y/N]: " ANSWER_THREAT || true
  case "${ANSWER_THREAT,,}" in
    y|yes) ENABLE_THREAT_INTEL="yes" ;;
    *) ENABLE_THREAT_INTEL="no" ;;
  esac

  if [[ "$ENABLE_THREAT_INTEL" == "yes" ]]; then
    read -rp "Threat Intel IP listesi dosyası [/etc/outbound-logger/threat_intel.txt]: " THREAT_FILE_INPUT || true
    THREAT_INTEL_FILE="${THREAT_FILE_INPUT:-$THREAT_INTEL_FILE}"
    if [[ ! -f "$THREAT_INTEL_FILE" ]]; then
      echo "# Threat Intel IP listesi (CIDR desteği)" > "$THREAT_INTEL_FILE"
      echo "# Örnek:" >> "$THREAT_INTEL_FILE"
      echo "# 192.168.1.100" >> "$THREAT_INTEL_FILE"
      echo "# 10.0.0.0/8" >> "$THREAT_INTEL_FILE"
    fi
  fi

  read -rp "Docker/Kubernetes container detection aktif olsun mu? [y/N]: " ANSWER_CONTAINER || true
  case "${ANSWER_CONTAINER,,}" in
    y|yes) ENABLE_CONTAINER_DETECTION="yes" ;;
    *) ENABLE_CONTAINER_DETECTION="no" ;;
  esac

  if [[ "$ENABLE_CONTAINER_DETECTION" == "yes" ]]; then
    read -rp "Docker socket path [/var/run/docker.sock]: " DOCKER_SOCKET_INPUT || true
    DOCKER_SOCKET="${DOCKER_SOCKET_INPUT:-$DOCKER_SOCKET}"
  fi
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
LOG_UDP="${LOG_UDP}"
LOG_DNS_QUERIES="${LOG_DNS_QUERIES}"
ENABLE_PROCESS_WHITELIST="${ENABLE_PROCESS_WHITELIST}"
ENABLE_PORT_FILTER="${ENABLE_PORT_FILTER}"
ENABLE_GEOIP="${ENABLE_GEOIP}"
ENABLE_THREAT_INTEL="${ENABLE_THREAT_INTEL}"
ENABLE_CONTAINER_DETECTION="${ENABLE_CONTAINER_DETECTION}"
DOCKER_SOCKET="${DOCKER_SOCKET}"
GEOIP_DB_PATH="${GEOIP_DB_PATH}"
THREAT_INTEL_FILE="${THREAT_INTEL_FILE}"
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
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from bcc import BPF
except Exception as e:
    print(f"BCC import hatası: {e}", file=sys.stderr)
    sys.exit(1)

GEOIP2_AVAILABLE = False
try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    pass

DOCKER_AVAILABLE = False
DOCKER_CLIENT = None
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    pass

APP_NAME = "outbound-logger"
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json").strip().lower()
IGNORE_LOOPBACK = os.environ.get("IGNORE_LOOPBACK", "yes").strip().lower() == "yes"
IGNORE_PRIVATE = os.environ.get("IGNORE_PRIVATE", "no").strip().lower() == "yes"
IGNORE_ROOT = os.environ.get("IGNORE_ROOT", "no").strip().lower() == "yes"
ENABLE_HOST_ENRICHMENT = os.environ.get("ENABLE_HOST_ENRICHMENT", "yes").strip().lower() == "yes"
LOG_UDP = os.environ.get("LOG_UDP", "yes").strip().lower() == "yes"
LOG_DNS_QUERIES = os.environ.get("LOG_DNS_QUERIES", "yes").strip().lower() == "yes"
ENABLE_PROCESS_WHITELIST = os.environ.get("ENABLE_PROCESS_WHITELIST", "no").strip().lower() == "yes"
ENABLE_PORT_FILTER = os.environ.get("ENABLE_PORT_FILTER", "no").strip().lower() == "yes"
ENABLE_GEOIP = os.environ.get("ENABLE_GEOIP", "no").strip().lower() == "yes"
ENABLE_THREAT_INTEL = os.environ.get("ENABLE_THREAT_INTEL", "no").strip().lower() == "yes"
ENABLE_CONTAINER_DETECTION = os.environ.get("ENABLE_CONTAINER_DETECTION", "no").strip().lower() == "yes"
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-Country.mmdb")
THREAT_INTEL_FILE = os.environ.get("THREAT_INTEL_FILE", "/etc/outbound-logger/threat_intel.txt")
WHITELIST_FILE = "/etc/outbound-logger/process_whitelist.txt"
PORT_FILTER_FILE = "/etc/outbound-logger/port_filter.txt"
HOSTNAME = socket.gethostname()

HOST_CACHE = {}
HOST_TTL = 20

PROCESS_WHITELIST = set()
PORT_FILTER_MODE = "blacklist"
PORT_FILTER_SET = set()
GEOIP_READER = None
THREAT_INTEL_NETWORKS = []
CONTAINER_CACHE = {}
CONTAINER_CACHE_TTL = 60

def init_docker():
    global DOCKER_CLIENT
    if not ENABLE_CONTAINER_DETECTION or not DOCKER_AVAILABLE:
        return
    try:
        if os.path.exists(DOCKER_SOCKET):
            DOCKER_CLIENT = docker.DockerClient(base_url=f"unix://{DOCKER_SOCKET}")
        else:
            print(json.dumps({"logger_error": "docker_socket_not_found", "path": DOCKER_SOCKET}), flush=True)
    except Exception as e:
        print(json.dumps({"logger_error": "docker_init_failed", "error": str(e)}), flush=True)

def get_container_id_from_pid(pid):
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        if not os.path.exists(cgroup_path):
            return None
        
        with open(cgroup_path, "r") as f:
            for line in f:
                line = line.strip()
                if "/docker/" in line:
                    parts = line.split("/docker/")
                    if len(parts) > 1:
                        cid = parts[1].split("/")[0].split(".")[0]
                        if len(cid) >= 12:
                            return cid
                elif "/kubepods/" in line or "/kubepods-besteffort/" in line:
                    parts = line.split("/")
                    for i, p in enumerate(parts):
                        if p.startswith("pod") or "containerd" in p:
                            for j in range(i+1, len(parts)):
                                if len(parts[j]) >= 12 and not parts[j].startswith("pod"):
                                    return parts[j][:64]
                elif ".scope" in line and "docker" in line:
                    parts = line.split("-")
                    for p in parts:
                        if len(p) >= 12 and p[0:1].isdigit():
                            return p[:64]
        return None
    except Exception:
        return None

def cleanup_container_cache():
    now = time.time()
    expired = [cid for cid, value in CONTAINER_CACHE.items() if now - value["ts"] > CONTAINER_CACHE_TTL]
    for cid in expired:
        CONTAINER_CACHE.pop(cid, None)

def get_container_info(container_id):
    if not container_id or not DOCKER_CLIENT:
        return {}
    
    cleanup_container_cache()
    
    cached = CONTAINER_CACHE.get(container_id)
    if cached:
        return cached["info"]
    
    try:
        container = DOCKER_CLIENT.containers.get(container_id[:12])
        info = {
            "container_id": container_id[:12],
            "container_name": container.name,
            "container_image": container.image.tags[0] if container.image.tags else container.image.id[:12],
            "container_image_id": container.image.id[:12],
            "container_status": container.status,
        }
        
        labels = container.labels or {}
        if "io.kubernetes.pod.name" in labels:
            info["k8s_pod_name"] = labels.get("io.kubernetes.pod.name", "")
            info["k8s_pod_namespace"] = labels.get("io.kubernetes.pod.namespace", "")
            info["k8s_pod_uid"] = labels.get("io.kubernetes.pod.uid", "")
            info["k8s_container_name"] = labels.get("io.kubernetes.container.name", "")
        
        CONTAINER_CACHE[container_id] = {"info": info, "ts": time.time()}
        return info
    except Exception:
        return {"container_id": container_id[:12] if container_id else None}

def get_container_info_from_pid(pid):
    if not ENABLE_CONTAINER_DETECTION:
        return {}
    
    container_id = get_container_id_from_pid(pid)
    if container_id:
        return get_container_info(container_id)
    return {}

def load_process_whitelist():
    global PROCESS_WHITELIST
    if not ENABLE_PROCESS_WHITELIST:
        return
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                for line in f:
                    proc = line.strip()
                    if proc and not proc.startswith("#"):
                        PROCESS_WHITELIST.add(proc)
    except Exception as e:
        print(json.dumps({"logger_error": "whitelist_load_failed", "error": str(e)}), flush=True)

def load_port_filter():
    global PORT_FILTER_MODE, PORT_FILTER_SET
    if not ENABLE_PORT_FILTER:
        return
    try:
        if os.path.exists(PORT_FILTER_FILE):
            with open(PORT_FILTER_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("# mode="):
                        PORT_FILTER_MODE = line.split("=")[1].strip()
                    elif line and not line.startswith("#"):
                        try:
                            PORT_FILTER_SET.add(int(line))
                        except ValueError:
                            pass
    except Exception as e:
        print(json.dumps({"logger_error": "port_filter_load_failed", "error": str(e)}), flush=True)

def init_geoip():
    global GEOIP_READER
    if not ENABLE_GEOIP or not GEOIP2_AVAILABLE:
        return
    try:
        if os.path.exists(GEOIP_DB_PATH):
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
        else:
            print(json.dumps({"logger_error": "geoip_db_not_found", "path": GEOIP_DB_PATH}), flush=True)
    except Exception as e:
        print(json.dumps({"logger_error": "geoip_init_failed", "error": str(e)}), flush=True)

def load_threat_intel():
    global THREAT_INTEL_NETWORKS
    if not ENABLE_THREAT_INTEL:
        return
    try:
        if os.path.exists(THREAT_INTEL_FILE):
            with open(THREAT_INTEL_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            THREAT_INTEL_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                        except ValueError:
                            pass
    except Exception as e:
        print(json.dumps({"logger_error": "threat_intel_load_failed", "error": str(e)}), flush=True)

def download_geoip_db():
    if not ENABLE_GEOIP:
        return
    db_dir = os.path.dirname(GEOIP_DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    if not os.path.exists(GEOIP_DB_PATH):
        print(json.dumps({"logger_info": "geoip_db_download_start"}), flush=True)
        try:
            url = "https://git.io/GeoLite2-Country.mmdb"
            urllib.request.urlretrieve(url, GEOIP_DB_PATH)
            print(json.dumps({"logger_info": "geoip_db_download_success"}), flush=True)
        except Exception as e:
            print(json.dumps({"logger_error": "geoip_db_download_failed", "error": str(e)}), flush=True)

def get_geoip(ip):
    if not GEOIP_READER:
        return {}
    try:
        resp = GEOIP_READER.country(ip)
        return {
            "geo_country": resp.country.iso_code or "",
            "geo_country_name": resp.country.name or "",
            "geo_continent": resp.continent.iso_code or "",
        }
    except Exception:
        return {}

def check_threat_intel(ip):
    if not THREAT_INTEL_NETWORKS:
        return {"threat": False}
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in THREAT_INTEL_NETWORKS:
            if ip_obj in network:
                return {"threat": True, "threat_network": str(network)}
        return {"threat": False}
    except Exception:
        return {"threat": False}

def is_port_filtered(dport):
    if not ENABLE_PORT_FILTER:
        return False
    if PORT_FILTER_MODE == "whitelist":
        return dport not in PORT_FILTER_SET
    else:
        return dport in PORT_FILTER_SET

def is_process_whitelisted(comm):
    if not ENABLE_PROCESS_WHITELIST:
        return False
    return comm in PROCESS_WHITELIST

CONFIG_RELOAD_INTERVAL = 30

def config_reload_thread():
    while True:
        time.sleep(CONFIG_RELOAD_INTERVAL)
        try:
            load_process_whitelist()
            load_port_filter()
            load_threat_intel()
        except Exception:
            pass

def start_config_reload():
    if ENABLE_PROCESS_WHITELIST or ENABLE_PORT_FILTER or ENABLE_THREAT_INTEL:
        t = threading.Thread(target=config_reload_thread, daemon=True)
        t.start()

load_process_whitelist()
load_port_filter()
download_geoip_db()
init_geoip()
load_threat_intel()
init_docker()
start_config_reload()

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

struct udp_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 family;
    u16 sport;
    u16 dport;
    u32 saddr_v4;
    u32 daddr_v4;
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    char comm[TASK_COMM_LEN];
};

struct dns_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 family;
    u16 sport;
    u16 dport;
    u32 saddr_v4;
    u32 daddr_v4;
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    char comm[TASK_COMM_LEN];
    u16 dns_qtype;
    u16 dns_qclass;
    char dns_qname[256];
};

struct host_event_t {
    u32 pid;
    u32 uid;
    u8 source;   // 1=dns(getaddrinfo), 2=sni(openssl)
    char host[HOST_LEN];
};

BPF_HASH(currsock, u64, struct sock *);
BPF_HASH(currudp, u64, struct sock *);
BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);
BPF_PERF_OUTPUT(udp_events);
BPF_PERF_OUTPUT(dns_events);
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

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    if (sk == NULL || len == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    currudp.update(&pid_tgid, &sk);
    return 0;
}

static inline int parse_dns_query(struct pt_regs *ctx, void *data, u32 data_len, struct dns_event_t *evt) {
    if (data_len < 12) {
        return -1;
    }

    u8 *ptr = (u8 *)data;
    u16 *flags_ptr = (u16 *)(ptr + 2);
    u16 flags;
    bpf_probe_read_user(&flags, sizeof(flags), flags_ptr);
    flags = ntohs(flags);

    if ((flags & 0x8000) != 0) {
        return -1;
    }

    u16 *qdcount_ptr = (u16 *)(ptr + 4);
    u16 qdcount;
    bpf_probe_read_user(&qdcount, sizeof(qdcount), qdcount_ptr);
    qdcount = ntohs(qdcount);
    if (qdcount == 0) {
        return -1;
    }

    u32 offset = 12;
    u32 name_pos = 0;

    #pragma unroll
    for (int i = 0; i < 128 && offset < data_len && name_pos < 255; i++) {
        u8 label_len;
        if (bpf_probe_read_user(&label_len, 1, ptr + offset) < 0) {
            break;
        }
        offset++;

        if (label_len == 0) {
            break;
        }

        if (label_len > 63 || offset + label_len > data_len) {
            break;
        }

        if (name_pos > 0) {
            evt->dns_qname[name_pos] = '.';
            name_pos++;
        }

        if (name_pos + label_len > 255) {
            break;
        }

        if (bpf_probe_read_user(&evt->dns_qname[name_pos], label_len, ptr + offset) < 0) {
            break;
        }
        name_pos += label_len;
        offset += label_len;
    }

    evt->dns_qname[name_pos] = '\0';

    if (offset + 4 > data_len) {
        return -1;
    }

    u16 *qtype_ptr = (u16 *)(ptr + offset);
    u16 *qclass_ptr = (u16 *)(ptr + offset + 2);
    bpf_probe_read_user(&evt->dns_qtype, sizeof(evt->dns_qtype), qtype_ptr);
    bpf_probe_read_user(&evt->dns_qclass, sizeof(evt->dns_qclass), qclass_ptr);
    evt->dns_qtype = ntohs(evt->dns_qtype);
    evt->dns_qclass = ntohs(evt->dns_qclass);

    return 0;
}

int trace_udp_sendmsg_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currudp.lookup(&pid_tgid);

    if (skpp == 0) {
        return 0;
    }

    currudp.delete(&pid_tgid);

    if (ret <= 0) {
        return 0;
    }

    struct sock *sk = *skpp;
    u16 family = 0, dport = 0, sport = 0;

    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = ntohs(dport);

    struct udp_event_t udp_evt = {};
    udp_evt.ts_us = bpf_ktime_get_ns() / 1000;
    udp_evt.pid = pid_tgid >> 32;
    udp_evt.uid = bpf_get_current_uid_gid();
    udp_evt.family = family;
    udp_evt.sport = sport;
    udp_evt.dport = dport;
    bpf_get_current_comm(&udp_evt.comm, sizeof(udp_evt.comm));

    if (family == 2) {
        bpf_probe_read_kernel(&udp_evt.saddr_v4, sizeof(udp_evt.saddr_v4), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&udp_evt.daddr_v4, sizeof(udp_evt.daddr_v4), &sk->__sk_common.skc_daddr);
    } else if (family == 10) {
        bpf_probe_read_kernel(&udp_evt.saddr_v6, sizeof(udp_evt.saddr_v6), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&udp_evt.daddr_v6, sizeof(udp_evt.daddr_v6), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    udp_events.perf_submit(ctx, &udp_evt, sizeof(udp_evt));

    if (dport == 53) {
        struct pt_regs *regs = (struct pt_regs *)ctx;
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

        if (msg == NULL) {
            return 0;
        }

        struct iovec *iov = NULL;
        void *iov_base = NULL;
        size_t iov_len = 0;
        unsigned long iter_count = 0;

        bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
        bpf_probe_read_kernel(&iter_count, sizeof(iter_count), &msg->msg_iter.count);

        if (iov != NULL && iter_count >= 12 && iter_count <= 512) {
            bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);

            if (iov_base != NULL) {
                struct dns_event_t dns_evt = {};
                dns_evt.ts_us = udp_evt.ts_us;
                dns_evt.pid = udp_evt.pid;
                dns_evt.uid = udp_evt.uid;
                dns_evt.family = family;
                dns_evt.sport = sport;
                dns_evt.dport = dport;
                dns_evt.saddr_v4 = udp_evt.saddr_v4;
                dns_evt.daddr_v4 = udp_evt.daddr_v4;
                dns_evt.saddr_v6 = udp_evt.saddr_v6;
                dns_evt.daddr_v6 = udp_evt.daddr_v6;
                __builtin_memcpy(&dns_evt.comm, &udp_evt.comm, sizeof(dns_evt.comm));

                if (parse_dns_query(ctx, iov_base, (u32)iter_count, &dns_evt) == 0) {
                    dns_events.perf_submit(ctx, &dns_evt, sizeof(dns_evt));
                }
            }
        }
    }

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

class UdpEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("family", ct.c_ushort),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("saddr_v4", ct.c_uint),
        ("daddr_v4", ct.c_uint),
        ("saddr_v6", ct.c_ubyte * 16),
        ("daddr_v6", ct.c_ubyte * 16),
        ("comm", ct.c_char * 16),
    ]

class DnsEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("family", ct.c_ushort),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("saddr_v4", ct.c_uint),
        ("daddr_v4", ct.c_uint),
        ("saddr_v6", ct.c_ubyte * 16),
        ("daddr_v6", ct.c_ubyte * 16),
        ("comm", ct.c_char * 16),
        ("dns_qtype", ct.c_ushort),
        ("dns_qclass", ct.c_ushort),
        ("dns_qname", ct.c_char * 256),
    ]

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 255: "ANY",
}

DNS_QCLASSES = {
    1: "IN", 2: "CS", 3: "CH", 4: "HS", 255: "ANY",
}

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

    if is_process_whitelisted(rec["comm"]):
        return True

    if is_port_filtered(rec["dst_port"]):
        return True

    if IGNORE_LOOPBACK and is_loopback(rec["src_ip"]) and is_loopback(rec["dst_ip"]):
        return True

    if IGNORE_PRIVATE and is_private(rec["dst_ip"]):
        return True

    return False

def emit_record(rec):
    if should_skip(rec):
        return

    if ENABLE_CONTAINER_DETECTION and "pid" in rec:
        container_info = get_container_info_from_pid(rec["pid"])
        if container_info:
            rec.update(container_info)

    if ENABLE_GEOIP and "dst_ip" in rec:
        geo = get_geoip(rec["dst_ip"])
        if geo:
            rec.update(geo)

    if ENABLE_THREAT_INTEL and "dst_ip" in rec:
        threat = check_threat_intel(rec["dst_ip"])
        if threat:
            rec.update(threat)

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
            rec.get("proto", "tcp"),
            rec.get("event_type", "connect"),
            rec.get("dns_qname", ""),
            rec.get("dns_qtype", ""),
            rec.get("dns_qclass", ""),
            rec.get("geo_country", ""),
            rec.get("geo_country_name", ""),
            rec.get("threat", ""),
            rec.get("threat_network", ""),
            rec.get("container_id", ""),
            rec.get("container_name", ""),
            rec.get("container_image", ""),
            rec.get("k8s_pod_name", ""),
            rec.get("k8s_pod_namespace", ""),
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

def handle_udp(cpu, data, size):
    try:
        event = b["udp_events"].event(data)
        uid = int(event.uid)
        pid = int(event.pid)
        family = int(event.family)

        family_str = "ipv4" if family == 2 else "ipv6" if family == 10 else f"unknown({family})"

        if family == 2:
            src_ip = ip4_to_str(event.saddr_v4)
            dst_ip = ip4_to_str(event.daddr_v4)
        elif family == 10:
            src_ip = ip6_to_str(bytes(event.saddr_v6))
            dst_ip = ip6_to_str(bytes(event.daddr_v6))
        else:
            src_ip = ""
            dst_ip = ""

        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": HOSTNAME,
            "uid": uid,
            "user": get_username(uid),
            "pid": pid,
            "comm": event.comm.decode(errors="replace").rstrip("\x00"),
            "cmdline": get_cmdline(pid),
            "family": family_str,
            "src_ip": src_ip,
            "src_port": int(event.sport),
            "dst_ip": dst_ip,
            "dst_port": int(event.dport),
            "proto": "udp",
        }

        dst_host, dst_host_source = get_host_for_pid(pid)
        if dst_host:
            rec["dst_host"] = dst_host
            rec["dst_host_source"] = dst_host_source

        emit_record(rec)
    except Exception as e:
        print(json.dumps({
            "logger_error": "handle_udp_failed",
            "error": str(e)
        }), flush=True)

def handle_dns(cpu, data, size):
    try:
        event = b["dns_events"].event(data)
        uid = int(event.uid)
        pid = int(event.pid)
        family = int(event.family)

        family_str = "ipv4" if family == 2 else "ipv6" if family == 10 else f"unknown({family})"

        if family == 2:
            src_ip = ip4_to_str(event.saddr_v4)
            dst_ip = ip4_to_str(event.daddr_v4)
        elif family == 10:
            src_ip = ip6_to_str(bytes(event.saddr_v6))
            dst_ip = ip6_to_str(bytes(event.daddr_v6))
        else:
            src_ip = ""
            dst_ip = ""

        qname = bytes(event.dns_qname).split(b"\x00", 1)[0].decode(errors="replace").strip()
        qtype = int(event.dns_qtype)
        qclass = int(event.dns_qclass)

        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": HOSTNAME,
            "uid": uid,
            "user": get_username(uid),
            "pid": pid,
            "comm": event.comm.decode(errors="replace").rstrip("\x00"),
            "cmdline": get_cmdline(pid),
            "family": family_str,
            "src_ip": src_ip,
            "src_port": int(event.sport),
            "dst_ip": dst_ip,
            "dst_port": int(event.dport),
            "proto": "udp",
            "event_type": "dns_query",
            "dns_qname": qname,
            "dns_qtype": DNS_QTYPES.get(qtype, str(qtype)),
            "dns_qtype_id": qtype,
            "dns_qclass": DNS_QCLASSES.get(qclass, str(qclass)),
            "dns_qclass_id": qclass,
        }

        if qname:
            remember_host(pid, qname, "dns_query")

        emit_record(rec)
    except Exception as e:
        print(json.dumps({
            "logger_error": "handle_dns_failed",
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

if LOG_UDP:
    b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
    b.attach_kretprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg_ret")

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

if LOG_UDP:
    b["udp_events"].open_perf_buffer(handle_udp)

if LOG_DNS_QUERIES:
    b["dns_events"].open_perf_buffer(handle_dns)

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
    echo "dig google.com"
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
    echo "Çıktı modu         : ${OUTPUT_MODE}"
    echo "Log formatı        : ${LOG_FORMAT}"
    echo "Loopback ignore    : ${IGNORE_LOOPBACK}"
    echo "Private ignore     : ${IGNORE_PRIVATE}"
    echo "Root ignore        : ${IGNORE_ROOT}"
    echo "Host enrichment    : ${ENABLE_HOST_ENRICHMENT}"
    echo "UDP loglama        : ${LOG_UDP}"
    echo "DNS query logla    : ${LOG_DNS_QUERIES}"
    echo "Process whitelist  : ${ENABLE_PROCESS_WHITELIST}"
    echo "Port filter        : ${ENABLE_PORT_FILTER}"
    echo "GeoIP enrichment   : ${ENABLE_GEOIP}"
    echo "Threat Intel       : ${ENABLE_THREAT_INTEL}"
    echo "Container detection: ${ENABLE_CONTAINER_DETECTION}"

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
  rm -f "$WHITELIST_FILE"
  rm -f "$PORT_FILTER_FILE"
  rm -f "$THREAT_INTEL_FILE"

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
