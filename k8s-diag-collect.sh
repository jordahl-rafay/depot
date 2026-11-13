#!/usr/bin/env bash
#
# k8s-diag-collect.sh - read-only Kubernetes diagnostic collector with built-in redaction.
#
# Run it on a cluster node with kubectl access (sudo recommended). It collects:
#   * cluster state via kubectl (resources, events, logs of unhealthy and infrastructure pods)
#   * node state (systemd units and journals, container runtime, kernel/sysctl, network,
#     certificates, time sync, proxy configuration)
#   * repeated snapshots over time, to show whether the cluster is settling
# Then it REDACTS sensitive data (IPs, hostnames, domains, emails, secrets, tokens, keys)
# and packages a single .tar.gz to send for analysis.
#
# The script makes NO changes to the cluster or the node.
#
# Requirements: bash 4.4+, python3 3.6+, coreutils, tar, gzip. kubectl for cluster data.
# Supported:    Ubuntu 24.04, RHEL 8/9 and derivatives.
#
# Run with --help for options.

set -uo pipefail
umask 077

readonly KDIAG_VERSION="0.1.0"

# ----------------------------------------------------------------------------------------
# Defaults (override with flags)
# ----------------------------------------------------------------------------------------
OUTPUT_DIR="$PWD"
CASE_ID=""
DESCRIPTION=""
STAGE=""
KUBECONFIG_ARG=""
KUBE_CONTEXT=""
KUBECTL_BIN=""
SNAPSHOTS=3
INTERVAL=60
SINCE_HOURS=6
LOG_TAIL=1000
LOG_TAIL_PREV=500
LOG_TAIL_HEALTHY=200
JOURNAL_LINES=8000
MAX_UNHEALTHY_PODS=200
MAX_HEALTHY_PODS=100
MAX_CRI_LOGS=60
REQUEST_TIMEOUT="20s"
DO_CLUSTER=1
DO_NODE=1
STRICT=0
REVIEW=0
WRITE_MAP=1
ASSUME_YES=0
USE_SUDO=1
KEEP_WORK=0
KEY_FILE="${HOME:-/root}/.k8s-diag/redaction.key"
REDACT_ONLY=""
DETOKENIZE=""
MAP_FILE=""
declare -a EXTRA_NAMESPACES=() INCLUDES=() ENDPOINTS=() REDACT_TERMS=() ALLOW_DOMAINS=()

# Infrastructure namespaces: logs of ALL pods here are collected (healthy ones capped).
FOCUS_NS_REGEX='^(kube-system|kube-flannel|calico-.*|tigera-operator|cilium.*|.*rafay.*|cert-manager|ingress-nginx|metallb-system|local-path-storage|openebs|longhorn-system|rook-ceph|gpu-operator)$'
# Namespaces where every pod is described (not just unhealthy ones).
DESCRIBE_ALL_NS_REGEX='^(.*rafay.*)$'
# systemd units whose status, unit files and journal are collected.
UNIT_REGEX='(kube|containerd|docker|crio|cri-o|etcd|rafay|salt|conjurer|calico|cilium|flannel|haproxy|keepalived|chrony|ntp|timesyncd|firewalld|ufw|nftables|iptables|nvidia|iscsi|multipath)'
# Extra files collected automatically if present (installer / agent logs). TUNE for Rafay.
AUTO_INCLUDE_GLOBS=(
  "/var/log/*rafay*"
  "/var/log/rafay*/*"
  "/opt/rafay*/*.log"
  "/opt/rafay*/log*/*"
)
# ConfigMaps collected in full (namespace/name), if they exist.
CONFIGMAP_ALLOWLIST=(
  kube-system/coredns kube-system/kube-proxy kube-system/kubeadm-config kube-system/kubelet-config
  kube-system/calico-config kube-system/cilium-config kube-system/kube-flannel-cfg
  kube-flannel/kube-flannel-cfg kube-system/nodelocaldns kube-system/extension-apiserver-authentication
)

# ----------------------------------------------------------------------------------------
# Runtime state
# ----------------------------------------------------------------------------------------
WORK=""
RAW=""
HELPER=""
CMD_LOG=""
RUN_LOG=""
BUNDLE_NAME=""
API_OK=0
RUN_AS="user"
KUBECONFIG_SOURCE="none"
CRICTL=()
declare -a SUDO=() KUBECTL=()
STARTED_UTC=""
ORIG_ARGS=""

# ----------------------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------------------
log() {
  printf '%s [k8s-diag] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2
  if [[ -n "$RUN_LOG" ]]; then printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$RUN_LOG"; fi
  return 0
}
die() { log "ERROR: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'EOF'
k8s-diag-collect.sh - read-only Kubernetes diagnostic collector with redaction

USAGE
  sudo ./k8s-diag-collect.sh [options]

COMMON OPTIONS
  -d, --description TEXT   Short description of the problem (prompted if omitted on a TTY)
      --stage TEXT         Install step or context (e.g. "installer step 3: CNI")
      --case-id ID         Case/ticket ID (default: generated)
  -o, --output DIR         Where to write the bundle (default: current directory)
  -y, --yes                Non-interactive: no prompts

CLUSTER ACCESS
      --kubeconfig PATH    kubeconfig to use (default: $KUBECONFIG, ~/.kube/config, /etc/kubernetes/admin.conf)
      --context NAME       kubeconfig context
      --kubectl PATH       kubectl binary
  -n, --namespace NS       Extra namespace(s) to collect all pod logs from (repeatable)

COLLECTION
      --snapshots N        Number of state snapshots (default: 3)
      --interval SEC       Seconds between snapshots (default: 60)
      --quick              Single snapshot (same as --snapshots 1)
      --since-hours N      Journal lookback in hours (default: 6)
      --include PATH       Extra file or directory to include, redacted (repeatable)
      --endpoint HOST:PORT Test DNS/TCP/TLS connectivity to an endpoint (repeatable),
                           e.g. the Rafay controller or a private registry
      --no-cluster         Skip kubectl collection
      --no-node            Skip node-level collection
      --no-sudo            Never use sudo

REDACTION
      --redact-term TEXT   Extra literal to redact everywhere (repeatable): company, project, cluster names
      --allow-domain DOM   Domain to keep unredacted (repeatable)
      --strict             Also redact ALL env var values and ConfigMap data
      --review             Pause before packaging so you can inspect the redacted files
      --no-map             Don't write the token map file
      --key-file PATH      Redaction key (default: ~/.k8s-diag/redaction.key, created if missing)

UTILITIES
      --redact-only PATH   Only redact a file or directory (no collection) into --output
      --detokenize FILE --map MAPFILE
                           Restore real values in a returned report using your local map file
  -h, --help               This help
      --version            Print version

OUTPUT
  k8sdiag_<case>_<timestamp>.tar.gz              send this file
  k8sdiag_<case>_<timestamp>.DO-NOT-SEND.map.json keep this locally (token -> real value)
EOF
}

need_val() { [[ $# -ge 2 && -n "${2:-}" ]] || die "option $1 requires a value"; }

parse_args() {
  ORIG_ARGS="$*"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--description) need_val "$@"; DESCRIPTION="$2"; shift 2 ;;
      --stage) need_val "$@"; STAGE="$2"; shift 2 ;;
      --case-id) need_val "$@"; CASE_ID="$2"; shift 2 ;;
      -o|--output) need_val "$@"; OUTPUT_DIR="$2"; shift 2 ;;
      -y|--yes) ASSUME_YES=1; shift ;;
      --kubeconfig) need_val "$@"; KUBECONFIG_ARG="$2"; shift 2 ;;
      --context) need_val "$@"; KUBE_CONTEXT="$2"; shift 2 ;;
      --kubectl) need_val "$@"; KUBECTL_BIN="$2"; shift 2 ;;
      -n|--namespace) need_val "$@"; EXTRA_NAMESPACES+=("$2"); shift 2 ;;
      --snapshots) need_val "$@"; SNAPSHOTS="$2"; shift 2 ;;
      --interval) need_val "$@"; INTERVAL="$2"; shift 2 ;;
      --quick) SNAPSHOTS=1; shift ;;
      --since-hours) need_val "$@"; SINCE_HOURS="$2"; shift 2 ;;
      --include) need_val "$@"; INCLUDES+=("$2"); shift 2 ;;
      --endpoint) need_val "$@"; ENDPOINTS+=("$2"); shift 2 ;;
      --no-cluster) DO_CLUSTER=0; shift ;;
      --no-node) DO_NODE=0; shift ;;
      --no-sudo) USE_SUDO=0; shift ;;
      --redact-term) need_val "$@"; REDACT_TERMS+=("$2"); shift 2 ;;
      --allow-domain) need_val "$@"; ALLOW_DOMAINS+=("$2"); shift 2 ;;
      --strict) STRICT=1; shift ;;
      --review) REVIEW=1; shift ;;
      --no-map) WRITE_MAP=0; shift ;;
      --key-file) need_val "$@"; KEY_FILE="$2"; shift 2 ;;
      --redact-only) need_val "$@"; REDACT_ONLY="$2"; shift 2 ;;
      --detokenize) need_val "$@"; DETOKENIZE="$2"; shift 2 ;;
      --map) need_val "$@"; MAP_FILE="$2"; shift 2 ;;
      --keep-workdir) KEEP_WORK=1; shift ;;   # debugging only: leaves redacted staging dir
      -h|--help) usage; exit 0 ;;
      --version) echo "k8s-diag-collect $KDIAG_VERSION"; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
  [[ "$SNAPSHOTS" =~ ^[0-9]+$ && "$SNAPSHOTS" -ge 1 ]] || die "--snapshots must be a positive integer"
  [[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval must be an integer (seconds)"
  [[ "$SINCE_HOURS" =~ ^[0-9]+$ && "$SINCE_HOURS" -ge 1 ]] || die "--since-hours must be a positive integer"
  if ((${#EXTRA_NAMESPACES[@]})); then
    local ns extra=""
    for ns in "${EXTRA_NAMESPACES[@]}"; do extra+="|$(printf '%s' "$ns" | sed 's/[^A-Za-z0-9-]//g')"; done
    FOCUS_NS_REGEX="${FOCUS_NS_REGEX%)\$}${extra})\$"
  fi
  return 0
}

# run_to <relpath> <timeout-sec> <cmd...>: run a command, capture stdout to $RAW/<relpath>,
# stderr to <relpath>.stderr (kept only if non-empty), and log rc/duration to commands.tsv.
run_to() {
  local rel="$1" t="$2"; shift 2
  local out="$RAW/$rel" start rc
  mkdir -p "$(dirname "$out")"
  start=$(date +%s)
  timeout --kill-after=5 "$t" "$@" >"$out" 2>"$out.stderr" </dev/null
  rc=$?
  [[ -s "$out.stderr" ]] || rm -f "$out.stderr"
  printf '%s\t%s\t%s\t%s\n' "$rc" "$(( $(date +%s) - start ))" "$rel" "$*" >>"$CMD_LOG"
  return "$rc"
}
# run_root: same as run_to, with sudo when available.
run_root() { local rel="$1" t="$2"; shift 2; run_to "$rel" "$t" ${SUDO[@]+"${SUDO[@]}"} "$@"; }
# kc: run kubectl through run_to.
kc() { local rel="$1" t="$2"; shift 2; run_to "$rel" "$t" "${KUBECTL[@]}" "$@"; }
safe_name() { printf '%s' "$1" | sed 's#^/##; s#[^A-Za-z0-9._-]#_#g'; }

# ----------------------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------------------
preflight() {
  have python3 || die "python3 is required (used for redaction). Install python3 and re-run."
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
    || die "python3 >= 3.6 is required"
  have tar || die "tar is required"
  have gzip || die "gzip is required"
  have timeout || die "timeout (coreutils) is required"
}

setup_work() {
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/k8s-diag.XXXXXX") || die "cannot create temp dir"
  chmod 700 "$WORK"
  trap cleanup EXIT
  trap 'log "interrupted"; exit 130' INT TERM
  HELPER="$WORK/kdiag_helper.py"
  write_helper "$HELPER"
}

cleanup() {
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    rm -rf "$WORK/raw"   # unredacted data: always removed
    if [[ "$KEEP_WORK" == 1 ]]; then
      log "keeping work dir (redacted only): $WORK"
    else
      rm -rf "$WORK"
    fi
  fi
}

detect_sudo() {
  SUDO=()
  if [[ $EUID -eq 0 ]]; then
    RUN_AS="root"
  elif [[ "$USE_SUDO" == 1 ]] && have sudo && sudo -n true 2>/dev/null; then
    SUDO=(sudo -n); RUN_AS="sudo"
  else
    RUN_AS="user"
    log "WARNING: not root and passwordless sudo unavailable; some node data will be missing."
    log "         Re-run with sudo for a complete bundle."
  fi
}

detect_kubectl() {
  KUBECTL=()
  local bin="$KUBECTL_BIN" c
  [[ -z "$bin" ]] && bin=$(command -v kubectl 2>/dev/null || true)
  for c in /usr/local/bin/kubectl /usr/bin/kubectl /opt/bin/kubectl /var/lib/rancher/rke2/bin/kubectl; do
    [[ -z "$bin" && -x "$c" ]] && bin="$c"
  done
  if [[ -z "$bin" ]]; then
    log "WARNING: kubectl not found; cluster-level collection disabled (node-level continues)."
    DO_CLUSTER=0; return 0
  fi
  KUBECTL=("$bin" "--request-timeout=$REQUEST_TIMEOUT")
  local kcfg=""
  if [[ -n "$KUBECONFIG_ARG" ]]; then kcfg="$KUBECONFIG_ARG"; KUBECONFIG_SOURCE="flag"
  elif [[ -n "${KUBECONFIG:-}" ]]; then KUBECONFIG_SOURCE="env"
  elif [[ -r "${HOME:-/nonexistent}/.kube/config" ]]; then KUBECONFIG_SOURCE="home"
  elif [[ -e /etc/kubernetes/admin.conf ]]; then kcfg="/etc/kubernetes/admin.conf"; KUBECONFIG_SOURCE="admin.conf"
  else KUBECONFIG_SOURCE="default"
  fi
  if [[ -n "$kcfg" ]]; then
    if [[ ! -r "$kcfg" ]] && ((${#SUDO[@]})); then KUBECTL=("${SUDO[@]}" "${KUBECTL[@]}"); fi
    KUBECTL+=("--kubeconfig=$kcfg")
  fi
  [[ -n "$KUBE_CONTEXT" ]] && KUBECTL+=("--context=$KUBE_CONTEXT")
  return 0
}

detect_crictl() {
  CRICTL=()
  local bin c sock
  bin=$(command -v crictl 2>/dev/null || true)
  for c in /usr/local/bin/crictl /usr/bin/crictl /opt/bin/crictl; do [[ -z "$bin" && -x "$c" ]] && bin="$c"; done
  [[ -z "$bin" ]] && return 0
  CRICTL=("$bin")
  if [[ ! -e /etc/crictl.yaml ]]; then
    for sock in /run/containerd/containerd.sock /var/run/crio/crio.sock /run/k3s/containerd/containerd.sock; do
      if [[ -S "$sock" ]]; then CRICTL+=("--runtime-endpoint" "unix://$sock"); break; fi
    done
  fi
  return 0
}

ensure_key() {
  python3 "$HELPER" ensure-key "$KEY_FILE" || die "cannot create redaction key at $KEY_FILE (use --key-file)"
}

# ----------------------------------------------------------------------------------------
# Cluster collection (kubectl)
# ----------------------------------------------------------------------------------------
check_api() {
  API_OK=0
  ((DO_CLUSTER)) || return 0
  log "Checking API server reachability"
  if kc cluster/version.json 60 version -o json && grep -q '"serverVersion"' "$RAW/cluster/version.json"; then
    API_OK=1
  else
    log "WARNING: API server not reachable via kubectl. Continuing with node-level collection."
  fi
  kc cluster/readyz.txt 30 get --raw '/readyz?verbose'
  kc cluster/livez.txt 30 get --raw '/livez?verbose'
  kc cluster/kubeconfig-minified.yaml 15 config view --minify
  return 0
}

take_snapshot() {
  local i="$1" d
  d=$(printf 'snapshots/%02d' "$i")
  mkdir -p "$RAW/$d"
  date -u +%Y-%m-%dT%H:%M:%SZ >"$RAW/$d/timestamp"
  log "Snapshot $i/$SNAPSHOTS"
  if ((DO_CLUSTER && API_OK)); then
    kc "$d/pods.json" 120 get pods -A -o json
    kc "$d/nodes.json" 60 get nodes -o json
    kc "$d/events.json" 120 get events -A -o json
  fi
  if ((DO_NODE)) && ((${#CRICTL[@]})); then
    run_root "$d/crictl-ps.txt" 30 "${CRICTL[@]}" ps -a
  fi
  return 0
}

collect_cluster() {
  ((DO_CLUSTER && API_OK)) || return 0
  local r
  log "Collecting cluster resources"
  local -a ns_res=(pods deployments daemonsets statefulsets replicasets jobs cronjobs services
    endpointslices events persistentvolumeclaims resourcequotas limitranges poddisruptionbudgets
    networkpolicies ingresses horizontalpodautoscalers)
  local -a cl_res=(nodes namespaces persistentvolumes storageclasses volumeattachments csidrivers csinodes
    validatingwebhookconfigurations mutatingwebhookconfigurations apiservices priorityclasses
    runtimeclasses certificatesigningrequests ingressclasses)
  for r in "${ns_res[@]}"; do kc "cluster/resources/$r.json" 180 get "$r" -A -o json; done
  for r in "${cl_res[@]}"; do kc "cluster/resources/$r.json" 120 get "$r" -o json; done
  kc cluster/resources/leases-kube-system.json 60 get leases -n kube-system -o json

  log "Collecting cluster summaries"
  kc cluster/text/nodes-wide.txt 60 get nodes -o wide
  kc cluster/text/pods-wide.txt 120 get pods -A -o wide
  kc cluster/text/describe-nodes.txt 180 describe nodes
  kc cluster/text/top-nodes.txt 30 top nodes
  kc cluster/text/top-pods.txt 60 top pods -A
  kc cluster/text/api-resources.txt 60 api-resources
  kc cluster/text/crds.txt 60 get crd -o 'custom-columns=NAME:.metadata.name,ESTABLISHED:.status.conditions[?(@.type=="Established")].status,CREATED:.metadata.creationTimestamp'
  kc cluster/text/secrets-list.txt 60 get secrets -A -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp'
  kc cluster/text/configmaps-list.txt 60 get configmaps -A -o 'jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'
  kc cluster/text/cluster-info.txt 30 cluster-info

  log "Collecting selected ConfigMaps"
  local spec ns name
  for spec in "${CONFIGMAP_ALLOWLIST[@]}"; do
    ns="${spec%%/*}"; name="${spec#*/}"
    if grep -q -P "^\Q${ns}\E\t\Q${name}\E$" "$RAW/cluster/text/configmaps-list.txt" 2>/dev/null; then
      kc "cluster/configmaps/${ns}_${name}.json" 60 get configmap -n "$ns" "$name" -o json
    fi
  done
  while IFS= read -r ns; do
    [[ -n "$ns" ]] && kc "cluster/configmaps/${ns}_ALL.json" 60 get configmaps -n "$ns" -o json
  done < <(python3 "$HELPER" ns-list "$RAW/cluster/resources/namespaces.json" "$DESCRIBE_ALL_NS_REGEX")

  collect_pod_details
  return 0
}

collect_pod_details() {
  local sel="$WORK/pod-selection.tsv"
  python3 "$HELPER" select-pods "$RAW/cluster/resources/pods.json" "$FOCUS_NS_REGEX" \
    "$DESCRIBE_ALL_NS_REGEX" "$MAX_UNHEALTHY_PODS" "$MAX_HEALTHY_PODS" >"$sel" 2>>"$RUN_LOG"
  local n; n=$(cut -f1,2 "$sel" | sort -u | grep -c . || true)
  log "Collecting logs/describe for $n pods (unhealthy + infrastructure namespaces)"
  declare -A described=()
  local ns pod ctr _kind prev cls desc logs base tail
  while IFS=$'\t' read -r -u 3 ns pod ctr _kind prev cls desc logs; do
    [[ -z "$ns" ]] && continue
    base="logs/$ns/$pod"
    if [[ "$desc" == 1 && -z "${described[$ns/$pod]:-}" ]]; then
      described[$ns/$pod]=1
      kc "describe/pods/$ns/$pod.txt" 60 describe pod -n "$ns" "$pod"
    fi
    [[ "$logs" == 1 ]] || continue
    tail=$LOG_TAIL; [[ "$cls" == focus ]] && tail=$LOG_TAIL_HEALTHY
    kc "$base/$ctr.log" 60 logs -n "$ns" "$pod" -c "$ctr" --timestamps "--tail=$tail"
    if [[ "$prev" == 1 ]]; then
      kc "$base/$ctr.previous.log" 60 logs -n "$ns" "$pod" -c "$ctr" --previous --timestamps "--tail=$LOG_TAIL_PREV"
    fi
  done 3<"$sel"
  return 0
}

# ----------------------------------------------------------------------------------------
# Node collection
# ----------------------------------------------------------------------------------------
collect_node() {
  ((DO_NODE)) || return 0
  local d=node f u
  log "Collecting node: OS, resources, kernel"
  run_to $d/os/os-release 5 cat /etc/os-release
  run_to $d/os/uname.txt 5 uname -a
  run_to $d/os/uptime.txt 5 uptime
  run_to $d/os/date-utc.txt 5 date -u +%Y-%m-%dT%H:%M:%SZ
  run_to $d/os/hostnamectl.txt 10 hostnamectl
  run_to $d/os/timedatectl.txt 10 timedatectl
  have chronyc && run_to $d/os/chrony-tracking.txt 10 chronyc tracking
  have chronyc && run_to $d/os/chrony-sources.txt 10 chronyc sources
  run_to $d/resources/nproc.txt 5 nproc
  run_to $d/resources/free.txt 5 free -m
  run_to $d/resources/df.txt 15 df -hT
  run_to $d/resources/df-inodes.txt 15 df -i
  run_to $d/resources/lsblk.txt 10 lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
  run_to $d/resources/pressure.txt 5 bash -c 'for f in /proc/pressure/*; do echo "== $f"; cat "$f"; done'
  run_to $d/resources/vmstat.txt 15 vmstat 1 5
  run_to $d/resources/top.txt 15 bash -c 'top -b -n 1 | head -n 60'
  run_to $d/resources/ps-mem.txt 15 bash -c 'ps -eo pid,user,%cpu,%mem,rss,etime,args --sort=-%mem | head -n 60'
  run_to $d/resources/swap.txt 5 bash -c 'swapon --show; echo "== /proc/swaps"; cat /proc/swaps'
  run_to $d/kernel/sysctl.txt 15 bash -c "sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.ip_forward|net\.ipv6\.conf\.all\.forwarding|net\.bridge\.|net\.ipv4\.conf\.(all|default)\.rp_filter|fs\.inotify\.|fs\.file-max|fs\.nr_open|vm\.max_map_count|vm\.swappiness|vm\.overcommit|kernel\.pid_max|kernel\.panic|net\.core\.somaxconn|net\.netfilter\.nf_conntrack_(max|count)|net\.ipv4\.ip_local_port_range|user\.max_)'"
  run_to $d/kernel/lsmod.txt 10 lsmod
  run_root $d/kernel/dmesg-tail.txt 20 bash -c 'dmesg -T 2>/dev/null | tail -n 1500'
  run_to $d/kernel/limits.txt 5 bash -c 'ulimit -a'

  log "Collecting node: security, firewall, network"
  have getenforce && run_to $d/security/getenforce.txt 5 getenforce
  have sestatus && run_to $d/security/sestatus.txt 5 sestatus
  have aa-status && run_root $d/security/apparmor.txt 10 aa-status
  have ausearch && run_root $d/security/selinux-avc.txt 30 bash -c 'ausearch -m AVC,USER_AVC -ts today 2>&1 | tail -n 300'
  run_to $d/security/firewall-services.txt 10 bash -c 'for s in firewalld ufw nftables iptables; do printf "%s: " "$s"; systemctl is-active "$s" 2>&1; done'
  have firewall-cmd && run_root $d/security/firewalld.txt 20 firewall-cmd --list-all
  have ufw && run_root $d/security/ufw.txt 10 ufw status verbose
  run_to $d/network/ip-link.txt 10 ip link
  run_to $d/network/ip-addr.txt 10 ip -br addr
  run_to $d/network/ip-route.txt 10 ip route
  run_to $d/network/ip6-route.txt 10 ip -6 route
  run_to $d/network/ip-rule.txt 10 ip rule
  run_root $d/network/listening.txt 15 ss -tulnp
  run_to $d/network/resolv.conf 5 cat /etc/resolv.conf
  have resolvectl && run_to $d/network/resolvectl.txt 10 resolvectl status
  run_to $d/network/hosts 5 cat /etc/hosts
  run_root $d/network/iptables-save.txt 30 bash -c 'iptables-save 2>&1 | head -n 6000'
  run_root $d/network/iptables-rule-count.txt 30 bash -c 'iptables-save 2>/dev/null | grep -c "^-A"'
  have nft && run_root $d/network/nft-ruleset.txt 30 bash -c 'nft list ruleset 2>&1 | head -n 6000'
  run_to $d/network/conntrack.txt 5 bash -c 'for f in /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max; do echo "$f: $(cat "$f" 2>&1)"; done'

  log "Collecting node: proxy configuration"
  run_to $d/proxy/etc-environment 5 cat /etc/environment
  run_to $d/proxy/shell-env.txt 5 bash -c 'env | grep -i -E "^(https?_proxy|no_proxy|all_proxy)=" || echo "(no proxy variables in collector shell)"'
  run_root $d/proxy/process-env.txt 15 bash -c '
    for p in kubelet containerd dockerd crio; do
      pid=$(pgrep -xo "$p" 2>/dev/null) || { echo "== $p: not running"; continue; }
      echo "== $p (pid $pid)"
      tr "\0" "\n" </proc/"$pid"/environ | grep -i -E "^(https?_proxy|no_proxy|all_proxy)=" || echo "(no proxy variables)"
    done'

  log "Collecting node: systemd units and journals (last ${SINCE_HOURS}h)"
  run_to $d/systemd/failed-units.txt 15 systemctl --failed --no-pager
  run_to $d/systemd/services.txt 15 systemctl list-units --type=service --all --no-pager --plain
  local units
  units=$(systemctl list-units --type=service --all --no-legend --plain 2>/dev/null \
          | awk '{print $1}' | grep -E "$UNIT_REGEX" | grep -v '@' | sort -u | head -n 40)
  for u in $units; do
    run_to "$d/systemd/units/$u.status.txt" 15 systemctl status "$u" --no-pager -l
    run_to "$d/systemd/units/$u.unit.txt" 15 systemctl cat "$u" --no-pager
    run_root "$d/journal/$u.log" 90 bash -c 'journalctl -u "$1" --since "-$2h" --no-pager -o short-iso 2>&1 | tail -n "$3"' _ "$u" "$SINCE_HOURS" "$JOURNAL_LINES"
  done
  run_root $d/journal/priority-err.log 90 bash -c 'journalctl -p err --since "-$1h" --no-pager -o short-iso 2>&1 | tail -n 3000' _ "$SINCE_HOURS"
  run_root $d/journal/boots.txt 15 journalctl --list-boots --no-pager

  log "Collecting node: kubelet / runtime configuration, certificates"
  for f in /var/lib/kubelet/config.yaml /var/lib/kubelet/kubeadm-flags.env /etc/default/kubelet \
           /etc/sysconfig/kubelet /etc/containerd/config.toml /etc/crictl.yaml /etc/docker/daemon.json \
           /etc/crio/crio.conf; do
    run_root "$d/config/$(safe_name "$f").txt" 10 bash -c '[ -e "$1" ] && cat "$1" || echo "(absent)"' _ "$f"
  done
  run_root $d/config/static-pod-manifests.txt 15 bash -c 'for f in /etc/kubernetes/manifests/*; do [ -f "$f" ] || continue; echo "===== $f"; cat "$f"; done'
  run_root $d/config/cni-net.d.txt 15 bash -c 'ls -la /etc/cni/net.d 2>&1; for f in /etc/cni/net.d/*; do [ -f "$f" ] || continue; echo "===== $f"; head -c 65536 "$f"; echo; done'
  run_root $d/config/listings.txt 15 bash -c 'for p in /etc/kubernetes /etc/kubernetes/pki /etc/kubernetes/pki/etcd /var/lib/kubelet/pki /opt/cni/bin /etc/cni/net.d /var/lib/etcd; do echo "===== $p"; ls -la "$p" 2>&1; done'
  run_root $d/certs/certificates.txt 60 bash -c '
    command -v openssl >/dev/null || { echo "openssl not available"; exit 0; }
    for f in /etc/kubernetes/pki/*.crt /etc/kubernetes/pki/etcd/*.crt /var/lib/kubelet/pki/*.crt /var/lib/kubelet/pki/kubelet-client-current.pem; do
      [ -f "$f" ] || continue
      echo "===== $f"
      openssl x509 -noout -subject -issuer -startdate -enddate -in "$f" 2>&1
      openssl x509 -noout -ext subjectAltName -in "$f" 2>/dev/null
    done'
  have kubeadm && run_root $d/certs/kubeadm-check-expiration.txt 30 kubeadm certs check-expiration

  if ((${#CRICTL[@]})); then
    log "Collecting node: container runtime (crictl)"
    run_root $d/cri/version.txt 15 "${CRICTL[@]}" version
    run_root $d/cri/info.json 15 "${CRICTL[@]}" info
    run_root $d/cri/ps-a.txt 30 "${CRICTL[@]}" ps -a
    run_root $d/cri/ps-a.json 30 "${CRICTL[@]}" ps -a -o json
    run_root $d/cri/pods.txt 30 "${CRICTL[@]}" pods
    run_root $d/cri/images.txt 30 "${CRICTL[@]}" images
    local id ns pod name attempt state
    while IFS=$'\t' read -r -u 3 id ns pod name attempt state; do
      [[ -z "$id" ]] && continue
      run_root "$d/cri/logs/${ns:-none}_${pod:-none}_${name}_${attempt}_${state}.log" 30 "${CRICTL[@]}" logs --tail 500 "$id"
    done 3< <(python3 "$HELPER" select-cri "$RAW/$d/cri/ps-a.json" "$API_OK" "$FOCUS_NS_REGEX" "$MAX_CRI_LOGS" 2>>"$RUN_LOG")
  else
    log "crictl not found; skipping container runtime details"
  fi

  if have etcdctl && [[ -f /etc/kubernetes/pki/etcd/ca.crt ]]; then
    log "Collecting node: etcd health"
    local -a e=(etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt
                --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt --key=/etc/kubernetes/pki/etcd/healthcheck-client.key
                --command-timeout=10s)
    run_root $d/etcd/endpoint-health.txt 20 env ETCDCTL_API=3 "${e[@]}" endpoint health -w table
    run_root $d/etcd/endpoint-status.txt 20 env ETCDCTL_API=3 "${e[@]}" endpoint status -w table
    run_root $d/etcd/member-list.txt 20 env ETCDCTL_API=3 "${e[@]}" member list -w table
    run_root $d/etcd/alarms.txt 20 env ETCDCTL_API=3 "${e[@]}" alarm list
  fi

  collect_connectivity
  return 0
}

collect_connectivity() {
  local -a eps=()
  ((${#ENDPOINTS[@]})) && eps+=("${ENDPOINTS[@]}")
  # API server endpoint from kubeconfig
  if ((DO_CLUSTER)) && ((${#KUBECTL[@]})); then
    local server
    server=$(timeout 15 "${KUBECTL[@]}" config view --minify -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null || true)
    server="${server#https://}"; server="${server#http://}"; server="${server%%/*}"
    if [[ -n "$server" ]]; then [[ "$server" == *:* ]] || server="$server:443"; eps+=("$server"); fi
  fi
  ((${#eps[@]})) || return 0
  log "Testing connectivity to ${#eps[@]} endpoint(s)"
  local ep host port
  for ep in "${eps[@]}"; do
    host="${ep%:*}"; port="${ep##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || { host="$ep"; port=443; }
    run_to "node/connectivity/$(safe_name "$host")_$port.txt" 60 bash -c '
      h="$1"; p="$2"
      echo "== target: $h:$p"
      echo "== DNS (getent ahosts)"; getent ahosts "$h" || echo "DNS: FAILED"
      echo "== TCP connect"
      if timeout 8 bash -c "</dev/tcp/$h/$p" 2>/dev/null; then echo "TCP: OK"; else echo "TCP: FAILED"; fi
      if command -v curl >/dev/null; then
        echo "== HTTPS (curl, honours proxy env of this shell)"
        curl -sS -o /dev/null --max-time 15 -w "http_code=%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s verify_result=%{ssl_verify_result}\n" "https://$h:$p/" 2>&1
        echo "== TLS details"
        curl -sv -o /dev/null --max-time 15 "https://$h:$p/" 2>&1 | grep -E "^\* (Connected|Uses proxy|Establish|SSL connection|Server certificate|ALPN| subject| issuer| expire| start|.*SSL certificate verify|.*TLS)" | head -n 40
      fi' _ "$host" "$port"
  done
  return 0
}

collect_includes() {
  local -a paths=()
  local g p f
  shopt -s nullglob
  ((${#INCLUDES[@]})) && paths+=("${INCLUDES[@]}")
  for g in "${AUTO_INCLUDE_GLOBS[@]}"; do
    # shellcheck disable=SC2206  # intentional glob expansion
    local -a m=($g)
    ((${#m[@]})) && paths+=("${m[@]}")
  done
  shopt -u nullglob
  ((${#paths[@]})) || return 0
  log "Collecting ${#paths[@]} extra path(s)"
  for p in "${paths[@]}"; do
    while IFS= read -r f; do
      [[ -n "$f" ]] && run_root "extra/$(safe_name "$f")" 30 tail -n 20000 "$f"
    done < <(${SUDO[@]+"${SUDO[@]}"} find "$p" -maxdepth 4 -type f 2>/dev/null | head -n 300)
  done
  return 0
}

# ----------------------------------------------------------------------------------------
# Redaction inputs, manifest, packaging
# ----------------------------------------------------------------------------------------
build_terms() {
  local t="$WORK/terms.tsv" n
  : >"$t"
  { printf 'HOST\t%s\n' "$(hostname -s 2>/dev/null)"; printf 'HOST\t%s\n' "$(hostname -f 2>/dev/null)"; } >>"$t"
  for n in "$RAW/cluster/resources/nodes.json" "$RAW/snapshots/01/nodes.json"; do
    [[ -s "$n" ]] && python3 "$HELPER" node-names "$n" | sed 's/^/NODE\t/' >>"$t"
  done
  if ((DO_CLUSTER)) && ((${#KUBECTL[@]})); then
    printf 'CLUSTER\t%s\n' "$(timeout 15 "${KUBECTL[@]}" config view --minify -o 'jsonpath={.contexts[0].context.cluster}' 2>/dev/null)" >>"$t"
    printf 'CLUSTER\t%s\n' "$(timeout 15 "${KUBECTL[@]}" config current-context 2>/dev/null)" >>"$t"
  fi
  if ((${#REDACT_TERMS[@]})); then for n in "${REDACT_TERMS[@]}"; do printf 'TERM\t%s\n' "$n" >>"$t"; done; fi
  : >"$WORK/allow.txt"
  if ((${#ALLOW_DOMAINS[@]})); then for n in "${ALLOW_DOMAINS[@]}"; do printf '%s\n' "$n" >>"$WORK/allow.txt"; done; fi
}

write_context() {
  mkdir -p "$RAW/_meta"
  {
    echo "description: ${DESCRIPTION:-<not provided>}"
    echo "stage: ${STAGE:-<not provided>}"
  } >"$RAW/context.txt"
}

write_manifest() {
  KD_VERSION="$KDIAG_VERSION" KD_CASE_ID="$CASE_ID" KD_BUNDLE="$BUNDLE_NAME" \
  KD_STARTED="$STARTED_UTC" KD_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  KD_DESCRIPTION="$DESCRIPTION" KD_STAGE="$STAGE" KD_API_OK="$API_OK" KD_RUN_AS="$RUN_AS" \
  KD_KUBECONFIG_SOURCE="$KUBECONFIG_SOURCE" KD_KUBECTL="${#KUBECTL[@]}" KD_CRICTL="${#CRICTL[@]}" \
  KD_SNAPSHOTS="$SNAPSHOTS" KD_INTERVAL="$INTERVAL" KD_SINCE_HOURS="$SINCE_HOURS" KD_STRICT="$STRICT" \
  KD_DO_CLUSTER="$DO_CLUSTER" KD_DO_NODE="$DO_NODE" KD_ARGS="$ORIG_ARGS" \
    python3 "$HELPER" manifest "$CMD_LOG" "$RAW/manifest.json"
}

redact_and_package() {
  local out="$WORK/out"
  local map="$OUTPUT_DIR/$BUNDLE_NAME.DO-NOT-SEND.map.json"
  mkdir -p "$out"
  log "Redacting"
  RUN_LOG=""   # collector.log lives in the raw dir, which is deleted below
  local -a margs=()
  ((WRITE_MAP)) && margs=(--map-out "$map")
  python3 "$HELPER" redact --src "$WORK/raw/$BUNDLE_NAME" --dst "$out/$BUNDLE_NAME" --key-file "$KEY_FILE" \
    --terms "$WORK/terms.tsv" --allow "$WORK/allow.txt" --strict "$STRICT" ${margs[@]+"${margs[@]}"} \
    || die "redaction failed; nothing was packaged"
  rm -rf "$WORK/raw"
  log "Unredacted staging data deleted"

  if ((REVIEW)); then
    echo
    echo "Redacted bundle staged at: $out/$BUNDLE_NAME"
    echo "Inspect it now (e.g. grep -r 'something-sensitive' $out/$BUNDLE_NAME)."
    read -r -p "Press Enter to package, or Ctrl-C to abort... " _ </dev/tty
  fi

  local tarball="$OUTPUT_DIR/$BUNDLE_NAME.tar.gz"
  tar -C "$out" -czf "$tarball" "$BUNDLE_NAME" || die "packaging failed"
  chmod 644 "$tarball"
  local size sha
  size=$(stat -c %s "$tarball" | awk '{ s=$1; split("B KB MB GB", u); i=1; while (s >= 1024 && i < 4) { s /= 1024; i++ } printf "%.1f %s", s, u[i] }')
  sha=$(sha256sum "$tarball" | cut -d' ' -f1)
  echo
  echo "================================================================================"
  echo " k8s-diag collection complete   case: $CASE_ID"
  echo "================================================================================"
  echo " SEND THIS FILE:   $tarball  ($size)"
  echo "   sha256:         $sha"
  if ((WRITE_MAP)); then
    echo " KEEP LOCALLY:     $map"
    echo "   (maps redaction tokens back to real values. Do NOT send it.)"
    echo "   Restore real values in the report you receive:"
    echo "     $0 --detokenize report.md --map $map"
  fi
  echo " Review contents:  tar -tzf $tarball | less"
  echo "================================================================================"
}

redact_only() {
  [[ -e "$REDACT_ONLY" ]] || die "no such path: $REDACT_ONLY"
  local base; base=$(basename "$REDACT_ONLY")
  local dst="$OUTPUT_DIR/$base.redacted"
  [[ -e "$dst" ]] && die "output already exists: $dst"
  mkdir -p "$WORK/raw/src"
  cp -a "$REDACT_ONLY" "$WORK/raw/src/" || die "copy failed"
  : >"$WORK/terms.tsv"; : >"$WORK/allow.txt"
  build_terms_only_user
  local -a margs=()
  ((WRITE_MAP)) && margs=(--map-out "$OUTPUT_DIR/$base.DO-NOT-SEND.map.json")
  python3 "$HELPER" redact --src "$WORK/raw/src" --dst "$dst" --key-file "$KEY_FILE" \
    --terms "$WORK/terms.tsv" --allow "$WORK/allow.txt" --strict "$STRICT" ${margs[@]+"${margs[@]}"} \
    || die "redaction failed"
  log "Redacted output: $dst"
}

build_terms_only_user() {
  local n
  if ((${#REDACT_TERMS[@]})); then for n in "${REDACT_TERMS[@]}"; do printf 'TERM\t%s\n' "$n" >>"$WORK/terms.tsv"; done; fi
  if ((${#ALLOW_DOMAINS[@]})); then for n in "${ALLOW_DOMAINS[@]}"; do printf '%s\n' "$n" >>"$WORK/allow.txt"; done; fi
  printf 'HOST\t%s\n' "$(hostname -s 2>/dev/null)" >>"$WORK/terms.tsv"
}

# ----------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------
main() {
  parse_args "$@"
  preflight
  mkdir -p "$OUTPUT_DIR" || die "cannot create output dir $OUTPUT_DIR"
  OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
  setup_work

  if [[ -n "$DETOKENIZE" ]]; then
    [[ -n "$MAP_FILE" ]] || die "--detokenize requires --map MAPFILE"
    python3 "$HELPER" detokenize "$DETOKENIZE" "$MAP_FILE"
    exit $?
  fi

  ensure_key
  if [[ -n "$REDACT_ONLY" ]]; then redact_only; exit 0; fi

  STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  [[ -n "$CASE_ID" ]] || CASE_ID="KD-$(date -u +%Y%m%d)-$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  CASE_ID=$(printf '%s' "$CASE_ID" | sed 's/[^A-Za-z0-9._-]/_/g')
  BUNDLE_NAME="k8sdiag_${CASE_ID}_$(date -u +%Y%m%dT%H%M%SZ)"
  RAW="$WORK/raw/$BUNDLE_NAME"
  mkdir -p "$RAW/_meta"
  CMD_LOG="$RAW/_meta/commands.tsv"
  RUN_LOG="$RAW/_meta/collector.log"
  : >"$CMD_LOG"

  log "k8s-diag-collect $KDIAG_VERSION  case=$CASE_ID"
  if [[ -z "$DESCRIPTION" && "$ASSUME_YES" == 0 && -t 0 ]]; then
    read -r -p "Briefly describe the problem (optional, Enter to skip): " DESCRIPTION || true
  fi

  detect_sudo
  ((DO_CLUSTER)) && detect_kubectl
  ((DO_NODE)) && detect_crictl
  log "run_as=$RUN_AS kubeconfig=$KUBECONFIG_SOURCE crictl=$([[ ${#CRICTL[@]} -gt 0 ]] && echo yes || echo no)"
  write_context

  check_api
  local t0; t0=$(date +%s)
  take_snapshot 1
  collect_cluster
  collect_node
  collect_includes
  local i target now
  for ((i = 2; i <= SNAPSHOTS; i++)); do
    target=$(( t0 + (i - 1) * INTERVAL ))
    now=$(date +%s)
    if (( target > now )); then
      log "Waiting $(( target - now ))s for snapshot $i (shows whether the cluster is settling)"
      sleep $(( target - now ))
    fi
    take_snapshot "$i"
  done

  build_terms
  write_manifest
  redact_and_package
}

# ----------------------------------------------------------------------------------------
# Embedded Python helper (redaction, selection, manifest). Python 3.6+ compatible.
# ----------------------------------------------------------------------------------------
write_helper() {
  cat >"$1" <<'KDIAG_PY_EOF'
import sys, os, re, json, hmac, hashlib, ipaddress, secrets, platform

def eprint(msg):
    sys.stderr.write("kdiag-helper: %s\n" % msg)

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as ex:
        eprint("cannot parse %s: %s" % (path, ex))
        return {}

# ------------------------------------------------------------------ selection helpers
def pod_is_unhealthy(p):
    md = p.get("metadata") or {}
    st = p.get("status") or {}
    if md.get("deletionTimestamp"):
        return True
    phase = st.get("phase", "")
    if phase in ("Pending", "Failed", "Unknown"):
        return True
    cs = st.get("containerStatuses") or []
    ics = st.get("initContainerStatuses") or []
    if phase == "Running" and any(not c.get("ready") for c in cs):
        return True
    if any((c.get("restartCount") or 0) > 0 for c in cs + ics):
        return True
    return False

def cmd_select_pods(argv):
    path, focus_re, desc_re = argv[0], argv[1], argv[2]
    max_unh, max_h = int(argv[3]), int(argv[4])
    focus, desc = re.compile(focus_re), re.compile(desc_re)
    items = load_json(path).get("items") or []
    items = sorted(items, key=lambda p: 0 if pod_is_unhealthy(p) else 1)
    n_unh = n_h = 0
    out = []
    for p in items:
        md = p.get("metadata") or {}
        spec = p.get("spec") or {}
        st = p.get("status") or {}
        ns, name = md.get("namespace", ""), md.get("name", "")
        bad = pod_is_unhealthy(p)
        if not bad and not focus.match(ns):
            continue
        if bad:
            if n_unh >= max_unh:
                continue
            n_unh += 1
        else:
            if n_h >= max_h:
                continue
            n_h += 1
        do_desc = "1" if (bad or desc.match(ns)) else "0"
        statuses = {}
        for c in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
            statuses[c.get("name")] = c
        evicted = st.get("reason") == "Evicted"
        for kind, lst in (("init", spec.get("initContainers") or []), ("main", spec.get("containers") or [])):
            for c in lst:
                cn = c.get("name", "")
                cs = statuses.get(cn) or {}
                state = cs.get("state") or {}
                last = cs.get("lastState") or {}
                started = bool(state.get("running") or state.get("terminated") or last.get("terminated"))
                prev = "1" if ((cs.get("restartCount") or 0) > 0 or last.get("terminated")) else "0"
                logs = "1" if (started and not evicted) else "0"
                out.append("\t".join([ns, name, cn, kind, prev, "unhealthy" if bad else "focus", do_desc, logs]))
    if out:
        print("\n".join(out))

CONTROL_PLANE = set(["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler",
                     "kube-proxy", "kube-vip", "haproxy", "keepalived", "coredns"])

def cmd_select_cri(argv):
    path, api_ok, focus_re, cap = argv[0], argv[1] == "1", re.compile(argv[2]), int(argv[3])
    ctrs = load_json(path).get("containers") or []
    ctrs = sorted(ctrs, key=lambda c: int(c.get("createdAt") or 0), reverse=True)
    seen_run, seen_exit, rows = set(), set(), []
    for c in ctrs:
        meta = c.get("metadata") or {}
        labels = c.get("labels") or {}
        name = meta.get("name", "")
        ns = labels.get("io.kubernetes.pod.namespace", "")
        pod = labels.get("io.kubernetes.pod.name", "")
        state = c.get("state", "")
        exited = state != "CONTAINER_RUNNING"
        relevant = (not api_ok) or (name in CONTROL_PLANE) or (exited and bool(focus_re.match(ns)))
        if not relevant:
            continue
        bucket = seen_exit if exited else seen_run
        key = (ns, pod, name)
        if key in bucket:
            continue
        bucket.add(key)
        rows.append("\t".join([c.get("id", ""), ns, pod, name, str(meta.get("attempt", 0)),
                               state.replace("CONTAINER_", "").lower()]))
        if len(rows) >= cap:
            break
    if rows:
        print("\n".join(rows))

def cmd_ns_list(argv):
    rx = re.compile(argv[1])
    for n in load_json(argv[0]).get("items") or []:
        name = (n.get("metadata") or {}).get("name", "")
        if rx.match(name):
            print(name)

def cmd_node_names(argv):
    for n in load_json(argv[0]).get("items") or []:
        name = (n.get("metadata") or {}).get("name", "")
        if name:
            print(name)

# ------------------------------------------------------------------ manifest
def os_pretty():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.platform()

def cmd_manifest(argv):
    cmdlog, out = argv
    e = os.environ
    cmds = []
    if os.path.exists(cmdlog):
        with open(cmdlog, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t", 3)
                if len(parts) < 4:
                    continue
                rc, dur, rel, cmd = parts
                cmds.append({"rc": int(rc) if rc.lstrip("-").isdigit() else rc,
                             "seconds": int(dur) if dur.isdigit() else dur,
                             "output": rel, "command": cmd})
    flag = lambda k: e.get(k) == "1"
    m = {
        "schema_version": "1",
        "collector": {"name": "k8s-diag-collect", "version": e.get("KD_VERSION")},
        "case_id": e.get("KD_CASE_ID"),
        "bundle_name": e.get("KD_BUNDLE"),
        "started_utc": e.get("KD_STARTED"),
        "finished_utc": e.get("KD_FINISHED"),
        "description": e.get("KD_DESCRIPTION") or None,
        "stage": e.get("KD_STAGE") or None,
        "options": {
            "snapshots": int(e.get("KD_SNAPSHOTS") or 0),
            "interval_seconds": int(e.get("KD_INTERVAL") or 0),
            "journal_since_hours": int(e.get("KD_SINCE_HOURS") or 0),
            "strict_redaction": flag("KD_STRICT"),
            "cluster_collection": flag("KD_DO_CLUSTER"),
            "node_collection": flag("KD_DO_NODE"),
            "args": e.get("KD_ARGS"),
        },
        "environment": {
            "run_as": e.get("KD_RUN_AS"),
            "kubeconfig_source": e.get("KD_KUBECONFIG_SOURCE"),
            "kubectl_found": e.get("KD_KUBECTL", "0") != "0",
            "crictl_found": e.get("KD_CRICTL", "0") != "0",
            "api_reachable": flag("KD_API_OK"),
            "collector_host_os": os_pretty(),
            "python": sys.version.split()[0],
        },
        "commands": {
            "total": len(cmds),
            "failed": sum(1 for c in cmds if c["rc"] != 0),
            "timed_out": sum(1 for c in cmds if c["rc"] in (124, 137)),
            "log": cmds,
        },
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)

# ------------------------------------------------------------------ redaction
ALLOW_DOMAINS = [
    "kubernetes.io", "k8s.io", "x-k8s.io", "etcd.io", "golang.org", "go.dev", "gopkg.in",
    "github.com", "githubusercontent.com", "github.io", "ghcr.io", "docker.io", "docker.com",
    "quay.io", "gcr.io", "pkg.dev", "googleapis.com", "google.com", "pki.goog",
    "mcr.microsoft.com", "microsoft.com", "management.azure.com", "login.microsoftonline.com",
    "amazonaws.com", "amazon.com", "ecr.aws", "ubuntu.com", "canonical.com", "launchpad.net",
    "snapcraft.io", "redhat.com", "redhat.io", "fedoraproject.org", "centos.org", "rockylinux.org",
    "almalinux.org", "oracle.com", "debian.org", "kernel.org", "cncf.io", "helm.sh",
    "tigera.io", "projectcalico.org", "cilium.io", "isovalent.com", "coreos.com", "jetstack.io",
    "cert-manager.io", "nvidia.com", "nvcr.io", "prometheus.io", "grafana.com", "istio.io",
    "linkerd.io", "envoyproxy.io", "argoproj.io", "fluxcd.io", "opentelemetry.io",
    "letsencrypt.org", "digicert.com", "sectigo.com", "cluster.local", "example.com",
    "example.org", "ec2.internal", "compute.internal", "rafay.dev", "rafay.co",
]
# Keep the platform suffix, but tokenize the customer-specific labels in front of it.
PLATFORM_SUFFIXES = [
    "elb.amazonaws.com", "azurecr.io", "azmk8s.io", "cloudapp.azure.com", "blob.core.windows.net",
    "vault.azure.net", "file.core.windows.net",
]
TLDS = set("""com net org edu gov mil io co ai dev app cloud biz us uk ca au de fr nl be ch at se no
dk fi es it pl ie in jp cn kr sg hk tw nz br mx za ru il ae local internal corp lan intra intranet
home private priv test example online site tech systems solutions global""".split())
TERM_STOPLIST = set(["", "localhost", "master", "worker", "node", "control-plane", "kubernetes",
                     "default", "admin", "cluster", "none", "unknown", "localhost.localdomain"])
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

SENS_KEY = (r"[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|"
            r"private[_-]?key|client[_-]?secret|credentials?|auth[_-]?key|auth)")
SENS_KEY_FULL = re.compile(r"(?i)^" + SENS_KEY + r"$")
SENS_ENV = re.compile(r"(?i)(password|passwd|secret|token|key|credential|auth|cert|pass$|pwd)")
SKIP_VALUES = set(["true", "false", "null", "none", "nil", "<nil>", "yes", "no", "", "[redacted]"])

RX_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
RX_PEM_B64 = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]*")
RX_B64_LONG = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
RX_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
RX_BEARER = re.compile(r"(?i)\b(bearer|basic)([ \t]+)[A-Za-z0-9._~+/=-]{8,}")
RX_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@\"']+):([^/\s@\"']+)@")
RX_KV = re.compile(r"(?i)(?P<k>\"?" + SENS_KEY + r"\"?)(?P<sep>[ \t]*[:=][ \t]*)(?P<q>[\"']?)(?P<v>[^\s\"',;}\]]+)")
RX_AWS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")
RX_BOOT_TOKEN = re.compile(r"(?<![a-z0-9])[a-z0-9]{6}\.[a-z0-9]{16}(?![a-z0-9])")
RX_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
RX_ARN = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})")
RX_ECR = re.compile(r"(?<![0-9])(\d{12})(\.dkr\.ecr\.)")
RX_AZ = re.compile(r"(?i)(/subscriptions/|/tenants/|(?:subscription|tenant)[_-]?id\"?[ \t]*[:=][ \t]*\"?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
RX_IPHOST = re.compile(r"(?<![A-Za-z0-9])ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?![0-9])")
RX_MAC = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])")
RX_IP4 = re.compile(r"(?<![0-9.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?(?![0-9])(?!\.\d)")
RX_IP6 = re.compile(r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(/\d{1,3})?(?![0-9A-Za-z:]|\.\w)")
RX_DOMAIN = re.compile(r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([a-z]{2,24}))(?![A-Za-z0-9_-])")
RX_TOKEN_LABEL = re.compile(r"^(HOST|NODE|CLUSTER|TERM)-[0-9a-f]{8,16}$")
RX_HOME = re.compile(r"(/home/|/Users/)([^/\s\"']+)")
RX_QUICK = re.compile(r"[0-9.:@=/]|BEGIN|LS0t|eyJ|(?i:bearer|basic|password|secret|token|key|auth|cred)")

class Redactor(object):
    def __init__(self, key, terms, allow, strict):
        self.key = key
        self.strict = strict
        self.allow = [a.lower().strip(".") for a in ALLOW_DOMAINS + allow if a.strip()]
        self.map = {}
        self.counts = {}
        self.cache = {}
        uniq = {}
        for cat, t in terms:
            t = t.strip()
            if len(t) < 4 or t.lower() in TERM_STOPLIST:
                continue
            uniq[t.lower()] = (cat, t)
        self.term_cat = dict((k, v[0]) for k, v in uniq.items())
        if uniq:
            alts = sorted(uniq.keys(), key=len, reverse=True)
            # '-' and '_' are boundaries: static pods are named <component>-<nodename>, file names use '_'
            self.rx_terms = re.compile(r"(?i)(?<![A-Za-z0-9])(" + "|".join(re.escape(a) for a in alts) + r")(?![A-Za-z0-9])")
        else:
            self.rx_terms = None

    def bump(self, cat):
        self.counts[cat] = self.counts.get(cat, 0) + 1

    def token(self, prefix, cat, original, norm=None):
        h = hmac.new(self.key, (cat + "|" + (norm or original)).encode("utf-8"), hashlib.sha256).hexdigest()
        t = prefix + h[:8]
        if t in self.map and self.map[t] != original and (norm is None or self.map[t].lower() != norm):
            t = prefix + h[:16]
        self.map.setdefault(t, original)
        self.bump(cat)
        return t

    # --- IPv4 octet-level prefix-preserving pseudonymization
    def _shift(self, prefix, x):
        d = hmac.new(self.key, ("ip4|" + prefix).encode("utf-8"), hashlib.sha256).digest()
        return (x + d[0]) % 256

    def pseudo_ip4(self, o):
        # Private ranges keep their well-known prefix (10. / 172.16-31. / 192.168. / 100.64-127.) so the
        # RFC1918 block stays obvious; the rest is shifted per prefix. Last octet is kept.
        a, b, c, d = o
        ip = ipaddress.ip_address("%d.%d.%d.%d" % (a, b, c, d))
        if a == 10:
            head = "10.r%d" % self._shift("10", b)
        elif any(ip in n for n in PRIVATE_NETS):
            head = "%d.%d" % (a, b)
        else:
            head = "r%d.r%d" % (self._shift("", a), self._shift(str(a), b))
        return "%s.r%d.%d" % (head, self._shift("%d.%d" % (a, b), c), d)

    @staticmethod
    def ip4_keep(o):
        a, b = o[0], o[1]
        return a in (0, 127, 255) or (a == 169 and b == 254) or a >= 224

    def _ip4(self, m):
        o = [int(x) for x in m.group(1, 2, 3, 4)]
        if any(x > 255 for x in o) or self.ip4_keep(o):
            return m.group(0)
        s = m.start()
        src = m.string
        if s > 0 and src[s - 1] in "vV" and (s < 2 or src[s - 2] != "\\"):
            return m.group(0)  # version string like v1.2.3.4
        t = self.pseudo_ip4(o)
        self.map.setdefault(t, "%d.%d.%d.%d" % tuple(o))
        self.bump("ipv4")
        return t + (m.group(5) or "")

    def _iphost(self, m):
        o = [int(x) for x in m.group(1, 2, 3, 4)]
        if any(x > 255 for x in o):
            return m.group(0)
        t = "ip-" + self.pseudo_ip4(o).replace(".", "-")
        self.map.setdefault(t, m.group(0))
        self.bump("ipv4-hostname")
        return t

    def _ip6(self, m):
        cand = m.group(1)
        if cand.count(":") < 2 or cand in ("::", "::1"):
            return m.group(0)
        try:
            ip = ipaddress.IPv6Address(cand)
        except Exception:
            return m.group(0)
        if ip.is_loopback or ip.is_unspecified:
            return m.group(0)
        return self.token("IPV6-", "ipv6", cand.lower()) + (m.group(2) or "")

    def _domain(self, m):
        fq, tld = m.group(1), m.group(2)
        if tld not in TLDS:
            return fq
        low = fq.lower()
        for suf in PLATFORM_SUFFIXES:
            if low.endswith("." + suf):
                lead = fq[: -(len(suf) + 1)]
                return self.token("DOM-", "domain", lead, lead.lower()) + "." + suf
        if self._allowed(low):
            return fq
        labels = fq.split(".")
        if len(labels) >= 3 and RX_TOKEN_LABEL.match(labels[0]):
            # keep the node/host token visible: NODE-1a2b3c4d.DOM-5e6f7a8b
            rest = ".".join(labels[1:])
            return labels[0] + "." + (rest if self._allowed(rest.lower()) else self.token("DOM-", "domain", rest, rest.lower()))
        return self.token("DOM-", "domain", fq, low)

    def _allowed(self, low):
        for a in self.allow:
            if low == a or low.endswith("." + a):
                return True
        return False

    def _kv(self, m):
        v = m.group("v")
        if v.lower() in SKIP_VALUES or v.startswith("[REDACTED") or v.startswith("REDACTED"):
            return m.group(0)
        self.bump("secret-kv")
        return m.group("k") + m.group("sep") + m.group("q") + "[REDACTED]"

    def _b64(self, m):
        s = m.group(0)
        if re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and re.search(r"[0-9]", s):
            self.bump("base64-blob")
            return "[REDACTED-B64]"
        return s

    def _sub(self, rx, repl, text, cat):
        def f(m):
            self.bump(cat)
            return m.expand(repl) if isinstance(repl, str) else repl
        return rx.sub(f, text)

    def text(self, s):
        if not s:
            return s
        if len(s) < 256:
            c = self.cache.get(s)
            if c is not None:
                return c
        orig = s
        if RX_QUICK.search(s):
            # 1. secrets: values removed, not tokenized
            s = self._sub(RX_PEM, r"[REDACTED-PEM \1]", s, "pem")
            s = self._sub(RX_PEM_B64, "[REDACTED-PEM-B64]", s, "pem-b64")
            s = self._sub(RX_JWT, "[REDACTED-JWT]", s, "jwt")
            s = self._sub(RX_BEARER, r"\1\2[REDACTED]", s, "bearer")
            s = self._sub(RX_URL_CRED, r"\1[REDACTED]:[REDACTED]@", s, "url-credentials")
            s = RX_KV.sub(self._kv, s)
            s = self._sub(RX_AWS_KEY, "[REDACTED-AWS-KEY]", s, "aws-access-key")
            s = self._sub(RX_BOOT_TOKEN, "[REDACTED-BOOTSTRAP-TOKEN]", s, "bootstrap-token")
            s = RX_B64_LONG.sub(self._b64, s)
        # 2. literal terms (hostnames, node names, cluster names, user terms)
        if self.rx_terms is not None:
            s = self.rx_terms.sub(lambda m: self.token(self.term_cat[m.group(1).lower()] + "-", "term",
                                                      m.group(1), m.group(1).lower()), s)
        if RX_QUICK.search(s) or "." in s:
            # 3. identities and infrastructure
            s = RX_EMAIL.sub(lambda m: self.token("EMAIL-", "email", m.group(0), m.group(0).lower()), s)
            s = RX_ARN.sub(lambda m: m.group(1) + self.token("ACCT-", "cloud-account", m.group(2)), s)
            s = RX_ECR.sub(lambda m: self.token("ACCT-", "cloud-account", m.group(1)) + m.group(2), s)
            s = RX_AZ.sub(lambda m: m.group(1) + self.token("AZ-", "cloud-account", m.group(2).lower()), s)
            s = RX_IPHOST.sub(self._iphost, s)
            s = RX_MAC.sub(lambda m: m.group(0) if m.group(0).lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                           else self.token("MAC-", "mac", m.group(0).lower()), s)
            s = RX_IP4.sub(self._ip4, s)
            if ":" in s:
                s = RX_IP6.sub(self._ip6, s)
            s = RX_DOMAIN.sub(self._domain, s)
            s = RX_HOME.sub(lambda m: m.group(1) + self.token("USER-", "user", m.group(2)), s)
        if len(orig) < 256 and len(self.cache) < 200000:
            self.cache[orig] = s
        return s

    # --- structural JSON sanitization
    def sanitize(self, o):
        if isinstance(o, dict):
            o.pop("managedFields", None)
            ann = o.get("annotations")
            if isinstance(ann, dict) and "kubectl.kubernetes.io/last-applied-configuration" in ann:
                ann["kubectl.kubernetes.io/last-applied-configuration"] = "[REMOVED]"
                self.bump("last-applied-annotation")
            kind = o.get("kind")
            if kind == "Secret":
                for k in ("data", "stringData"):
                    if isinstance(o.get(k), dict):
                        o[k] = dict((x, "[REDACTED]") for x in o[k])
                        self.bump("secret-object")
            if kind == "ConfigMap" and self.strict:
                for k in ("data", "binaryData"):
                    if isinstance(o.get(k), dict):
                        o[k] = dict((x, "[REDACTED]") for x in o[k])
                        self.bump("configmap-strict")
            env = o.get("env")
            if isinstance(env, list):
                for e in env:
                    if isinstance(e, dict) and "value" in e and (self.strict or SENS_ENV.search(str(e.get("name", "")))):
                        e["value"] = "[REDACTED]"
                        self.bump("env-value")
            # string values under sensitive keys ({"password": "..."}, {"apiKey": "..."})
            for k, v in list(o.items()):
                if isinstance(v, str) and v.strip().lower() not in SKIP_VALUES and SENS_KEY_FULL.match(str(k)):
                    o[k] = "[REDACTED]"
                    self.bump("secret-kv")
            return dict((self.text(k), self.sanitize(v)) for k, v in o.items())
        if isinstance(o, list):
            return [self.sanitize(v) for v in o]
        if isinstance(o, str):
            return self.text(o)
        return o

def read_key(path):
    with open(path, "r") as f:
        k = f.read().strip()
    if len(k) < 32:
        raise ValueError("redaction key too short")
    return k.encode("utf-8")

def cmd_ensure_key(argv):
    path = argv[0]
    if os.path.exists(path):
        read_key(path)
        return
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32) + "\n")

def parse_opts(argv):
    opts = {}
    i = 0
    while i < len(argv):
        if argv[i].startswith("--") and i + 1 < len(argv):
            opts[argv[i][2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return opts

def cmd_redact(argv):
    o = parse_opts(argv)
    src, dst = o["src"], o["dst"]
    terms = []
    if o.get("terms") and os.path.exists(o["terms"]):
        with open(o["terms"], encoding="utf-8", errors="replace") as f:
            for line in f:
                if "\t" in line:
                    cat, t = line.rstrip("\n").split("\t", 1)
                    terms.append((cat, t))
    allow = []
    if o.get("allow") and os.path.exists(o["allow"]):
        with open(o["allow"], encoding="utf-8", errors="replace") as f:
            allow = [l.strip() for l in f if l.strip()]
    r = Redactor(read_key(o["key-file"]), terms, allow, o.get("strict") == "1")
    processed, skipped, json_fallback = 0, [], []
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for fn in sorted(files):
            sp = os.path.join(root, fn)
            rel = os.path.relpath(sp, src)
            rrel = os.path.join(*[r.text(p) for p in rel.split(os.sep)])
            dp = os.path.join(dst, rrel)
            if os.path.islink(sp) or not os.path.isfile(sp):
                continue
            with open(sp, "rb") as f:
                data = f.read()
            if b"\0" in data[:8192]:
                skipped.append(rrel)
                continue
            text = data.decode("utf-8", "replace")
            out = None
            if fn.endswith(".json") and text.strip():
                try:
                    out = json.dumps(r.sanitize(json.loads(text)), indent=1, ensure_ascii=False)
                except ValueError:
                    json_fallback.append(rrel)
            if out is None:
                out = r.text(text)
            d = os.path.dirname(dp)
            if not os.path.isdir(d):
                os.makedirs(d)
            with open(dp, "w", encoding="utf-8") as f:
                f.write(out)
            processed += 1
    report = {
        "redaction_version": "1",
        "strict": r.strict,
        "files_processed": processed,
        "files_skipped_binary": skipped,
        "json_files_redacted_as_text": json_fallback,
        "replacements_by_category": dict(sorted(r.counts.items())),
        "distinct_tokens": len(r.map),
        "notes": [
            "IPv4 addresses are pseudonymized per octet with a keyed shift: private ranges keep the first "
            "octet (10.r81.r7.5), public IPs get an r-prefixed first octet (r17.r81.r7.5). The last octet "
            "is kept. Shared /8, /16 and /24 prefixes stay recognizable.",
            "HOST-, NODE-, CLUSTER-, TERM-, DOM-, EMAIL-, MAC-, IPV6-, ACCT-, AZ-, USER- tokens are keyed "
            "hashes. The same value always yields the same token at this site.",
            "[REDACTED*] markers are removed secrets (keys, tokens, passwords, certificates) and cannot be recovered.",
        ],
    }
    if not os.path.isdir(dst):
        os.makedirs(dst)
    with open(os.path.join(dst, "redaction-report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    if o.get("map-out"):
        fd = os.open(o["map-out"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"warning": "DO NOT SEND. Maps redaction tokens to real values.",
                       "tokens": r.map}, f, indent=1, sort_keys=True)

def cmd_detokenize(argv):
    path, mapfile = argv
    with open(mapfile, encoding="utf-8") as f:
        mp = json.load(f).get("tokens") or {}
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if mp:
        keys = sorted(mp.keys(), key=len, reverse=True)
        rx = re.compile("(?<![A-Za-z0-9])(" + "|".join(re.escape(k) for k in keys) + ")(?![A-Za-z0-9])")
        for _ in range(3):
            new = rx.sub(lambda m: mp[m.group(1)], text)
            if new == text:
                break
            text = new
    sys.stdout.write(text)

COMMANDS = {
    "select-pods": cmd_select_pods, "select-cri": cmd_select_cri, "ns-list": cmd_ns_list,
    "node-names": cmd_node_names, "manifest": cmd_manifest, "ensure-key": cmd_ensure_key,
    "redact": cmd_redact, "detokenize": cmd_detokenize,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        eprint("usage: helper <%s> ..." % "|".join(sorted(COMMANDS)))
        sys.exit(2)
    COMMANDS[sys.argv[1]](sys.argv[2:])
KDIAG_PY_EOF
}

main "$@"
