#!/usr/bin/env bash
# deploy_mailpit.sh - stand up a Mailpit SMTP sink on a Rafay controller in its
# own namespace. It labels everything it creates and refuses to modify objects
# it did not create.
#
# Two separate steps:
#   1. Controller install time: put the smtp block from
#        ./deploy_mailpit.sh --smtp-config
#      into radm's config.yaml (no cluster access needed).
#   2. After the controller is up: ./deploy_mailpit.sh
#      The controller finds the sink at the service name the block points to.
#
# Why config.yaml and not the Ops Console: the controller's mail sender
# (event-framework) refuses AUTH without TLS and verifies the server
# certificate. The Ops Console form can't turn verification off;
# config.yaml's tls_verify: false can.
#
# The sink: STARTTLS with a self-signed cert (SINK_TLS=starttls, default),
# AUTH advertised, any username/password accepted; listens on 1025, exposed by
# the Service on 587 (tcp- named for the controller's Istio sidecars). TLS is
# mandatory: plain SMTP can't be used for the controller's user-facing emails.
#
# Usage:
#   ./deploy_mailpit.sh                   # create / re-apply the sink
#   ./deploy_mailpit.sh --smtp-config     # print the config.yaml smtp block only
#   ./deploy_mailpit.sh --rotate-ui-auth  # new UI password, restart, print it
#   ./deploy_mailpit.sh --uninstall       # delete our namespace (only if we created it)
# Env:
#   NS            namespace                  (default rafay-smtp-sink)
#   NAME          deployment/service name    (default smtp-sink)
#   SINK_TLS      starttls (default) | off. Use starttls for the controller;
#                 off (no STARTTLS) is only for testing other senders.
#   MAILPIT_IMAGE image to run (default ghcr.io/axllent/mailpit:v1.31.2).
#                 (GHCR avoids Docker Hub anonymous rate limits.) Air-gapped:
#                 mirror that tag into your registry and point here.
#   UI_EXPOSE     how to publish the mail UI:
#                   nodeport (default)  http://<node-public-ip>:$UI_NODEPORT
#                   ingress             http://$UI_HOST via the cluster's ingress
#                   none                port-forward only
#   UI_NODEPORT   NodePort for the UI (default 30825)
#   UI_HOST       hostname for UI_EXPOSE=ingress, e.g. mailpit.<controller-domain>
#   INGRESS_CLASS ingressClassName for UI_EXPOSE=ingress (default: cluster default)
#   UI_USER       UI login user (default admin). The exposed UI always requires a
#                 login: captured mail holds temp passwords and reset links.
#   UI_PASSWORD   UI password for first install or --rotate-ui-auth
#                 (default: random). Stored in secret $NAME-ui-auth.
#   UI_TLS        on (default) | off. The UI is served over HTTPS with a self-signed
#                 cert (secret $NAME-ui-tls). nodeport/none: Mailpit serves HTTPS
#                 itself; ingress: the Ingress terminates TLS with that cert.
#   UI_CERT_SANS  extra cert names, e.g. "IP:203.0.113.10,DNS:mail.example.com".
#                 Add the node's public IP here if k8s doesn't know it. The cert
#                 always covers node IPs k8s knows, UI_HOST, the service names and
#                 localhost; it is regenerated when that list changes.
set -euo pipefail
KUBECTL=${KUBECTL:-kubectl}
NS=${NS:-rafay-smtp-sink}
NAME=${NAME:-smtp-sink}
FQDN="$NAME.$NS.svc.cluster.local"
UI_EXPOSE=${UI_EXPOSE:-nodeport}
UI_NODEPORT=${UI_NODEPORT:-30825}
UI_HOST=${UI_HOST:-}
INGRESS_CLASS=${INGRESS_CLASS:-}
UI_USER=${UI_USER:-admin}
UI_PASSWORD=${UI_PASSWORD:-}
UI_TLS=${UI_TLS:-on}
UI_CERT_SANS=${UI_CERT_SANS:-}
MAILPIT_IMAGE=${MAILPIT_IMAGE:-ghcr.io/axllent/mailpit:v1.31.2}
SINK_TLS=${SINK_TLS:-starttls}
OWNER_LABEL="app.kubernetes.io/managed-by=rafay-smtp-sink-script"
ACTION=${1:-install}

case $ACTION in
  install|--smtp-config|--rotate-ui-auth|--uninstall) ;;
  -h|--help) sed -n '2,52p' "$0"; exit 0 ;;
  *) echo "unknown option: $ACTION (see --help)"; exit 1 ;;
esac

# --------------------------------------------------------------- --smtp-config
if [[ $ACTION == --smtp-config ]]; then
  cat <<EOF
# radm config.yaml - controller-level SMTP pointing at the sink.
# Deploy the sink after the controller is up: ./deploy_mailpit.sh
# (NS=$NS NAME=$NAME; if you change them, regenerate this block.)
smtp:
  enabled: true
  smtp_address: "$FQDN"
  port: 587
  username: "rafay"        # anything; the sink accepts any credentials
  password: "$(printf 'rafay' | base64)"     # base64 of "rafay"
  tls_verify: false        # the sink's cert is self-signed

# Don't set partner-level SMTP in Ops Console > System > SMTP: it overrides this.
# After radm application, confirm radm rendered it (expect smtp_enabled true,
# smtp_tls_verify false):
#   kubectl -n istio-system get cm values -o jsonpath='{.data.merged-values}' | grep '"smtp_'
EOF
  exit 0
fi

# True if namespace $NS exists and carries our managed-by label.
ns_is_ours() {
  [[ $($KUBECTL get ns "$NS" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null) \
     == rafay-smtp-sink-script ]]
}

# ----------------------------------------------------------------- --uninstall
if [[ $ACTION == --uninstall ]]; then
  if ns_is_ours; then
    $KUBECTL delete ns "$NS"
    echo "Also set smtp.enabled: false in config.yaml (or point it at a real relay) and re-run radm."
  else
    echo "Namespace $NS was not created by this script (or doesn't exist); not deleting."
  fi
  exit 0
fi

# Refuse to adopt anything we didn't create.
if $KUBECTL get ns "$NS" >/dev/null 2>&1 && ! ns_is_ours; then
  echo "Namespace $NS already exists and was not created by this script. Pick another: NS=<new> $0"
  exit 1
fi

# ------------------------------------------------------------ --rotate-ui-auth
# The password reaches Mailpit as an env var, which is only read at container
# start. The deployment carries a hash of the secret as a pod annotation, so a
# changed secret + re-apply rolls the pod. Restarting clears captured mail.
if [[ $ACTION == --rotate-ui-auth ]]; then
  ns_is_ours || { echo "Sink not installed in $NS; run $0 first."; exit 1; }
  $KUBECTL -n "$NS" create secret generic "$NAME-ui-auth" \
    --from-literal=auth="$UI_USER:${UI_PASSWORD:-$(openssl rand -hex 12)}" \
    --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
  $KUBECTL -n "$NS" label secret "$NAME-ui-auth" "$OWNER_LABEL" --overwrite >/dev/null
  echo "UI login updated; re-applying so the pod restarts with it."
  ACTION=install
fi

# -------------------------------------------------------------------- install
case $UI_EXPOSE in
  nodeport|none) ;;
  ingress) [[ -n $UI_HOST ]] || { echo "UI_EXPOSE=ingress needs UI_HOST=<hostname>"; exit 1; } ;;
  *) echo "UI_EXPOSE must be nodeport, ingress or none"; exit 1 ;;
esac
[[ $SINK_TLS == off || $SINK_TLS == starttls ]] || { echo "SINK_TLS must be off or starttls"; exit 1; }
[[ $UI_TLS == on || $UI_TLS == off ]] || { echo "UI_TLS must be on or off"; exit 1; }

echo "Image: $MAILPIT_IMAGE   SINK_TLS: $SINK_TLS   UI_TLS: $UI_TLS"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

$KUBECTL create namespace "$NS" --dry-run=client -o yaml | $KUBECTL apply -f -
$KUBECTL label ns "$NS" "$OWNER_LABEL" --overwrite >/dev/null

TLS_ENV="" TLS_MOUNT="" TLS_VOL=""
if [[ $SINK_TLS == starttls ]]; then
  # Keep the cert stable across re-runs; only generate it once.
  if ! $KUBECTL -n "$NS" get secret "$NAME-tls" >/dev/null 2>&1; then
    echo "Generating self-signed cert for $FQDN"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$WORK/tls.key" -out "$WORK/tls.crt" -subj "/CN=$FQDN" \
      -addext "subjectAltName=DNS:$NAME,DNS:$NAME.$NS,DNS:$NAME.$NS.svc,DNS:$FQDN" 2>/dev/null
    $KUBECTL -n "$NS" create secret tls "$NAME-tls" --cert="$WORK/tls.crt" --key="$WORK/tls.key"
    $KUBECTL -n "$NS" label secret "$NAME-tls" "$OWNER_LABEL" >/dev/null
  fi
  TLS_ENV="
        - {name: MP_SMTP_TLS_CERT, value: /tls/tls.crt}
        - {name: MP_SMTP_TLS_KEY, value: /tls/tls.key}"
  TLS_MOUNT="
        - {name: tls, mountPath: /tls, readOnly: true}"
  TLS_VOL="
      - {name: tls, secret: {secretName: $NAME-tls}}"
fi

# UI login: generate once, keep across re-runs (change it with --rotate-ui-auth).
if ! $KUBECTL -n "$NS" get secret "$NAME-ui-auth" >/dev/null 2>&1; then
  $KUBECTL -n "$NS" create secret generic "$NAME-ui-auth" \
    --from-literal=auth="$UI_USER:${UI_PASSWORD:-$(openssl rand -hex 12)}"
  $KUBECTL -n "$NS" label secret "$NAME-ui-auth" "$OWNER_LABEL" >/dev/null
fi
UI_AUTH_B64=$($KUBECTL -n "$NS" get secret "$NAME-ui-auth" -o jsonpath='{.data.auth}')
UI_AUTH_ENV=""
if [[ $UI_EXPOSE != none ]]; then
  UI_AUTH_ENV="
        - name: MP_UI_AUTH
          valueFrom: {secretKeyRef: {name: $NAME-ui-auth, key: auth}}"
fi

# UI HTTPS cert: self-signed, (re)generated only when the wanted SAN list changes.
UI_TLS_ENV="" UI_TLS_MOUNT="" UI_TLS_VOL="" UI_CERT_FP=""
if [[ $UI_TLS == on ]]; then
  NODE_ADDRS=$($KUBECTL get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address} {end}{range .status.addresses[?(@.type=="ExternalIP")]}{.address} {end}{end}')
  SANS="DNS:localhost,IP:127.0.0.1,DNS:$NAME,DNS:$NAME.$NS,DNS:$NAME.$NS.svc,DNS:$FQDN"
  [[ -n $UI_HOST ]] && SANS+=",DNS:$UI_HOST"
  for ip in $NODE_ADDRS; do SANS+=",IP:$ip"; done
  [[ -n $UI_CERT_SANS ]] && SANS+=",$UI_CERT_SANS"
  SANS=$(tr ',' '\n' <<<"$SANS" | sed '/^$/d' | sort -u | paste -sd, -)
  HAVE_SANS=$($KUBECTL -n "$NS" get secret "$NAME-ui-tls" -o jsonpath='{.metadata.annotations.rafay-smtp-sink/sans}' 2>/dev/null || true)
  if [[ $HAVE_SANS != "$SANS" ]]; then
    echo "Generating self-signed UI cert for: $SANS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$WORK/ui.key" -out "$WORK/ui.crt" -subj "/CN=${UI_HOST:-$NAME mail UI}" \
      -addext "subjectAltName=$SANS" 2>/dev/null
    $KUBECTL -n "$NS" create secret tls "$NAME-ui-tls" --cert="$WORK/ui.crt" --key="$WORK/ui.key" \
      --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
    $KUBECTL -n "$NS" label secret "$NAME-ui-tls" "$OWNER_LABEL" --overwrite >/dev/null
    $KUBECTL -n "$NS" annotate secret "$NAME-ui-tls" "rafay-smtp-sink/sans=$SANS" --overwrite >/dev/null
  fi
  UI_CERT_FP=$($KUBECTL -n "$NS" get secret "$NAME-ui-tls" -o jsonpath='{.data.tls\.crt}' | base64 -d \
               | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
  if [[ $UI_EXPOSE != ingress ]]; then
    UI_TLS_ENV="
        - {name: MP_UI_TLS_CERT, value: /ui-tls/tls.crt}
        - {name: MP_UI_TLS_KEY, value: /ui-tls/tls.key}"
    UI_TLS_MOUNT="
        - {name: ui-tls, mountPath: /ui-tls, readOnly: true}"
    UI_TLS_VOL="
      - {name: ui-tls, secret: {secretName: $NAME-ui-tls}}"
  fi
fi
# Pod restarts when the UI login or UI cert changes (both are read at start).
POD_HASH=$(printf '%s|%s' "$UI_AUTH_B64" "$UI_CERT_FP" | sha256sum | cut -c1-16)

# Remove exposure objects from a previous run that used a different UI_EXPOSE.
[[ $UI_EXPOSE != nodeport ]] && $KUBECTL -n "$NS" delete svc "$NAME-ui" --ignore-not-found >/dev/null
[[ $UI_EXPOSE != ingress ]] && $KUBECTL -n "$NS" delete ingress "$NAME-ui" --ignore-not-found >/dev/null

UI_SVC=""
if [[ $UI_EXPOSE == nodeport ]]; then
  UI_SVC="---
apiVersion: v1
kind: Service
metadata:
  name: $NAME-ui
  namespace: $NS
  labels: {app: $NAME, app.kubernetes.io/managed-by: rafay-smtp-sink-script}
spec:
  type: NodePort
  selector: {app: $NAME}
  ports:
  - {name: http, port: 8025, targetPort: 8025, nodePort: $UI_NODEPORT}"
elif [[ $UI_EXPOSE == ingress ]]; then
  UI_SVC="---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: $NAME-ui
  namespace: $NS
  labels: {app: $NAME, app.kubernetes.io/managed-by: rafay-smtp-sink-script}
spec:${INGRESS_CLASS:+
  ingressClassName: $INGRESS_CLASS}$([[ $UI_TLS == on ]] && printf '\n  tls:\n  - hosts: [%s]\n    secretName: %s' "$UI_HOST" "$NAME-ui-tls")
  rules:
  - host: $UI_HOST
    http:
      paths:
      - path: /
        pathType: Prefix
        backend: {service: {name: $NAME, port: {number: 8025}}}"
fi

$KUBECTL apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $NAME
  namespace: $NS
  labels: {app: $NAME, app.kubernetes.io/managed-by: rafay-smtp-sink-script}
spec:
  replicas: 1
  selector: {matchLabels: {app: $NAME}}
  template:
    metadata:
      labels: {app: $NAME}
      annotations:
        sidecar.istio.io/inject: "false"
        # The UI login (env from secret) and UI cert are read only at container
        # start; a change to either changes this hash, which rolls the pod.
        rafay-smtp-sink/pod-config-hash: "$POD_HASH"
    spec:
      containers:
      - name: mailpit
        image: $MAILPIT_IMAGE
        env:
        - {name: MP_SMTP_BIND_ADDR, value: "0.0.0.0:1025"}
        - {name: MP_UI_BIND_ADDR, value: "0.0.0.0:8025"}
        - {name: MP_SMTP_AUTH_ACCEPT_ANY, value: "true"}
        - {name: MP_SMTP_AUTH_ALLOW_INSECURE, value: "true"}
        - {name: MP_MAX_MESSAGES, value: "5000"}
        - {name: MP_VERBOSE, value: "true"}$TLS_ENV$UI_AUTH_ENV$UI_TLS_ENV
        ports:
        - {name: smtp, containerPort: 1025}
        - {name: http, containerPort: 8025}
        readinessProbe: {tcpSocket: {port: 8025}, periodSeconds: 10}  # UI port: keeps probe noise out of the SMTP log
        resources:
          requests: {cpu: 50m, memory: 64Mi}
          limits: {memory: 256Mi}
        volumeMounts:
        - {name: data, mountPath: /data}$TLS_MOUNT$UI_TLS_MOUNT
      volumes:
      - {name: data, emptyDir: {}}$TLS_VOL$UI_TLS_VOL
---
apiVersion: v1
kind: Service
metadata:
  name: $NAME
  namespace: $NS
  labels: {app: $NAME, app.kubernetes.io/managed-by: rafay-smtp-sink-script}
spec:
  selector: {app: $NAME}
  ports:
  # SMTP is server-speaks-first. The controller's senders have Istio sidecars;
  # an unnamed/unknown port triggers Envoy protocol sniffing, which waits for the
  # client to talk while the client waits for the server banner -> hang/timeout.
  # The tcp- prefix + appProtocol make Envoy treat these as plain TCP.
  - {name: tcp-smtp-submission, port: 587, targetPort: 1025, appProtocol: tcp}
  - {name: http, port: 8025, targetPort: 8025}
$UI_SVC
EOF

$KUBECTL -n "$NS" rollout status deploy/"$NAME" --timeout=120s

SCHEME=http; [[ $UI_TLS == on ]] && SCHEME=https
case $UI_EXPOSE in
  nodeport)
    NODE_IPS=$($KUBECTL get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="ExternalIP")]}{.address} {end}{end}')
    # No ExternalIP in k8s: fall back to the first IP given in UI_CERT_SANS.
    [[ -z ${NODE_IPS// /} ]] && NODE_IPS=$(grep -oE 'IP:[0-9a-fA-F.:]+' <<<"$UI_CERT_SANS" | head -1 | cut -d: -f2- || true)
    if [[ -n ${NODE_IPS// /} ]]; then
      UI_HINT="$SCHEME://${NODE_IPS%% *}:$UI_NODEPORT"
    else
      UI_HINT="$SCHEME://<node-public-ip>:$UI_NODEPORT
           (no ExternalIP in k8s: use the node's public IP, and open TCP $UI_NODEPORT
            in the cloud security list / host firewall;
            add that IP to the cert with UI_CERT_SANS=IP:<public-ip>)"
    fi ;;
  ingress)
    UI_HINT="$SCHEME://$UI_HOST   (DNS for $UI_HOST must point at the ingress)" ;;
  none)
    UI_HINT="kubectl -n $NS port-forward svc/$NAME 8025:8025  ->  $SCHEME://localhost:8025" ;;
esac
UI_LOGIN=$(printf '%s' "$UI_AUTH_B64" | base64 -d)

cat <<EOF

SMTP sink is up (SINK_TLS=$SINK_TLS).
  SMTP:    $FQDN:587 (STARTTLS)
  Mail UI: $UI_HINT
  Login:   ${UI_LOGIN%%:*} / ${UI_LOGIN#*:}$([[ $UI_EXPOSE == none ]] && echo "  (not enforced: UI not exposed)")$([[ $UI_TLS == on ]] && printf '\n  UI cert: self-signed (browser warning expected), SHA-256 %s' "$UI_CERT_FP")

Watch SMTP sessions:   kubectl -n $NS logs -f deploy/$NAME
config.yaml block:     $0 --smtp-config
Change the UI login:   $0 --rotate-ui-auth   (restarts the pod; clears captured mail)
Remove:                $0 --uninstall
EOF
