# SMTP sink (Mailpit) for a self-hosted Rafay controller

This gives a controller that was built with SMTP disabled a working mail target. The sink captures every message in a web UI and delivers nothing. With it you can finish email-driven flows (user invites, temporary passwords, password resets, org sign-up) without a real mail relay, including on air-gapped controllers.

**Workflow:** two separate steps.
1. **At controller install time**, put the `smtp` block from `./deploy_mailpit.sh --smtp-config` into radm's `config.yaml`, with `tls_verify: false`.
2. **Once the controller is up**, run `./deploy_mailpit.sh`.

Two constraints shape this:
- **TLS is mandatory.** Unencrypted SMTP can't be used for user-facing workflows (invites, temporary passwords, password resets), so don't use port 25 or plain SMTP, in `config.yaml` or in the console. The sink always runs with STARTTLS on port 587.
- **Only `config.yaml` works; the Ops Console SMTP form doesn't.** Entering the same values in the console fails, even with `tls_verify: false` set in `config.yaml`. See *Why the console route fails*.

Status: **verified end to end on a live controller (2026-10-08)** with `tls_verify: false`. Rafay does not document Mailpit as a supported SMTP target.

## Recipe

### 1. Controller install: config.yaml

```bash
./deploy_mailpit.sh --smtp-config      # prints the block; no cluster access needed
```
```yaml
smtp:
  enabled: true
  smtp_address: "smtp-sink.rafay-smtp-sink.svc.cluster.local"
  port: 587
  username: "rafay"        # anything; the sink accepts any credentials
  password: "cmFmYXk="     # base64 of "rafay"
  tls_verify: false        # the sink's cert is self-signed
```

Don't set partner-level SMTP in Ops Console → System → SMTP, because it overrides this. The installer doesn't contact the SMTP server, so the sink can come later. Until it exists, emails just fail to send.

To confirm radm rendered it after `radm application` (expect `smtp_enabled` true and `smtp_tls_verify` false):
```bash
kubectl -n istio-system get cm values -o jsonpath='{.data.merged-values}' | grep '"smtp_'
```

### 2. After the controller is up: the sink

```bash
./deploy_mailpit.sh                    # prints the SMTP endpoint, mail UI URL and login
```
On an air-gapped controller, push the image to the local registry first and set `MAILPIT_IMAGE`.

Then trigger a real email, such as a user invite or password reset, and watch it arrive in the mail UI. **Send Test Email** in the Ops Console checks the saved partner-level settings, so it may not test the controller-level config.

### Existing controller (Day 2)

Deploy the sink, add the `smtp` block to `config.yaml`, run `radm dependency` and `radm application`, and delete any partner-level SMTP config.

### UI login

The login is stored in secret `smtp-sink-ui-auth` and reaches Mailpit as an environment variable. That's read only when the container starts, so **editing the secret alone doesn't change the running login**. Use:
```bash
./deploy_mailpit.sh --rotate-ui-auth                  # random password
UI_PASSWORD='choose-one' ./deploy_mailpit.sh --rotate-ui-auth
```
This updates the secret and restarts the pod, which clears captured mail. If you edit the secret by hand, re-run `./deploy_mailpit.sh`. The deployment carries a hash of the login, so a changed secret rolls the pod.

## Mail UI

| `UI_EXPOSE` | UI address | Notes |
|---|---|---|
| `nodeport` (default) | `https://<node-public-ip>:30825` | Open TCP 30825 in the cloud security list / host firewall. Change the port with `UI_NODEPORT`. |
| `ingress` | `https://$UI_HOST` | e.g. `UI_EXPOSE=ingress UI_HOST=mailpit.<controller-domain> INGRESS_CLASS=<class> ./deploy_mailpit.sh`. Needs DNS for the host and an ingress controller that serves plain Ingress objects. |
| `none` | port-forward only | |

**The UI is HTTPS by default (`UI_TLS=on`)** with a self-signed certificate in secret `smtp-sink-ui-tls`, so expect a browser warning.
- **Certificate names:** it covers localhost, the service names, the node IPs Kubernetes knows, and `UI_HOST`. Add the public IP (or any other name) with `UI_CERT_SANS`, e.g. `UI_CERT_SANS=IP:158.101.29.99 ./deploy_mailpit.sh`. The URL the script prints then uses that IP too.
- **Regeneration:** the certificate is created again only when that list of names changes, and the pod restarts to pick it up.
- **Where TLS happens:** with `nodeport` and `none`, Mailpit serves HTTPS itself. With `ingress`, the Ingress terminates TLS using the same certificate.
- **To turn it off:** `UI_TLS=off`.

**The exposed UI always requires a login.** Captured mail contains temporary passwords and password-reset links for controller users. The password is generated on the first run and kept in secret `smtp-sink-ui-auth`. To read it:

```bash
kubectl -n rafay-smtp-sink get secret smtp-sink-ui-auth -o jsonpath='{.data.auth}' | base64 -d
```

Watch the SMTP sessions live with:

```bash
kubectl -n rafay-smtp-sink logs -f deploy/smtp-sink
```

## What discovery showed (rctrl01.rafay.lab, 2026-10-08)

- **The sender is `rafay-core/event-framework`**, a Go service. At startup it logs: *"controller SMTP configuration is not set; email will use organization or partner SMTP configuration if available"*. The controller-level (radm) config is the default it falls back to.
- **Every `rafay-core` service has an Istio sidecar.** Istio egress is `ALLOW_ANY` and there are no NetworkPolicies, so the sink is reachable. But SMTP is server-speaks-first, and Istio protocol sniffing on an unrecognized port name hangs that handshake. The sink Service therefore names its SMTP ports `tcp-*` with `appProtocol: tcp`. This is also the most likely reason the earlier Mailpit didn't work.
- radm renders SMTP into the Helm globals `smtp_enabled`, `smtp_addr`, `smtp_tls_verify` and `smtp_use_insecure`. The Ops Console form doesn't expose the last two. `use_insecure` (plain-text SMTP) isn't an option, because user-facing workflows require TLS.

## Why the console route fails

**Confirmed (2026-10-09):** settings entered in the console are always checked with certificate verification on. The controller-level `tls_verify: false` in `config.yaml` applies **only** to the controller-level SMTP config.

The test: the same values that work in `config.yaml` were entered in Ops Console → System → SMTP, then *Send Test Email* was clicked.
- event-framework connected to the in-cluster sink and started TLS. Istio log: `outbound|587||smtp-sink.rafay-smtp-sink.svc.cluster.local`, ~1.6 KB sent / 2.9 KB received.
- It then failed with `failed to start TLS: tls: failed to verify certificate: x509: certificate signed by unknown authority`.

**TLS off in the console doesn't help (2026-10-09).** With TLS off, event-framework still upgraded via STARTTLS, because the sink offers it, and failed identically: the same bytes on the wire and the same `x509` error. The console's TLS switch means "don't *require* TLS", not "don't *use* it". Every combination fails:

| Sink | Console TLS | Result |
|---|---|---|
| STARTTLS | on | `x509` verification failure |
| STARTTLS | off | upgrades anyway → `x509` failure |
| no STARTTLS | off | `authentication requires TLS` |
| no STARTTLS | on | can't start TLS |

So the console does **not** block in-cluster SMTP hosts; the in-cluster/SSRF theory is ruled out. The only blocker is certificate verification. The console has no way to turn it off, and the sink can't present a certificate event-framework trusts (its trust bundle is public CAs only).

Other confirmed constraints:
- event-framework won't log in without TLS (`smtp: authentication requires TLS`), and the form requires credentials.
- Plain SMTP (port 25, `use_insecure`) isn't allowed for user-facing workflows anyway.

## Confirmed by testing (2026-10-08)

- **Send Test Email** calls `POST /event/v1/email/config/verification` on **event-framework**. It tests the **saved** configuration, not what's in the form, so click **Save** first.
- With TLS off and a username/password set, event-framework connects to the sink but refuses to authenticate: `failed to authenticate with SMTP server: smtp: authentication requires TLS`.
- The form won't save without a username and password, so sending without authentication isn't an option.
- With `SINK_TLS=starttls` and TLS on, event-framework verifies the certificate: `failed to start TLS: tls: failed to verify certificate: x509: certificate signed by unknown authority`. Verification has to be turned off, because no trusted certificate is available (next point).
- The controller's own ops-console certificate is self-signed (empty subject and issuer; SAN `ops-console.<domain>`, 10-year validity), so there's no publicly trusted wildcard certificate to reuse. event-framework's full trust bundle (150 CAs) is public CAs only, and none of the cluster's cert-manager CAs are in it.

Other failure modes:

| Symptom | Likely cause | Check |
|---|---|---|
| Nothing in the sink log when mail should be sent | A partner-level config is still overriding; or a network path problem | Ops Console SMTP page; `smtp_path_test.sh` |
| `x509 …` | `tls_verify: false` didn't take effect | `merged-values` check above |
| `authentication requires TLS` | The sink is in `off` mode; TLS is mandatory | `./deploy_mailpit.sh` (default `SINK_TLS=starttls`) |
| Real flows send nothing for one org | An org-level SMTP override (Web Console → Settings → SMTP Configuration) | Org settings |

## Diagnostics

```bash
# Finds which controller pod actually sends mail, its mail-related log errors,
# NetworkPolicies and Istio egress settings. Read-only; secret values are redacted.
python3 smtp_discover.py --since 1h | tee discover.txt      # add --all-logs if no sender is found

# From inside that sender pod: DNS, TCP, what the sink advertises (STARTTLS/AUTH),
# and a test message that should appear in the mail UI.
./smtp_path_test.sh -n rafay-core -p $(kubectl -n rafay-core get pods -o name | grep -m1 event-framework | cut -d/ -f2) -c event-framework
```

`capture_click.sh` captures every controller log line around one UI action. `tls_trust_discover.sh` shows which certificate authorities event-framework trusts.

## Files

| File | Purpose |
|---|---|
| `deploy_mailpit.sh` | Creates the sink in its own `rafay-smtp-sink` namespace. `--smtp-config` prints the `config.yaml` block, `--rotate-ui-auth` changes the UI login, and `--uninstall` removes it. It never modifies objects it didn't create. |
| `smtp_discover.py` | Read-only interrogation of the controller cluster for SMTP senders, config, logs and network policy |
| `smtp_path_test.sh` | Network and SMTP probe run from inside the sending pod (ephemeral container; `MODE=pod` fallback) |
| `capture_click.sh` | Captures all `rafay-core` logs, including Istio access logs, around one UI action |
| `tls_trust_discover.sh` | Read-only: event-framework's CA trust, the controller's served certificate, cert-manager issuers, DNS options |

## Notes

- Image: `ghcr.io/axllent/mailpit:v1.31.2`. On an air-gapped controller, copy it into your registry and set `MAILPIT_IMAGE`.
- Captured mail is kept in an `emptyDir` (temporary pod storage) and lost when the pod restarts. That's fine for a sink.
- Removal: `./deploy_mailpit.sh --uninstall`, then set `smtp.enabled: false` in `config.yaml` and re-run radm. Alternatively, point `config.yaml` at a real relay.
