# Configuration and activation

Deploy a JSON object outside the web root, readable by PHP workers, and set `SOCA_CONFIG_FILE` to its absolute path. No database setting overrides this file. The existing host GUI displays effective values and sources, with all fields locked. JSON booleans must be actual booleans. Secret references must be absolute readable paths; no key material belongs in the GUI or repository.

Generate a persistent P-256 key with `openssl ecparam -name prime256v1 -genkey -noout -out client.pem` and a separate state key with `openssl rand -out state.key 32`. Mount both as deployment secrets. Protect access, take an encrypted backup and retain key identity through upgrades. This version cannot use a non-exportable KMS/HSM signer or rotate keys automatically.

| Setting | Default, type and effect |
| --- | --- |
| `origin` | Required canonical HTTPS installation URL, including any path prefix. Never inferred from incoming Host or forwarded headers. |
| `issuer` | `https://auth.resoauth.cloud`, an exact, explicitly trusted HTTPS issuer. One provider profile per installation is currently supported. |
| `client_name` | Native application/site name where exposed, otherwise the host product name. Explicit deployment value wins. |
| `client_uri`, `logo_uri`, `policy_uri`, `tos_uri` | Application public HTTPS URLs. `client_uri` defaults to `origin`. Unknown optional branding/legal pages are omitted. Automatic discovery of all host branding/legal pages is still a gap. |
| `private_key_file`, `state_key_file` | Required absolute deployment secret references. State key content must be 32–4096 bytes. PEM private material is loaded only into server memory. |
| `key_id` | Stable ID derived from the public key unless explicitly set. Changing key identity invalidates candidate evidence. |
| `enabled` | `false`. Allows ordinary SSO only when current revision document and candidate-login evidence exists. This switch itself does not stale candidate evidence. |
| `provision` | `false`. Opt-in new account creation after protocol validation and admission. |
| `group_id`, `site_id` | `group_id` must be `view`; `site_id` is the positive decimal Matomo website ID. Linked users need view access to that site. Superusers, accounts with any administrator grant, pending invitations and accounts without local access are denied. |
| `session_max_age` | 900 seconds, integer 60–86400. SOCA sessions are checked on the next covered host request and cannot outlive this bound. Native host session expiry can be shorter. |
| `metadata_mode` | `hosted` or `proxy`; hosted is the production default. Local HTTPS demo uses proxy mode. |
| `metadata_jwks_mode` | `uri` by default in hosted mode, `inline` in proxy mode. Explicit `uri`/`inline` overrides are supported. URI mode needs publicly reachable HTTPS JWKS. |
| `proxy_template` | `https://dynamic-cimd.resoauth.cloud/cimd/%s`. Exactly one `%s` in an HTTPS path, no query, fragment or credentials. The deterministic payload excludes `client_id`; the proxy must return the exact resulting URL as `client_id`. |
| `assertion_alg`, `id_token_alg` | Independently pinned `ES256` defaults. `ES384` and `RS256` require explicit deployment approval and compatible keys/provider support. No algorithm fallback. All other required algorithms remain gaps. |
| `assertion_audience` | `token_endpoint`; explicitly allow `issuer` only where the trusted provider requires it. |
| `scopes` | `openid email profile`. Only `openid`, `email`, `profile` are permitted. Narrow to `openid email` if profile retrieval is not needed. No offline access or refresh tokens. |
| `userinfo` | `optional`, `required` or `disabled`. Returned identity conflicts always fail, including optional retrieval. Validated ID-token values take precedence; missing supported fields may be filled from matching UserInfo. |
| `max_age` | `null`, or an integer 0–86400 seconds. `0` requests fresh authentication and requires validated `auth_time`. |
| `required_acr`, `required_amr` | Empty lists. Configured values require exact validated assurance matches. At most 20 values per list, each 1–200 bytes without whitespace/control characters. Provider MFA semantics need operator documentation; email verification is not MFA. |
| `allowed_emails`, `allowed_domains`, `denied_emails`, `denied_domains` | Empty lists, so admission denies by default. Deny rules take precedence. Email rules require a valid address and boolean `email_verified: true`. |
| Derived endpoint URLs | `/index.php?module=Soca&action=metadata`, `...&action=jwks`, `...&action=callback`. Optional explicit values must equal the corresponding native endpoint exactly. |

Domain rules accept `example.com` or `*.example.com`; exact rules match only the apex and wildcard rules match one or more complete subdomain labels. Invalid syntax, single labels, repeated/embedded wildcards, URLs and email addresses are rejected. Wildcards never match the apex or a suffix embedded in another label.

`SOCA_EMERGENCY_DISABLE=1` overrides the file and blocks ordinary and test sign-in. For fail-closed interpretation any non-empty value except `0` disables SSO. Remove the variable or set it to `0` to clear it. Restart PHP workers when changing their environment.

1. Deploy with `enabled: false`, `provision: false`, explicit admission rules, a stable key and a canonical callback.
2. Publish candidate metadata and JWKS. Run `php console soca:manage status`, then `php console soca:manage check`. The settings GUI provides the same document check. A document check is not a provider login.
3. As a locally authenticated administrator, open the native settings page and select **Test candidate sign-in**. Complete the trusted provider flow in the same browser. Normal protocol, assurance and admission validation applies. The test writes only revision-bound readiness evidence, without account, link, profile or privilege changes and without replacing the operator's local session.
4. Approve account links using the headless command below, or explicitly opt into provisioning with the documented least privilege target. Enable ordinary SSO through an atomic deployment JSON update. Changing origin, issuer, keys, callbacks, metadata, admission, assurance or account settings invalidates readiness and pending transactions. Existing evidence is never reused for another revision.
5. Run the local recovery acceptance procedure before allowing ordinary users to rely on SSO. A failed check/test is a release gate, not a reason to disable TLS or protocol checks.

Use `php console soca:manage link 'https://auth.resoauth.cloud' 'exact-validated-subject' 'local-user-id' 'approval-ticket-reference'` for audited administrator approval. The issuer must equal the configured issuer. This is privileged deployment access, so record the approving operator and ticket in the deployment audit system. Email alone never selects or links an account. Use `unlink` with the same issuer, subject, user-ID placeholder and reason arguments for recovery. Links store only a SHA-256 issuer/subject identifier and a local account ID. Subject changes or pairwise client-ID changes need explicit recovery, with unlink/relink and a new audit approval.

Proxy JSON uses recursively sorted object keys, compact UTF-8 JSON and unpadded base64url encoding. The public payload is limited to 6144 bytes and the complete client-ID URL to 8192 bytes; transport responses are separately bounded. Proxy URLs disclose their full public metadata to the proxy and provider. Inline-key proxy rollover changes the client ID, consent and potentially pairwise subject. This candidate has no automatic rotation, overlapping-key publication or migration wizard; keep the key stable and plan an explicit identity migration before replacing it. Document checks reject changed or redirected metadata.
