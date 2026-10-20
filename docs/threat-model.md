# Threat model, version 0.1.0

The protected surface is Matomo browser viewers for one explicitly configured analytics site, excluding administrators and superusers. The trusted computing base consists of the host security/session APIs, shared host database, deployment file/secret mounts, PHP/OpenSSL, the pinned maintained JWT library, the explicitly trusted issuer and the operators who control those systems. Host compromise, a malicious trusted issuer or stolen local administrator credentials can defeat the integration.

| Threat | Implemented control | Remaining acceptance work |
| --- | --- | --- |
| Login CSRF, copied callback, replay, parallel tabs | Independent random state/nonce/verifier; native browser session binding; encrypted server session snapshots; atomic shared database consumption; five-minute expiry. | Browser automation and native multi-worker fault tests. |
| Issuer mix-up or token substitution | Exact configured issuer, callback response `iss`, signature/key type/algorithm, audience/azp, nonce/time/conditional hashes and matching UserInfo subject. | Independent OIDC conformance and hostile-network review. |
| Email reuse or account takeover by email | Unique issuer/subject hash links; no email matching; privileged CLI approval or opt-in provisioning; native eligibility on login. | Reauthentication self-linking, lifecycle migration UI and wider races. |
| Privilege escalation | Protected administrative users excluded; explicit least privilege provisioning target; no implicit claim-to-role mapping. | Allowlisted mappings with ceilings and independent elevation approval. |
| SSRF or metadata poisoning | HTTPS/TLS validation, DNS answer screening and address pinning, no redirects, exact public-document equality, response bounds. | DNS resolver deadline, IPv6/mixed-answer live cases and independent transport assessment. |
| Private data leakage | Deployment secret references, public-only JWKS/metadata, sealed native-session transactions, discarded external tokens, redacted errors and query-free demo logs. | Production proxy/CDN log review, access/audit retention and encrypted backup drills. |
| Stale configuration or emergency lockout | Revision-bound document/test evidence, deployment precedence, fail-closed emergency switch, preserved local administrator login. | Key rotation, restoration/revocation race tests, signed release and full accessibility checks. |

Keep the signing key stable until automated rotation and controlled client-ID migration are implemented. Do not enable disabled algorithms, accept private-address metadata fetches or switch off TLS validation to make a demo succeed. Synthetic provider injection exists only in the test files; production host adapters instantiate the strict transport.
