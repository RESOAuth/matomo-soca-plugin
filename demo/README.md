# Disposable Matomo HTTPS demo

Run `./demo/run.sh` from a reviewed checkout with Podman (default), Python 3, OpenSSL and an available network. Use `CONTAINER_ENGINE=docker` for Docker. The script builds a native host image from pinned upstream digests, generates unique credentials outside the source/public tree and binds its HTTPS listener to loopback.

The default URL is `https://analytics.soca.localhost:8093`. `.localhost` is resolved by current browsers; an explicit local hosts entry may be needed in other clients. Trust the generated development certificate explicitly, or use curl `--cacert PATH/server.crt --resolve analytics.soca.localhost:8093:127.0.0.1`. Do not disable TLS verification. The script prints the private secrets directory and password file location, never their content. Local administrator: `localadmin`. SSO stays disabled and provisioning stays opt-in.

Set `SOCA_DEMO_NAME`, `SOCA_DEMO_PORT` and `SOCA_DEMO_SECRETS` to avoid collisions. A secrets directory containing a configuration is preserved and a new initialisation refuses to overwrite it. Use the documented deployment JSON process for subsequent changes. Individual files are mounted read-only into `/run/soca`; the host directory remains mode 0700. No signing key is copied into the image or public web root.

The generated candidate uses proxy metadata with inline public keys so that the provider can resolve public metadata while callbacks terminate on local HTTPS. The proxy sees only public metadata. Its actual provider compatibility and callback-origin restrictions must pass a real candidate test. No mock-network, private-address fetch allowance or TLS bypass exists in the production adapter. If the host has rootless network DNS restrictions, supply an approved network/DNS configuration for issuer and proxy egress; the build uses host networking only to obtain pinned dependencies.

Use **Administration → System → SOCA sign-in** to inspect locked effective configuration, check documents and initiate an operator-bound candidate test. The `php console soca:manage status` command reports document and actual test-login evidence separately. See [configuration](../docs/configuration.md) for activation, account links and key migration constraints.

Native fixture command:

```sh
podman exec -u www-data -e SOCA_NATIVE_TESTS=1 soca-matomo-demo php plugins/Soca/tests/native.php
```

The fixture creates and removes local test accounts, links and privileges. Use a disposable host only. Recorded evidence was obtained against **Matomo 5.14.0, MariaDB 11.4 and PHP 8.4.26**, with **11 native assertions**, plus **129 protocol assertions** and **35 bridge assertions where pcntl is present**. Actual HTTPS metadata/JWKS and disabled-login routes were also checked using an explicitly trusted local certificate. Neither document smoke tests nor fixture logins count as dated live-provider sign-in.

Stop the containers with `podman stop soca-matomo-demo` and `podman stop soca-matomo-demo-db`. Remove them only when their disposable data is no longer needed; delete the printed secrets directory deliberately. Native databases and keys must be backed up together if you choose to retain the demo. Containers and volumes are not automatically deleted or overwritten by the launcher.
