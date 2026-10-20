# SOCA for Matomo

An installable SOCA OpenID Connect and CIMD integration for Matomo browser viewers for one explicitly configured analytics site, excluding administrators and superusers. Version 0.1.0 is an alpha review candidate. It uses authorisation code flow, mandatory S256 PKCE and ES256 `private_key_jwt`, with explicit issuer/subject account links.

Ordinary SSO and account creation start disabled. Public document checks and an operator-bound candidate test must pass for the current configuration before ordinary sign-in is admitted. Existing local administrator authentication remains available.

1. Run `composer install --no-dev --prefer-dist` in this checkout.
2. Copy the plugin, including `vendor/`, into the Matomo `plugins/Soca` directory. Keep deployment JSON and keys outside the web root.
3. Set `SOCA_CONFIG_FILE` in the PHP worker environment and run `php console plugin:activate Soca`. The native plugin install hook creates InnoDB link, replay and evidence tables.
4. Configure one existing website ID. The native login navigation gains a SOCA link; the ordinary Matomo password form remains available.

Start with [config.example.json](config.example.json), then follow [configuration and activation](docs/configuration.md). The native settings page is **Administration → System → SOCA sign-in**. Every setting is deployment managed and the GUI shows redacted, read-only effective values.

Run `demo/run.sh` for a disposable HTTPS host, or follow [the demo guide](demo/README.md). Run `composer install` and `composer test` for the 129-assertion protocol suite and host coordination tests. The [dated verification record](docs/verification.md) separates synthetic protocol results, actual host tests and outstanding real-provider logins. The [requirements assessment](docs/requirements.md) covers every F-01–F-25 and N-01–N-09 requirement and its remaining gap.

See [operations and recovery](docs/operations.md), [the threat model](docs/threat-model.md), [security reporting](SECURITY.md) and [the AGPL-3.0 licence](LICENSE). Do not roll this candidate into production before completing the documented live-provider, browser, accessibility and independent security acceptance gates.
