# IRIS CLI

The IRIS command-line tool for local policy development, agent
registration, and evidence inspection. Pairs with the iris-sdk Python
packages, or stands alone for CI/CD policy validation.

```bash
pip install iris-security-cli
iris org-policy validate
```

Full documentation: **https://iris-security.github.io/iris-sdk/cli-reference.html**

## GitHub Action: IRIS Agent Flight Recorder

Put a flight recorder on every pull request. The Action in this repository
finds AI agents and AI calls IRIS does not govern, flags AI supply chain
risks, and threat models each agent against the OWASP LLM and Agentic
Top 10. It runs offline with the open source CLI; no account required.

```yaml
- uses: actions/checkout@v4
- uses: IRIS-Security/iris-cli@v1
  with:
    fail-on: high
```

The earlier compliance check is still available:

```yaml
- uses: IRIS-Security/iris-cli@v1
  with:
    command: compliance scan
    fail-on: blocker
```

See **https://iris-security.github.io/iris-sdk/github-action.html** for inputs and fail-on thresholds.
IRIS's own public repos run this check on every pull request.

Scale to team-wide governance, centralized evidence, and enterprise
SSO with IRIS Cloud → [iris-security.io](https://iris-security.io)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, tests, and the
OSS/Cloud scope boundary. Please read
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) too.

## License

Apache 2.0 — see LICENSE.
