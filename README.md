# IRIS CLI

The IRIS command-line tool for local policy development, agent
registration, and evidence inspection. Pairs with the iris-sdk Python
packages, or stands alone for CI/CD policy validation.

```bash
pip install iris-security-cli
iris org-policy validate
```

Full documentation: **https://iris-security.github.io/iris-sdk/cli-reference.html**

## GitHub Action

Add AI governance to any repo's CI with the composite Action in this
repository (offline/OSS by default — no cloud account required):

```yaml
- uses: IRIS-Security/iris-cli@v1
  with:
    command: compliance scan
    fail-on: blocker
```

Optional cloud push (requires IRIS Cloud API key + entitlement):

```yaml
- uses: IRIS-Security/iris-cli@v1
  with:
    command: compliance scan
    fail-on: blocker
    api-key: ${{ secrets.IRIS_API_KEY }}
```

See **https://iris-security.github.io/iris-sdk/github-action.html** for inputs and fail-on thresholds.
IRIS's own public repos run this check on every pull request.

Scale to team-wide governance, centralized evidence, and enterprise
SSO with IRIS Cloud → [iris-security.io](https://iris-security.io)

## License

Apache 2.0 — see LICENSE.
