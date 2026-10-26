# Security Policy

## Supported versions

IRIS is pre-1.0 (Alpha). Security fixes are made against the latest
release published on PyPI / the Terraform Registry — please upgrade
before reporting an issue that might already be fixed.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security
vulnerabilities.

- **Preferred:** use GitHub's private vulnerability reporting for this
  repository — go to the **Security** tab → **Report a vulnerability**.
- **Alternative:** email **security@iris-security.io** with a
  description, reproduction steps, and an impact assessment.

We will acknowledge your report within 48 hours and aim to share a fix
or mitigation timeline within 7 days. Please give us a reasonable
window to ship a fix before any public disclosure.

## Scope

This repository ships local-enforcement code: policy decisions are
evaluated on your own infrastructure with no required network calls.
Vulnerabilities in IRIS Cloud (the hosted platform) are out of scope
for this repo but should be reported to the same address —
security@iris-security.io — and will be triaged separately.
