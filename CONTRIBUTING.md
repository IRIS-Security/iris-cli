# Contributing to IRIS CLI

## Scope

This repo is the open-source `iris` command-line tool and its GitHub
Action — local policy compile/validate/scan/witness commands, and the
composite Action that wraps them for CI. Cloud push (`--api-key`,
hosted evidence, org reporting) calls out to IRIS Cloud, but the
client-side code that does the calling is what's open here.

## Development setup

```bash
git clone https://github.com/IRIS-Security/iris-cli
cd iris-cli
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest pytest-asyncio
```

## Running tests

```bash
pytest tests/ -v
```

## Submitting a change

1. Fork the repo and branch off `main`.
2. Add tests for new commands/flags.
3. `pytest tests/` must pass.
4. Open a PR — the IRIS Governance Action runs on your diff
   automatically.

Commit messages: `<type>(<scope>): <description>`.

## GitHub Action changes

If you change `action.yml` or its runtime behavior, test it against a
throwaway repo before opening a PR — Action changes affect every repo
that consumes `IRIS-Security/iris-cli@main`.

## Reporting bugs / requesting features

Use the issue templates. For security vulnerabilities, see
[SECURITY.md](SECURITY.md) — please don't file a public issue.

## License

By contributing, you agree your contribution is licensed under
Apache 2.0, the same license as this repository.
