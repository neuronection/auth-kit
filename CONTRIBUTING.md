# Contributing

Thanks for contributing to Neuronection Auth Kit — the family identity
& authentication library.

## Ground rules

1. **Never commit untested code.** Run the verification gate
   (`./scripts/verify.sh` — ruff + mypy strict + pytest) before every
   commit; tests for new behavior land in the same commit.
2. **Docs ship with code.** Behavior/schema/API changes update docs and
   `CHANGELOG.md` (`## [Unreleased]`) in the same commit.
3. **Docstrings on public APIs** (Google-style); inline comments only
   for non-obvious *why* (security rationale, subtle invariants).
4. **Secrets stay out.** `.env` is gitignored; never commit keys or
   tokens. Test keys come from `nx_auth.testing` — never real ones.
5. **Auth behavior changes are contract changes.** Observable behavior
   (claims, lifetimes, cookie names/flags, status codes, endpoint
   shapes) updates the contract docs in the same commit; new token
   kinds/claims need a written contract proposal first.

## Development setup

```bash
git clone https://github.com/neuronection/auth-kit && cd auth-kit
uv venv .venv && uv pip install -e ".[dev]"   # or: pip install -e ".[dev]"
./scripts/verify.sh                            # the gate CI runs
```

Python ≥ 3.11. The test suite is self-contained (in-memory SQLite,
fixed test keys) — no external services needed.

## Pull requests

- One logical change per PR; verification gate green in CI.
- User-visible changes include a changelog entry.
- Security-sensitive changes (crypto, token handling, cookie flags,
  enforcement order) call out the threat-model impact in the PR
  description and add negative tests.
