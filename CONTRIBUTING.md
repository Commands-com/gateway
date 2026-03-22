# Contributing

Thanks for helping improve the Commands.com OSS gateway.

This repository is for the self-hosted gateway, its deployment/docs, and the tooling needed to run and validate it. The goal is to keep the project easy to audit, easy to self-host, and easy to extend without hidden infrastructure requirements.

## What Belongs Here

Good fits for this repo:

- Gateway features, bug fixes, and hardening work
- OAuth, relay, tunnel, or console improvements
- Deployment and local-development tooling
- Documentation that helps people run, verify, or self-host the gateway
- Tests that improve confidence in security-sensitive behavior

Usually not a fit:

- Changes that belong only in a closed-source app repo
- Undocumented breaking changes to public behavior or environment variables
- New operational dependencies without a strong reason
- Large refactors without matching test and docs updates

## Ground Rules

Please keep contributions self-contained, reviewable, and honest about tradeoffs.

- Prefer simple operational behavior over clever infrastructure.
- Preserve the zero-external-dependency spirit unless there is a strong reason not to.
- Keep security-sensitive changes narrow and well-tested.
- Document new environment variables, endpoints, and deployment assumptions.
- Do not weaken auth, encryption, replay protection, or tunnel safeguards without a matching rationale and docs update.

## Development

Typical local setup:

```bash
cp .env.example .env
go test ./...
go run ./cmd/server
```

Useful checks:

```bash
go test ./...
go vet ./...
```

If you change formatting-sensitive Go files, run `gofmt` before opening a PR.

## Required Documentation

Every contribution should make its operational impact obvious.

- If you add environment variables, document them in the README and/or config docs.
- If you change HTTP behavior, update the OpenAPI spec when needed.
- If you change deployment assumptions, update Railway or local-run docs.
- If a change affects security posture, call that out explicitly in the PR.

## Testing Expectations

This project handles auth, sessions, encryption, and public ingress, so tests matter.

- Add or update tests for non-trivial behavior changes.
- Prefer targeted unit/integration tests over manual-only validation.
- Include the commands you ran in the PR description.
- If a change is hard to test automatically, explain what you validated manually and why.

## PR Checklist

Please aim to include:

- A short explanation of what changed and why
- Any new environment variables or migration notes
- Tests/validation you ran
- Docs updates when behavior or operations changed
- Security notes when auth, relay, or ingress behavior changed

## Compatibility Expectations

Keep self-hosters and downstream clients in mind.

- Avoid unnecessary breaking changes.
- If you change public endpoints or request/response shapes, update `docs/openapi.yaml`.
- If you change auth or token behavior, document client impact clearly.
- Keep demo/local-dev flows working unless there is a strong reason not to.

## Security

This repo handles public ingress and encrypted relay behavior. Please be especially careful around:

- OAuth/OIDC flows
- token issuance and validation
- replay protection and sequencing
- WebSocket/tunnel authentication
- CORS and public ingress limits
- share/grant authorization boundaries

If you find a sensitive issue that should not be disclosed publicly first, please open a private channel with the maintainers instead of posting a public exploit.

## Questions

If a change is large, security-sensitive, or likely to affect compatibility, open an issue or draft PR first so the shape can be aligned before too much code lands.
