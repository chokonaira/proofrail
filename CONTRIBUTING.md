# Contributing

PermitRail is early, but the contribution rules are intentionally strict because
the project is security-sensitive.

## Contribution Requirements

- Keep changes small and reviewable.
- Add tests for security behavior and policy decisions.
- Use pull requests for changes to `main`.
- Keep CI green before merge.
- Do not add dependencies without a short design note explaining why they are
  necessary and how they affect the threat model.
- Do not log secrets, raw identity documents, access tokens, private keys, or
  personal data.
- Preserve attribution and notices.

## Developer Certificate of Origin

Contributions use the Developer Certificate of Origin (DCO). Add a sign-off to
every commit:

```bash
git commit -s -m "Add policy evaluator"
```

The sign-off means you certify that you have the right to submit the work under
the project license.

## Design Notes

For major changes, include a short design note in `docs/design/` covering:

- problem
- proposed API
- security impact
- alternatives considered
- migration risk

## Security Review Checklist

Before opening a PR, check:

- Does this widen what an agent can do without proof?
- Can a prompt injection influence policy decisions?
- Can a proof be replayed for a different action or audience?
- Are action inputs hashed into receipts where useful?
- Are errors safe and non-leaky?

## Releasing

Releases use [Changesets](https://github.com/changesets/changesets). When a pull
request changes a published package, add a changeset describing the bump:

```bash
npx changeset
```

On merge to `main`, a "Version Packages" pull request opens with the version bumps
and changelog entries. Merging that pull request publishes only the changed
packages to npm with provenance. Unchanged packages are left as they are.
