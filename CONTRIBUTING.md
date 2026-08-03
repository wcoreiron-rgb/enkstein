# Contributing to Enkstein

Thanks for looking. Enkstein is early-preview software built mostly by one
person, so the most valuable contribution right now is **telling me what did not
make sense** — not necessarily code.

## The most useful thing you can do

Install it, try one workflow, and open an issue describing where you got stuck
or what you expected to happen instead. Blunt feedback about confusing naming,
unclear screens, or a workflow that did not pay off is more useful than a patch.

## Running it locally

```bash
git clone https://github.com/wcoreiron-rgb/enkstein.git
cd enkstein
docker compose up --build
```

The UI comes up at `http://localhost:3000` and the API at
`http://localhost:8000/docs`. Docker Desktop and about 4 GB of RAM are required.
See [installation](docs/installation.md) for the packaged path.

## Before you open a pull request

Run the checks for whatever you touched:

```bash
cd backend  && pytest                    # backend
cd frontend && npm run lint && npm run build
python -m pytest packaging/tests/        # packaging and installers
```

Then:

- Keep the diff scoped to the change. Unrelated refactors and formatting churn
  make review slow.
- Follow the patterns already in the file you are editing rather than
  introducing a new abstraction.
- Add tests when the change touches shared behavior or a security boundary.
- Explain what changed, why, and how you verified it.

## Security-sensitive changes

Anything that touches model routing, connectors, tool execution, remediation, or
tenant scoping must keep its Trust Fabric decision. A code path that reaches a
model or executes an action without a policy evaluation will not be merged, even
if it is faster.

Never log raw secrets, tokens, or tenant payloads. Cross-tenant data mixing is
treated as a critical bug.

Found a vulnerability? Do not open a PR for it — see [SECURITY.md](SECURITY.md).

## What I am unlikely to merge

- New connectors before the existing ones are genuinely reliable.
- Large architectural rewrites proposed without a discussion issue first.
- Additional model providers where the point is breadth rather than a real gap.

The project's problem is focus, not surface area. Changes that make one existing
workflow work better are much more welcome than new ones.

## License

Contributions are MIT-licensed, matching the project.
