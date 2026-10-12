# AGENTS.md

README.md is the spec; keep it exact when behaviour changes. The design is secrets-tokens-design.md (rev 3) in slicc-agent-plan.

- Only `forward` (by an accepted rule) may hand a value to the page; nothing ever reaches the agent role or the model.
- No third-party runtime JS in src/: CSS-only Spectrum 2, own code only.
- No comments in any file. Only README.md and AGENTS.md as docs.
- Unit tests live in the gitignored test/unit/ and must cover every changed line of src/ (`npm run test:unit`).
- Integration tests in test/integration/ run the built vault on *.sliccy.localhost; every behaviour needs one (`npm test`).
- `npm run lint` and `npm run build` must pass. Conventional commits.
