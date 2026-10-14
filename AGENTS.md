# AGENTS.md

README.md is the spec; keep it exact. The design is secrets-tokens-design.md (rev 4) in slicc-agent-plan.

- Only `forward` (by a rule), `materializeConsume` (by an `[exec]` grant) and `egress` (a refresh) may hand a value to the page. On the agent port only `model` and `mcp` may, in the prepared request's head for that provider's or server's own URLs, for immediate sending; never logged, stored, retried from storage or shown. Nothing else on the agent port carries one, and no value ever reaches the model.
- No third-party runtime JS in src/: CSS-only Spectrum 2; only certified ai-ecoverse packages, exact-pinned and bundled.
- No comments in any file. Only README.md and AGENTS.md as docs.
- Unit tests (gitignored test/unit/) cover every changed line of src/ (`npm run test:unit`).
- Integration tests (test/integration/, built vault on *.sliccy.localhost): one per behaviour (`npm test`).
- `npm run lint` and `npm run build` must pass. Conventional commits.
