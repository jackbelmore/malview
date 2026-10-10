# Design notes

These are the planning documents written while building malview. They are kept
as a record of how the tool was specified, not as a description of what it does
today.

- `ARCHITECTURE.md`: the original spec for the PE analyser (hybrid fast/slow
  engine, data model, TUI layout). This part is implemented.
- `PLAN_EXPANSION.md`, `DESIGN_INTEGRATION.md`: a planned "Sentry" expansion
  (HTTP security-header checks and NVD CVE lookup). **Not implemented.** The
  empty stub modules were removed from the package; see the main README's
  roadmap.
