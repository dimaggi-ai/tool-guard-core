# Repository agent rules


## Editorial quality gate (hard rule)

Reader-facing English prose MUST pass an editorial review before it is treated as final or publish-ready. This includes website and product copy, articles, release notes, announcements, README and documentation prose, UI onboarding/help/error text, narrative reports, and material rewrites.

Required sequence:

1. Draft from verified facts and keep the source meaning intact.
2. Edit for clarity, specificity, consistent terminology, and an appropriate tone.
3. Recheck every fact, number, quotation, product name, command, and link after editing.
4. In the handoff, report `Editorial review: passed — <files>` or `Editorial review: not applicable — code-only change`.

Reviewers MUST treat missing editorial-review evidence as blocking when changed prose is in scope.

Never invent metrics, quotations, customers, anecdotes, personal experience, or certainty during editing. Style may change; facts may not.

This gate does not apply to executable code, identifiers, machine-readable schemas or protocols, generated files, literal quotations, or legal/regulatory text that must remain exact. Code comments need technical clarity, not marketing treatment.

If editorial review cannot be completed, stop before merge, publish, or deploy and request review. Do not silently skip the gate.
