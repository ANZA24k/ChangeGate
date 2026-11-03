# Security model

## Implemented controls

- Immutable owner-scoped policies and claims; only the original registrant can submit and evaluate. No caller-supplied verdict, admin override, funds or arbitrary external calls.
- Full commit-pinned trusted-repository evidence, byte-exact SHA-256, strict schema and subject/environment/policy binding.
- Approval cardinality, explicit authorized identities, separation of duties, same-artifact approvals, strict sequencing, pre-deployment tests and bounded window.
- Data-only prompts; no evidence-defined tools or URLs; fixed four-control output with exact narrative quotes and independent validator assessments. Validators reject non-return values, malformed proposals, ungrounded quotes and mismatched substantive decisions.
- Three persisted evaluations per claim, append-only receipts and domain-bound hash chains. Unknown/invalid AI output never creates compliance. Integrity failures never establish violations.

## Assumptions and residual risk

The policy owner and repository publisher are trust roots. Hash pinning proves consistency with a commitment, not authenticity of identities or correctness of source exports. No signature verification, protected-branch enforcement, independent ticket-service integration or anti-backdating guarantee is provided. Registration may be retrospective. User-selected policy criteria may be weak. Inspect the actual policy and all attempts before relying on a result.

LLMs can misunderstand policy, accept prompt injection, hallucinate or agree incorrectly. Substring grounding is not proof of factual truth or contextual sufficiency. Independent assessments reduce but do not eliminate correlated model failure. Availability, latency, response size and consensus liveness depend on GenLayer's host/network. Oversized responses are rejected after download; host-level resource caps must be maintained.

All state and evidence are public. Use synthetic or redacted exports. Never commit real secrets, customer details or access tokens. No private API credentials are embedded in the contract. The demo signer is a newly generated disposable Studionet identity, not an imported funded wallet; its key is not committed.

No external audit has been performed. Report issues using a repository issue with a sanitized reproducer; do not include secrets.
