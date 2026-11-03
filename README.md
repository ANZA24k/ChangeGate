# ChangeGate

**IT change-management compliance verification on GenLayer.** A standalone Intelligent Contract; no frontend or off-chain verdict server is required.

ChangeGate locks an organization's policy, binds a change to a byte-exact evidence bundle and evaluates production release governance. Deterministic checks enforce deployment windows, approved identities, separation of duties, approval sequence, artifact identity, testing and rollback flags. GenLayer leaders and validators independently retrieve and review evidence for meaningful authorization scope, adequate testing and usable rollback procedures.

## Outcomes

| Outcome | Rule |
| --- | --- |
| `COMPLIANT` | Every semantic control is supported and no deterministic violation exists. |
| `CONDITIONAL` | At least one documented noncritical gap, no unknown control or violation. |
| `VIOLATION` | A verified deterministic violation or independently agreed semantic breach. |
| `INCONCLUSIVE` | Evidence is unavailable/invalid, AI output is invalid, or any control is unknown without a verified violation. |

Violations take precedence over unknowns **only after** evidence passes byte, hash, schema and identity checks. An integrity failure cannot establish either compliance or a violation. Validator disagreement is rejected by the protocol; it does not produce a local fallback approval.

## Workflow

1. `register_policy(policy_json)` returns a content-addressed owner-bound policy ID. Policy JSON is immutable; amendments require a new ID.
2. Publish an evidence JSON bundle in the policy's trusted GitHub repository. Include `policy_hash = SHA256(canonical(policy))`.
3. `submit_change(policy_id, manifest_json)` locks its change ID, artifact, full commit-pinned raw URL, SHA-256 and byte length. Only the policy registrant can submit or evaluate changes.
4. `evaluate_change(claim_id)` runs native `gl.vm.run_nondet_unsafe`. Each validator fetches the evidence independently and runs its own AI audit. Decision-critical statuses, deterministic findings and errors must match; prose may differ. Proposed quotes are separately checked against the exact evidence.
5. Read immutable receipts with `get_receipt(claim_id, attempt)`. Each claim has at most three persisted evaluations. History retains unfavorable attempts; there is no delete, replace, automatic certification or approval action.

`get_policy`, `get_change` and `get_status` complete the seven-method API. [ABI](docs/abi.json).

## Quick start

Python 3.12 or newer:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
genvm-lint check contracts/change_gate.py
genvm-lint schema contracts/change_gate.py --output docs/abi.json
```

The 38 tests load the actual pinned GenVM SDK and contract module, with in-memory lifecycle state and mocked web, AI and consensus transport. They are local tests, **not** evidence of live multi-validator agreement. They cover tampering, unsafe URLs, JSON ambiguity, approvals, verdict precedence, independent disagreement, ownership and hash-linked history.

Synthetic fixtures include a fully documented change, post-deployment approval violation, ambiguous test coverage and a prompt-injection attack. Regenerate them with `python scripts/make_fixtures.py`. [Evidence format](EVIDENCE.md), [deployment](DEPLOYMENT.md), [security model](SECURITY.md), [submission notes](SUBMISSION.md).

## Trust and scope

This is an audit primitive, not a deployment gateway or a legal compliance certification. A content hash authenticates bytes relative to the submitted commitment, not the truth of a ticket, named approver or log. The registrant chooses the trusted evidence repository and is responsible for its provenance, access controls, exports and attestations. The demo does not verify Jira identities, GitHub signatures or cryptographic approver signatures. A malicious organization can author convincing false records; GenLayer consensus cannot prove those records describe real events.

Policy registration is an on-chain immutable commitment, but the contract supports retrospective auditing and does not prove the policy existed before the historical deployment. Public evidence must be sanitized; never publish private tickets, secrets or production credentials. No funds are handled. There is no upgrade or admin override.

## Official references

Implementation checked against current official documentation on 2026-11-03:

- [Equivalence Principle and independent verification](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
- [Web access](https://docs.genlayer.com/developers/intelligent-contracts/features/web-access)
- [LLM calls](https://docs.genlayer.com/developers/intelligent-contracts/features/calling-llms)
- [GenVM linter](https://docs.genlayer.com/api-references/genlayer-linter)
- [Network configuration](https://docs.genlayer.com/developers/intelligent-contracts/deploying/network-configuration)

The dependency header pins the actual SDK used for validation. The pinned SDK's HTTP response field is `status`, even though some higher-level documentation examples use `status_code`.
