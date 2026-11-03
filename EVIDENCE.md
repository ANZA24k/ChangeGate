# Evidence protocol v1

## Canonicalization and commitments

Canonical JSON is Python `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`, UTF-8 encoded. Only integer numbers are permitted in input JSON; duplicate keys, NaN, infinity and floats are rejected. Policy ID hashes `{owner, policy}`. Policy hash hashes the policy alone. Claim ID hashes `{policy_id, manifest}`. Decision hash hashes the decision object. Receipt hash hashes the receipt including `decision_hash` but excluding `receipt_hash`. Receipts bind contract address, chain ID, claim and policy IDs, evidence SHA-256, attempt and previous hash. Genesis previous hash is 64 zeroes. All SHA-256 digests are lowercase hex without `0x`.

The evidence digest hashes **original file bytes**, not reserialized JSON. Newlines and whitespace matter.

## Policy

See `fixtures/policy.json`. Required fields:

- `organization`, `repository` (`owner/repo`), `environment`.
- `window_start`, `window_end`: integer Unix UTC seconds, start inclusive and end exclusive; maximum 4102444800 (2100-01-01).
- `approval_roles`: ordered unique role names, 1–8. Strictly increasing approval timestamps are required; equal timestamps do not prove an ordering.
- `approvers`: one to eight exact case-sensitive identities per role; identities cannot occur in multiple roles.
- `criteria`: exactly `scope`, `approvals`, `testing`, `rollback`, each a 1–1200 character requirement. Policy text is data, never permission to change verifier behavior.

Policy input is limited to 12000 UTF-8 bytes. The approved deployment window is a one-off absolute window, not a timezone-dependent recurring schedule. All tests and approvals must precede deployment; this version does not require tests to precede approvals. Missing, duplicate or unexpected role records are violations, not silently ignored entries. Deployer cannot approve their own change.

## Manifest

Exactly `change_id`, `artifact`, `url`, `sha256`, `bytes`, limited to 3000 input bytes. URL must have the form:

```
https://raw.githubusercontent.com/OWNER/REPO/FULL_40_CHARACTER_LOWERCASE_COMMIT_SHA/path.json
```

Repository must exactly match the locked policy. Branches, query strings, credentials, arbitrary hosts, encoded path characters and dot traversal are rejected. Evidence must contain 2–24000 bytes. Download status must be 200; no HTML rendering, link following, archive extraction, tool execution or AI-directed fetches occur. The SDK/host may handle HTTP redirects internally; any returned content must still pass byte and hash checks. Application size bounds are checked **after** the SDK request returns; this does not impose a streaming transport cap or independent HTTP timeout. Host resource limits remain necessary.

Use `python scripts/manifest.py fixtures/compliant.json COMMIT_SHA` after publishing the fixture. Never substitute a branch name for the commit.

## Bundle

See the synthetic fixtures. Required fields are enforced exactly: `change_id`, `artifact`, `environment`, `policy_hash`, `deployer`, `deployed_at`, `approvals`, `tests_passed`, `test_completed_at`, `rollback_ready`, `narratives`. Booleans cannot be integers. Approval entries contain `role`, `identity`, `at`, `artifact`. At most 16 entries. Narratives must contain the four control names and 1–3200 characters each.

Bundle identity, artifact, environment and policy digest must match the locked claim and policy. Times and flags are deterministic assertions from the trusted export; the contract cannot independently prove their real-world truth. Preserve source record identifiers and original exported records within the narratives so an auditor can trace them externally. Authenticity is an organizational trust assumption, not a cryptographic feature of this version.

## AI findings

For each control: `status` (`SUPPORTED`, `GAP`, `BREACH`, `UNKNOWN`), `quote` (12–400 characters exactly present in that control's narrative), and `reason` (1–600 characters). No aliases, coerced types or repaired malformed outputs. JSON string responses are parsed strictly; JSON objects are accepted directly. One LLM call per assessment, no hidden corrective retries. A validator performs its own assessment, matches all four statuses, and separately grounds proposed quotations. Quotation substring checks establish occurrence; semantic relevance relies on independent AI judgment and can still be wrong.

Evidence is immutable per claim. Corrected evidence creates a new claim. A maximum of three evaluations per claim limits persisted retries; rejected/rolled-back chain transactions do not consume a persisted slot and cannot be counted by contract state. This is not a global anti-spam or real-world change uniqueness registry.
