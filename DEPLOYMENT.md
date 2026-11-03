# Deployment and reproduction

## Live Studionet instance

- Network: Studionet, chain ID **61999** (test environment; resets are possible).
- Contract: `0x217b9BC1B62c47443e441D40EDCE1Cd799A195fE`
- [Contract explorer](https://explorer-studio.genlayer.com/address/0x217b9BC1B62c47443e441D40EDCE1Cd799A195fE)
- [Deployment transaction](https://explorer-studio.genlayer.com/tx/0xb88f470e36c1d8b1307e563b92029efe0f41b1105ffb86e4eb01dc77b39d0297)
- Deployment finalized with successful execution and majority agreement. `leader_only` was false. Two quorum-cancelled validator slots were idle, not affirmative votes; inspect `deployments/studionet.json` for actual votes.
- [Deployed source](https://github.com/ANZA24k/ChangeGate/blob/44cd5ba1257c545ba4ac1eea42ddc9c8b6bc15f9/contracts/change_gate.py). The contract dependency header is pinned; later documentation commits do not alter the deployed code.

The explorer is a navigation convenience. The RPC receipt and read-back state are the evidence of execution. A finalized transaction can still have failed execution; always check both fields.

## Observed live evaluation

A synthetic fully documented fixture produced **COMPLIANT** with four supported semantic controls and no deterministic failures. The evaluation finalized successfully with native consensus enabled, and `get_receipt` returned the persisted receipt. Its decision and receipt hashes were recomputed locally and matched.

- [Evaluation transaction](https://explorer-studio.genlayer.com/tx/0x7c1972bc4bfd2693390077417e6f1f48961de292c7c8bec3311e6aaf564d1d7d)
- Full manifest, IDs, quotations, reasons, transaction status and votes: `deployments/live-compliant.json`.

Verify the exported commitments with:

```sh
python scripts/verify_receipt.py deployments/live-compliant.json
```

A second synthetic fixture with change-manager approval after deployment produced **VIOLATION**. The deterministic finding was `APPROVAL_SEQUENCE:change_manager`; independent AI findings also marked the approvals control `BREACH`. The evaluation finalized successfully with majority agreement and no leader rotation.

- [Violation evaluation transaction](https://explorer-studio.genlayer.com/tx/0xfed97ffada91a30df4022e57cb6536c0a5a55b3e0edc91d921b4763aca7d9d35)
- Full evidence and stored receipt: `deployments/live-violation.json`.

Both live evaluation reports have valid recomputed decision/receipt hashes. Six contract transactions in total (deployment, policy, two submissions and two evaluations) finalized with successful leader execution. Quorum-cancelled validators are not counted as successful executions or agreeing votes.

Synthetic input is self-attested demonstration data, not a verified organizational release.

## Deploy your own instance

Use a fresh test account and the official GenLayer CLI:

```sh
genlayer deploy --contract contracts/change_gate.py --rpc https://studio.genlayer.com/api
```

Alternatively use `genlayer_py.create_client(chain=studionet, account=account).deploy_contract(code=source, args=[])`. Wait for `FINALIZED` and confirm the leader execution result is `SUCCESS`; save the contract address and deployment transaction. Never use `leader_only=True` as evidence of consensus.

## Run the synthetic live demonstration

Install `requirements-dev.txt`, publish the fixtures and use their full commit SHA. Supply your own disposable Studionet key through a file outside the repository:

```sh
export CHANGEGATE_KEY_FILE=/absolute/path/to/disposable-studionet.key
python scripts/live_demo.py --address YOUR_CONTRACT_ADDRESS --commit FIXTURE_COMMIT_SHA --variant compliant
python scripts/live_demo.py --address YOUR_CONTRACT_ADDRESS --commit FIXTURE_COMMIT_SHA --variant violation
```

Available variants: `compliant`, `violation`, `ambiguous`, `injection`. The script records transactions before waiting, supports resuming a recorded run, verifies execution success and reads the actual receipt back from contract storage. The evidence manifest and public results are saved in `deployments/live-VARIANT.json`. Archive or remove that report before intentionally starting a different deployment/run with the same variant.

`fund_account` on the hosted Studio RPC was available for the initial disposable test signer. Network faucet behavior can change; deployment does not require an existing personal wallet or real tokens. No private key is part of this repository.

## Verification limits

Local tests mock external I/O and consensus transport. GenVM lint, schema extraction and SDK validation confirm loadability and ABI compatibility, not semantic correctness or network availability. A live synthetic verdict demonstrates the workflow on that input only. Review all stored attempts and findings, not merely a transaction's status or a chosen favorable verdict.
