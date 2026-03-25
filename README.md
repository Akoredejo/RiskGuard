# RiskGuard: Automated Risk Assessment for Smart Contracts

## Table of Contents
* Introduction
* Key Features
* System Architecture
* Contract Constants
* Error Codes Reference
* Data Schema
* Function Reference
    * Private Functions
    * Public Functions
    * Read-Only Functions
* Governance and Security
* Installation and Deployment
* Contributing
* License

---

## Introduction
**RiskGuard** is a decentralized framework built on the Stacks blockchain using the Clarity smart contract language. It is designed to provide a transparent, immutable, and rigorous environment for the risk profiling of smart contracts. By utilizing a weighted scoring system and a multi-tiered authorization model, RiskGuard ensures that contract vulnerabilities, architectural complexity, and centralization risks are quantified and made publicly accessible.

The system is designed for audit firms, DAO treasury managers, and DeFi protocols that require a standardized method for vetting third-party integrations.

---

## Key Features
* **Weighted Scoring Engine:** Automatically calculates risk based on three critical vectors: Vulnerability (50%), Complexity (30%), and Centralization (20%).
* **Role-Based Access Control (RBAC):** Granular management of authorized assessors to maintain the integrity of the data.
* **Circuit Breaker Mechanism:** Administrative ability to pause all state-changing operations during emergencies or upgrades.
* **Structured Appeal Workflow:** A multi-step re-evaluation process for developers to contest scores after mitigating identified risks, protected against spam via appeal limits.
* **Audit-Ready Logging:** Extensive use of the `print` function to ensure all lifecycle events (submission, assessment, appeals) are indexed by off-chain explorers.

---

## System Architecture



The contract operates as a state machine where a contract principal moves from `Submitted` to `Assessed`. If the user is dissatisfied, the state transitions into an `Appeal` phase. If the appeal is `Approved`, the state resets to allow for a fresh evaluation, creating a continuous improvement loop for decentralized security.

---

## Contract Constants
The following constants define the foundational rules and ownership of the RiskGuard ecosystem:

| Constant | Value / Type | Description |
| :--- | :--- | :--- |
| `contract-owner` | `tx-sender` | The principal that deployed the contract; holds administrative rights. |
| `risk-threshold` | `u75` (Default) | The score at which a contract is automatically "Flagged" as high risk. |
| `u100` | `uint` | The maximum possible score for any individual risk category. |

---

## Error Codes Reference
Standardized error codes are used to ensure predictable failure states and easy debugging for frontend integrations.

* `err-owner-only (u100)`: Operation restricted to the contract deployer.
* `err-not-found (u101)`: The requested Assessment ID or Appeal does not exist.
* `err-already-assessed (u102)`: Attempting to assess a contract that already has a finalized score.
* `err-invalid-score (u103)`: Provided score exceeds the maximum limit (u100).
* `err-unauthorized (u104)`: User lacks the necessary permissions (e.g., not an assessor).
* `err-not-assessed (u105)`: Attempting to appeal a contract that hasn't been evaluated yet.
* `err-max-appeals (u106)`: The submitter has exhausted the limit of 3 appeals.
* `err-paused (u107)`: The contract is currently in a paused state.
* `err-invalid-status (u108)`: The appeal is in a state (e.g., pending) that prevents the requested action.

---

## Data Schema

### 1. Assessors Map
Stores the authorization status of entities permitted to provide risk scores.
```clarity
(define-map assessors principal bool)
```

### 2. Assessments Map
The primary ledger for risk data.
* `contract-principal`: The address of the code being vetted.
* `vulnerability-score`: Weighted at 50%.
* `complexity-score`: Weighted at 30%.
* `centralization-score`: Weighted at 20%.
* `flagged`: Boolean indicating if `overall-risk` >= `risk-threshold`.

### 3. Appeals Map
Tracks the history of re-evaluation requests.
* `appeal-count`: Counter to prevent system abuse (Max 3).
* `justification-hash`: A `buff 32` representing an off-chain IPFS link or document hash containing mitigation evidence.

---

## Function Reference

### Private Functions
These functions are internal to the contract logic and cannot be called directly by external users.

#### `calculate-overall-risk`
Calculates the final score using the formula:
$$Risk = \frac{(Vuln \times 5) + (Comp \times 3) + (Cent \times 2)}{10}$$
This ensures that security vulnerabilities carry the highest weight in the final determination.

#### `is-assessor`
A helper that queries the `assessors` map to verify if a principal has evaluation privileges.

#### `check-not-paused`
A validation wrapper used by most public functions to enforce the circuit breaker state.

---

### Public Functions

#### Administrative Functions
* **`pause-contract`**: Sets the `contract-paused` variable to true. Restricted to `contract-owner`.
* **`resume-contract`**: Sets the `contract-paused` variable to false. Restricted to `contract-owner`.
* **`add-assessor (assessor principal)`**: Grants a principal the right to submit scores.
* **`remove-assessor (assessor principal)`**: Revokes evaluation rights.
* **`update-threshold (new-threshold uint)`**: Adjusts the sensitivity of the "Flagged" status for high-risk contracts.

#### Operational Functions
* **`submit-contract (contract principal)`**: Initializes a new assessment record. Returns a unique `assessment-id`.
* **`assess-contract (assessment-id uint, vuln-score uint, comp-score uint, cent-score uint)`**: Called by an authorized assessor to finalize a score. It validates that scores are $\le 100$ and calculates the weighted average.
* **`appeal-assessment (assessment-id uint, justification (buff 32))`**: Allows the original submitter to request a re-evaluation. Requires a justification hash and checks against the maximum appeal limit.
* **`resolve-appeal (assessment-id uint, approve bool)`**: Allows an assessor or owner to process a pending appeal. If approved, it clears the previous scores to allow a fresh `assess-contract` call.

---

### Read-Only Functions

#### `get-assessment (assessment-id uint)`
Returns the full tuple of assessment data, including scores and flagged status.

#### `get-appeal (assessment-id uint)`
Returns the history and status ("pending", "approved", "rejected") of an appeal for a specific ID.

#### `check-is-assessor (user principal)`
Returns a boolean indicating if the specified address is an authorized assessor.

#### `get-risk-threshold`
Returns the current `uint` value used to flag high-risk contracts.

#### `is-contract-paused`
Returns the current operational status of the contract.

---

## Governance and Security
RiskGuard follows the "Trust but Verify" model. While the `contract-owner` manages the list of `assessors`, the assessments themselves are immutable once recorded, unless a formal `appeal` is processed.

**Security Recommendations:**
1.  **Justification Hashes:** Always store the full mitigation report on IPFS and provide the CID hash during the appeal process.
2.  **Multisig Ownership:** It is highly recommended that the `contract-owner` be set to a multisig wallet (e.g., ExecutorDAO) to prevent a single point of failure in assessor management.

---

## Installation and Deployment

### Prerequisites
* [Clarinet](https://github.com/hirosystems/clarinet) for local development.
* A Stacks wallet with STX for deployment.

### Testing
To run the test suite:
```bash
clarinet test
```

### Deployment
To deploy to mainnet:
```bash
clarinet deploy --mainnet
```

---

## Contributing
I welcome contributions from the community to improve the risk calculation logic or add new assessment vectors.
1.  Fork the repository.
2.  Create a feature branch.
3.  Ensure all Clarity tests pass.
4.  Submit a Pull Request with a detailed description of changes.

---

## License
MIT License

Copyright (c) 2026 RiskGuard Protocol

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

