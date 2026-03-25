;; contract title: Automated Risk Assessment for Smart Contracts
;; 
;; This contract allows users to submit their smart contracts for an automated
;; risk assessment process. Authorized assessors can evaluate the contracts based
;; on vulnerabilities, complexity, and centralization, producing a final risk score.
;; The contract also features a secure appeal mechanism for re-evaluation, and
;; administrative functions for pausing the contract during emergencies.

;; constants
(define-constant contract-owner tx-sender)

;; Error Codes
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-assessed (err u102))
(define-constant err-invalid-score (err u103))
(define-constant err-unauthorized (err u104))
(define-constant err-not-assessed (err u105))
(define-constant err-max-appeals (err u106))
(define-constant err-paused (err u107))
(define-constant err-invalid-status (err u108))

;; data maps and vars

;; @desc Map of authorized assessors who can submit risk scores
(define-map assessors principal bool)

;; @desc Map storing the primary assessment data for each submitted contract
(define-map assessments 
    uint 
    {
        contract-principal: principal,
        submitter: principal,
        vulnerability-score: uint,
        complexity-score: uint,
        centralization-score: uint,
        overall-risk: uint,
        is-assessed: bool,
        flagged: bool
    }
)

;; @desc Map storing the appeal data for contracts seeking re-evaluation
(define-map appeals 
    uint 
    {
        appeal-count: uint,
        last-risk-score: uint,
        justification-hash: (buff 32),
        status: (string-ascii 20), ;; Can be "pending", "approved", or "rejected"
        resolved-by: (optional principal)
    }
)

;; Global State Variables
(define-data-var assessment-counter uint u0)
(define-data-var risk-threshold uint u75)
(define-data-var contract-paused bool false)

;; private functions

;; @desc Calculates the weighted overall risk score.
;; Weights applied: Vulnerability (50%), Complexity (30%), Centralization (20%)
(define-private (calculate-overall-risk (vuln uint) (comp uint) (cent uint))
    (/ (+ (+ (* vuln u5) (* comp u3)) (* cent u2)) u10)
)

;; @desc Checks if a given principal is an authorized assessor.
(define-private (is-assessor (user principal))
    (default-to false (map-get? assessors user))
)

;; @desc Helper to ensure the contract is not paused (circuit breaker check).
(define-private (check-not-paused)
    (if (var-get contract-paused)
        err-paused
        (ok true)
    )
)

;; public functions

;; @desc Pause the contract in case of an emergency (Circuit Breaker).
;; @restricted Contract Owner
(define-public (pause-contract)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (var-set contract-paused true))
    )
)

;; @desc Resume the contract operations.
;; @restricted Contract Owner
(define-public (resume-contract)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (var-set contract-paused false))
    )
)

;; @desc Add a new assessor to the authorized list.
;; @restricted Contract Owner
(define-public (add-assessor (assessor principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (try! (check-not-paused))
        (print { event: "add-assessor", assessor: assessor })
        (ok (map-set assessors assessor true))
    )
)

;; @desc Remove an existing assessor from the authorized list.
;; @restricted Contract Owner
(define-public (remove-assessor (assessor principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (try! (check-not-paused))
        (print { event: "remove-assessor", assessor: assessor })
        (ok (map-delete assessors assessor))
    )
)

;; @desc Submit a smart contract for risk assessment.
;; @param contract The principal of the smart contract to be assessed.
(define-public (submit-contract (contract principal))
    (let
        (
            (assessment-id (+ (var-get assessment-counter) u1))
        )
        (try! (check-not-paused))
        (map-set assessments assessment-id {
            contract-principal: contract,
            submitter: tx-sender,
            vulnerability-score: u0,
            complexity-score: u0,
            centralization-score: u0,
            overall-risk: u0,
            is-assessed: false,
            flagged: false
        })
        (var-set assessment-counter assessment-id)
        (print { event: "submit-contract", id: assessment-id, contract: contract, submitter: tx-sender })
        (ok assessment-id)
    )
)

;; @desc Assess a submitted contract and calculate its risk.
;; @param assessment-id The ID of the assessment.
;; @param vuln-score Score out of 100 for vulnerabilities.
;; @param comp-score Score out of 100 for code complexity.
;; @param cent-score Score out of 100 for centralization risks.
(define-public (assess-contract (assessment-id uint) (vuln-score uint) (comp-score uint) (cent-score uint))
    (let
        (
            (assessment (unwrap! (map-get? assessments assessment-id) err-not-found))
            (overall (calculate-overall-risk vuln-score comp-score cent-score))
            (threshold (var-get risk-threshold))
            (is-flagged (>= overall threshold))
        )
        (try! (check-not-paused))
        
        ;; Security checks
        (asserts! (is-assessor tx-sender) err-unauthorized)
        (asserts! (not (get is-assessed assessment)) err-already-assessed)
        (asserts! (and (<= vuln-score u100) (<= comp-score u100) (<= cent-score u100)) err-invalid-score)
        
        ;; Update the assessment state
        (map-set assessments assessment-id 
            (merge assessment {
                vulnerability-score: vuln-score,
                complexity-score: comp-score,
                centralization-score: cent-score,
                overall-risk: overall,
                is-assessed: true,
                flagged: is-flagged
            })
        )
        (print { event: "assess-contract", id: assessment-id, overall-risk: overall, flagged: is-flagged })
        (ok overall)
    )
)

;; @desc Get details of a specific assessment.
(define-read-only (get-assessment (assessment-id uint))
    (map-get? assessments assessment-id)
)

;; @desc Check if a principal is an authorized assessor.
(define-read-only (check-is-assessor (user principal))
    (is-assessor user)
)

;; @desc Get the current risk threshold.
(define-read-only (get-risk-threshold)
    (var-get risk-threshold)
)

;; @desc Check if the contract operations are currently paused.
(define-read-only (is-contract-paused)
    (var-get contract-paused)
)

;; @desc Update the risk threshold that flags contracts.
;; @restricted Contract Owner
(define-public (update-threshold (new-threshold uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (try! (check-not-paused))
        (asserts! (<= new-threshold u100) err-invalid-score)
        (print { event: "update-threshold", old: (var-get risk-threshold), new: new-threshold })
        (ok (var-set risk-threshold new-threshold))
    )
)

;; @desc Feature: Appeal and Re-assessment Process
;; This feature allows a submitter to appeal an assessment if they have mitigated
;; the identified risks. It enforces a strict appeal limit, requires a justification
;; hash for auditability, and resets the assessment state to allow authorized
;; assessors to evaluate the updated contract securely.
(define-public (appeal-assessment (assessment-id uint) (justification (buff 32)))
    (let
        (
            (assessment (unwrap! (map-get? assessments assessment-id) err-not-found))
            (appeal-record (default-to 
                { appeal-count: u0, last-risk-score: u0, justification-hash: 0x00, status: "none", resolved-by: none } 
                (map-get? appeals assessment-id)))
            (current-appeal-count (get appeal-count appeal-record))
        )
        (try! (check-not-paused))
        
        ;; Security check: only the original submitter can initiate an appeal
        (asserts! (is-eq tx-sender (get submitter assessment)) err-unauthorized)
        
        ;; Ensure the contract has actually been assessed before an appeal
        (asserts! (get is-assessed assessment) err-not-assessed)
        
        ;; Limit appeals to prevent spam and abuse of the assessment process
        (asserts! (< current-appeal-count u3) err-max-appeals)
        
        ;; Ensure there isn't an already pending appeal
        (asserts! (not (is-eq (get status appeal-record) "pending")) err-invalid-status)
        
        ;; Record the appeal securely, preserving the previous risk score
        (map-set appeals assessment-id {
            appeal-count: (+ current-appeal-count u1),
            last-risk-score: (get overall-risk assessment),
            justification-hash: justification,
            status: "pending",
            resolved-by: none
        })
        
        (print { event: "appeal-submitted", id: assessment-id, count: (+ current-appeal-count u1) })
        (ok true)
    )
)

;; @desc Get details of a specific appeal.
(define-read-only (get-appeal (assessment-id uint))
    (map-get? appeals assessment-id)
)

;; @desc Resolve an appeal by either approving it for re-assessment or rejecting it.
;; This function ensures that only an authorized assessor or the owner can decide
;; the outcome of a pending appeal. If approved, the assessment state is cleared,
;; allowing a new assessment to take place. If rejected, the status is updated.
(define-public (resolve-appeal (assessment-id uint) (approve bool))
    (let
        (
            (assessment (unwrap! (map-get? assessments assessment-id) err-not-found))
            (appeal-record (unwrap! (map-get? appeals assessment-id) err-not-found))
        )
        (try! (check-not-paused))
        
        ;; Security check: only authorized assessors or owner can resolve an appeal
        (asserts! (or (is-eq tx-sender contract-owner) (is-assessor tx-sender)) err-unauthorized)
        
        ;; Ensure the appeal is currently pending
        (asserts! (is-eq (get status appeal-record) "pending") err-invalid-status)
        
        (if approve
            (begin
                ;; If approved, reset the assessment state to prepare for the re-evaluation
                (map-set assessments assessment-id 
                    (merge assessment {
                        vulnerability-score: u0,
                        complexity-score: u0,
                        centralization-score: u0,
                        overall-risk: u0,
                        is-assessed: false,
                        flagged: false
                    })
                )
                (map-set appeals assessment-id 
                    (merge appeal-record {
                        status: "approved",
                        resolved-by: (some tx-sender)
                    })
                )
                (print { event: "appeal-resolved", id: assessment-id, status: "approved", resolved-by: tx-sender })
                (ok true)
            )
            (begin
                ;; If rejected, simply update the appeal status, preserving the old assessment
                (map-set appeals assessment-id 
                    (merge appeal-record {
                        status: "rejected",
                        resolved-by: (some tx-sender)
                    })
                )
                (print { event: "appeal-resolved", id: assessment-id, status: "rejected", resolved-by: tx-sender })
                (ok true)
            )
        )
    )
)


