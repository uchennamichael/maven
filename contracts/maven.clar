;; Oracle contract with signature verification and access control
(define-map oracles principal { signer: principal, last-value: (buff 32), last-height: uint })

;; Contract owner for admin functions
(define-data-var contract-owner principal tx-sender)

;; Oracle update counter for tracking
(define-data-var oracle-updates uint u0)

;; Constants
(define-constant MIN-BLOCK-INTERVAL u10) ;; Minimum blocks between updates
(define-constant MAX-VALUE-AGE u1000) ;; Maximum age for oracle values

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ORACLE-NOT-FOUND (err u101))
(define-constant ERR-INVALID-SIGNATURE (err u102))
(define-constant ERR-TOO-FREQUENT (err u103))
(define-constant ERR-NOT-OWNER (err u104))

;; Register an oracle with authorized signer
(define-public (register-oracle (signer principal))
  (begin 
    (map-set oracles tx-sender { 
      signer: signer, 
      last-value: 0x0000000000000000000000000000000000000000000000000000000000000000, 
      last-height: u0 
    })
    (print { event: "oracle-registered", user: tx-sender, signer: signer })
    (ok true)))

;; Submit oracle proof with signature verification and enhanced validation
(define-public (submit-proof (user principal) (value (buff 32)) (sig (buff 64)))
  (let ((oracle-data (unwrap! (map-get? oracles user) ERR-ORACLE-NOT-FOUND)))
    (let ((registered-signer (get signer oracle-data))
          (last-update-height (get last-height oracle-data))
          ;; Create message hash from user + value for signature verification
          (message-hash (keccak256 (concat (unwrap-panic (to-consensus-buff? user)) value))))
      ;; Enhanced validation: Prevent spam by requiring minimum block interval
      (asserts! (or (is-eq last-update-height u0) 
                    (>= stacks-block-height (+ last-update-height MIN-BLOCK-INTERVAL))) 
                ERR-TOO-FREQUENT)
      ;; Verify the signature was created by the registered signer
      ;; Note: For now, we'll use tx-sender verification as a placeholder
      ;; In production, you'd need to implement proper public key to principal mapping
      (asserts! (is-eq tx-sender registered-signer) ERR-INVALID-SIGNATURE)
      ;; Update oracle data only if all validations pass
      (map-set oracles user { 
        signer: registered-signer, 
        last-value: value, 
        last-height: stacks-block-height 
      })
      ;; Increment update counter and emit event
      (var-set oracle-updates (+ (var-get oracle-updates) u1))
      (print { event: "proof-submitted", user: user, value: value, height: stacks-block-height })
      (ok true))))

;; Admin function: Update oracle signer
(define-public (update-oracle-signer (user principal) (new-signer principal))
  (let ((oracle-data (unwrap! (map-get? oracles user) ERR-ORACLE-NOT-FOUND)))
    (begin
      (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
      (map-set oracles user (merge oracle-data { signer: new-signer }))
      (print { event: "signer-updated", user: user, old-signer: (get signer oracle-data), new-signer: new-signer })
      (ok true))))

;; Admin function: Remove oracle
(define-public (remove-oracle (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (asserts! (is-some (map-get? oracles user)) ERR-ORACLE-NOT-FOUND)
    (map-delete oracles user)
    (print { event: "oracle-removed", user: user })
    (ok true)))

;; Admin function: Transfer ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (var-set contract-owner new-owner)
    (print { event: "ownership-transferred", old-owner: tx-sender, new-owner: new-owner })
    (ok true)))

;; Read-only function to get oracle data
(define-read-only (get-oracle-data (user principal))
  (map-get? oracles user))

;; Read-only function to check if oracle data is fresh (within specified blocks)
(define-read-only (is-oracle-fresh (user principal) (max-age uint))
  (match (map-get? oracles user)
    oracle-data (>= (+ (get last-height oracle-data) max-age) stacks-block-height)
    false))

;; Read-only function to get just the latest value
(define-read-only (get-latest-value (user principal))
  (match (map-get? oracles user)
    oracle-data (some (get last-value oracle-data))
    none))

;; Read-only function to get contract owner
(define-read-only (get-contract-owner)
  (var-get contract-owner))

;; Read-only function to get total oracle updates
(define-read-only (get-oracle-updates-count)
  (var-get oracle-updates))

;; Read-only function to check if oracle can be updated (respects minimum interval)
(define-read-only (can-update-oracle (user principal))
  (match (map-get? oracles user)
    oracle-data (let ((last-update (get last-height oracle-data)))
                  (or (is-eq last-update u0)
                      (>= stacks-block-height (+ last-update MIN-BLOCK-INTERVAL))))
    false))