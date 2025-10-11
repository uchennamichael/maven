;; Oracle contract with signature verification, replay protection, and access control

;; Storage: oracles keyed by user principal
;; - signer-pubkey: compressed secp256k1 pubkey (33 bytes)
;; - last-value: optional 32-byte buffer (none before first update)
;; - last-height: last update block height
;; - nonce: monotonically increasing counter to prevent signature replay
(define-map oracles
  principal
  {
    signer-pubkey: (buff 33),
    last-value: (optional (buff 32)),
    last-height: uint,
    nonce: uint
  }
)

;; Contract owner for admin functions
(define-data-var contract-owner principal tx-sender)

;; Oracle update counter for tracking
(define-data-var oracle-updates uint u0)

;; Constants
(define-constant MIN-BLOCK-INTERVAL u10) ;; Minimum blocks between updates
(define-constant MAX-VALUE-AGE u1000)    ;; Maximum age for oracle values (used by helper)

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ORACLE-NOT-FOUND (err u101))
(define-constant ERR-INVALID-SIGNATURE (err u102))
(define-constant ERR-TOO-FREQUENT (err u103))
(define-constant ERR-NOT-OWNER (err u104))
(define-constant ERR-INVALID-NONCE (err u105))

;; Domain separator for message hashing (ASCII: "maven-oracle-v1")
(define-constant MSG_DOMAIN 0x6d6176656e2d6f7261636c652d7631)

;; Private helper: build the message hash for signing.
;; Hash = keccak256( MSG_DOMAIN || user || value || nonce )
;; Notes:
;; - user and nonce are converted to consensus buffers to ensure canonical encoding.
(define-private (make-message-hash (user principal) (value (buff 32)) (nonce uint))
  (let (
        (user-buff (unwrap-panic (to-consensus-buff? user)))
        (nonce-buff (unwrap-panic (to-consensus-buff? nonce)))
       )
    (keccak256 (concat MSG_DOMAIN (concat user-buff (concat value nonce-buff))))
  )
)

;; Register or update an oracle's signer pubkey.
;; - If the caller has no entry, create it with empty last-value and zeroed height/nonce.
;; - If an entry exists, only update signer-pubkey without resetting last-height, last-value, or nonce.
(define-public (register-oracle (signer-pubkey (buff 33)))
  (match (map-get? oracles tx-sender)
    existing
      (begin
        (map-set oracles tx-sender (merge existing { signer-pubkey: signer-pubkey }))
        (print { event: "oracle-signer-updated", user: tx-sender })
        (ok true))
    (begin
      (map-set oracles tx-sender {
        signer-pubkey: signer-pubkey,
        last-value: none,
        last-height: u0,
        nonce: u0
      })
      (print { event: "oracle-registered", user: tx-sender })
      (ok true)))
)

;; Submit oracle proof with signature verification, nonce-based replay protection, and rate limiting.
;; - nonce must equal stored nonce + 1.
;; - signature must verify against keccak256(MSG_DOMAIN || user || value || nonce) and stored signer-pubkey.
(define-public (submit-proof (user principal) (value (buff 32)) (sig (buff 65)) (nonce uint))
  (let (
        (oracle-data (unwrap! (map-get? oracles user) ERR-ORACLE-NOT-FOUND))
        (registered-pub (get signer-pubkey oracle-data))
        (last-update-height (get last-height oracle-data))
        (stored-nonce (get nonce oracle-data))
        (msg-hash (make-message-hash user value nonce))
       )
    ;; Enforce minimum block interval (first update exempt when last-height == u0)
    (asserts! (or (is-eq last-update-height u0)
                  (>= stacks-block-height (+ last-update-height MIN-BLOCK-INTERVAL)))
              ERR-TOO-FREQUENT)
    ;; Nonce must strictly increase by 1 to prevent replay
    (asserts! (is-eq nonce (+ stored-nonce u1)) ERR-INVALID-NONCE)
    ;; Verify signature was produced by the stored signer-pubkey
    (asserts! (secp256k1-verify msg-hash sig registered-pub) ERR-INVALID-SIGNATURE)
    ;; Update oracle state
    (map-set oracles user {
      signer-pubkey: registered-pub,
      last-value: (some value),
      last-height: stacks-block-height,
      nonce: nonce
    })
    ;; Increment update counter and emit event
    (var-set oracle-updates (+ (var-get oracle-updates) u1))
    (print { event: "proof-submitted", user: user, value: value, height: stacks-block-height, nonce: nonce })
    (ok true))
)

;; Admin function: Update oracle signer pubkey (owner-only).
;; Does not modify last-height, last-value, or nonce.
(define-public (update-oracle-signer (user principal) (new-signer-pubkey (buff 33)))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (let ((oracle-data (unwrap! (map-get? oracles user) ERR-ORACLE-NOT-FOUND)))
      (map-set oracles user (merge oracle-data { signer-pubkey: new-signer-pubkey }))
      (print {
        event: "signer-updated",
        user: user
      })
      (ok true)))
)

;; Admin function: Remove oracle (owner-only).
(define-public (remove-oracle (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (asserts! (is-some (map-get? oracles user)) ERR-ORACLE-NOT-FOUND)
    (map-delete oracles user)
    (print { event: "oracle-removed", user: user })
    (ok true))
)

;; Admin function: Transfer ownership (owner-only).
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (var-set contract-owner new-owner)
    (print { event: "ownership-transferred", old-owner: tx-sender, new-owner: new-owner })
    (ok true))
)

;; Read-only function to get oracle data
(define-read-only (get-oracle-data (user principal))
  (map-get? oracles user)
)

;; Read-only function to check if oracle data is fresh (within specified blocks, caller-provided)
(define-read-only (is-oracle-fresh (user principal) (max-age uint))
  (match (map-get? oracles user)
    oracle-data (>= (+ (get last-height oracle-data) max-age) stacks-block-height)
    false)
)

;; Read-only helper: return latest value only if it's considered fresh using MAX-VALUE-AGE.
(define-read-only (get-latest-value-if-fresh (user principal))
  (match (map-get? oracles user)
    oracle-data (if (>= (+ (get last-height oracle-data) MAX-VALUE-AGE) stacks-block-height)
                    (get last-value oracle-data) ;; may be none if never updated
                    none)
    none)
)

;; Read-only function to get just the latest value (may be none if never updated)
(define-read-only (get-latest-value (user principal))
  (match (map-get? oracles user)
    oracle-data (get last-value oracle-data)
    none)
)

;; Read-only function to get contract owner
(define-read-only (get-contract-owner)
  (var-get contract-owner)
)

;; Read-only function to get total oracle updates
(define-read-only (get-oracle-updates-count)
  (var-get oracle-updates)
)

;; Read-only function to check if oracle can be updated (respects minimum interval)
(define-read-only (can-update-oracle (user principal))
  (match (map-get? oracles user)
    oracle-data (let ((last-update (get last-height oracle-data)))
                  (or (is-eq last-update u0)
                      (>= stacks-block-height (+ last-update MIN-BLOCK-INTERVAL))))
    false)
)
