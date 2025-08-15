;; SecretKeeper - A secure repository where secrets are only disclosed when protection fails
;; Smart Contract for Stacks Blockchain

;; Contract constants
(define-constant admin-address tx-sender)
(define-constant err-admin-only (err u100))
(define-constant err-not-permitted (err u101))
(define-constant err-repository-not-found (err u102))
(define-constant err-protection-intact (err u103))
(define-constant err-already-disclosed (err u104))
(define-constant err-insufficient-alerts (err u105))
(define-constant err-invalid-input (err u106))
(define-constant err-duplicate-alert (err u107))

;; Data variables
(define-data-var repository-counter uint u0)
(define-data-var minimum-alert-count uint u3)

;; Data maps
(define-map secret-repositories
  { repository-id: uint }
  {
    creator: principal,
    encrypted-secret: (string-ascii 500),
    disclosed-secret: (optional (string-ascii 500)),
    protection-rules: (list 5 (string-ascii 100)),
    alert-count: uint,
    alert-senders: (list 10 principal),
    is-disclosed: bool,
    creation-time: uint,
    disclosure-time: (optional uint)
  }
)

(define-map protection-alerts
  { repository-id: uint, sender: principal }
  {
    violated-rule: (string-ascii 100),
    proof: (string-ascii 300),
    alert-time: uint,
    validated: bool
  }
)

(define-map trusted-validators
  { validator: principal }
  { permitted: bool }
)

;; Private functions
(define-private (is-trusted-validator (validator principal))
  (default-to false (get permitted (map-get? trusted-validators { validator: validator })))
)

(define-private (increment-repository-counter)
  (let ((current-count (var-get repository-counter)))
    (var-set repository-counter (+ current-count u1))
    (+ current-count u1)
  )
)

(define-private (validate-string-input (input (string-ascii 500)))
  (and (> (len input) u0) (<= (len input) u500))
)

(define-private (validate-proof-input (input (string-ascii 300)))
  (and (> (len input) u0) (<= (len input) u300))
)

(define-private (validate-rule-input (input (string-ascii 100)))
  (and (> (len input) u0) (<= (len input) u100))
)

(define-private (validate-rules-list (rules (list 5 (string-ascii 100))))
  (and (> (len rules) u0) (<= (len rules) u5))
)

;; Public functions

;; Create a new secret repository with encrypted data and protection rules
(define-public (create-repository 
  (encrypted-secret (string-ascii 500))
  (protection-rules (list 5 (string-ascii 100))))
  (let ((validated-secret encrypted-secret)
        (validated-rules protection-rules)
        (repository-id (increment-repository-counter)))
    (asserts! (validate-string-input validated-secret) err-invalid-input)
    (asserts! (validate-rules-list validated-rules) err-invalid-input)
    (map-set secret-repositories
      { repository-id: repository-id }
      {
        creator: tx-sender,
        encrypted-secret: validated-secret,
        disclosed-secret: none,
        protection-rules: validated-rules,
        alert-count: u0,
        alert-senders: (list),
        is-disclosed: false,
        creation-time: block-height,
        disclosure-time: none
      }
    )
    (ok repository-id)
  )
)

;; Send an alert about protection rule violation
(define-public (send-alert 
  (repository-id uint)
  (violated-rule (string-ascii 100))
  (proof (string-ascii 300)))
  (let ((validated-id repository-id)
        (validated-rule violated-rule)
        (validated-proof proof)
        (repository-data (unwrap! (map-get? secret-repositories { repository-id: validated-id }) err-repository-not-found)))
    (asserts! (> validated-id u0) err-invalid-input)
    (asserts! (validate-rule-input validated-rule) err-invalid-input)
    (asserts! (validate-proof-input validated-proof) err-invalid-input)
    (asserts! (not (get is-disclosed repository-data)) err-already-disclosed)
    (asserts! (is-none (map-get? protection-alerts { repository-id: validated-id, sender: tx-sender })) err-duplicate-alert)
    
    ;; Record the protection alert
    (map-set protection-alerts
      { repository-id: validated-id, sender: tx-sender }
      {
        violated-rule: validated-rule,
        proof: validated-proof,
        alert-time: block-height,
        validated: false
      }
    )
    ;; Update repository with new alert
    (map-set secret-repositories
      { repository-id: validated-id }
      (merge repository-data {
        alert-count: (+ (get alert-count repository-data) u1),
        alert-senders: (unwrap-panic (as-max-len? 
          (append (get alert-senders repository-data) tx-sender) u10))
      })
    )
    (ok true)
  )
)

;; Validate a protection alert (only trusted validators)
(define-public (validate-alert 
  (repository-id uint)
  (sender principal))
  (let ((validated-id repository-id)
        (validated-sender sender))
    (asserts! (> validated-id u0) err-invalid-input)
    (asserts! (is-trusted-validator tx-sender) err-not-permitted)
    (let ((alert-data (unwrap! (map-get? protection-alerts { repository-id: validated-id, sender: validated-sender }) err-repository-not-found)))
      (map-set protection-alerts
        { repository-id: validated-id, sender: validated-sender }
        (merge alert-data { validated: true })
      )
      (ok true)
    )
  )
)

;; Disclose the secret when protection rules are sufficiently violated
(define-public (disclose-secret 
  (repository-id uint)
  (decrypted-secret (string-ascii 500)))
  (let ((validated-id repository-id)
        (validated-secret decrypted-secret)
        (repository-data (unwrap! (map-get? secret-repositories { repository-id: validated-id }) err-repository-not-found)))
    (asserts! (> validated-id u0) err-invalid-input)
    (asserts! (validate-string-input validated-secret) err-invalid-input)
    (asserts! (not (get is-disclosed repository-data)) err-already-disclosed)
    (asserts! (>= (get alert-count repository-data) (var-get minimum-alert-count)) err-insufficient-alerts)
    (asserts! (is-eq tx-sender (get creator repository-data)) err-not-permitted)
    
    (map-set secret-repositories
      { repository-id: validated-id }
      (merge repository-data {
        disclosed-secret: (some validated-secret),
        is-disclosed: true,
        disclosure-time: (some block-height)
      })
    )
    (ok true)
  )
)

;; Admin override to disclose secret
(define-public (admin-disclose 
  (repository-id uint)
  (decrypted-secret (string-ascii 500)))
  (let ((validated-id repository-id)
        (validated-secret decrypted-secret))
    (asserts! (is-eq tx-sender admin-address) err-admin-only)
    (asserts! (> validated-id u0) err-invalid-input)
    (asserts! (validate-string-input validated-secret) err-invalid-input)
    (let ((repository-data (unwrap! (map-get? secret-repositories { repository-id: validated-id }) err-repository-not-found)))
      (map-set secret-repositories
        { repository-id: validated-id }
        (merge repository-data {
          disclosed-secret: (some validated-secret),
          is-disclosed: true,
          disclosure-time: (some block-height)
        })
      )
      (ok true)
    )
  )
)

;; Grant validator permissions
(define-public (grant-validator-access (validator principal))
  (let ((validated-validator validator))
    (asserts! (is-eq tx-sender admin-address) err-admin-only)
    (map-set trusted-validators
      { validator: validated-validator }
      { permitted: true }
    )
    (ok true)
  )
)

;; Update minimum alert requirement
(define-public (update-alert-threshold (new-minimum uint))
  (let ((validated-minimum new-minimum))
    (asserts! (is-eq tx-sender admin-address) err-admin-only)
    (asserts! (and (> validated-minimum u0) (<= validated-minimum u10)) err-invalid-input)
    (var-set minimum-alert-count validated-minimum)
    (ok true)
  )
)

;; Read-only functions

;; Get repository information (hides disclosed secret from unauthorized users)
(define-read-only (get-repository-info (repository-id uint))
  (let ((validated-id repository-id))
    (if (> validated-id u0)
      (let ((repository-data (map-get? secret-repositories { repository-id: validated-id })))
        (match repository-data
          repo-info
          (if (get is-disclosed repo-info)
            (some {
              creator: (get creator repo-info),
              protection-rules: (get protection-rules repo-info),
              alert-count: (get alert-count repo-info),
              is-disclosed: (get is-disclosed repo-info),
              creation-time: (get creation-time repo-info),
              disclosure-time: (get disclosure-time repo-info),
              disclosed-secret: (get disclosed-secret repo-info)
            })
            (some {
              creator: (get creator repo-info),
              protection-rules: (get protection-rules repo-info),
              alert-count: (get alert-count repo-info),
              is-disclosed: (get is-disclosed repo-info),
              creation-time: (get creation-time repo-info),
              disclosure-time: none,
              disclosed-secret: none
            })
          )
          none
        )
      )
      none
    )
  )
)

;; Get protection alert details
(define-read-only (get-alert-details (repository-id uint) (sender principal))
  (let ((validated-id repository-id)
        (validated-sender sender))
    (if (> validated-id u0)
      (map-get? protection-alerts { repository-id: validated-id, sender: validated-sender })
      none
    )
  )
)

;; Get current alert threshold
(define-read-only (get-alert-threshold)
  (var-get minimum-alert-count)
)

;; Get total number of repositories
(define-read-only (get-repository-count)
  (var-get repository-counter)
)

;; Check if a validator has permissions
(define-read-only (is-validator-trusted (validator principal))
  (is-trusted-validator validator)
)