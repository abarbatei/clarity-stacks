;; code-body-prover
;; Check if a Stacks contract with a specific code body has been deployed.
;; Only works for Nakamoto blocks.
;; Uses clarity-stacks.

(define-constant chain-id-bytes (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? chain-id)) u13 u17)))
(define-constant tx-version (if is-in-mainnet 0x00 0x80))
(define-constant auth-type-standard 0x04)
(define-constant hash-mode-p2pkh 0x00)
(define-constant key-encoding 0x00)
(define-constant anchor-mode 0x03)
(define-constant post-conditions-mode-allow 0x01)
(define-constant versioned-smart-contract 0x06)
(define-constant clarity-version 0x03)

(define-constant err-invalid-length-nonce (err u2000))
(define-constant err-invalid-length-fee (err u2001))
(define-constant err-invalid-length-signature (err u2002))
(define-constant err-invalid-principal-version (err u2003))
(define-constant err-principal-not-contract (err u2004))

(define-read-only (contract-name-length-byte (length uint))
	(unwrap-panic (slice? (unwrap-panic (to-consensus-buff? length)) u16 u17))
)

(define-read-only (contract-code-length-length-bytes (length uint))
	(unwrap-panic (slice? (unwrap-panic (to-consensus-buff? length)) u13 u17))
)

(define-read-only (string-to-buff (str (string-ascii 80)))
	(unwrap-panic (slice? (unwrap-panic (to-consensus-buff? str)) u5 (+ (len str) u5)))
)

(define-read-only (calculate-txid
	(nonce (buff 8))
	(fee (buff 8))
	(signature (buff 65))
	(contract principal)
	(code-body (buff 80000))
	)
	(let
		(
			(principal-data (unwrap! (principal-destruct? contract) err-invalid-principal-version))
			(contract-name (unwrap! (get name principal-data) err-principal-not-contract))
		)
		(asserts! (is-eq (len nonce) u8) err-invalid-length-nonce)
		(asserts! (is-eq (len fee) u8) err-invalid-length-fee)
		(asserts! (is-eq (len signature) u65) err-invalid-length-signature)
		(ok (sha512/256
			(concat tx-version
			(concat chain-id-bytes
			(concat auth-type-standard
			(concat hash-mode-p2pkh
			(concat (get hash-bytes principal-data)
			(concat nonce
			(concat fee
			(concat key-encoding
			(concat signature
			(concat anchor-mode
			(concat post-conditions-mode-allow
			(concat 0x00000000 ;; no post conditions
			(concat versioned-smart-contract
			(concat clarity-version
			(concat (contract-name-length-byte (len contract-name))
			(concat (string-to-buff contract-name)
			(concat (contract-code-length-length-bytes (len code-body)) code-body
			)))))))))))))))))
		))
	)
)

(define-read-only (calculate-verification-txid
	(nonce (buff 8))
	(fee (buff 8))
	(signature (buff 65))
	(contract principal)
	)
	(begin
		;; Here we need to check if <contract>::has-successfully-deployed was called
		;; as the exact next transaction from the same user (nonce + 1)
		;;
		;; This transaction can only exist if the contract was deployed, otherwise we get:
		;; Broadcast error: {
		;;		error: 'transaction rejected',
		;;		reason: 'NoSuchContract',
		;;		txid: '<som TXID>'
		;; }
		;; since Stacks does not allow calling functions on non-existing contracts
		;;
		;;
		;; (define-read-only (has-successfully-deployed)
		;;		(ok true)
		;; )
		;;
		;; TODO: implement on-chain ContractCall TXID calculation
		;;
		(asserts! (is-eq tx-version 0x00) err-invalid-length-fee)
		(ok tx-version)
	)
)

(define-private (increment-buff8 (b (buff 8)))
  (let ((inc-buff (unwrap-panic (to-consensus-buff? (+ (buff-to-int-be b) 1)))))
		(unwrap-panic (as-max-len? (unwrap-panic (slice? inc-buff u9 u17)) u8))
  )
)

;; Returns (ok true) if the transaction was mined.
(define-read-only (is-contract-deployed
	(nonce (buff 8))
	(fee (buff 8))
	(signature (buff 65))
	(contract principal)
	(code-body (buff 80000))
	(proof { tx-index: uint, hashes: (list 14 (buff 32)), tree-depth: uint})
	(tx-block-height uint)
	(block-header-without-signer-signatures (buff 712))
	)
	(contract-call? .clarity-stacks was-tx-mined-compact
		(try! (calculate-txid nonce fee signature contract code-body))
		proof
		tx-block-height
		block-header-without-signer-signatures
	)
)

;; Returns (ok true) if the transaction was mined.
(define-read-only (is-contract-deployed-two-step
	(nonce (buff 8))
	(contract principal)
	(deploy-tx {
		fee: (buff 8),
		signature: (buff 65),
		code-body: (buff 80000),
		proof: { tx-index: uint, hashes: (list 14 (buff 32)), tree-depth: uint},
		tx-block-height: uint,
		block-header-without-signer-signatures: (buff 712)
	})
	(verification-tx {
		fee: (buff 8),
		signature: (buff 65),
		proof: { tx-index: uint, hashes: (list 14 (buff 32)), tree-depth: uint},
		tx-block-height: uint,
		block-header-without-signer-signatures: (buff 712)
	})
	)
	(begin
		(try! (contract-call? .clarity-stacks was-tx-mined-compact
			(try! (calculate-txid nonce (get fee deploy-tx) (get signature deploy-tx) contract (get code-body deploy-tx)))
			(get proof deploy-tx)
			(get tx-block-height deploy-tx)
			(get block-header-without-signer-signatures deploy-tx)
		))
		(contract-call? .clarity-stacks was-tx-mined-compact
			(try! (calculate-verification-txid
							(increment-buff8 nonce)
							(get fee verification-tx)
							(get signature verification-tx)
							contract))
			(get proof verification-tx)
			(get tx-block-height verification-tx)
			(get block-header-without-signer-signatures verification-tx)
		)
	)
)
