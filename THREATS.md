# TrustVault Threat Model & Security Architecture (`THREATS.md`)

TrustVault is engineered on the principle of **Default Deny** and **Cryptographic Tamper-Evidence**. In high-assurance environments (audits, executive compensation, customer MSAs, IP drawings), authorization is never delegated to client-side logic or static UI visibility. Every single request is evaluated by the server at execution time.

This document details the threat landscape, attack vectors considered, mitigations implemented, automated test coverage, and consciously accepted residual risks.

---

## Threat Matrix Overview

| Threat ID | Threat / Attack Vector | Severity | Mitigation Status | Automated Test |
| :--- | :--- | :--- | :--- | :--- |
| **TV-01** | Insecure Direct Object References (IDOR) on View / Download | **CRITICAL** | **Mitigated** | `test_unauthorized_user_cannot_view_or_download_document` |
| **TV-02** | Stale / Revoked JWT Token Reuse (Zombie Sessions) | **CRITICAL** | **Mitigated** | `test_immediate_revocation_terminates_access_instantly` |
| **TV-03** | Audit Trail Tampering by Rogue DBA / SQL Injection | **CRITICAL** | **Mitigated** | `test_audit_log_tampering_is_detected` |
| **TV-04** | Brute Force & Credential Stuffing Attacks | **HIGH** | **Mitigated** | `test_login_rate_limiting_prevents_brute_force` |
| **TV-05** | Side-Channel Timing Attacks on User Enumeration | **MEDIUM** | **Mitigated** | `test_auth_security.py` |
| **TV-06** | Weak Password & Entropy Exhaustion | **HIGH** | **Mitigated** | `test_password_strength_enforcement` |
| **TV-07** | Path Traversal & Arbitrary File Overwrite via Upload | **HIGH** | **Mitigated** | `validators.py` / `test_permissions.py` |
| **TV-08** | MIME Spoofing & Polyglot File Injection | **HIGH** | **Mitigated** | `validate_file_upload` |
| **TV-09** | Physical Disk Theft / Cloud Storage Exfiltration | **HIGH** | **Mitigated** | `test_files_are_encrypted_on_disk` |
| **TV-10** | Privilege Escalation via Read-to-Edit Drift | **HIGH** | **Mitigated** | `test_read_only_user_cannot_edit_or_delete` |
| **TV-11** | Autonomous AI Access Widening & Confused Deputy | **HIGH** | **Mitigated** | `test_ai_advisor_requires_human_confirmation_and_audits` |
| **TV-12** | Denial of Service via Huge File Uploads (Zip Bomb) | **MEDIUM** | **Mitigated** | `validate_file_upload` (50MB ceiling) |
| **TV-13** | Time-of-Check to Time-of-Use (TOCTOU) Race on Revocation | **HIGH** | **Mitigated** | In-Transaction Database Checks |

---

## Detailed Threat Analysis & Defenses

### 1. Insecure Direct Object Reference (IDOR) on File Downloads (`TV-01`)
* **The Attack:** An attacker knows or guesses the UUID of another user's confidential document (e.g. `/api/documents/7c9e6679-7425-40de-944b-e07fc1f90ae7/download`) and attempts direct HTTP GET requests.
* **Why Traditional Apps Fail:** Many apps rely on the UI hiding the button or checking if the user is authenticated, without checking resource-level access.
* **Our Defense:**
  - `PermissionService.check_access()` is invoked synchronously inside the route handler on **every single GET request**.
  - Access is evaluated under strict Default Deny:
    $$\text{Access} = (\text{user.id} == \text{doc.owner\_id}) \lor (\text{active non-expired non-revoked permission exists})$$
  - Failed attempts immediately raise `HTTP 403 Forbidden` and append an immutable `DOWNLOAD_DENIED` entry to the cryptographic audit trail.
* **Test Verification:** `test_unauthorized_user_cannot_view_or_download_document` in `tests/test_permissions.py`.

---

### 2. Immediate Revocation & Zombie Tokens (`TV-02`)
* **The Attack:** A user is granted access, receives a JWT valid for 15 minutes, and downloads a document. The owner revokes their permission or the admin deactivates their account. The attacker uses the still-valid JWT signature to continue downloading files until the token naturally expires.
* **Why Traditional Apps Fail:** Stateless JWTs cannot be revoked without distributed blacklists or waiting for expiration.
* **Our Defense:**
  - Dual-layer immediate invalidation:
    1. **Resource Gate:** `PermissionService.check_access` checks the live database state on every request. Even with a valid token, the permission row is marked `is_revoked = True`, denying access immediately.
    2. **Token Invalidation:** When a permission is revoked, the target user's `token_generation` counter in the `users` table is incremented. The `get_current_user` middleware compares `payload["tg"] == user.token_generation`. Any token issued prior to the revocation instant fails authentication immediately with `HTTP 401`.
* **Cost:** One indexed integer check per authenticated request (sub-millisecond overhead).
* **Test Verification:** `test_immediate_revocation_terminates_access_instantly` in `tests/test_permissions.py`.

---

### 3. Audit Trail Tampering (`TV-03`)
* **The Attack:** An attacker breaches the database or a rogue DBA modifies audit logs to erase evidence of unauthorized document access (e.g., updating `VIEW_DENIED` to `VIEW`, or deleting entries).
* **Why Traditional Apps Fail:** Standard relational audit tables allow `UPDATE` or `DELETE` statements without leaving cryptographic proof of modification.
* **Our Defense:**
  - **Cryptographic Hash Chaining (Merkle Chain):**
    Each entry includes:
    $$\text{entry\_hash} = \text{SHA256}(\text{prev\_hash} \parallel \text{action} \parallel \text{user\_id} \parallel \text{document\_id} \parallel \text{details} \parallel \text{timestamp})$$
  - Any alteration breaks the hash chain forward from that entry.
  - The verification endpoint `/api/audit/verify` recalculates the hash chain from genesis block #1 to current head. If a single byte is changed, it identifies the exact row ID where the chain was broken.
* **Test Verification:** `test_audit_log_tampering_is_detected` in `tests/test_audit_chain.py`.

---

### 4. Brute Force & Credential Stuffing (`TV-04`)
* **The Attack:** Automated botnets launch thousands of login attempts against user accounts.
* **Our Defense:**
  - In-memory sliding-window rate limiter enforcing a strict ceiling of **5 login attempts per 60 seconds per IP**.
  - 6th attempt triggers `HTTP 429 Too Many Requests` with a `Retry-After: 60` response header.
  - Every failed attempt generates a `LOGIN_FAILED` audit entry with IP and User-Agent telemetry.
* **Test Verification:** `test_login_rate_limiting_prevents_brute_force` in `tests/test_auth_security.py`.

---

### 5. Side-Channel Timing Attacks on Authentication (`TV-05`)
* **The Attack:** An attacker measures server response time differences between valid emails and non-existent emails to enumerate corporate user accounts.
* **Our Defense:**
  - When an email is not found in the database, `AuthService.authenticate()` executes a dummy Argon2id hash operation on a fixed dummy password before returning `None`. This guarantees identical computational latency regardless of account existence.
* **Test Verification:** Covered in `app/services/auth_service.py` timing mitigation.

---

### 6. Storage Encryption at Rest & Key Isolation (`TV-09`)
* **The Attack:** A cloud storage volume snapshot or server backup is stolen or accessed by an unprivileged system engineer.
* **Our Defense:**
  - Document payloads are encrypted using **AES-256-GCM** before writing to disk.
  - Each file receives an independent 96-bit cryptographically secure initialization vector (IV) and produces a 128-bit authentication tag.
  - Files are stored on disk using random UUID names (`uploads/<uuid>`), completely decoupling filesystem naming from confidential corporate metadata.
  - Raw filesystem reads reveal only ciphertext. Decryption occurs strictly in-memory during streaming via authenticated file proxy.
* **Test Verification:** `test_files_are_encrypted_on_disk` in `tests/test_encryption.py`.

---

### 7. AI Autonomous Access Widening & Confused Deputy (`TV-11`)
* **The Attack:** An attacker prompts or exploits an internal AI advisor to widen access permissions to sensitive documents autonomously.
* **Our Defense:**
  - Strict human-in-the-loop guarantee: The AI suggestion engine produces recommendations (`/api/ai/suggest-permissions`), but has **zero write permissions** to the `permissions` table.
  - Every access grant requires explicit human confirmation via `POST /api/documents/{id}/permissions`.
  - Both the suggestion generation and the human confirmation are recorded in the audit trail.
* **Test Verification:** `test_ai_advisor_requires_human_confirmation_and_audits` in `tests/test_ai_advisor.py`.

---

## Consciously Accepted Risks & Future Enhancements

1. **Client-Side Document Exfiltration after Download:**
   - *Risk:* Once a legitimate user downloads a decrypted PDF, they can forward it via personal email or photograph the screen.
   - *Rationale:* TrustVault is a document sharing and provenance platform, not an endpoint DLP/DRM agent. Mitigated by dynamic user watermarking in enterprise tiers.
2. **Database Superuser Audit Truncation:**
   - *Risk:* A malicious root DBA could wipe the entire database including the genesis audit record.
   - *Mitigation in Production:* Stream hash checkpoints to an external write-once-read-many (WORM) storage bucket (e.g. AWS S3 Object Lock) or public timestamp ledger.
3. **In-Memory Rate Limiting across Distributed Clusters:**
   - *Risk:* The current sliding-window rate limiter is in-memory per node.
   - *Mitigation in Production:* Use Redis cluster (`redis-py`) for distributed rate limiting across horizontal pods.
