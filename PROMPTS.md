# AI Engineering Interaction & Correction Log (`PROMPTS.md`)

This log documents the interaction history, prompts directed to AI coding assistants during the TrustVault build, specific critical security/architectural flaws identified in AI-generated code, and the corrective actions implemented.

---

## Entry 1: Cryptographic Audit Hash Chaining & Cross-Database Timestamp Formatting
* **Date:** 2026-10-19
* **Topic:** Audit Trail & Cryptographic Verification
* **What was asked:**
  > "Implement an append-only audit log with SHA-256 hash chaining where each entry's hash includes the previous entry's hash and the record timestamp, and write a verification function to check chain integrity."
* **What the AI produced:**
  The AI computed the hash using Python's `datetime.now(timezone.utc).isoformat()` when inserting the log entry into the database, and during `verify_integrity()`, it recomputed the hash using `entry.created_at.isoformat()`.
* **What was wrong with it specifically:**
  In SQLite and different PostgreSQL database drivers, `DateTime(timezone=True)` columns serialize and deserialize differently. In SQLite, Python stores `'2026-10-19 18:01:25.123456'`, stripping the `+00:00` timezone offset and altering microsecond formatting. When read back in `verify_integrity()`, `entry.created_at.isoformat()` returned `'2026-10-19T18:01:25.123456'` instead of the original `'2026-10-19T18:01:25.123456+00:00'`. This non-canonical representation produced completely mismatched SHA-256 hashes, causing valid, untampered audit chains to falsely fail verification on Block #1!
* **What was done instead:**
  Created a deterministic `AuditLog.normalize_timestamp()` method that strips microsecond variance and formats timestamps canonically as UTC `YYYY-MM-DDTHH:MM:SSZ`. Both the insertion hash calculation in `AuditService.log()` and the verification algorithm in `AuditService.verify_integrity()` now pass through this canonicalizer, guaranteeing 100% deterministic cryptographic hashing across all SQL engines. Verified with `test_audit_hash_chain_intact`.

---

## Entry 2: Zombie JWT Tokens on Immediate Revocation
* **Date:** 2026-10-19
* **Topic:** Authorization & Access Control
* **What was asked:**
  > "How can we make taking access away work immediately when using stateless JWT tokens?"
* **What the AI produced:**
  The AI suggested simply setting a short token expiration (15 minutes) and updating the `Permission.is_revoked = True` column in the database, claiming: *"Once the token expires in 15 minutes, the user will have to refresh and will be denied."*
* **What was wrong with it specifically:**
  This violated Non-Negotiable Requirement Three: *"Taking access away works immediately. Whatever you have issued to that person before that moment stops working."* A 15-minute vulnerability window allows an attacker or terminated employee to download dozens of confidential documents using their unexpired token.
* **What was done instead:**
  Implemented dual immediate revocation:
  1. Every document route checks the live `Permission` record in the database synchronously on every request.
  2. Implemented a `token_generation` integer column on the `User` model. When an owner revokes access or an admin deactivates an account, `user.token_generation` is incremented. The `get_current_user` middleware compares `payload["tg"] == user.token_generation`. Any token issued prior to the revocation instant fails authentication immediately with `HTTP 401`. Verified with `test_immediate_revocation_terminates_access_instantly`.

---

## Entry 3: Async SQLAlchemy Lazy-Loading `MissingGreenlet` in Endpoint Serialization
* **Date:** 2026-10-19
* **Topic:** Backend Architecture & Performance
* **What was asked:**
  > "Add relationship between Document and User owner so document responses include the owner's full name."
* **What the AI produced:**
  `owner = relationship("User", back_populates="documents")` using default lazy loading, and in `_build_doc_response`: `owner_name = doc.owner.full_name`.
* **What was wrong with it specifically:**
  In SQLAlchemy 2.0 async mode with `AsyncSession`, accessing `doc.owner` triggers a synchronous lazy query outside an async greenlet context, crashing the request with:
  `sqlalchemy.exc.MissingGreenlet: greenlet_spawn has not been called; can't call await_only() here. Was IO attempted in an unexpected place?`
  This crashed both document listing and retrieval routes during concurrent requests.
* **What was done instead:**
  Configured `lazy="selectin"` on `Document.owner` and `Document.permissions` (`owner = relationship("User", back_populates="documents", lazy="selectin")`). This instructs SQLAlchemy to emit an async `SELECT ... IN` query eagerly during the primary query, eliminating lazy IO during Pydantic response model validation.

---

## Entry 4: Global Rate Limiting State Bleeding Across Automated Pytest Executions
* **Date:** 2026-10-19
* **Topic:** Security Testing & Rate Limiting
* **What was asked:**
  > "Create an in-memory rate limiter middleware for `/api/auth/login` to prevent brute force attacks, and write a test confirming 429 Too Many Requests after 5 rapid attempts."
* **What the AI produced:**
  A module-level dictionary `_rate_limits: Dict[str, list[float]] = {}` in `main.py` tracking timestamps by client IP.
* **What was wrong with it specifically:**
  When `pytest` ran `test_login_rate_limiting_prevents_brute_force`, it fired 6 rapid requests from IP `'testclient'`. Because `_rate_limits` was global and never reset between test functions, `'testclient'` remained throttled for 60 seconds, causing all subsequent tests in `test_permissions.py` attempting to log in as Alice or Bob to fail with `HTTP 429 Too Many Requests`.
* **What was done instead:**
  Updated `conftest.py`'s `client` fixture to explicitly import and clear `_rate_limits.clear()` before each test function runs, isolating each test's rate-limiting envelope while preserving real-world throttling behavior in production.

---

## Entry 5: AI Permission Assistant Autonomous Privilege Escalation
* **Date:** 2026-10-19
* **Topic:** AI Boundary & Security Policy
* **What was asked:**
  > "Build an AI agent that automatically assigns viewers to new documents uploaded to TrustVault based on category."
* **What the AI produced:**
  A background hook that invoked an LLM completion and directly inserted `Permission` records into the database upon document upload.
* **What was wrong with it specifically:**
  This directly violated the core design constraint: *"If you want AI inside the product, the obvious place is helping an owner decide who should see a document. A suggestion is useful. The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit."* Autonomous grant generation is vulnerable to prompt injection, confused deputy attacks, and data leakage.
* **What was done instead:**
  Built a sandboxed recommendation endpoint `POST /api/ai/suggest-permissions` that returns structured recommendations with data classifications and confidence scores. The model has **zero write capability**. Grants must be explicitly reviewed and confirmed by an authorized human, and both `AI_SUGGESTION_GENERATED` and the human `PERMISSION_GRANT` are immutably logged into the audit chain. Verified with `test_ai_advisor_requires_human_confirmation_and_audits`.
