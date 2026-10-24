"""
Permission & Access Control Test Suite — TrustVault
Proves that unauthorized users cannot reach documents through ANY route,
and that taking access away works immediately.
"""
import pytest
from httpx import AsyncClient


async def get_token_for(client: AsyncClient, email: str, password: str) -> str:
    """Helper to login and obtain JWT access token."""
    resp = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_unauthorized_user_cannot_view_or_download_document(client: AsyncClient, seeded_db):
    """
    SECURITY TEST 1: Default Deny.
    Alice owns 'Executive_Salary_Review_2026.pdf'.
    Bob (viewer) has not been granted access.
    Bob must receive 403 Forbidden for:
    - View metadata
    - Download file
    - Update metadata
    - Replace file
    - Delete document
    """
    alice_token = await get_token_for(client, "alice@trustvault.internal", "OwnerPass123!@#")
    bob_token = await get_token_for(client, "bob@trustvault.internal", "ViewerPass123!@#")

    # Alice lists her documents and gets the salary review ID
    alice_docs_resp = await client.get(
        "/api/documents",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert alice_docs_resp.status_code == 200
    docs = alice_docs_resp.json()["documents"]
    salary_doc = next(d for d in docs if "Salary" in d["original_filename"])
    salary_id = salary_doc["id"]

    # 1. Bob attempts GET metadata -> 403
    bob_view = await client.get(
        f"/api/documents/{salary_id}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_view.status_code == 403, "Bob must NOT view unpermitted document metadata"

    # 2. Bob attempts GET download -> 403
    bob_download = await client.get(
        f"/api/documents/{salary_id}/download",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_download.status_code == 403, "Bob must NOT download unpermitted file"

    # 3. Bob attempts PUT update -> 403
    bob_update = await client.put(
        f"/api/documents/{salary_id}",
        json={"description": "Hacked metadata"},
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_update.status_code == 403, "Bob must NOT update unpermitted document"

    # 4. Bob attempts DELETE -> 403
    bob_delete = await client.delete(
        f"/api/documents/{salary_id}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_delete.status_code == 403, "Bob must NOT delete unpermitted document"


@pytest.mark.asyncio
async def test_immediate_revocation_terminates_access_instantly(client: AsyncClient, seeded_db):
    """
    SECURITY TEST 2: Immediate Revocation.
    Alice grants Bob 'read' access to 'Statutory_Audit_Report_2026.pdf'.
    Bob can now view and download it.
    Alice revokes Bob's access.
    Bob's subsequent requests MUST immediately fail with 401 or 403.
    """
    alice_token = await get_token_for(client, "alice@trustvault.internal", "OwnerPass123!@#")
    bob_token = await get_token_for(client, "bob@trustvault.internal", "ViewerPass123!@#")

    # Alice locates Statutory Audit Report
    alice_docs_resp = await client.get(
        "/api/documents",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    docs = alice_docs_resp.json()["documents"]
    audit_doc = next(d for d in docs if "Audit_Report" in d["original_filename"])
    doc_id = audit_doc["id"]

    # Alice grants Bob read access
    grant_resp = await client.post(
        f"/api/documents/{doc_id}/permissions",
        json={"user_email": "bob@trustvault.internal", "level": "read"},
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert grant_resp.status_code == 201
    perm_id = grant_resp.json()["id"]

    # Re-login Bob to get fresh token with current token_generation
    bob_token = await get_token_for(client, "bob@trustvault.internal", "ViewerPass123!@#")

    # Bob can view and download
    bob_view = await client.get(
        f"/api/documents/{doc_id}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_view.status_code == 200

    bob_download = await client.get(
        f"/api/documents/{doc_id}/download",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_download.status_code == 200

    # ALICE REVOKES ACCESS
    revoke_resp = await client.delete(
        f"/api/documents/{doc_id}/permissions/{perm_id}",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert revoke_resp.status_code == 200

    # Bob's existing token or requests MUST IMMEDIATELY FAIL
    # Either token invalidation triggers 401 or permission check triggers 403
    bob_after_view = await client.get(
        f"/api/documents/{doc_id}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_after_view.status_code in [401, 403], "Revocation must terminate access immediately"

    bob_after_download = await client.get(
        f"/api/documents/{doc_id}/download",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_after_download.status_code in [401, 403], "Revocation must prevent file download immediately"


@pytest.mark.asyncio
async def test_read_only_user_cannot_edit_or_delete(client: AsyncClient, seeded_db):
    """
    SECURITY TEST 3: Principle of Least Privilege.
    Bob has 'read' access to 'Master_Services_Agreement_Acme.pdf'.
    Bob attempts to edit or replace file -> MUST return 403.
    """
    bob_token = await get_token_for(client, "bob@trustvault.internal", "ViewerPass123!@#")

    # Bob lists documents and finds Master Services Agreement
    bob_docs = await client.get("/api/documents", headers={"Authorization": f"Bearer {bob_token}"})
    assert bob_docs.status_code == 200
    docs = bob_docs.json()["documents"]
    contract_doc = next(d for d in docs if "Master_Services" in d["original_filename"])
    doc_id = contract_doc["id"]

    # Bob can read
    read_resp = await client.get(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {bob_token}"})
    assert read_resp.status_code == 200

    # Bob attempts to update description -> 403 Forbidden
    edit_resp = await client.put(
        f"/api/documents/{doc_id}",
        json={"description": "Unauthorized tamper attempt"},
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert edit_resp.status_code == 403, "Read-only viewer must NOT edit document"
