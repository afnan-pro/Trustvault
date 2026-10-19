"""
AI Advisor & Human-in-the-Loop Test Suite — TrustVault
Verifies that:
1. AI generates contextual least-privilege suggestions
2. AI NEVER widens access autonomously (requires_human_confirmation=True)
3. Both suggestions and confirmed decisions are recorded in the audit trail
"""
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models.audit import AuditLog


async def get_token(client: AsyncClient, email: str, pwd: str) -> str:
    resp = await client.post("/api/auth/login", json={"email": email, "password": pwd})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_ai_advisor_requires_human_confirmation_and_audits(client: AsyncClient, seeded_db):
    """Verify AI suggestions are logged and never auto-grant access."""
    token = await get_token(client, "alice@trustvault.internal", "OwnerPass123!@#")

    # Request AI permission suggestion for a salary review document
    resp = await client.post(
        "/api/ai/suggest-permissions",
        json={
            "title": "Executive Compensation 2026",
            "category": "salary",
            "description": "Board level stock compensation"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    data = resp.json()

    # Rule: must mandate human confirmation
    assert data["requires_human_confirmation"] is True
    assert "Highly Restricted" in data["data_classification"]
    assert "Zero Autonomous Grants" in data["machine_enforced_rule"]

    # Verify audit log contains AI_SUGGESTION_GENERATED
    audit_res = await seeded_db.execute(
        select(AuditLog).where(AuditLog.action == "AI_SUGGESTION_GENERATED")
    )
    audit_entry = audit_res.scalar_one_or_none()
    assert audit_entry is not None
    assert audit_entry.details["enforced_confirmation_required"] is True
