"""
AI Access Advisor Router — TrustVault
Assists document owners with least-privilege permission recommendations.
CRITICAL SECURITY RULE:
The machine never widens access automatically.
Every suggestion requires explicit human review and confirmation.
Both the AI suggestion and the human decision are written to the immutable audit trail.
"""
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.user import User
from app.models.document import Document
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/ai", tags=["AI Advisor"])


class AISuggestionRequest(BaseModel):
    document_id: Optional[UUID] = None
    title: Optional[str] = None
    category: Optional[str] = "general"
    description: Optional[str] = None


class UserRecommendation(BaseModel):
    user_id: UUID
    user_email: str
    user_name: str
    recommended_level: str  # read, edit
    confidence: float
    justification: str


class AISuggestionResponse(BaseModel):
    document_title: str
    data_classification: str  # Public, Internal, Confidential, Highly Restricted
    sensitivity_summary: str
    recommendations: List[UserRecommendation]
    machine_enforced_rule: str
    requires_human_confirmation: bool = True


@router.post("/suggest-permissions", response_model=AISuggestionResponse)
async def suggest_permissions(
    data: AISuggestionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate an AI-assisted permission proposal for a document.
    Analyzes document category, metadata, and user directory.
    Logs AI_SUGGESTION_GENERATED to the audit trail.
    """
    doc_title = data.title or "Untitled Document"
    category = (data.category or "general").lower()
    desc = (data.description or "").lower()

    if data.document_id:
        doc_res = await db.execute(
            select(Document).where(Document.id == data.document_id, Document.is_deleted == False)
        )
        doc = doc_res.scalar_one_or_none()
        if doc:
            doc_title = doc.original_filename
            category = doc.category.lower() if doc.category else "general"
            desc = (doc.description or "").lower()

    # Determine data classification and rules
    if "salary" in category or "payroll" in category or "salary" in doc_title.lower() or "compensation" in desc:
        classification = "Highly Restricted (HR / Finance)"
        sensitivity_summary = "Document contains personal financial or compensation records. Strictly enforce Read-Only to non-HR personnel."
        restricted_level = "read"
    elif "contract" in category or "agreement" in doc_title.lower() or "nda" in doc_title.lower():
        classification = "Confidential (Legal / Executive)"
        sensitivity_summary = "Legal agreements require dual-role protection. Counterparties/viewers must receive Read-Only; Editors should be strictly internal counsel."
        restricted_level = "read"
    elif "drawing" in category or "patent" in doc_title.lower() or "blueprint" in desc:
        classification = "Confidential (Engineering / IP)"
        sensitivity_summary = "Intellectual property and proprietary technical assets. Reviewers should be limited to verified partners."
        restricted_level = "read"
    elif "audit" in category or "compliance" in doc_title.lower():
        classification = "Regulated (Compliance / Audit)"
        sensitivity_summary = "Regulatory submission or internal audit paper. Evidence integrity must be preserved with strict Read-Only grants."
        restricted_level = "read"
    else:
        classification = "Internal"
        sensitivity_summary = "Standard internal company communication."
        restricted_level = "read"

    # Fetch available active users
    users_res = await db.execute(
        select(User).where(User.is_active == True, User.id != current_user.id)
    )
    users = users_res.scalars().all()

    recommendations = []
    for u in users:
        # Intelligent contextual matching
        is_relevant = False
        confidence = 0.5
        justification = ""

        if classification.startswith("Highly Restricted"):
            if "hr" in u.email or "finance" in u.email or u.role == "admin":
                is_relevant = True
                confidence = 0.92
                justification = "Matches Finance/HR department clearance for compensation documents."
            else:
                is_relevant = False  # Do not suggest general viewers for salary letters!
        elif classification.startswith("Confidential (Legal"):
            if "legal" in u.email or u.role in ["admin", "owner"]:
                is_relevant = True
                confidence = 0.88
                justification = "Authorized for legal review & contract governance."
            elif u.role == "viewer":
                is_relevant = True
                confidence = 0.70
                justification = "External partner/client viewing rights."
        elif classification.startswith("Regulated"):
            if "audit" in u.email or "compliance" in u.email or u.role == "admin":
                is_relevant = True
                confidence = 0.95
                justification = "Designated regulatory auditor."
            elif u.role == "viewer":
                is_relevant = True
                confidence = 0.65
                justification = "Auditee observer access."
        else:
            is_relevant = True
            confidence = 0.75
            justification = f"Standard collaboration access for team member ({u.role})."

        if is_relevant:
            recommendations.append(UserRecommendation(
                user_id=u.id,
                user_email=u.email,
                user_name=u.full_name,
                recommended_level=restricted_level,
                confidence=confidence,
                justification=justification,
            ))

    # Sort by confidence descending
    recommendations.sort(key=lambda r: r.confidence, reverse=True)

    # Immutable Audit Log Entry
    await AuditService.log(
        db=db,
        action="AI_SUGGESTION_GENERATED",
        user_id=current_user.id,
        document_id=data.document_id,
        details={
            "document_title": doc_title,
            "classification": classification,
            "suggested_count": len(recommendations),
            "candidates": [r.user_email for r in recommendations],
            "enforced_confirmation_required": True,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    return AISuggestionResponse(
        document_title=doc_title,
        data_classification=classification,
        sensitivity_summary=sensitivity_summary,
        recommendations=recommendations,
        machine_enforced_rule="Zero Autonomous Grants: An authorized human must explicitly confirm or adjust these selections before access is granted.",
        requires_human_confirmation=True,
    )
