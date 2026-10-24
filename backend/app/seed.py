"""
Seed Data Script — TrustVault
Populates standard demonstration credentials, sample confidential files,
and a verified cryptographic audit chain.
"""
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.document import Document
from app.models.permission import Permission
from app.services.auth_service import AuthService
from app.services.document_service import DocumentService
from app.services.permission_service import PermissionService
from app.services.audit_service import AuditService

DEMO_CREDENTIALS = [
    {
        "email": "admin@trustvault.internal",
        "full_name": "Eleanor Vance (Security Officer)",
        "password": "AdminPass123!@#",
        "role": "admin"
    },
    {
        "email": "alice@trustvault.internal",
        "full_name": "Alice Wright (Head of Operations)",
        "password": "OwnerPass123!@#",
        "role": "owner"
    },
    {
        "email": "bob@trustvault.internal",
        "full_name": "Bob Jenkins (Finance & Audit Analyst)",
        "password": "ViewerPass123!@#",
        "role": "viewer"
    },
    {
        "email": "charlie@client.corp",
        "full_name": "Charlie Zhang (External Legal Counsel)",
        "password": "PartnerPass123!@#",
        "role": "viewer"
    }
]


async def seed_database(db: AsyncSession):
    """Seed users, documents, permissions, and audit chain if empty."""
    user_count_q = await db.execute(select(func.count(User.id)))
    if user_count_q.scalar_one() > 0:
        return  # Already seeded

    print("Seeding TrustVault demo personas...")
    users = {}
    for cred in DEMO_CREDENTIALS:
        u = await AuthService.register_user(
            db=db,
            email=cred["email"],
            full_name=cred["full_name"],
            password=cred["password"],
            role=cred["role"],
        )
        users[cred["email"]] = u
        # Log user creation in audit trail
        await AuditService.log(
            db=db,
            action="USER_CREATE",
            user_id=None,
            target_user_id=u.id,
            details={"email": u.email, "role": u.role, "system_seed": True},
            ip_address="127.0.0.1",
            user_agent="TrustVault-SeedEngine/1.0",
            success=True,
        )

    alice = users["alice@trustvault.internal"]
    bob = users["bob@trustvault.internal"]
    charlie = users["charlie@client.corp"]

    # Sample documents content
    sample_files = [
        {
            "filename": "Executive_Salary_Review_2026.pdf",
            "category": "salary",
            "content": b"%PDF-1.4\n1 0 obj\n<< /Title (Executive Salary Review 2026) /Author (Alice Wright) >>\nendobj\nConfidential C-Suite Compensation Letters and Share Allocations for Q3-Q4.",
            "mime_type": "application/pdf",
            "description": "Strictly confidential executive remuneration, bonuses, and severance agreements."
        },
        {
            "filename": "Master_Services_Agreement_Acme.pdf",
            "category": "contracts",
            "content": b"%PDF-1.4\n1 0 obj\n<< /Title (Acme Corp Master Services Agreement) >>\nendobj\nLegally binding SLA, liability caps, and recurring fee terms between TrustVault Inc and Acme Corp.",
            "mime_type": "application/pdf",
            "description": "Multi-year enterprise contract with strict confidentiality and dispute arbitration clauses."
        },
        {
            "filename": "Proprietary_Chipset_Drawing_v4.png",
            "category": "drawings",
            "content": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82",
            "mime_type": "image/png",
            "description": "Engineering architectural CAD schematics for high-assurance hardware security module (HSM)."
        },
        {
            "filename": "Statutory_Audit_Report_2026.pdf",
            "category": "audit",
            "content": b"%PDF-1.4\n1 0 obj\n<< /Title (Statutory Audit Report 2026) >>\nendobj\nIndependent Auditor's Report for regulatory authorities and tax commissioners.",
            "mime_type": "application/pdf",
            "description": "Unqualified independent auditor review assessing SOX compliance and security controls."
        }
    ]

    docs = {}
    for f in sample_files:
        doc = await DocumentService.upload(
            db=db,
            owner=alice,
            file_data=f["content"],
            original_filename=f["filename"],
            mime_type=f["mime_type"],
            category=f["category"],
            description=f["description"],
        )
        docs[f["filename"]] = doc
        await AuditService.log(
            db=db,
            action="UPLOAD",
            user_id=alice.id,
            document_id=doc.id,
            details={
                "filename": f["filename"],
                "category": f["category"],
                "size_bytes": len(f["content"]),
                "encryption": "AES-256-GCM",
            },
            ip_address="192.168.1.42",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrustVault/1.0",
            success=True,
        )

    # Permissions setup:
    # 1. Alice grants Bob Read permission on Master Services Agreement
    contract_doc = docs["Master_Services_Agreement_Acme.pdf"]
    perm1 = await PermissionService.grant_permission(
        db=db,
        document_id=contract_doc.id,
        user_id=bob.id,
        level="read",
        granted_by=alice.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    await AuditService.log(
        db=db,
        action="PERMISSION_GRANT",
        user_id=alice.id,
        document_id=contract_doc.id,
        target_user_id=bob.id,
        details={"level": "read", "target_email": bob.email, "document": contract_doc.original_filename},
        ip_address="192.168.1.42",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        success=True,
    )

    # 2. Alice grants Charlie Edit permission on Master Services Agreement
    perm2 = await PermissionService.grant_permission(
        db=db,
        document_id=contract_doc.id,
        user_id=charlie.id,
        level="edit",
        granted_by=alice.id,
        expires_at=None,
    )
    await AuditService.log(
        db=db,
        action="PERMISSION_GRANT",
        user_id=alice.id,
        document_id=contract_doc.id,
        target_user_id=charlie.id,
        details={"level": "edit", "target_email": charlie.email, "document": contract_doc.original_filename},
        ip_address="192.168.1.42",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        success=True,
    )

    # 3. Alice grants and then revokes Bob on Proprietary Drawing (demonstrating immediate revocation)
    drawing_doc = docs["Proprietary_Chipset_Drawing_v4.png"]
    perm3 = await PermissionService.grant_permission(
        db=db,
        document_id=drawing_doc.id,
        user_id=bob.id,
        level="read",
        granted_by=alice.id,
    )
    await AuditService.log(
        db=db,
        action="PERMISSION_GRANT",
        user_id=alice.id,
        document_id=drawing_doc.id,
        target_user_id=bob.id,
        details={"level": "read", "target_email": bob.email, "document": drawing_doc.original_filename},
        ip_address="192.168.1.42",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        success=True,
    )

    # Alice revokes Bob's permission
    await PermissionService.revoke_permission(
        db=db,
        permission_id=perm3.id,
        document_id=drawing_doc.id,
        revoker=alice,
    )
    await AuditService.log(
        db=db,
        action="PERMISSION_REVOKE",
        user_id=alice.id,
        document_id=drawing_doc.id,
        target_user_id=bob.id,
        details={"reason": "Project phase completed. Immediate access termination enforced.", "document": drawing_doc.original_filename},
        ip_address="192.168.1.42",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        success=True,
    )

    # 4. Refused attempt: Bob tried to access Executive Salary Review (ACCESS DENIED LOGGED)
    salary_doc = docs["Executive_Salary_Review_2026.pdf"]
    await AuditService.log(
        db=db,
        action="VIEW_DENIED",
        user_id=bob.id,
        document_id=salary_doc.id,
        details={"attempted_level": "read", "reason": "No valid permission grant found (Default Deny)"},
        ip_address="192.168.1.99",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        success=False,
    )

    await db.commit()
    print("TrustVault seed data populated successfully with verified audit chain.")
