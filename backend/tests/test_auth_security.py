"""
Authentication & Login Security Test Suite — TrustVault
Tests Argon2id hashing, brute force rate limiting, password complexity, and token invalidation.
"""
import pytest
from httpx import AsyncClient
from app.utils.security import check_password_strength, verify_password, hash_password


def test_password_strength_enforcement():
    """Verify strong password policy: length, upper, lower, digit, special char."""
    assert check_password_strength("short")[0] is False
    assert check_password_strength("nouppercase123!")[0] is False
    assert check_password_strength("NOLOWERCASE123!")[0] is False
    assert check_password_strength("NoDigitsSpecial!")[0] is False
    assert check_password_strength("NoSpecialChar123")[0] is False
    assert check_password_strength("ValidPassword123!@#")[0] is True


def test_argon2id_hashing():
    """Verify Argon2id produces secure salted hashes and verifies accurately."""
    pwd = "CorrectHorseBatteryStaple123!"
    hashed = hash_password(pwd)
    assert hashed.startswith("$argon2id$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


@pytest.mark.asyncio
async def test_login_rate_limiting_prevents_brute_force(client: AsyncClient, seeded_db):
    """
    SECURITY TEST: Brute Force Protection.
    After 5 consecutive rapid login attempts, the server must throttle with 429 Too Many Requests.
    """
    for i in range(5):
        resp = await client.post(
            "/api/auth/login",
            json={"email": "admin@trustvault.internal", "password": "WrongPasswordAttempt!"}
        )
        assert resp.status_code == 401, f"Attempt {i+1} should return 401"

    # 6th attempt must be throttled
    throttled = await client.post(
        "/api/auth/login",
        json={"email": "admin@trustvault.internal", "password": "WrongPasswordAttempt!"}
    )
    assert throttled.status_code == 429, f"6th attempt must be rate-limited, got {throttled.status_code}"
    assert "Too many failed login attempts" in throttled.json()["detail"]


@pytest.mark.asyncio
async def test_password_change_invalidates_all_active_tokens(client: AsyncClient, seeded_db):
    """
    SECURITY TEST: Password change immediately increments token_generation,
    revoking all existing tokens.
    """
    # 1. Login Bob
    login_resp = await client.post(
        "/api/auth/login",
        json={"email": "bob@trustvault.internal", "password": "ViewerPass123!@#"}
    )
    assert login_resp.status_code == 200
    old_token = login_resp.json()["access_token"]

    # 2. Bob changes his password
    change_resp = await client.put(
        "/api/auth/password",
        json={"current_password": "ViewerPass123!@#", "new_password": "NewSecretPass456!@#"},
        headers={"Authorization": f"Bearer {old_token}"}
    )
    assert change_resp.status_code == 200

    # 3. Bob's old token MUST now be rejected with 401
    me_resp = await client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {old_token}"}
    )
    assert me_resp.status_code == 401
    assert "revoked" in me_resp.json()["detail"].lower()
