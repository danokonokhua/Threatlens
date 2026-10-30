from datetime import timedelta
from jose import jwt
from app.models import RoleEnum
from app.auth import get_password_hash, verify_password, create_access_token
from app.config import settings

def test_six_rbac_roles_defined():
    """Verify all 6 canonical roles from Section 11.1 of the PRD are present."""
    expected_roles = {
        "admin",
        "security_engineer",
        "incident_responder",
        "threat_hunter",
        "soc_analyst",
        "executive"
    }
    actual_roles = {r.value for r in RoleEnum}
    assert expected_roles == actual_roles

def test_password_hashing_and_verification():
    """Verify adaptive bcrypt password hashing and verification."""
    password = "Sec0ps_Str0ng_Password!2026"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_jwt_token_claims_and_decoding():
    """Verify JWT access tokens encode user email and RBAC role."""
    user_email = "rachel.ciso@sentinova.com"
    user_role = "executive"
    
    token = create_access_token(
        data={"sub": user_email, "role": user_role},
        expires_delta=timedelta(minutes=15)
    )
    
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert decoded["sub"] == user_email
    assert decoded["role"] == user_role
    assert "exp" in decoded

