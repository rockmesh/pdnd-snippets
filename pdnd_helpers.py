
import hashlib
import base64
import uuid
from jose import jwt
from jose.constants import Algorithms
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

# ==========================================================================
# Sicurezza ModI: Digest, Agid-JWT-Signature, Agid-JWT-TrackingEvidence
# ==========================================================================

def calcola_digest(body: bytes) -> str:
    """Header HTTP 'Digest' (RFC 3230) sul body della richiesta (o su b'' per le GET)."""
    digest_bytes = hashlib.sha256(body).digest()
    digest_b64 = base64.b64encode(digest_bytes).decode("ascii")
    return f"SHA-256={digest_b64}"


def crea_agid_jwt_signature(
    audience: str,
    digest_header: str,
    content_type: Optional[str],
    kid: str,
    alg: str,
    private_key: str,
    validity_seconds: int = 60,
) -> str:
    """JWS per l'header 'Agid-JWT-Signature' (pattern INTEGRITY_REST_02)."""
    now = datetime.now(timezone.utc)
    signed_headers = [{"digest": digest_header}]
    if content_type:
        signed_headers.append({"content-type": content_type})
    payload = {
        "aud": audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=validity_seconds)).timestamp()),
        "signed_headers": signed_headers,
    }
    jose_headers = {"alg": alg, "typ": "JWT", "kid": kid}
    return jwt.encode(payload, private_key, algorithm=alg, headers=jose_headers)


def crea_agid_jwt_tracking_evidence(
    issuer: str,
    subject: str,
    audience: str,
    purpose_id: str,
    user_id: str,
    user_location: str,
    loa: str,
    kid: str,
    alg: str,
    private_key: str,
    validity_seconds: int = 60,
) -> str:
    """JWS per l'header 'Agid-JWT-TrackingEvidence' (pattern AUDIT_REST_01)."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=validity_seconds)).timestamp()),
        "jti": str(uuid.uuid4()),
        "purposeId": purpose_id,
        "userID": user_id,
        "userLocation": user_location,
        "LoA": loa,
    }
    jose_headers = {"alg": alg, "typ": "JWT", "kid": kid}
    return jwt.encode(payload, private_key, algorithm=alg, headers=jose_headers)


def _crea_header_sicurezza(
    url: str,
    body_bytes: bytes,
    content_type: Optional[str],
    config: dict,
    private_key: str,
    user_id: str,
    user_location: str,
    loa: str,
) -> Dict[str, str]:
    """Costruisce Digest + Agid-JWT-Signature + Agid-JWT-TrackingEvidence per una chiamata."""
    security_cfg = config["security"]
    eservice_cfg = config["eservice"]

    digest_header = calcola_digest(body_bytes)

    agid_jwt_signature = crea_agid_jwt_signature(
        audience=url,
        digest_header=digest_header,
        content_type=content_type,
        kid=security_cfg["kid"],
        alg=security_cfg["alg"],
        private_key=private_key,
    )

    agid_jwt_tracking_evidence = crea_agid_jwt_tracking_evidence(
        issuer=eservice_cfg["issuer"],
        subject=eservice_cfg["subject"],
        audience=url,
        purpose_id=eservice_cfg["purposeId"],
        user_id=user_id,
        user_location=user_location,
        loa=loa,
        kid=security_cfg["kid"],
        alg=security_cfg["alg"],
        private_key=private_key,
    )

    return {
        "Digest": digest_header,
        "Agid-JWT-Signature": agid_jwt_signature,
        "Agid-JWT-TrackingEvidence": agid_jwt_tracking_evidence,
    }
