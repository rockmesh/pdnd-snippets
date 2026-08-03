
import hashlib
import base64
import uuid
import datetime
import requests
import yaml

from jose import jwt
from jose.constants import Algorithms
#from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

# ==========================================================================
# Helper functions 
# ==========================================================================
def yaml_load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_yaml_value(config: dict, *keys, default=None):
    """Naviga dizionari annidati in sicurezza, es: get(config, 'security', 'kid')"""
    d = config
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d

def get_private_key(key_path):
  with open(key_path, "rb") as private_key:
    encoded_string = private_key.read()
    return encoded_string





def calcola_digest(body: bytes) -> str:
    """Header HTTP 'Digest' (RFC 3230) sul body della richiesta (o su b'' per le GET)."""
    digest_bytes = hashlib.sha256(body).digest()
    digest_b64 = base64.b64encode(digest_bytes).decode("ascii")
    return f"SHA-256={digest_b64}"

# ==========================================================================
# PDND: funzionalità base
# ==========================================================================
def get_client_assertion(config_path : str, key_path : str):
    """ Richiede la client assertion sulla base dello yaml di configurazione (config_path). Vedi UI di PDND"""
    config = yaml_load_config(config_path)
    kid = get_yaml_value(config, "security", "kid")
    alg = get_yaml_value(config, "security", "alg")
    typ = get_yaml_value(config, "security", "typ")
    issuer = get_yaml_value(config, "eservice", "issuer")
    subject = get_yaml_value(config, "eservice", "subject")
    audience = "auth.interop.pagopa.it/client-assertion"
    purposeId = get_yaml_value(config, "eservice", "purposeId")

    issued = datetime.datetime.utcnow()
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    jti = uuid.uuid4()

    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
        }

    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "purposeId": purposeId,
        "jti": str(jti),
        "iat": issued,
        "exp": expire_in
        }

    rsaKey = get_private_key(key_path)
    client_assertion = jwt.encode(payload, rsaKey, algorithm=Algorithms.RS256, headers=headers_rsa)
    return client_assertion


def get_JWT_token(client_assertion):
    """ Richiede il jwt token a PDND passando la client assertion """
    url = "https://auth.interop.pagopa.it/token.oauth2"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "client_id": "59e9b50f-282a-48ee-9494-5c4baf952efd",
        "client_assertion": client_assertion,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "grant_type": "client_credentials"
    }

    response = requests.post(url, headers=headers, data=data)
    return response


# ==========================================================================
# Sicurezza ModI: Digest, Agid-JWT-Signature, Agid-JWT-TrackingEvidence
# ==========================================================================

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
    now = datetime.datetime.now(datetime.timezone.utc)
    signed_headers = [{"digest": digest_header}]
    if content_type:
        signed_headers.append({"content-type": content_type})
    payload = {
        "aud": audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=validity_seconds)).timestamp()),
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
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=validity_seconds)).timestamp()),
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
