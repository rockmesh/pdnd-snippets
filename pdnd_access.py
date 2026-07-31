"""
Implementazione dei pattern di sicurezza ModI (AgID) per la chiamata
a servizi REST erogati da PA tramite PDND:

- ID_AUTH_CHANNEL_01  -> canale HTTPS/TLS con verifica del certificato server
- INTEGRITY_REST_02   -> integrita' del payload tramite header 'Digest' +
                         JWS 'Agid-JWT-Signature' (kid riferito alla PDND)
- AUDIT_REST_01       -> tracciamento della provenienza tramite JWS
                         'Agid-JWT-TrackingEvidence' (userID, userLocation, LoA)

NB: l'access token (voucher) ottenuto dalla PDND tramite client_credentials
(pattern ID_AUTH_REST_01) NON viene generato qui: si presume gia' disponibile
(vedi lo script separato per la chiamata a auth.interop.pagopa.it/token.oauth2).
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta

import jwt  # PyJWT
import requests
import yaml


# --------------------------------------------------------------------------
# Caricamento configurazione
# --------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Carica il file YAML con i parametri di sicurezza e di e-service."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_private_key(path: str) -> str:
    """Carica la chiave privata (PEM) usata per firmare i JWT/JWS."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------------------------
# INTEGRITY_REST_02 - Integrita' del payload
# --------------------------------------------------------------------------

def calcola_digest(body: bytes) -> str:
    """
    Calcola l'header HTTP 'Digest' (RFC 3230) sul body della richiesta.
    E' il valore che viene poi firmato all'interno del JWS Agid-JWT-Signature.
    """
    digest_bytes = hashlib.sha256(body).digest()
    digest_b64 = base64.b64encode(digest_bytes).decode("ascii")
    return f"SHA-256={digest_b64}"


def crea_agid_jwt_signature(
    audience: str,
    digest_header: str,
    content_type: str,
    kid: str,
    alg: str,
    private_key: str,
    validity_seconds: int = 60,
) -> str:
    """
    Genera il JWS da inserire nell'header 'Agid-JWT-Signature' (pattern
    INTEGRITY_REST_02). Il claim 'signed_headers' contiene gli header HTTP
    protetti dalla firma (Digest e Content-Type sono sempre obbligatori
    quando presenti). Il 'kid' nell'header JOSE referenzia il certificato
    depositato sul portachiavi PDND (non serve piu' includere x5c/x5t/x5u).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "aud": audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=validity_seconds)).timestamp()),
        "signed_headers": [
            {"digest": digest_header},
            {"content-type": content_type},
        ],
    }
    jose_headers = {
        "alg": alg,
        "typ": "JWT",
        "kid": kid,
    }
    return jwt.encode(payload, private_key, algorithm=alg, headers=jose_headers)


# --------------------------------------------------------------------------
# AUDIT_REST_01 - Tracciamento della provenienza
# --------------------------------------------------------------------------

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
    validity_seconds: int = 600,
) -> str:
    """
    Genera il JWS da inserire nell'header 'Agid-JWT-TrackingEvidence'
    (pattern AUDIT_REST_01). Permette all'erogatore di identificare la
    provenienza specifica della richiesta all'interno del dominio fruitore:
    - userID: identificativo univoco dell'utente/operatore interno
    - userLocation: identificativo della postazione/applicativo interno
    - LoA: livello di garanzia dell'autenticazione informatica adottata
    """
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
    jose_headers = {
        "alg": alg,
        "typ": "JWT",
        "kid": kid,
    }
    return jwt.encode(payload, private_key, algorithm=alg, headers=jose_headers)


# --------------------------------------------------------------------------
# Orchestrazione della chiamata REST completa
# --------------------------------------------------------------------------

def chiama_servizio_pdnd(
    url: str,
    body: dict,
    access_token: str,
    config: dict,
    private_key: str,
    user_id: str,
    user_location: str,
    loa: str = "2",
) -> requests.Response:
    """
    Esegue la chiamata REST al servizio erogatore applicando i pattern:
    - ID_AUTH_CHANNEL_01: HTTPS con verifica del certificato server
      (gestito nativamente da 'requests' con verify=True, valore di default)
    - INTEGRITY_REST_02: header 'Digest' + 'Agid-JWT-Signature'
    - AUDIT_REST_01: header 'Agid-JWT-TrackingEvidence'

    'access_token' e' il voucher gia' ottenuto dalla PDND (ID_AUTH_REST_01),
    da passare come Bearer nell'header Authorization.
    """
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    content_type = "application/json"

    digest_header = calcola_digest(body_bytes)

    security_cfg = config["security"]
    eservice_cfg = config["eservice"]

    # L'audience del JWS di integrita'/audit e' l'URL del servizio erogatore,
    # non l'audience usata per ottenere il voucher OAuth2 dalla PDND.
    service_audience = url

    agid_jwt_signature = crea_agid_jwt_signature(
        audience=service_audience,
        digest_header=digest_header,
        content_type=content_type,
        kid=security_cfg["kid"],
        alg=security_cfg["alg"],
        private_key=private_key,
    )

    agid_jwt_tracking_evidence = crea_agid_jwt_tracking_evidence(
        issuer=eservice_cfg["issuer"],
        subject=eservice_cfg["subject"],
        audience=service_audience,
        purpose_id=eservice_cfg["purposeId"],
        user_id=user_id,
        user_location=user_location,
        loa=loa,
        kid=security_cfg["kid"],
        alg=security_cfg["alg"],
        private_key=private_key,
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": content_type,
        "Accept": "application/json",
        "Digest": digest_header,
        "Agid-JWT-Signature": agid_jwt_signature,
        "Agid-JWT-TrackingEvidence": agid_jwt_tracking_evidence,
    }

    # ID_AUTH_CHANNEL_01: verify=True impone la validazione del certificato
    # TLS del server (NON usare mai verify=False in produzione).
    response = requests.post(url, data=body_bytes, headers=headers, verify=True)
    return response


# --------------------------------------------------------------------------
# Esempio d'uso
# --------------------------------------------------------------------------

if __name__ == "__main__":
    config = load_config("config.yaml")
    private_key = load_private_key("private_key.pem")

    response = chiama_servizio_pdnd(
        url="URL_SERVIZIO_CHE_VUOI_CHIAMARE",
        body={"param1": "value1"},
        access_token="IL_TUO_VOUCHER_OTTENUTO_DALLA_PDND",  # vedi client_credentials
        config=config,
        private_key=private_key,
        user_id="operatore.rossi",       # identificativo utente/operatore interno
        user_location="postazione-01",   # identificativo postazione/applicativo interno
        loa="2",                          # livello di garanzia dell'autenticazione
    )

    print(response.status_code)
    print(response.text)
