"""
Client per il servizio "Certificazione Casellario Giudiziale - Persone Fisiche"
erogato dal Ministero della Giustizia tramite PDND.

Fonte: Specifica_API_Certificato_Casellario_Giudiziale_-_Persone_fisiche_Ministero_della_Giustizia_v1.json
       + Documentazione_casellario_giudiziale_-_persone_fisiche.pdf

Flusso implementato:
1. POST /richiesta-certificazione  -> invio della richiesta (fino a 100 nominativi)
2. attesa (default 2 minuti, essendo il servizio asincrono)
3. GET  /esiti                     -> polling con paginazione (offset/size) fino ad esaurimento
4. GET  /risposta-certificazione/{identificativoRisposta}
                                    -> SOLO per gli esiti con stato == "COMPLETATO"

Pattern di sicurezza ModI applicati su OGNI chiamata (vedi § 2 del PDF e 'security' nello spec):
- ID_AUTH_CHANNEL_01 : HTTPS (verify=True, mai disattivare in produzione)
- ID_AUTH_REST_01    : Authorization: Bearer <voucher PDND>  (ottenuto altrove, non qui)
- INTEGRITY_REST_02  : header 'Digest' + JWS 'Agid-JWT-Signature'
- AUDIT_REST_01      : JWS 'Agid-JWT-TrackingEvidence' (Username, UserLocation, LoA)

IMPORTANTE - limite del solo codice fiscale:
Lo schema 'DatiNominativoPersonaFisica' richiede obbligatoriamente anche
'cognome', 'nome' e 'sesso'. Cognome e nome NON sono ricavabili in modo
affidabile dal CF (l'algoritmo di generazione non e' invertibile in modo
univoco). Questo client richiede quindi CF + cognome + nome per ciascun
nominativo, e deriva automaticamente da CF: sesso, dataNascita,
codiceCatastoComuneItaliano/codiceCatastoStato (algoritmo verificato contro
l'esempio ufficiale dello spec: RSSMRA80A01H501U -> H501/Z000).

L'unico punto non deducibile con certezza dal solo CF a 2 cifre e' il SECOLO
di nascita (es. '80' potrebbe essere 1980 o 2080): di default si assume che
un anno <= anno corrente a 2 cifre sia nel 2000, altrimenti nel 1900. Se hai
un caso limite (nati proprio a cavallo del cambio secolo), passa
'secolo_hint' esplicitamente.
"""

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

import jwt  # PyJWT
import requests
import yaml


BASE_URL = (
    "https://interoperabilita.giustizia.it/channel01/govway/rest/in/"
    "MinisteroGiustizia/RichiestaCertificazionePersoneFisiche/v1"
)

URL_RICHIESTA = f"{BASE_URL}/richiesta-certificazione"
URL_ESITI = f"{BASE_URL}/esiti"
URL_RISPOSTA = f"{BASE_URL}/risposta-certificazione/{{identificativo_risposta}}"


# ==========================================================================
# Modello dati in input
# ==========================================================================

@dataclass
class Nominativo:
    """Dati minimi richiesti per certificare una persona fisica."""
    cf: str
    cognome: str
    nome: str
    numero_protocollo: str
    data_protocollo: Optional[str] = None     # 'YYYY-MM-DD', default: oggi
    info_da_stampare: Optional[str] = None
    lingua_tedesca: bool = False
    secolo_hint: Optional[int] = None          # 1900 o 2000, per casi limite


# ==========================================================================
# Decodifica parziale del codice fiscale
# ==========================================================================

_MESI_CF = "ABCDEHLMPRST"  # gennaio..dicembre, ordine fisso dell'algoritmo CF


def decodifica_cf(cf: str, secolo_hint: Optional[int] = None) -> Dict[str, Any]:
    """
    Estrae sesso, data di nascita e codice catastale del comune/stato di
    nascita dal codice fiscale (algoritmo standard italiano).
    NON restituisce cognome/nome: non sono ricavabili in modo affidabile.
    """
    cf = cf.strip().upper()
    if len(cf) != 16:
        raise ValueError(f"Codice fiscale di lunghezza non valida: {cf}")

    anno = int(cf[6:8])
    mese_lettera = cf[8]
    giorno_raw = int(cf[9:11])

    if mese_lettera not in _MESI_CF:
        raise ValueError(f"Codice fiscale non valido (carattere mese '{mese_lettera}'): {cf}")
    mese = _MESI_CF.index(mese_lettera) + 1

    sesso = "F" if giorno_raw > 40 else "M"
    giorno = giorno_raw - 40 if giorno_raw > 40 else giorno_raw

    if secolo_hint:
        secolo = secolo_hint
    else:
        anno_corrente_2cifre = datetime.now().year % 100
        secolo = 2000 if anno <= anno_corrente_2cifre else 1900
    anno_completo = secolo + anno

    data_nascita = f"{anno_completo:04d}-{mese:02d}-{giorno:02d}"

    codice_catasto = cf[11:15]
    if codice_catasto.startswith("Z"):
        # nato all'estero: cf[11:15] è già il codice catastale dello Stato estero
        codice_catasto_comune = None
        codice_catasto_stato = codice_catasto
    else:
        # nato in Italia: cf[11:15] è il codice catastale del comune;
        # codiceCatastoStato è valorizzato a 'Z000' (confermato dall'esempio
        # ufficiale dello spec per un nominativo nato in Italia)
        codice_catasto_comune = codice_catasto
        codice_catasto_stato = "Z000"

    return {
        "sesso": sesso,
        "dataNascita": data_nascita,
        "codiceCatastoComuneItaliano": codice_catasto_comune,
        "codiceCatastoStato": codice_catasto_stato,
    }


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


# ==========================================================================
# Costruzione del payload di richiesta
# ==========================================================================

def _costruisci_payload_richiesta(identificativo_richiesta: str, nominativi: List[Nominativo]) -> dict:
    oggi = datetime.now().strftime("%Y-%m-%d")
    nominativi_richiesti = []
    for i, n in enumerate(nominativi, start=1):
        dati_cf = decodifica_cf(n.cf, secolo_hint=n.secolo_hint)
        nominativi_richiesti.append({
            "progressivoNominativo": str(i),
            "datiNominativo": {
                "cognome": n.cognome,
                "nome": n.nome,
                "sesso": dati_cf["sesso"],
                "cf": n.cf.strip().upper(),
                "cui": None,
                "dataNascita": dati_cf["dataNascita"],
                "annoNascita": None,
                "codiceCatastoComuneItaliano": dati_cf["codiceCatastoComuneItaliano"],
                "codiceCatastoStato": dati_cf["codiceCatastoStato"],
            },
            "altriDati": {
                "infoDaStampare": n.info_da_stampare,
                "infoDaRestituire": None,
                "linguaTedesca": n.lingua_tedesca,
                "numeroProtocollo": n.numero_protocollo,
                "dataProtocollo": n.data_protocollo or oggi,
            },
        })

    return {
        "datiRichiesta": {
            "identificativoRichiesta": identificativo_richiesta,
            "dataRichiesta": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        },
        "nominativiRichiesti": nominativi_richiesti,
    }


# ==========================================================================
# Client principale
# ==========================================================================

class CasellarioClient:
    def __init__(
        self,
        access_token: str,
        config: dict,
        private_key: str,
        user_id: str,
        user_location: str,
        loa: str = "2",
        session: Optional[requests.Session] = None,
    ):
        """
        access_token : voucher Bearer già ottenuto dalla PDND (client_credentials)
        config       : dict caricato dal config.yaml (sezioni 'security' ed 'eservice')
        private_key  : chiave privata PEM corrispondente al 'kid' in config['security']
        user_id, user_location, loa : claim per AUDIT_REST_01
        """
        self.access_token = access_token
        self.config = config
        self.private_key = private_key
        self.user_id = user_id
        self.user_location = user_location
        self.loa = loa
        self.session = session or requests.Session()

    def _headers_comuni(self, url: str, body_bytes: bytes, content_type: Optional[str]) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }
        if content_type:
            headers["Content-Type"] = content_type
        headers.update(_crea_header_sicurezza(
            url=url,
            body_bytes=body_bytes,
            content_type=content_type,
            config=self.config,
            private_key=self.private_key,
            user_id=self.user_id,
            user_location=self.user_location,
            loa=self.loa,
        ))
        return headers

    # ---------------------------------------------------------------- #

    def invia_richiesta(self, identificativo_richiesta: str, nominativi: List[Nominativo]) -> str:
        """POST /richiesta-certificazione. Ritorna l'identificativoRichiesta confermato."""
        if not (1 <= len(nominativi) <= 100):
            raise ValueError("Il servizio accetta da 1 a 100 nominativi per richiesta.")

        payload = _costruisci_payload_richiesta(identificativo_richiesta, nominativi)
        body_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        headers = self._headers_comuni(URL_RICHIESTA, body_bytes, "application/json")
        resp = self.session.post(URL_RICHIESTA, data=body_bytes, headers=headers, verify=True, timeout=30)

        if resp.status_code != 202:
            raise RuntimeError(f"Richiesta non accettata (HTTP {resp.status_code}): {resp.text}")

        ack = resp.json()
        return ack["identificativoRichiesta"]

    # ---------------------------------------------------------------- #

    def poll_esiti(self, size: int = 100, max_iterazioni: int = 50) -> List[dict]:
        """
        GET /esiti in paginazione (offset/size) fino ad esaurimento
        (HTTP 200 = nessun ulteriore esito disponibile in questo momento).
        Ritorna TUTTI gli esiti restituiti dal servizio per l'ente/finalità
        (non solo quelli della richiesta corrente: vanno poi filtrati per
        identificativoRichiesta, vedi richiedi_certificati()).
        """
        esiti: List[dict] = []
        offset = 0
        for _ in range(max_iterazioni):
            body_bytes = b""  # GET senza body: Digest calcolato sul body vuoto
            url_con_query = f"{URL_ESITI}?offset={offset}&size={size}"
            headers = self._headers_comuni(url_con_query, body_bytes, content_type=None)

            resp = self.session.get(url_con_query, headers=headers, verify=True, timeout=30)

            if resp.status_code not in (200, 206):
                raise RuntimeError(f"Errore nel polling esiti (HTTP {resp.status_code}): {resp.text}")

            dati = resp.json()
            pagina_esiti = dati.get("esiti", [])
            esiti.extend(pagina_esiti)

            if resp.status_code == 200:
                # nessun ulteriore esito disponibile al momento
                break

            last_offset = dati.get("lastOffset")
            if last_offset is None or not pagina_esiti:
                break
            offset = last_offset
        return esiti

    # ---------------------------------------------------------------- #

    def recupera_risposta(self, identificativo_risposta: str) -> dict:
        """GET /risposta-certificazione/{identificativoRisposta}."""
        url = URL_RISPOSTA.format(identificativo_risposta=identificativo_risposta)
        body_bytes = b""
        headers = self._headers_comuni(url, body_bytes, content_type=None)

        resp = self.session.get(url, headers=headers, verify=True, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Errore nel recupero risposta (HTTP {resp.status_code}): {resp.text}")
        return resp.json()

    # ---------------------------------------------------------------- #

    def richiedi_certificati(
        self,
        identificativo_richiesta: str,
        nominativi: List[Nominativo],
        attesa_secondi: int = 120,
        salva_pdf_in: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Orchestrazione completa:
        1. invia la richiesta
        2. attende 'attesa_secondi' (default 2 minuti)
        3. fa polling su /esiti
        4. per ogni esito COMPLETATO relativo a questa richiesta, scarica la risposta
        5. per ogni esito ERRORE, riporta solo lo stato (nessuna risposta da recuperare)

        Ritorna un dict:
        {
            "identificativoRichiesta": ...,
            "completati": [ {identificativoRisposta, risposta}, ... ],
            "errori": [ {identificativoRichiesta, offset}, ... ],
            "non_ancora_disponibili": bool,   # True se, dopo il polling, mancano ancora esiti
        }
        """
        id_confermato = self.invia_richiesta(identificativo_richiesta, nominativi)

        time.sleep(attesa_secondi)

        esiti = self.poll_esiti()
        esiti_richiesta = [e for e in esiti if e.get("identificativoRichiesta") == id_confermato]

        completati = []
        errori = []
        for esito in esiti_richiesta:
            stato = esito.get("stato")
            if stato == "COMPLETATO":
                identificativo_risposta = esito["identificativoRisposta"]
                risposta = self.recupera_risposta(identificativo_risposta)

                if salva_pdf_in:
                    self._salva_certificati_pdf(risposta, salva_pdf_in, identificativo_risposta)

                completati.append({
                    "identificativoRisposta": identificativo_risposta,
                    "risposta": risposta,
                })
            elif stato == "ERRORE":
                errori.append(esito)

        # nota: se il numero di nominativi richiesti supera quello degli esiti
        # trovati, l'elaborazione potrebbe non essere ancora terminata
        # (il servizio e' asincrono: aumentare attesa_secondi o rilanciare
        # solo il poll_esiti() in un secondo momento)
        non_ancora_disponibili = len(esiti_richiesta) < len(nominativi)

        return {
            "identificativoRichiesta": id_confermato,
            "completati": completati,
            "errori": errori,
            "non_ancora_disponibili": non_ancora_disponibili,
        }

    @staticmethod
    def _salva_certificati_pdf(risposta: dict, cartella: str, identificativo_risposta: str) -> None:
        """Decodifica ed eventualmente salva su disco i PDF (base64) presenti nella risposta."""
        import os
        os.makedirs(cartella, exist_ok=True)
        for i, voce in enumerate(risposta.get("risposta", []), start=1):
            certificato_b64 = voce.get("datiRisposta", {}).get("certificato")
            if certificato_b64:
                pdf_bytes = base64.b64decode(certificato_b64)
                path = os.path.join(cartella, f"{identificativo_risposta}_{i}.pdf")
                with open(path, "wb") as f:
                    f.write(pdf_bytes)


# ==========================================================================
# Esempio d'uso
# ==========================================================================

if __name__ == "__main__":
    with open("config.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    with open("private_key.pem", "r", encoding="utf-8") as f:
        private_key = f.read()

    client = CasellarioClient(
        access_token="IL_TUO_VOUCHER_OTTENUTO_DALLA_PDND",
        config=config,
        private_key=private_key,
        user_id="operatore.rossi",
        user_location="postazione-01",
        loa="2",
    )

    nominativi = [
        Nominativo(
            cf="RSSMRA80A01H501U",
            cognome="ROSSI",
            nome="MARIO",
            numero_protocollo="1",
        ),
        # aggiungi qui altri nominativi (cf, cognome, nome, numero_protocollo)...
    ]

    risultato = client.richiedi_certificati(
        identificativo_richiesta="REQ_2026_0001",   # max 15 caratteri, univoco
        nominativi=nominativi,
        attesa_secondi=120,
        salva_pdf_in="./certificati",
    )

    print(json.dumps(risultato, indent=2, ensure_ascii=False))
