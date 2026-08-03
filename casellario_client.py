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

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

import cf_helpers as cfh
import pdnd_helpers as pdnd

import pandas as pd
import requests
import yaml

import argparse

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

def load_nominativi_from_file(filename : str) -> List[Nominativo]:
    df = pd.read_csv(filename, sep=";", dtype=str)  # dtype=str evita che pandas interpreti CF/protocolli come numeri
    df = df.fillna("")  # evita valori NaN nei campi opzionali

    print(df.head(2))

    nominativi = [
        Nominativo(
            cf=row["cf"].strip().upper(),
            cognome=row["cognome"].strip(),
            nome=row["nome"].strip(),
            numero_protocollo=str(row["numero_protocollo"]).strip(),
        )
        for _, row in df.iterrows()
    ]
    return nominativi


# ==========================================================================
# Costruzione del payload di richiesta
# ==========================================================================

def _costruisci_payload_richiesta(identificativo_richiesta: str, nominativi: List[Nominativo]) -> dict:
    oggi = datetime.now().strftime("%Y-%m-%d")
    nominativi_richiesti = []
    for i, n in enumerate(nominativi, start=1):
        dati_cf = cfh.decodifica_cf(n.cf, secolo_hint=n.secolo_hint)
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
        headers.update(pdnd._crea_header_sicurezza(
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

        try:
            resp = self.session.post(URL_RICHIESTA, data=body_bytes, headers=headers, verify=True, timeout=10)
            if resp.status_code != 202:
                raise RuntimeError(f"Richiesta non accettata (HTTP {resp.status_code}): {resp.text}")
        except requests.exceptions.ConnectTimeout as e:
            print("Timeout di connessione")
            print(f"Errore nella request: {e}")
        except requests.exceptions.RequestException as e:
            print(f"Errore nella request: {e}")
            raise e

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

        print(id_confermato)
        print("Attendiamo {attesa_secondi} secondi.... ",endl="")
        time.sleep(attesa_secondi)
        print("Fatto!")

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
# MAIN
# ==========================================================================

if __name__ == "__main__":
    with open("config.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    parser = argparse.ArgumentParser(description='Inputs')

    parser.add_argument('--f', required=True)
    parser.add_argument('--key', required=True)
    args = parser.parse_args()

    with open(args.key, "r", encoding="utf-8") as f:
        private_key = f.read()


    client = CasellarioClient(
        access_token="IL_TUO_VOUCHER_OTTENUTO_DALLA_PDND",
        config=config,
        private_key=private_key,
        user_id="operatore.rossi",
        user_location="postazione-01",
        loa="2",
    )

    nominativi = load_nominativi_from_file(args.f)

    risultato = client.richiedi_certificati(
        identificativo_richiesta="REQ_2026_0001",   # max 15 caratteri, univoco
        nominativi=nominativi,
        attesa_secondi=120,
        salva_pdf_in="./certificati",
    )

    print(json.dumps(risultato, indent=2, ensure_ascii=False))

