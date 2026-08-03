Ho controllato lo spec OpenAPI: gli endpoint effettivi sono `/richiesta-certificazione`, `/esiti` (non `/status`, usato solo per health-check) e `/risposta-certificazione/{identificativoRisposta}`, tutti sotto il security scheme `BearerAuth` con gli header aggiuntivi `Agid-JWT-Signature`, `Agid-JWT-TrackingEvidence`, `Digest` — coerente con la documentazione PDF. Prima di scrivere il client, un punto importante da segnalarti:

**Il solo codice fiscale non basta** per popolare `DatiNominativoPersonaFisica`: `cognome`, `nome` e `sesso` sono campi **obbligatori** nello schema, e cognome/nome non sono ricavabili in modo affidabile dal CF (che codifica solo consonanti/vocali estratte, non è reversibile). Quello che *posso* derivare in modo affidabile dal CF sono `sesso`, `dataNascita` e il codice catastale del comune/stato di nascita (confermato anche dall'esempio nello spec: `RSSMRA80A01H501U` → `codiceCatastoComuneItaliano: H501`, `codiceCatastoStato: Z000`).

Quindi ho progettato il client per accettare in input **CF + cognome + nome** per ciascuna persona (il minimo indispensabile), derivando automaticamente il resto dal CF. Lo testo per verificarne la correttezza prima di consegnartelo.Confermato. Ora scrivo il client completo.Ora testo il codice end-to-end simulando le tre chiamate HTTP, per verificare che non ci siano errori e che il flusso (invio → attesa → polling → recupero risposte) funzioni correttamente.Tutto funziona correttamente: invio richiesta, attesa, polling con paginazione, filtro esiti COMPLETATO/ERRORE, recupero risposta e salvataggio PDF. Copio il file negli output.**Come si usa (esempio già incluso in fondo al file):**

```python
client = CasellarioClient(
    access_token="...",   # voucher PDND (client_credentials, già visto in questa conversazione)
    config=config,         # dict con security.kid/alg + eservice.issuer/subject/purposeId
    private_key=private_key,
    user_id="operatore.rossi",
    user_location="postazione-01",
    loa="2",
)

nominativi = [
    Nominativo(cf="RSSMRA80A01H501U", cognome="ROSSI", nome="MARIO", numero_protocollo="1"),
    # ... fino a 100 nominativi in un'unica richiesta massiva
]

risultato = client.richiedi_certificati(
    identificativo_richiesta="REQ_2026_0001",  # max 15 caratteri, univoco per richiesta+finalità
    nominativi=nominativi,
    attesa_secondi=120,
    salva_pdf_in="./certificati",  # opzionale: salva i PDF decodificati su disco
)
```

## Punti chiave dell'implementazione

- **Sicurezza**: ogni chiamata (POST e le due GET) porta `Digest`, `Agid-JWT-Signature` e `Agid-JWT-TrackingEvidence`, con `aud` del JWS impostato sull'URL specifico chiamato — anche le GET senza body calcolano il `Digest` su bytes vuoti, come richiesto dallo schema (header sempre `required`).
- **Polling**: gestisce correttamente la paginazione HTTP 206 (ci sono altri esiti, continua con `offset=lastOffset`) vs 200 (esauriti, stop) come descritto nell'esempio del PDF.
- **Filtro "per quelli ok"**: solo gli esiti con `stato == "COMPLETATO"` generano una chiamata a `/risposta-certificazione/{id}`; quelli con `stato == "ERRORE"` vengono riportati ma senza tentare il recupero (non avrebbe nulla da restituire).
- **`non_ancora_disponibili`**: se dopo il polling il numero di esiti trovati per la tua richiesta è inferiore al numero di nominativi inviati, il flag te lo segnala — il servizio è asincrono, quindi con liste grandi 2 minuti potrebbero non bastare.

## Cosa devi ancora fornire tu

1. `access_token` — ottenuto con la chiamata OAuth2 già vista.
2. `config.yaml` e `private_key.pem` — stessi già discussi.
3. **Per ogni CF, anche cognome e nome** — non derivabili dal solo CF, come spiegato sopra.
4. Verifica che il **secolo di nascita** dedotto automaticamente sia corretto per i tuoi casi limite (usa `secolo_hint=1900` o `2000` su `Nominativo` se necessario).
