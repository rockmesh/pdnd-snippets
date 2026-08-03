Partendo dalla spec OpenAPI: gli endpoint effettivi sono `/richiesta-certificazione`, `/esiti` e `/risposta-certificazione/{identificativoRisposta}`, tutti sotto il security scheme `BearerAuth` con gli header aggiuntivi `Agid-JWT-Signature`, `Agid-JWT-TrackingEvidence`, `Digest` — coerente con la documentazione PDF. Un punto importante da segnalare:

**Il solo codice fiscale non basta** per popolare `DatiNominativoPersonaFisica`: `cognome`, `nome` e `sesso` sono campi **obbligatori** nello schema, e cognome/nome non sono ricavabili in modo affidabile dal CF (che codifica solo consonanti/vocali estratte, non è reversibile). Quello si *puo'* derivare in modo affidabile dal CF sono `sesso`, `dataNascita` e il codice catastale del comune/stato di nascita (confermato anche dall'esempio nello spec: `RSSMRA80A01H501U` → `codiceCatastoComuneItaliano: H501`, `codiceCatastoStato: Z000`). Quindi il client accetta in input **CF + cognome + nome** per ciascuna persona (il minimo indispensabile), derivando automaticamente il resto dal CF. 

Flusso (invio → attesa → polling → recupero risposte): invio richiesta, attesa, polling con paginazione, filtro esiti COMPLETATO/ERRORE, recupero risposta e salvataggio PDF. 


## Punti chiave dell'implementazione

- **Sicurezza**: ogni chiamata (POST e le due GET) porta `Digest`, `Agid-JWT-Signature` e `Agid-JWT-TrackingEvidence`, con `aud` del JWS impostato sull'URL specifico chiamato — anche le GET senza body calcolano il `Digest` su bytes vuoti, come richiesto dallo schema (header sempre `required`).
- **Polling**: gestisce correttamente la paginazione HTTP 206 (ci sono altri esiti, continua con `offset=lastOffset`) vs 200 (esauriti, stop) come descritto nell'esempio del PDF.
- **Filtro "per quelli ok"**: solo gli esiti con `stato == "COMPLETATO"` generano una chiamata a `/risposta-certificazione/{id}`; quelli con `stato == "ERRORE"` vengono riportati ma senza tentare il recupero (non avrebbe nulla da restituire).
- **`non_ancora_disponibili`**: se dopo il polling il numero di esiti trovati per la tua richiesta è inferiore al numero di nominativi inviati, il flag te lo segnala — il servizio è asincrono, quindi con liste grandi 2 minuti potrebbero non bastare.
