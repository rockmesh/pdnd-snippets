# Implementazione ID_AUTH_CHANNEL_01, INTEGRITY_REST_02, AUDIT_REST_01

Modulo Python che implementa i tre pattern di sicurezza ModI (AgID) per la
chiamata a servizi REST erogati da una PA tramite PDND.

## Come funziona, in breve

- **`ID_AUTH_CHANNEL_01`** — non richiede codice specifico: è gestito da
  `requests` con `verify=True` (default, non toccarlo mai in produzione),
  che impone la validazione del certificato TLS del server.

- **`INTEGRITY_REST_02`** — `calcola_digest()` calcola l'hash SHA-256 del
  body (header `Digest`), poi `crea_agid_jwt_signature()` genera il JWS da
  mettere nell'header `Agid-JWT-Signature`, firmando `digest` e
  `content-type` nel claim `signed_headers`, con `kid` che referenzia il
  certificato caricato sul portachiavi PDND.

- **`AUDIT_REST_01`** — `crea_agid_jwt_tracking_evidence()` genera il
  secondo JWS per l'header `Agid-JWT-TrackingEvidence`, con i tre claim
  che le linee guida richiedono: `userID`, `userLocation`, `LoA` — cioè
  chi/dove/con quale livello di garanzia è stata autenticata la richiesta
  all'interno del tuo dominio.

## Cosa personalizzare

1. `private_key.pem` — la chiave privata corrispondente al certificato il
   cui `kid` hai depositato sulla PDND (dev'essere la stessa già usata per
   la `client_assertion` del voucher, o un'altra a seconda di come hai
   configurato l'e-service).
2. `access_token` — il voucher Bearer ottenuto con la chiamata
   `client_credentials`.
3. `user_id`, `user_location`, `loa` — valori reali del tuo dominio (non
   andrebbero mai hardcodati in produzione: vanno presi dalla
   sessione/utente reale che origina la richiesta).

## Note

- La struttura dei due JWS (claim, header JOSE, uso del `kid` invece di
  `x5c`) è stata verificata contro la documentazione ufficiale
  AgID/GovWay/PDND aggiornata al 2023-2024, non da memoria.
- Alcuni erogatori richiedono claim aggiuntivi non standardizzati (es.
  `businessFlowID`, `SAcodiceAUSA` per servizi ANPR) — questi variano per
  servizio: conviene controllare la documentazione tecnica specifica
  dell'e-service prima di andare in produzione.
