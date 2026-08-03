*TO DO*

**SU PDND**
1) configure PDND client
2) crea finalità partendo da uno dei template messi a disposizione da Min. Giustizia
3) associa finalità al client
4) richiedi fruizione del servizio https://api.gov.it/it/catalogo/c881c211-3a50-4e8d-9667-ae51955d0711

**Negli script**
5) compila file `config_casellario.yaml` partendo da `template_config_casellario.yaml` e recuperando le info dalla UI privata di PDND
6) compila csv con lista dei nomi di cui chiedere il casellario (**MAX 100 nomi**). Campi da inserire:
    - codice fiscale
    - nome
    - cognome
    - numero protocollo

7) chiama servizio: `py casellario_client.py --key YOUR_RSA_PRIV_KEY --f names.csv`
