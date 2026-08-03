
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

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
