# YACE
Yet Another CAdES Extractor
Script Python per l'estrazione del contenuto da file **CAdES P7M** (firma digitale italiana).

## Cos'è un file P7M?

Il formato `.p7m` è una **busta crittografica CMS** (*Cryptographic Message Syntax*) che racchiude un documento firmato digitalmente secondo lo standard **CAdES** (*CMS Advanced Electronic Signatures*), largamente utilizzato in Italia per la firma digitale di documenti (PDF, XML, DOCX, fatture elettroniche, ecc.).

Lo script analizza la struttura ASN.1 del file, naviga nella gerarchia `ContentInfo → SignedData → EncapsulatedContentInfo → eContent` ed estrae il documento originale.

---

## Requisiti

- **Python 3.10+**
- Almeno uno dei seguenti (lo script li prova automaticamente nell'ordine):

| Metodo | Libreria | Installazione |
|--------|----------|---------------|
| `asn1crypto` *(consigliato)* | `asn1crypto` | `pip install asn1crypto` |
| `cryptography` | `pyOpenSSL` | `pip install pyOpenSSL` |
| `openssl` *(fallback)* | Tool OpenSSL di sistema | `apt install openssl` / `brew install openssl` / [Win](https://slproweb.com/products/Win32OpenSSL.html) |

---

## Installazione

```bash
# Clona il repository
git clone https://github.com/Panda83it/YACE.git
cd YACE

# Installa la dipendenza consigliata
pip install asn1crypto
```

---

## Utilizzo

### Sintassi

```
python extract_p7m.py <file_input.p7m> [file_output] [--method {auto,asn1crypto,cryptography,openssl}]
```

### Argomenti

| Argomento | Descrizione |
|-----------|-------------|
| `file_input.p7m` | **Obbligatorio.** Percorso del file P7M da estrarre. |
| `file_output` | *Opzionale.* Percorso del file di output. Se omesso, viene rimossa l'estensione `.p7m` dal nome del file di input. |
| `--method` | *Opzionale.* Metodo da usare: `auto` (default), `asn1crypto`, `cryptography`, `openssl`. |

### Esempi

```bash
# Caso più comune: documento.pdf.p7m → documento.pdf
python extract_p7m.py documento.pdf.p7m

# Specificare il file di output
python extract_p7m.py documento.pdf.p7m output.pdf

# Fattura elettronica XML
python extract_p7m.py fattura.xml.p7m fattura.xml

# Forzare l'uso di OpenSSL di sistema
python extract_p7m.py --method openssl documento.pdf.p7m

# Aiuto
python extract_p7m.py --help
```

### Output di esempio

```
============================================================
  Estrazione contenuto da file CAdES P7M
============================================================
  Input  : documento.pdf.p7m
  Output : documento.pdf
  Metodo : auto
============================================================

>>> Tentativo con metodo: asn1crypto
[asn1crypto] Contenuto estratto con successo.
  File di output : documento.pdf
  Dimensione     : 142,386 byte

Operazione completata con successo.
```

---

## Metodi di estrazione

Lo script supporta tre metodi, selezionabili con `--method`. In modalità `auto` vengono tentati nell'ordine seguente:

### 1. `asn1crypto` *(consigliato)*

Analizza la struttura ASN.1 DER/PEM direttamente in Python, senza dipendenze esterne di sistema. È il metodo più portatile e veloce.

```bash
pip install asn1crypto
```

### 2. `cryptography` / `pyOpenSSL`

Utilizza le API di basso livello di pyOpenSSL per verificare e de-bustare il PKCS#7. Richiede la libreria `pyOpenSSL`.

```bash
pip install pyOpenSSL
```

### 3. `openssl` *(fallback)*

Invoca il tool `openssl` installato nel sistema tramite subprocess. Tenta prima `openssl cms`, poi `openssl smime` per compatibilità con versioni più vecchie.

---

## Formati supportati

| Encoding | Supportato | Note |
|----------|-----------|------|
| DER (binario) | ✅ | Formato standard dei P7M italiani |
| PEM (base64) | ✅ | Rilevato automaticamente dall'header `-----BEGIN` |

---

## Struttura del progetto

```
YACE/
├── extract_p7m.py   # Script principale
└── README.md
```

---

## Casi d'uso comuni

- Estrazione di **fatture elettroniche** (FatturaPA XML) da buste P7M
- Recupero di documenti **PDF firmati digitalmente**
- Elaborazione batch di archivi di documenti firmati
- Verifica e ispezione di file P7M in pipeline automatizzate

---

## Licenza

[MIT](https://opensource.org/licenses/MIT)
