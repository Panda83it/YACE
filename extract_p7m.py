#!/usr/bin/env python3
"""
Script per l'estrazione del contenuto da file CAdES P7M (firma digitale italiana).

Il formato P7M e' una busta crittografica CMS (Cryptographic Message Syntax) che
contiene un documento firmato digitalmente secondo lo standard CAdES (CMS Advanced
Electronic Signatures).

Utilizzo:
    python extract_p7m.py <file.p7m> [file_output]
    python extract_p7m.py --method openssl documento.pdf.p7m
    python extract_p7m.py --help

Dipendenze opzionali:
    pip install asn1crypto          # Metodo 1 (consigliato)
    pip install cryptography        # Metodo 2 (alternativo)
    openssl (tool di sistema)       # Metodo 3 (fallback)
"""

import sys
import os
import argparse
import subprocess
import base64


# ---------------------------------------------------------------------------
# Metodo 1: estrazione tramite asn1crypto
# ---------------------------------------------------------------------------

def extract_with_asn1crypto(input_path: str, output_path: str) -> bool:
    """
    Estrae il contenuto del P7M analizzando direttamente la struttura ASN.1
    con la libreria asn1crypto.

    La struttura attesa e':
        ContentInfo
          content_type: signed_data
          content: SignedData
            encap_content_info: EncapsulatedContentInfo
              content: OctetString  <-- documento originale
    """
    try:
        from asn1crypto import cms  # type: ignore
    except ImportError:
        print("[asn1crypto] Libreria non installata. Eseguire: pip install asn1crypto")
        return False

    try:
        raw_data = _read_and_normalize(input_path)

        content_info = cms.ContentInfo.load(raw_data)
        content_type = content_info["content_type"].native

        if content_type != "signed_data":
            print(f"[asn1crypto] Tipo di contenuto non supportato: {content_type}")
            return False

        signed_data = content_info["content"]
        encap = signed_data["encap_content_info"]
        e_content = encap["content"]

        if e_content is None or e_content.native is None:
            print("[asn1crypto] Il campo eContent e' vuoto o assente.")
            return False

        content_bytes: bytes = e_content.native  # bytes dell'OCTET STRING

        with open(output_path, "wb") as fout:
            fout.write(content_bytes)

        _print_success("asn1crypto", output_path, len(content_bytes))
        return True

    except Exception as exc:
        print(f"[asn1crypto] Errore durante l'estrazione: {exc}")
        return False


# ---------------------------------------------------------------------------
# Metodo 2: estrazione tramite cryptography
# ---------------------------------------------------------------------------

def extract_with_cryptography(input_path: str, output_path: str) -> bool:
    """
    Estrae il contenuto del P7M usando la libreria cryptography di PyCA.
    Analizza la struttura DER/PEM del PKCS#7 / CMS SignedData.
    """
    try:
        from cryptography.hazmat.primitives import serialization  # noqa
        # La libreria cryptography non espone direttamente il parsing di CMS
        # raw; usiamo il backend OpenSSL interno tramite cffi se disponibile.
        from cryptography.hazmat.bindings._rust import pkcs7 as rust_pkcs7  # type: ignore
    except ImportError:
        pass  # prova comunque con il percorso alternativo

    # Percorso alternativo: usa cryptography per leggere e pyopenssl per parsare
    try:
        from OpenSSL.crypto import load_pkcs7_data, FILETYPE_ASN1, FILETYPE_PEM  # type: ignore

        raw_data = _read_and_normalize(input_path)
        pkcs7_obj = load_pkcs7_data(FILETYPE_ASN1, raw_data)

        # PyOpenSSL non espone direttamente il contenuto SignedData;
        # usiamo il livello OpenSSL raw
        from OpenSSL._util import ffi as _ffi, lib as _lib  # type: ignore
        bio_out = _lib.BIO_new(_lib.BIO_s_mem())
        try:
            ret = _lib.PKCS7_verify(
                pkcs7_obj._pkcs7,
                _ffi.NULL,
                _ffi.NULL,
                _ffi.NULL,
                bio_out,
                _lib.PKCS7_NOVERIFY | _lib.PKCS7_NOSIGS,
            )
            if ret != 1:
                print("[cryptography/pyopenssl] Verifica PKCS7 fallita.")
                return False

            buf_ptr = _ffi.new("char **")
            buf_len = _lib.BIO_get_mem_data(bio_out, buf_ptr)
            content_bytes = bytes(_ffi.buffer(buf_ptr[0], buf_len))
        finally:
            _lib.BIO_free(bio_out)

        with open(output_path, "wb") as fout:
            fout.write(content_bytes)

        _print_success("cryptography/pyopenssl", output_path, len(content_bytes))
        return True

    except ImportError:
        print("[cryptography] Libreria pyOpenSSL non installata. "
              "Eseguire: pip install pyOpenSSL")
        return False
    except Exception as exc:
        print(f"[cryptography] Errore durante l'estrazione: {exc}")
        return False


# ---------------------------------------------------------------------------
# Metodo 3: estrazione tramite OpenSSL (tool di sistema)
# ---------------------------------------------------------------------------

def extract_with_openssl(input_path: str, output_path: str) -> bool:
    """
    Estrae il contenuto del P7M invocando il tool openssl da riga di comando.
    Richiede che openssl sia installato e raggiungibile nel PATH di sistema.
    """
    # Tenta prima con 'openssl cms', poi con 'openssl smime' (compatibilita')
    commands = [
        ["openssl", "cms",   "-verify", "-in", input_path, "-inform", "DER",
         "-noverify", "-out", output_path],
        ["openssl", "smime", "-verify", "-in", input_path, "-inform", "DER",
         "-noverify", "-out", output_path],
    ]

    for cmd in commands:
        sub_cmd = cmd[1]  # 'cms' oppure 'smime'
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and os.path.exists(output_path):
                size = os.path.getsize(output_path)
                _print_success(f"openssl {sub_cmd}", output_path, size)
                return True
            else:
                # Log dell'errore specifico per aiutare il debug
                if result.stderr.strip():
                    print(f"[openssl {sub_cmd}] {result.stderr.strip()}")
        except FileNotFoundError:
            print("[openssl] Tool openssl non trovato nel PATH di sistema.")
            return False
        except subprocess.TimeoutExpired:
            print("[openssl] Timeout durante l'esecuzione di openssl.")
            return False
        except Exception as exc:
            print(f"[openssl {sub_cmd}] Errore: {exc}")

    return False


# ---------------------------------------------------------------------------
# Utilita' interne
# ---------------------------------------------------------------------------

def _read_and_normalize(path: str) -> bytes:
    """
    Legge il file e gestisce sia l'encoding DER (binario) che PEM (base64).
    Restituisce sempre i byte DER.
    """
    with open(path, "rb") as fin:
        data = fin.read()

    # Rilevamento PEM: inizia con '-----BEGIN'
    if data.lstrip().startswith(b"-----"):
        lines = data.decode("ascii", errors="ignore").splitlines()
        b64 = "".join(
            line for line in lines if not line.startswith("-----") and line.strip()
        )
        data = base64.b64decode(b64)

    return data


def _get_output_path(input_path: str, output_arg: str | None) -> str:
    """
    Determina il percorso del file di output.
    Se non specificato esplicitamente, rimuove l'estensione .p7m.
    """
    if output_arg:
        return output_arg
    if input_path.lower().endswith(".p7m"):
        return input_path[:-4]
    return input_path + ".extracted"


def _print_success(method: str, path: str, size: int) -> None:
    print(f"[{method}] Contenuto estratto con successo.")
    print(f"  File di output : {path}")
    print(f"  Dimensione     : {size:,} byte")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Estrae il contenuto da un file CAdES P7M (firma digitale).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python extract_p7m.py documento.pdf.p7m
  python extract_p7m.py documento.pdf.p7m output.pdf
  python extract_p7m.py --method openssl documento.xml.p7m
  python extract_p7m.py --method asn1crypto fattura.xml.p7m fattura.xml

Metodi disponibili (in ordine di tentativo in modalita' 'auto'):
  asn1crypto   Analisi ASN.1 nativa  (richiede: pip install asn1crypto)
  cryptography Usa pyOpenSSL          (richiede: pip install pyOpenSSL)
  openssl      Tool OpenSSL di sistema (deve essere nel PATH)
        """,
    )
    parser.add_argument(
        "input",
        help="Percorso del file P7M di input",
    )
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Percorso del file di output (opzionale; default: rimuove .p7m)",
    )
    parser.add_argument(
        "--method",
        choices=["auto", "asn1crypto", "cryptography", "openssl"],
        default="auto",
        help="Metodo di estrazione da utilizzare (default: auto)",
    )

    args = parser.parse_args()

    # -- Validazioni di input --------------------------------------------------
    if not os.path.isfile(args.input):
        print(f"Errore: il file '{args.input}' non esiste o non e' accessibile.")
        sys.exit(1)

    output_path = _get_output_path(args.input, args.output)

    print("=" * 60)
    print("  Estrazione contenuto da file CAdES P7M")
    print("=" * 60)
    print(f"  Input  : {args.input}")
    print(f"  Output : {output_path}")
    print(f"  Metodo : {args.method}")
    print("=" * 60)
    print()

    # -- Selezione e tentativo dei metodi -------------------------------------
    extractors = {
        "asn1crypto":   extract_with_asn1crypto,
        "cryptography": extract_with_cryptography,
        "openssl":      extract_with_openssl,
    }

    if args.method == "auto":
        order = ["asn1crypto", "cryptography", "openssl"]
    else:
        order = [args.method]

    success = False
    for method_name in order:
        print(f">>> Tentativo con metodo: {method_name}")
        fn = extractors[method_name]
        if fn(args.input, output_path):
            success = True
            break
        print()

    print()
    if success:
        print("Operazione completata con successo.")
    else:
        print("ERRORE: nessun metodo e' riuscito ad estrarre il contenuto.")
        print()
        print("Suggerimenti:")
        print("  - Assicurarsi che il file sia un P7M valido (CAdES/CMS SignedData).")
        print("  - Installare asn1crypto: pip install asn1crypto")
        print("  - Installare OpenSSL e verificare che sia nel PATH.")
        sys.exit(1)


if __name__ == "__main__":
    main()
