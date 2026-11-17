"""Verschlüsselt den passwortgeschützten Projektbereich.

Nur das Ergebnis (projekte.enc.json) kommt ins Repository. Der Klartext
(HTML + Bilder) bleibt außerhalb des Repos.

Verschlüsseln:
    python3 tools/encrypt.py encrypt <inhalt.html> <bilder-ordner> projekte.enc.json
Entschlüsseln (um den Klartext zum Bearbeiten zurückzuholen):
    python3 tools/encrypt.py decrypt projekte.enc.json <ausgabe.html>

Das Passwort wird über die Umgebungsvariable SITE_PASSWORD übergeben oder
interaktiv abgefragt. Verfahren: PBKDF2-SHA256 (600.000 Runden) + AES-256-GCM,
kompatibel mit der Web Crypto API im Browser (siehe projekte.html).
"""
import base64
import getpass
import json
import mimetypes
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000


def get_password():
    pw = os.environ.get("SITE_PASSWORD") or getpass.getpass("Passwort: ")
    if len(pw) < 12:
        sys.exit("Passwort muss mindestens 12 Zeichen lang sein.")
    return pw


def derive_key(password, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def inline_images(html, img_dir):
    def repl(match):
        name = match.group(1)
        for ext in (".jpg", ".jpeg", ".png", ".webp"):
            path = os.path.join(img_dir, name + ext)
            if os.path.exists(path):
                mime = mimetypes.guess_type(path)[0]
                with open(path, "rb") as f:
                    data = base64.b64encode(f.read()).decode()
                return f"data:{mime};base64,{data}"
        sys.exit(f"Bild nicht gefunden: {name}")
    return re.sub(r"\{\{img:([\w-]+)\}\}", repl, html)


def encrypt(src, img_dir, out):
    with open(src, encoding="utf-8") as f:
        html = inline_images(f.read(), img_dir)
    salt, iv = os.urandom(16), os.urandom(12)
    key = derive_key(get_password(), salt, ITERATIONS)
    ct = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode()
    with open(out, "w") as f:
        json.dump({"v": 1, "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}, f)
    print(f"{out} geschrieben ({os.path.getsize(out) // 1024} KB)")


def decrypt(src, out):
    with open(src) as f:
        d = json.load(f)
    unb = base64.b64decode
    key = derive_key(get_password(), unb(d["salt"]), d["iter"])
    html = AESGCM(key).decrypt(unb(d["iv"]), unb(d["ct"]), None).decode("utf-8")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{out} geschrieben (Bilder sind als data-URLs eingebettet)")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "encrypt":
        encrypt(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "decrypt":
        decrypt(*sys.argv[2:])
    else:
        sys.exit(__doc__)
