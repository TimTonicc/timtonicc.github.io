# timtonicc.github.io

Portfolio von Tim Eibl, gehostet mit GitHub Pages: https://timtonicc.github.io/

- `index.html`: öffentliche Startseite (Kurzvorstellung, Arbeitsweise, Toolset, Über mich, Kontakt)
- `projekte.html`: passwortgeschützte Projektseite
- `projekte.enc.json`: die Projektinhalte, **nur verschlüsselt** (AES-256-GCM, Schlüssel per PBKDF2 aus dem Passwort)
- `style.css`: Aussehen (Farben ganz oben in `:root`)
- `img/`: öffentliche Bilder
- `tools/encrypt.py`: verschlüsselt oder entschlüsselt die Projektinhalte

Der Klartext der Projektinhalte liegt bewusst nicht im Repository.
