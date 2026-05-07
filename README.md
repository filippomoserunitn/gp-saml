# gp-saml-fido2

CLI tool per autenticazione GlobalProtect VPN con SAML + FIDO2/WebAuthn (YubiKey, passkey).

Nessun browser necessario: lo script gestisce il flusso SAML e l'autenticazione FIDO2 interamente da linea di comando.

## Requisiti

- Python 3.10+
- OpenConnect (per la connessione VPN)
- Chiave di sicurezza FIDO2 (es. YubiKey)

### Permessi USB (Linux)

Per accedere alla chiave FIDO2 senza root, aggiungi le regole udev:

```bash
# Crea il file /etc/udev/rules.d/70-u2f.rules con:
sudo tee /etc/udev/rules.d/70-u2f.rules << 'EOF'
# YubiKey
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev"
# Generic FIDO/U2F
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0402|0403|0406|0407|0410", MODE="0660", GROUP="plugdev"
EOF

# Ricarica le regole
sudo udevadm control --reload-rules && sudo udevadm trigger

# Aggiungi il tuo utente al gruppo plugdev
sudo usermod -aG plugdev $USER
```

Effettua logout/login per applicare le modifiche al gruppo.

## Installazione

### 1. Clona il repository

```bash
git clone https://github.com/TUO_USER/gp-saml.git
cd gp-saml
```

### 2. Crea il virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installa le dipendenze

```bash
pip install -r requirements.txt
```

Oppure manualmente:

```bash
pip install requests fido2
```

### 4. Installa OpenConnect

```bash
# Debian/Ubuntu
sudo apt install openconnect

# Fedora
sudo dnf install openconnect

# Arch
sudo pacman -S openconnect
```

## Uso

### Autenticazione e stampa credenziali

```bash
./gp-saml-fido2-cli.py -u utente@dominio.it vpn.example.com
```

### Autenticazione ed esecuzione automatica di openconnect

```bash
./gp-saml-fido2-cli.py -x -u utente@dominio.it vpn.example.com
```

### Esempio per utenti UniTN

```bash
./gp-saml-fido2-cli.py -u <Username>@unitn.it vpn-mfa.icts.unitn.it
```

Sostituisci `<Username>` con il tuo nome utente UniTN (es: mario.rossi@unitn.it).

### Opzioni

```
usage: gp-saml-fido2-cli.py [-h] [-u USER] [-v] [-k] [-x] [--clientos {Linux,Windows,Mac}]
                            [--allow-insecure-crypto] [--max-steps MAX_STEPS]
                            [--http-timeout HTTP_TIMEOUT] [-g | -p] server

positional arguments:
  server                GlobalProtect server (es: vpn.example.com)

options:
  -h, --help            show this help message and exit
  -u USER, --user USER  Username (se richiesto prima di WebAuthn)
  -v, --verbose         Verbose output (-v, -vv, -vvv)
  -k, --insecure        Ignora errori certificato SSL
  -x, --execute         Esegui openconnect automaticamente
  --clientos {Linux,Windows,Mac}
                        Client OS da simulare
  --allow-insecure-crypto
                        Passa --allow-insecure-crypto a openconnect
  --max-steps MAX_STEPS
                        Numero massimo di step nel flusso SAML/FIDO2
  --http-timeout HTTP_TIMEOUT
                        Timeout HTTP in secondi per le richieste al portal/IdP
  -g, --gateway         Usa gateway interface (ssl-vpn/prelogin.esp)
  -p, --portal          Usa portal interface (global-protect/prelogin.esp) [default]
```

Nota: `--insecure` disabilita la verifica TLS/certificato. Usalo solo su reti e server fidati.

## Flusso di autenticazione

1. Lo script richiede il prelogin dal server GlobalProtect
2. Segue il redirect SAML all'IdP
3. Rileva il pulsante "Entra con passkey" e lo clicca automaticamente
4. Estrae la challenge WebAuthn dalla pagina
5. Richiede PIN della chiave FIDO2 e touch
6. Invia la risposta WebAuthn all'IdP
7. Completa il flusso SAML e ottiene il `prelogin-cookie`
8. (opzionale) Esegue `openconnect` con le credenziali ottenute

## Troubleshooting

### Errore "Nessun dispositivo FIDO2 trovato"

- Verifica che la chiave sia inserita
- Controlla i permessi USB (vedi sezione sopra)
- Prova con `sudo` per verificare se è un problema di permessi

### Errore SSL "UNSAFE_LEGACY_RENEGOTIATION_DISABLED"

Lo script include automaticamente un workaround per questo problema. Se persiste, usa `--allow-insecure-crypto`.

### Errore 512 da OpenConnect

Verifica di usare l'interface corretta (`-p` per portal, `-g` per gateway). Il default è `portal`.

## Crediti

Basato su [gp-saml-gui](https://github.com/dlenski/gp-saml-gui) di Dan Lenski.
