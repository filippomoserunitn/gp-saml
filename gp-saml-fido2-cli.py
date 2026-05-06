#!/usr/bin/env python3
"""
GlobalProtect SAML + FIDO2/WebAuthn authentication via command line.
Usa fido2 library per WebAuthn e requests per HTTP - nessun browser necessario.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib3
import requests
from base64 import urlsafe_b64decode, urlsafe_b64encode
from getpass import getpass
from html.parser import HTMLParser
from os import dup2, execvp
from shlex import quote
from urllib.parse import urlparse, urljoin

# Workaround per server con legacy SSL renegotiation
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context
    
    class LegacySSLAdapter(HTTPAdapter):
        """Adapter che permette legacy SSL renegotiation."""
        def init_poolmanager(self, *args, **kwargs):
            ctx = create_urllib3_context()
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
            kwargs['ssl_context'] = ctx
            return super().init_poolmanager(*args, **kwargs)
    
    HAS_LEGACY_SSL = True
except Exception:
    HAS_LEGACY_SSL = False

# fido2 imports
try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector, ClientError
    from fido2.webauthn import (
        PublicKeyCredentialRequestOptions, 
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )
except ImportError:
    print("Errore: libreria fido2 non installata. Installa con: pip install fido2", file=sys.stderr)
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FormParser(HTMLParser):
    """Parser HTML per estrarre form e campi hidden."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.inputs = {}
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'get').upper(),
                'inputs': {}
            }
        elif tag == 'input' and self.current_form is not None:
            name = attrs_dict.get('name')
            value = attrs_dict.get('value', '')
            input_type = attrs_dict.get('type', 'text')
            if name:
                self.current_form['inputs'][name] = {
                    'value': value,
                    'type': input_type
                }
                
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


class CliInteraction(UserInteraction):
    """Interazione utente per fido2 via CLI."""
    def prompt_up(self):
        print("\n🔑 Tocca la chiave di sicurezza...", file=sys.stderr)

    def request_pin(self, permissions, rd_id):
        return getpass("PIN della chiave FIDO2: ")

    def request_uv(self, permissions, rd_id):
        print("Verifica utente richiesta sulla chiave", file=sys.stderr)
        return True


def extract_webauthn_options(html):
    """Estrae le opzioni WebAuthn dal JavaScript della pagina."""
    # Pattern specifico Shibboleth/UniTN: var pkCredRequestOptions = {"publicKey":{...}}
    pk_match = re.search(r'pkCredRequestOptions\s*=\s*(\{[^}]+\{[^}]+\}[^}]*\})', html, re.DOTALL)
    if pk_match:
        try:
            json_str = pk_match.group(1)
            data = json.loads(json_str)
            if 'publicKey' in data:
                return data['publicKey']
            return data
        except json.JSONDecodeError:
            pass
    
    # Cerca il JSON delle opzioni nella pagina
    patterns = [
        r'pkCredRequestOptions\s*=\s*(\{"publicKey":\{.+?\}\})',
        r'publicKeyCredentialRequestOptions\s*[=:]\s*(\{[^;]+\})',
        r'navigator\.credentials\.get\s*\(\s*(\{[^)]+\})\s*\)',
        r'"publicKey"\s*:\s*(\{[^}]+allowCredentials[^}]+\})',
        r'get\s*\(\s*\{\s*"?publicKey"?\s*:\s*(\{.+?\})\s*\}',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.DOTALL)
        if match:
            try:
                json_str = match.group(1)
                # Fix comune: virgole finali
                json_str = re.sub(r',\s*}', '}', json_str)
                json_str = re.sub(r',\s*]', ']', json_str)
                data = json.loads(json_str)
                if 'publicKey' in data:
                    return data['publicKey']
                return data
            except json.JSONDecodeError:
                continue
    
    # Pattern alternativo: cerca direttamente i campi
    challenge_match = re.search(r'"challenge"\s*:\s*"([^"]+)"', html)
    rpid_match = re.search(r'"rpId"\s*:\s*"([^"]+)"', html)
    
    if challenge_match and rpid_match:
        return {
            'challenge': challenge_match.group(1),
            'rpId': rpid_match.group(1),
            'userVerification': 'preferred'
        }
    
    return None


def b64decode_padding(data):
    """Decodifica base64url aggiungendo padding se necessario."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return urlsafe_b64decode(data)


def b64encode_nopadding(data):
    """Codifica in base64url senza padding."""
    return urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def do_fido2_auth(options, origin):
    """Esegue l'autenticazione FIDO2 con la chiave hardware."""
    
    def chiedi_retry(messaggio):
        """Chiede all'utente se vuole riprovare."""
        print(messaggio, file=sys.stderr)
        try:
            risposta = input("Inserisci/cambia la chiave di sicurezza e premi Invio per riprovare (oppure 'q' per uscire): ").strip().lower()
            if risposta == 'q':
                raise RuntimeError("Operazione annullata dall'utente.")
        except (KeyboardInterrupt, EOFError):
            print("", file=sys.stderr)
            raise RuntimeError("Operazione annullata dall'utente.")
    
    # Prepara challenge (fatto una volta sola)
    challenge = options.get('challenge', '')
    if isinstance(challenge, str):
        challenge = b64decode_padding(challenge)
    
    rp_id = options.get('rpId', urlparse(origin).netloc)
    
    # Prepara allowCredentials se presente
    allow_credentials = options.get('allowCredentials', [])
    allow_creds_list = None
    
    if allow_credentials:
        allow_creds_list = []
        for cred in allow_credentials:
            cred_id = cred.get('id', '')
            if isinstance(cred_id, str):
                cred_id = b64decode_padding(cred_id)
            allow_creds_list.append(
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=cred_id
                )
            )
    
    # Mappa userVerification
    uv_map = {
        'required': UserVerificationRequirement.REQUIRED,
        'preferred': UserVerificationRequirement.PREFERRED,
        'discouraged': UserVerificationRequirement.DISCOURAGED,
    }
    user_verification = uv_map.get(
        options.get('userVerification', 'preferred'),
        UserVerificationRequirement.PREFERRED
    )
    
    # Costruisci le opzioni per l'asserzione
    request_options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=allow_creds_list,
        user_verification=user_verification,
        timeout=options.get('timeout', 60000),
    )
    
    # Loop per trovare e usare un dispositivo FIDO2 valido
    while True:
        # Trova dispositivi FIDO2
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            chiedi_retry("⚠️  Nessun dispositivo FIDO2 trovato.")
            continue
        
        device = devices[0]
        print(f"🔐 Trovata chiave: {device}", file=sys.stderr)
        
        # Crea client FIDO2 (fido2 v1.2+ richiede ClientDataCollector)
        client = Fido2Client(device, DefaultClientDataCollector(origin), user_interaction=CliInteraction())
        
        # Esegui l'asserzione
        print("⏳ Attendo autenticazione FIDO2... (tocca la chiave)", file=sys.stderr)
        try:
            result = client.get_assertion(request_options)
            break  # Successo, esce dal loop
        except ClientError as e:
            if 'CONFIGURATION_UNSUPPORTED' in str(e) or 'UNSUPPORTED_OPTION' in str(e):
                chiedi_retry(
                    f"⚠️  La chiave inserita ({device}) non supporta FIDO2/WebAuthn.\n"
                    "   Usa una chiave con supporto FIDO2 (es. YubiKey 5 o superiore)."
                )
                continue
            raise
    
    # Estrai la risposta - get_response(0) restituisce AuthenticationResponse
    auth_response = result.get_response(0)
    
    # auth_response ha:
    #   - raw_id: bytes (credential ID)
    #   - response: AuthenticatorAssertionResponse con client_data, authenticator_data, signature, user_handle
    assertion = auth_response.response
    
    # Costruisci la risposta nel formato WebAuthn per Shibboleth
    response = {
        'id': b64encode_nopadding(auth_response.raw_id),
        'rawId': b64encode_nopadding(auth_response.raw_id),
        'type': 'public-key',
        'response': {
            'authenticatorData': b64encode_nopadding(bytes(assertion.authenticator_data)),
            'clientDataJSON': b64encode_nopadding(bytes(assertion.client_data)),
            'signature': b64encode_nopadding(assertion.signature),
        },
        'clientExtensionResults': {}
    }
    
    if assertion.user_handle:
        response['response']['userHandle'] = b64encode_nopadding(assertion.user_handle)
    
    return response


def main():
    parser = argparse.ArgumentParser(description='GlobalProtect SAML + FIDO2 authentication')
    parser.add_argument('server', help='GlobalProtect server (es: vpn.example.com)')
    parser.add_argument('-u', '--user', help='Username (se richiesto prima di WebAuthn)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbose output (-v, -vv, -vvv)')
    parser.add_argument('-k', '--insecure', action='store_true', help='Ignora errori certificato SSL')
    parser.add_argument('-x', '-e', '--execute', action='store_true', help='Esegui openconnect automaticamente')
    parser.add_argument('--clientos', default='Linux', choices=['Linux', 'Windows', 'Mac'],
                        help='Client OS da simulare')
    parser.add_argument('--allow-insecure-crypto', action='store_true',
                        help='Passa --allow-insecure-crypto a openconnect')
    
    # Interface selection (come gp-saml-gui)
    iface_group = parser.add_mutually_exclusive_group()
    iface_group.add_argument('-g', '--gateway', dest='interface', action='store_const', const='gateway',
                             help='Usa gateway interface (ssl-vpn/prelogin.esp)')
    iface_group.add_argument('-p', '--portal', dest='interface', action='store_const', const='portal',
                             help='Usa portal interface (global-protect/prelogin.esp) [default]')
    parser.set_defaults(interface='portal')
    
    args = parser.parse_args()
    
    verify = not args.insecure
    
    # Sessione HTTP
    session = requests.Session()
    
    # Monta adapter per legacy SSL se necessario
    if HAS_LEGACY_SSL:
        session.mount('https://', LegacySSLAdapter())
    
    session.headers.update({
        'User-Agent': 'PAN GlobalProtect',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })
    
    # Step 1: Ottieni la pagina di prelogin
    # portal usa global-protect/prelogin.esp, gateway usa ssl-vpn/prelogin.esp
    prelogin_path = 'global-protect/prelogin.esp' if args.interface == 'portal' else 'ssl-vpn/prelogin.esp'
    prelogin_url = f'https://{args.server}/{prelogin_path}'
    if args.verbose:
        print(f"[1] Richiesta prelogin ({args.interface}): {prelogin_url}", file=sys.stderr)
    
    res = session.post(prelogin_url, data={
        'tmp': 'tmp',
        'kerberos-support': 'yes',
        'ipv6-support': 'yes',
        'clientVer': '4100',
        'clientos': args.clientos,
    }, verify=verify)
    
    if args.verbose > 1:
        print(f"[1] Risposta: {res.status_code}", file=sys.stderr)
    
    # Estrai URL SAML dal XML di prelogin
    saml_request_match = re.search(r'<saml-request>([^<]+)</saml-request>', res.text)
    saml_method_match = re.search(r'<saml-auth-method>([^<]+)</saml-auth-method>', res.text)
    
    if not saml_request_match:
        print("Errore: risposta prelogin non contiene SAML request", file=sys.stderr)
        if args.verbose:
            print(res.text[:1000], file=sys.stderr)
        sys.exit(1)
    
    saml_method = saml_method_match.group(1) if saml_method_match else 'POST'
    
    # Decodifica SAML request (può essere base64 o URL diretta)
    saml_data = saml_request_match.group(1)
    try:
        from base64 import b64decode
        decoded = b64decode(saml_data).decode('utf-8')
        # Se è HTML, contiene il form SAML
        if '<html' in decoded.lower() or '<form' in decoded.lower():
            saml_html = decoded
            # Estrai l'action del form
            action_match = re.search(r'action="([^"]+)"', saml_html, re.IGNORECASE)
            saml_url = action_match.group(1) if action_match else None
        else:
            # È un URL
            saml_url = decoded
            saml_html = None
    except:
        saml_url = saml_data
        saml_html = None
    
    if args.verbose:
        print(f"[2] SAML URL/Method: {saml_url} / {saml_method}", file=sys.stderr)
    
    # Step 2: Segui il flusso SAML fino alla pagina WebAuthn
    if saml_html:
        # Parse il form HTML e fai il POST
        parser = FormParser()
        parser.feed(saml_html)
        if parser.forms:
            form = parser.forms[0]
            saml_url = form['action']
            form_data = {k: v['value'] for k, v in form['inputs'].items()}
            res = session.post(saml_url, data=form_data, verify=verify, allow_redirects=True)
        else:
            res = session.get(saml_url, verify=verify, allow_redirects=True)
    else:
        res = session.get(saml_url, verify=verify, allow_redirects=True)
    
    current_url = res.url
    if args.verbose:
        print(f"[3] Pagina IdP: {current_url}", file=sys.stderr)
    
    # Step 3: Loop di autenticazione
    max_steps = 10
    webauthn_response = None
    
    for step in range(max_steps):
        if args.verbose > 1:
            print(f"[Step {step}] URL: {res.url}", file=sys.stderr)
        
        # Cerca form nella pagina
        parser = FormParser()
        parser.feed(res.text)
        
        # Controlla se siamo su una pagina WebAuthn
        webauthn_options = extract_webauthn_options(res.text)
        
        if webauthn_options:
            if args.verbose:
                print(f"[4] Trovate opzioni WebAuthn: rpId={webauthn_options.get('rpId')}", file=sys.stderr)
            
            # Esegui autenticazione FIDO2
            origin = f"https://{urlparse(res.url).netloc}"
            webauthn_response = do_fido2_auth(webauthn_options, origin)
            
            if args.verbose:
                print(f"✅ Autenticazione FIDO2 completata", file=sys.stderr)
            
            # Cerca il form per inviare la risposta WebAuthn (specifico Shibboleth/UniTN)
            for form in parser.forms:
                form_action = urljoin(res.url, form['action']) if form['action'] else res.url
                form_data = {k: v['value'] for k, v in form['inputs'].items()}
                
                # Shibboleth usa 'publicKeyCredential' per la risposta
                if 'publicKeyCredential' in form_data:
                    form_data['publicKeyCredential'] = json.dumps(webauthn_response)
                    form_data['_eventId'] = 'proceed'
                    if args.verbose:
                        print(f"[WebAuthn] Invio risposta a {form_action}", file=sys.stderr)
                    res = session.post(form_action, data=form_data, verify=verify, allow_redirects=True)
                    break
                
                # Altri IdP potrebbero usare nomi diversi
                for field_name in ['webauthn_response', 'response', 'assertion', 'fido_response', 'credential']:
                    if field_name in form_data:
                        form_data[field_name] = json.dumps(webauthn_response)
                        if '_eventId' in form_data or '_eventId_proceed' in form['inputs']:
                            form_data['_eventId'] = 'proceed'
                        res = session.post(form_action, data=form_data, verify=verify, allow_redirects=True)
                        break
                else:
                    continue
                break
            else:
                # Nessun form trovato, prova POST diretto
                res = session.post(res.url, data={'publicKeyCredential': json.dumps(webauthn_response), '_eventId': 'proceed'}, 
                                   verify=verify, allow_redirects=True)
            
            continue
        
        # Controlla se c'è un form di login (username/password)
        # MA prima cerca se c'è un link per WebAuthn/FIDO2 sulla pagina
        
        # Pattern 1: URL contiene webauthn/fido
        webauthn_link = re.search(
            r'href="([^"]*(?:webauthn|fido|security[_-]?key|passkey)[^"]*)"', 
            res.text, re.IGNORECASE
        )
        # Pattern 2: Link con testo WebAuthn
        webauthn_button = re.search(
            r'<a[^>]*href="([^"]+)"[^>]*>[^<]*(?:WebAuthn|FIDO|Security Key|Passkey|Chiave di sicurezza)[^<]*</a>',
            res.text, re.IGNORECASE
        )
        # Pattern 3: Immagini con src/alt contenente WebAuthn
        webauthn_img_link = re.search(
            r'<a[^>]*href="([^"]+)"[^>]*>\s*<img[^>]*(?:alt="[^"]*(?:WebAuthn|FIDO|Security)[^"]*"|src="[^"]*(?:webauthn|fido|WebAuthn)[^"]*")[^>]*>',
            res.text, re.IGNORECASE
        )
        # Pattern 4: Cerca qualsiasi link che contiene un'immagine WebAuthn.svg (specifico UniTN)
        webauthn_svg = re.search(
            r'<a[^>]*href="([^"]+)"[^>]*>[^<]*<img[^>]*src="[^"]*WebAuthn[^"]*"[^>]*>',
            res.text, re.IGNORECASE
        )
        # Pattern 5: Link generico vicino a testo WebAuthn
        webauthn_nearby = None
        if 'WebAuthn' in res.text or 'webauthn' in res.text.lower():
            # Cerca tutti i link nella pagina
            all_links = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>(.{0,200}?)</a>', res.text, re.DOTALL | re.IGNORECASE)
            for href, content in all_links:
                if re.search(r'webauthn|fido|security.?key', content, re.IGNORECASE):
                    webauthn_nearby = href
                    break
                # Cerca anche immagini WebAuthn nel contenuto del link
                if re.search(r'WebAuthn|FIDO', content):
                    webauthn_nearby = href
                    break
        
        found_link = webauthn_link or webauthn_button or webauthn_img_link or webauthn_svg
        if found_link:
            link = urljoin(res.url, found_link.group(1))
            if args.verbose:
                print(f"[WebAuthn] Trovato link: {link}", file=sys.stderr)
            res = session.get(link, verify=verify, allow_redirects=True)
            continue
        elif webauthn_nearby:
            link = urljoin(res.url, webauthn_nearby)
            if args.verbose:
                print(f"[WebAuthn] Trovato link (nearby): {link}", file=sys.stderr)
            res = session.get(link, verify=verify, allow_redirects=True)
            continue
        
        # Debug: stampa tutti i link se verbose > 2
        if args.verbose > 2 and 'execution=' in res.url:
            print(f"[DEBUG] Tutti i link nella pagina:", file=sys.stderr)
            for m in re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>(.{0,100}?)</a>', res.text, re.DOTALL):
                print(f"  - {m.group(1)[:80]} -> {m.group(2)[:50].strip()}", file=sys.stderr)
        
        # Cerca button "Entra con passkey" (Shibboleth UniTN)
        passkey_button = re.search(
            r'<button[^>]*name="(_eventId_runFlow_WebAuthn)"[^>]*type="submit"',
            res.text, re.IGNORECASE
        )
        if passkey_button:
            if args.verbose:
                print(f"[Passkey] Trovato button 'Entra con passkey'", file=sys.stderr)
            # Trova il form contenente questo button e fai submit
            for form in parser.forms:
                form_action = urljoin(res.url, form['action']) if form['action'] else res.url
                form_data = {k: v['value'] for k, v in form['inputs'].items()}
                form_data['_eventId'] = 'runFlow_WebAuthn'
                if args.verbose:
                    print(f"[Passkey] Submit form a {form_action}", file=sys.stderr)
                res = session.post(form_action, data=form_data, verify=verify, allow_redirects=True)
                break
            continue
        
        # Cerca link "Entra con passkey" (fallback)
        passkey_link = re.search(
            r'<a[^>]*href="([^"]+)"[^>]*>[^<]*(?:passkey|Passkey|PASSKEY)[^<]*</a>',
            res.text, re.IGNORECASE
        )
        if passkey_link:
            link = urljoin(res.url, passkey_link.group(1))
            if args.verbose:
                print(f"[Passkey] Trovato link 'Entra con passkey': {link}", file=sys.stderr)
            res = session.get(link, verify=verify, allow_redirects=True)
            continue
        
        login_form = None
        for form in parser.forms:
            inputs = form['inputs']
            # Cerca form con username o password
            has_password = any('password' in k.lower() or inputs.get(k, {}).get('type') == 'password' 
                              for k in inputs)
            has_username = any('user' in k.lower() or 'login' in k.lower() or 'email' in k.lower()
                              for k in inputs)
            if has_username or has_password:
                login_form = form
                login_form['_has_password'] = has_password
                login_form['_has_username'] = has_username
                break
        
        if login_form:
            form_action = urljoin(res.url, login_form['action']) if login_form['action'] else res.url
            form_data = {k: v['value'] for k, v in login_form['inputs'].items() if not k.startswith('_')}
            
            # Username
            username_filled = False
            for field in ['username', 'j_username', 'user', 'login', 'email']:
                if field in form_data:
                    if args.user:
                        form_data[field] = args.user
                    else:
                        form_data[field] = input(f"Username: ")
                    username_filled = True
                    break
            
            # Password - richiesta per passare alla selezione del secondo fattore
            for field in ['password', 'j_password', 'pass', 'passwd']:
                if field in form_data:
                    form_data[field] = getpass("Password: ")
                    break
            
            if args.verbose:
                print(f"[Login] Invio credenziali a {form_action}", file=sys.stderr)
            
            res = session.post(form_action, data=form_data, verify=verify, allow_redirects=True)
            continue
        
        # Controlla se c'è un form SAML di continuazione (SAMLResponse)
        saml_form = None
        for form in parser.forms:
            if 'SAMLResponse' in form['inputs']:
                saml_form = form
                break
        
        if saml_form:
            form_action = urljoin(res.url, saml_form['action']) if saml_form['action'] else res.url
            form_data = {k: v['value'] for k, v in saml_form['inputs'].items()}
            
            if args.verbose:
                print(f"[5] Invio SAMLResponse a {form_action}", file=sys.stderr)
            
            # Fai POST senza seguire redirect per catturare gli header
            res = session.post(form_action, data=form_data, verify=verify, allow_redirects=False)
            
            # Controlla gli header della risposta
            if args.verbose > 1:
                print(f"[5] Risposta {res.status_code}", file=sys.stderr)
                for h, v in res.headers.items():
                    if h.lower().startswith('saml-') or h.lower().startswith('prelogin') or h.lower() == 'set-cookie':
                        print(f"[5] Header {h}: {v[:100]}", file=sys.stderr)
            
            # Estrai cookie/header importanti
            result = {}
            for header, value in res.headers.items():
                h_lower = header.lower()
                if h_lower == 'prelogin-cookie':
                    result['prelogin-cookie'] = value
                elif h_lower == 'saml-username':
                    result['saml-username'] = value
                elif h_lower == 'portal-userauthcookie':
                    result['portal-userauthcookie'] = value
            
            # Se non trovato negli header, cerca nei commenti XML del body
            if not result.get('prelogin-cookie') and not result.get('portal-userauthcookie'):
                if args.verbose > 1:
                    print(f"[5] Cookie non trovato negli header, cerco nel body...", file=sys.stderr)
                
                # Cerca commenti HTML che contengono tag XML
                import xml.etree.ElementTree as ET
                for comment in re.findall(r'<!--(.+?)-->', res.text, re.DOTALL):
                    try:
                        xmlroot = ET.fromstring(f"<root>{comment}</root>")
                        for elem in xmlroot:
                            tag = elem.tag.lower()
                            if tag == 'prelogin-cookie':
                                result['prelogin-cookie'] = elem.text
                            elif tag == 'saml-username':
                                result['saml-username'] = elem.text
                            elif tag == 'portal-userauthcookie':
                                result['portal-userauthcookie'] = elem.text
                    except ET.ParseError:
                        pass
                
                if args.verbose > 1 and result:
                    print(f"[5] Trovato nei commenti XML: {list(result.keys())}", file=sys.stderr)
            
            if result.get('prelogin-cookie') or result.get('portal-userauthcookie'):
                # Successo!
                print("\n✅ Autenticazione completata!", file=sys.stderr)
                # L'interface dipende da quale prelogin endpoint abbiamo usato
                interface = args.interface
                if 'prelogin-cookie' in result:
                    cookie_name = 'prelogin-cookie'
                else:
                    cookie_name = 'portal-userauthcookie'
                cookie_value = result[cookie_name]
                username = result.get('saml-username', args.user or 'unknown')
                
                if args.execute:
                    # Esegui openconnect
                    cmd = [
                        'sudo', 'openconnect',
                        '--protocol=gp',
                        '--useragent=PAN GlobalProtect',
                        f'--user={username}',
                        f'--os={args.clientos.lower()}',
                        f'--usergroup={interface}:{cookie_name}',
                        '--passwd-on-stdin',
                        args.server
                    ]
                    if args.allow_insecure_crypto:
                        cmd.insert(2, '--allow-insecure-crypto')
                    
                    print(f"\n🚀 Eseguo: {' '.join(quote(c) for c in cmd)}", file=sys.stderr)
                    print(f"(con cookie come password)", file=sys.stderr)
                    
                    # Crea pipe per passare il cookie come stdin
                    import subprocess
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
                    proc.communicate(input=cookie_value)
                    sys.exit(proc.returncode)
                else:
                    # Stampa i risultati
                    print(f"\nHOST=https://{args.server}/{interface}:{cookie_name}")
                    print(f"USER={username}")
                    print(f"COOKIE={cookie_value}")
                    print(f"\nPer connetterti:")
                    print(f"  echo '{cookie_value}' | sudo openconnect --protocol=gp "
                          f"--user={username} --os={args.clientos.lower()} "
                          f"--usergroup={interface}:{cookie_name} --passwd-on-stdin {args.server}")
                
                sys.exit(0)
            
            # Segui il redirect manualmente
            if res.is_redirect:
                location = res.headers.get('Location', '')
                if location:
                    res = session.get(urljoin(res.url, location), verify=verify, allow_redirects=True)
                continue
            
            continue
        
        # Cerca bottoni/link di submit generici (proceed, continue, next)
        proceed_link = re.search(r'href="([^"]*(?:proceed|continue|next)[^"]*)"', res.text, re.IGNORECASE)
        if proceed_link:
            link = urljoin(res.url, proceed_link.group(1))
            if args.verbose:
                print(f"[Proceed] {link}", file=sys.stderr)
            res = session.get(link, verify=verify, allow_redirects=True)
            continue
        
        # Niente da fare, stampa la pagina per debug
        if args.verbose:
            print(f"[?] Pagina senza azioni riconosciute: {res.url}", file=sys.stderr)
            if args.verbose > 2:
                print(res.text[:2000], file=sys.stderr)
        break
    
    print("\n❌ Autenticazione fallita - non sono riuscito a completare il flusso SAML/FIDO2", file=sys.stderr)
    sys.exit(1)


if __name__ == '__main__':
    main()
