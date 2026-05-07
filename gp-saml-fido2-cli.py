#!/usr/bin/env python3
"""
GlobalProtect SAML + FIDO2/WebAuthn authentication via command line.
Usa fido2 library per WebAuthn e requests per HTTP - nessun browser necessario.
"""

import argparse
import json
import re
import ssl
import sys
import urllib3
import requests
import xml.etree.ElementTree as ET
from base64 import b64decode, urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from getpass import getpass
from html import unescape
from html.parser import HTMLParser
from shlex import quote
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

# Workaround per server con legacy SSL renegotiation
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context

    LEGACY_SSL_OPTION = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", None)

    class LegacySSLAdapter(HTTPAdapter):
        """Adapter che permette legacy SSL renegotiation."""

        def init_poolmanager(self, *args, **kwargs):
            ctx = create_urllib3_context()
            ctx.options |= LEGACY_SSL_OPTION
            kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    HAS_LEGACY_SSL = LEGACY_SSL_OPTION is not None
except (ImportError, AttributeError):
    LEGACY_SSL_OPTION = None
    HAS_LEGACY_SSL = False

# fido2 imports: i test del parsing devono poter girare anche senza fido2.
try:
    from fido2.hid import CtapHidDevice
    from fido2.client import (
        ClientError,
        DefaultClientDataCollector,
        Fido2Client,
        UserInteraction,
    )
    from fido2.webauthn import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )

    HAS_FIDO2 = True
except ImportError:
    CtapHidDevice = None
    ClientError = Exception
    DefaultClientDataCollector = None
    Fido2Client = None
    PublicKeyCredentialDescriptor = None
    PublicKeyCredentialRequestOptions = None
    PublicKeyCredentialType = None
    UserVerificationRequirement = None
    UserInteraction = object
    HAS_FIDO2 = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


WEBAUTHN_KEYWORDS = (
    "webauthn",
    "fido",
    "security key",
    "security-key",
    "security_key",
    "passkey",
    "chiave di sicurezza",
)
WEBAUTHN_RESPONSE_FIELDS = (
    "publicKeyCredential",
    "webauthn_response",
    "response",
    "assertion",
    "fido_response",
    "credential",
)
LOGIN_USERNAME_FIELDS = ("username", "j_username", "user", "login", "email")
LOGIN_PASSWORD_FIELDS = ("password", "j_password", "pass", "passwd")
HTTP_TIMEOUT_DEFAULT = 30.0


class GpSamlError(RuntimeError):
    """Errore previsto nel flusso GP/SAML."""


class FlowFailed(GpSamlError):
    """Il flusso non ha trovato un'azione successiva."""

    def __init__(self, message: str, response: Optional[requests.Response] = None):
        super().__init__(message)
        self.response = response


@dataclass
class PageContext:
    url: str
    status_code: int
    html: str
    forms: list[dict[str, Any]]
    webauthn_hints: list[str]


class FormParser(HTMLParser):
    """Parser HTML per estrarre form, input, bottoni e link."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.links: list[dict[str, str]] = []
        self.current_form: Optional[dict[str, Any]] = None
        self.current_link: Optional[dict[str, str]] = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): v if v is not None else "" for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").upper(),
                "inputs": {},
                "buttons": [],
            }
        elif tag == "input" and self.current_form is not None:
            name = attrs_dict.get("name")
            value = attrs_dict.get("value", "")
            input_type = attrs_dict.get("type", "text")
            if name:
                self.current_form["inputs"][name] = {
                    "value": value,
                    "type": input_type,
                    "attrs": attrs_dict,
                }
        elif tag == "button" and self.current_form is not None:
            self.current_form["buttons"].append({"text": "", "attrs": attrs_dict})
        elif tag == "a":
            self.current_link = {"href": attrs_dict.get("href", ""), "text": "", "attrs": attrs_dict}
        elif tag == "img":
            img_text = " ".join(
                attrs_dict.get(name, "") for name in ("alt", "title", "src") if attrs_dict.get(name)
            )
            if self.current_link is not None:
                self.current_link["text"] = f"{self.current_link['text']} {img_text}".strip()
            if self.current_form is not None and self.current_form["buttons"]:
                self.current_form["buttons"][-1]["text"] = (
                    f"{self.current_form['buttons'][-1]['text']} {img_text}".strip()
                )

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["text"] = f"{self.current_link['text']} {data}".strip()
        if self.current_form is not None and self.current_form["buttons"]:
            self.current_form["buttons"][-1]["text"] = (
                f"{self.current_form['buttons'][-1]['text']} {data}".strip()
            )

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
        elif tag == "a" and self.current_link:
            self.links.append(self.current_link)
            self.current_link = None


class CliInteraction(UserInteraction):
    """Interazione utente per fido2 via CLI."""

    def prompt_up(self):
        print("\nTocca la chiave di sicurezza...", file=sys.stderr)

    def request_pin(self, permissions, rd_id):
        return getpass("PIN della chiave FIDO2: ")

    def request_uv(self, permissions, rd_id):
        print("Verifica utente richiesta sulla chiave", file=sys.stderr)
        return True


def parse_html(html: str) -> FormParser:
    parser = FormParser()
    parser.feed(html or "")
    return parser


def form_data(form: dict[str, Any]) -> dict[str, str]:
    return {k: v.get("value", "") for k, v in form.get("inputs", {}).items()}


def b64decode_padding(data):
    """Decodifica base64url aggiungendo padding se necessario."""
    if isinstance(data, str):
        data = data.encode("ascii")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return urlsafe_b64decode(data)


def b64encode_nopadding(data):
    """Codifica in base64url senza padding."""
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?<!:)//.*?$", "", text, flags=re.MULTILINE)


def normalize_json_like(text: str) -> str:
    text = unescape(strip_js_comments(text).strip())
    text = re.sub(r"([{,]\s*)([A-Za-z_$][\w$-]*)\s*:", r'\1"\2":', text)
    text = re.sub(
        r"'([^'\\]*(?:\\.[^'\\]*)*)'",
        lambda match: json.dumps(match.group(1)),
        text,
    )
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


def balanced_js_object(text: str, start: int) -> Optional[str]:
    quote_char = ""
    escape = False
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if quote_char:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote_char:
                quote_char = ""
            continue
        if ch in ("'", '"'):
            quote_char = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return None


def parse_json_like_object(candidate: str) -> Optional[dict[str, Any]]:
    candidate = normalize_json_like(candidate)
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def extract_assigned_objects(html: str, names: tuple[str, ...]) -> list[dict[str, Any]]:
    objects = []
    name_pattern = "|".join(re.escape(name) for name in names)
    for match in re.finditer(rf"\b(?:var|let|const)?\s*(?:{name_pattern})\s*[:=]\s*", html, re.I):
        brace = html.find("{", match.end())
        if brace == -1:
            continue
        candidate = balanced_js_object(html, brace)
        if not candidate:
            continue
        data = parse_json_like_object(candidate)
        if data is not None:
            objects.append(data)
    return objects


def extract_navigator_get_objects(html: str) -> list[dict[str, Any]]:
    objects = []
    for match in re.finditer(r"navigator\.credentials\.get\s*\(", html, re.I):
        brace = html.find("{", match.end())
        if brace == -1:
            continue
        candidate = balanced_js_object(html, brace)
        if not candidate:
            continue
        data = parse_json_like_object(candidate)
        if data is not None:
            objects.append(data)
    return objects


def public_key_from_object(data: dict[str, Any]) -> Optional[dict[str, Any]]:
    if "publicKey" in data and isinstance(data["publicKey"], dict):
        return data["publicKey"]
    if "challenge" in data:
        return data
    return None


def extract_webauthn_options(html):
    """Estrae opzioni WebAuthn da JS/HTML con parser bilanciato e fallback regex."""
    variable_names = (
        "pkCredRequestOptions",
        "publicKeyCredentialRequestOptions",
        "requestOptions",
        "credentialRequestOptions",
        "options",
    )
    for data in extract_assigned_objects(html, variable_names) + extract_navigator_get_objects(html):
        public_key = public_key_from_object(data)
        if public_key:
            return public_key

    # Fallback per IdP con JS non JSON valido ma campi riconoscibili.
    challenge_match = re.search(r'["\']challenge["\']\s*:\s*["\']([^"\']+)["\']', html, re.DOTALL)
    rpid_match = re.search(r'["\']rpId["\']\s*:\s*["\']([^"\']+)["\']', html, re.DOTALL)
    if challenge_match:
        result = {
            "challenge": challenge_match.group(1),
            "userVerification": "preferred",
        }
        if rpid_match:
            result["rpId"] = rpid_match.group(1)
        return result
    return None


def find_webauthn_entrypoint(html: str, base_url: str) -> Optional[dict[str, Any]]:
    parser = parse_html(html)
    keyword_re = re.compile("|".join(re.escape(k) for k in WEBAUTHN_KEYWORDS), re.I)

    for link in parser.links:
        href = link.get("href", "")
        haystack = " ".join([href, link.get("text", ""), " ".join(link.get("attrs", {}).values())])
        if href and keyword_re.search(haystack):
            return {"type": "link", "url": urljoin(base_url, href)}

    for form in parser.forms:
        for name, meta in form.get("inputs", {}).items():
            attrs = meta.get("attrs", {})
            input_type = attrs.get("type", "text").lower()
            if input_type not in {"submit", "button", "image"}:
                continue
            haystack = " ".join(
                [
                    name,
                    meta.get("value", ""),
                    attrs.get("value", ""),
                    attrs.get("alt", ""),
                    attrs.get("title", ""),
                    attrs.get("name", ""),
                ]
            )
            if name == "_eventId_runFlow_WebAuthn" or keyword_re.search(haystack):
                data = form_data(form)
                if name == "_eventId_runFlow_WebAuthn":
                    data["_eventId"] = "runFlow_WebAuthn"
                elif name:
                    data[name] = meta.get("value", "")
                return {
                    "type": "form",
                    "url": urljoin(base_url, form.get("action", "")) if form.get("action") else base_url,
                    "method": form.get("method", "GET"),
                    "data": data,
                }

        for button in form.get("buttons", []):
            attrs = button.get("attrs", {})
            haystack = " ".join([button.get("text", ""), " ".join(attrs.values())])
            if attrs.get("name") == "_eventId_runFlow_WebAuthn" or keyword_re.search(haystack):
                data = form_data(form)
                if attrs.get("name") == "_eventId_runFlow_WebAuthn":
                    data["_eventId"] = "runFlow_WebAuthn"
                elif attrs.get("name"):
                    data[attrs["name"]] = attrs.get("value", "")
                return {
                    "type": "form",
                    "url": urljoin(base_url, form.get("action", "")) if form.get("action") else base_url,
                    "method": form.get("method", "GET"),
                    "data": data,
                }

    # Regex fallback per markup malformato o testo frammentato.
    fallback = re.search(
        r'href=["\']([^"\']*(?:webauthn|fido|security[_ -]?key|passkey)[^"\']*)["\']',
        html,
        re.I,
    )
    if fallback:
        return {"type": "link", "url": urljoin(base_url, fallback.group(1))}
    return None


def webauthn_hints(html: str) -> list[str]:
    hints = []
    for token in ("navigator.credentials.get", "publicKey", "allowCredentials", "pkCredRequestOptions"):
        if token.lower() in html.lower():
            hints.append(token)
    if find_webauthn_entrypoint(html, ""):
        hints.append("webauthn entrypoint")
    return sorted(set(hints))


def find_login_form(forms: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    for form in forms:
        inputs = form.get("inputs", {})
        has_password = any(
            "password" in name.lower() or meta.get("type", "").lower() == "password"
            for name, meta in inputs.items()
        )
        has_username = any(
            "user" in name.lower() or "login" in name.lower() or "email" in name.lower()
            for name in inputs
        )
        if has_username or has_password:
            form["_has_password"] = has_password
            form["_has_username"] = has_username
            return form
    return None


def find_saml_response_form(forms: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    for form in forms:
        if "SAMLResponse" in form.get("inputs", {}):
            return form
    return None


def form_has_button(form: dict[str, Any], name: str) -> bool:
    return any(button.get("attrs", {}).get("name") == name for button in form.get("buttons", []))


def mask_secret(value: str, visible: int = 4) -> str:
    if value is None:
        return ""
    value = str(value)
    if len(value) <= visible * 2:
        return "***"
    return f"{value[:visible]}...{value[-visible:]}"


def mask_cookie_header(value: str) -> str:
    def repl(match):
        return f"{match.group(1)}={mask_secret(match.group(2))}"

    return re.sub(r"(?i)([A-Za-z0-9_.-]*(?:cookie|session|token)[A-Za-z0-9_.-]*)=([^;,\s]+)", repl, value)


def safe_header_value(header: str, value: str) -> str:
    if header.lower() in {"prelogin-cookie", "portal-userauthcookie"}:
        return mask_secret(value)
    if header.lower() in {"set-cookie", "cookie"}:
        return mask_cookie_header(value)
    return value


def describe_forms(forms: list[dict[str, Any]]) -> list[str]:
    descriptions = []
    for idx, form in enumerate(forms, start=1):
        input_names = sorted(form.get("inputs", {}).keys())
        button_names = [b.get("attrs", {}).get("name", "") for b in form.get("buttons", []) if b.get("attrs")]
        descriptions.append(
            f"form#{idx} method={form.get('method', 'GET')} action={form.get('action', '') or '<current>'} "
            f"inputs={input_names} buttons={button_names}"
        )
    return descriptions


def debug_page_context(res: requests.Response) -> PageContext:
    parser = parse_html(res.text)
    return PageContext(
        url=res.url,
        status_code=res.status_code,
        html=res.text,
        forms=parser.forms,
        webauthn_hints=webauthn_hints(res.text),
    )


def print_failure_context(res: requests.Response, verbose: int, message: str):
    ctx = debug_page_context(res)
    print(f"\nErrore: {message}", file=sys.stderr)
    print(f"URL corrente: {ctx.url}", file=sys.stderr)
    print(f"Status code: {ctx.status_code}", file=sys.stderr)
    print("Form trovati:", file=sys.stderr)
    for line in describe_forms(ctx.forms) or ["<nessuno>"]:
        print(f"  - {line}", file=sys.stderr)
    print(f"Indizi WebAuthn: {', '.join(ctx.webauthn_hints) if ctx.webauthn_hints else '<nessuno>'}", file=sys.stderr)
    if verbose > 2:
        print(ctx.html[:2000], file=sys.stderr)


def setup_session(args) -> tuple[requests.Session, bool]:
    verify = not args.insecure
    if args.insecure:
        print(
            "ATTENZIONE: --insecure disabilita la verifica TLS/certificato. "
            "Usalo solo su reti e server fidati: espone a rischio MITM.",
            file=sys.stderr,
        )

    session = requests.Session()
    if HAS_LEGACY_SSL:
        session.mount("https://", LegacySSLAdapter())
    elif args.verbose > 1:
        print("[TLS] Legacy SSL adapter non disponibile su questa build Python/OpenSSL", file=sys.stderr)
    session.headers.update(
        {
            "User-Agent": "PAN GlobalProtect",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
    )
    return session, verify


def post_or_get_form(
    session,
    url: str,
    method: str,
    data: dict[str, str],
    verify: bool,
    timeout: float,
    allow_redirects=True,
):
    if method.upper() == "GET":
        return session.get(url, params=data, verify=verify, timeout=timeout, allow_redirects=allow_redirects)
    return session.post(url, data=data, verify=verify, timeout=timeout, allow_redirects=allow_redirects)


def start_gp_prelogin(session, args, verify: bool):
    prelogin_path = "global-protect/prelogin.esp" if args.interface == "portal" else "ssl-vpn/prelogin.esp"
    prelogin_url = f"https://{args.server}/{prelogin_path}"
    if args.verbose:
        print(f"[1] Richiesta prelogin ({args.interface}): {prelogin_url}", file=sys.stderr)

    res = session.post(
        prelogin_url,
        data={
            "tmp": "tmp",
            "kerberos-support": "yes",
            "ipv6-support": "yes",
            "clientVer": "4100",
            "clientos": args.clientos,
        },
        verify=verify,
        timeout=args.http_timeout,
    )
    if args.verbose > 1:
        print(f"[1] Risposta: {res.status_code}", file=sys.stderr)
    return res


def extract_saml_request(prelogin_response: requests.Response) -> tuple[str, str, Optional[str]]:
    saml_request_match = re.search(r"<saml-request>([^<]+)</saml-request>", prelogin_response.text)
    saml_method_match = re.search(r"<saml-auth-method>([^<]+)</saml-auth-method>", prelogin_response.text)
    if not saml_request_match:
        raise GpSamlError("risposta prelogin non contiene SAML request")

    saml_method = saml_method_match.group(1) if saml_method_match else "POST"
    saml_data = saml_request_match.group(1)
    try:
        decoded = b64decode(saml_data).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return saml_data, saml_method, None

    if "<html" in decoded.lower() or "<form" in decoded.lower():
        parser = parse_html(decoded)
        action = parser.forms[0]["action"] if parser.forms else None
        return action, saml_method, decoded
    return decoded, saml_method, None


def follow_initial_saml(session, saml_url: str, saml_html: Optional[str], verify: bool, timeout: float):
    if saml_html:
        parser = parse_html(saml_html)
        if parser.forms:
            form = parser.forms[0]
            action = form.get("action") or saml_url
            return post_or_get_form(
                session,
                action,
                form.get("method", "POST"),
                form_data(form),
                verify,
                timeout,
            )
    return session.get(saml_url, verify=verify, timeout=timeout, allow_redirects=True)


def do_fido2_auth(options, origin):
    """Esegue l'autenticazione FIDO2 con la chiave hardware."""
    if not HAS_FIDO2:
        raise GpSamlError("libreria fido2 non installata. Installa con: pip install fido2")

    def chiedi_retry(messaggio):
        print(messaggio, file=sys.stderr)
        try:
            risposta = input(
                "Inserisci/cambia la chiave di sicurezza e premi Invio per riprovare "
                "(oppure 'q' per uscire): "
            ).strip().lower()
            if risposta == "q":
                raise GpSamlError("Operazione annullata dall'utente.")
        except (KeyboardInterrupt, EOFError) as exc:
            print("", file=sys.stderr)
            raise GpSamlError("Operazione annullata dall'utente.") from exc

    challenge = options.get("challenge", "")
    if isinstance(challenge, str):
        challenge = b64decode_padding(challenge)
    rp_id = options.get("rpId", urlparse(origin).netloc)

    allow_creds_list = None
    allow_credentials = options.get("allowCredentials", [])
    if allow_credentials:
        allow_creds_list = []
        for cred in allow_credentials:
            cred_id = cred.get("id", "")
            if isinstance(cred_id, str):
                cred_id = b64decode_padding(cred_id)
            allow_creds_list.append(
                PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id)
            )

    uv_map = {
        "required": UserVerificationRequirement.REQUIRED,
        "preferred": UserVerificationRequirement.PREFERRED,
        "discouraged": UserVerificationRequirement.DISCOURAGED,
    }
    user_verification = uv_map.get(
        options.get("userVerification", "preferred"),
        UserVerificationRequirement.PREFERRED,
    )

    request_options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=allow_creds_list,
        user_verification=user_verification,
        timeout=options.get("timeout", 60000),
    )

    while True:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            chiedi_retry("Nessun dispositivo FIDO2 trovato.")
            continue

        device = devices[0]
        print(f"Trovata chiave: {device}", file=sys.stderr)
        client = Fido2Client(device, DefaultClientDataCollector(origin), user_interaction=CliInteraction())

        print("Attendo autenticazione FIDO2... (tocca la chiave)", file=sys.stderr)
        try:
            result = client.get_assertion(request_options)
            break
        except ClientError as exc:
            if "CONFIGURATION_UNSUPPORTED" in str(exc) or "UNSUPPORTED_OPTION" in str(exc):
                chiedi_retry(
                    f"La chiave inserita ({device}) non supporta FIDO2/WebAuthn.\n"
                    "Usa una chiave con supporto FIDO2 (es. YubiKey 5 o superiore)."
                )
                continue
            raise

    auth_response = result.get_response(0)
    assertion = auth_response.response
    response = {
        "id": b64encode_nopadding(auth_response.raw_id),
        "rawId": b64encode_nopadding(auth_response.raw_id),
        "type": "public-key",
        "response": {
            "authenticatorData": b64encode_nopadding(bytes(assertion.authenticator_data)),
            "clientDataJSON": b64encode_nopadding(bytes(assertion.client_data)),
            "signature": b64encode_nopadding(assertion.signature),
        },
        "clientExtensionResults": {},
    }
    if assertion.user_handle:
        response["response"]["userHandle"] = b64encode_nopadding(assertion.user_handle)
    return response


def handle_webauthn_page(session, res, parser, args, verify):
    webauthn_options = extract_webauthn_options(res.text)
    if not webauthn_options:
        return None

    challenge_key = (res.url, webauthn_options.get("rpId"), webauthn_options.get("challenge"))
    if getattr(args, "_last_webauthn_attempt", None) == challenge_key:
        raise FlowFailed(
            "pagina WebAuthn ripetuta dopo l'invio della risposta; "
            "evito di richiedere nuovamente PIN/touch sulla stessa challenge",
            res,
        )
    args._last_webauthn_attempt = challenge_key

    if args.verbose:
        print(f"[WebAuthn] Trovate opzioni: rpId={webauthn_options.get('rpId')}", file=sys.stderr)
    origin = f"https://{urlparse(res.url).netloc}"
    webauthn_response = do_fido2_auth(webauthn_options, origin)
    if args.verbose:
        print("Autenticazione FIDO2 completata", file=sys.stderr)

    payload = json.dumps(webauthn_response)
    for form in parser.forms:
        action = urljoin(res.url, form.get("action", "")) if form.get("action") else res.url
        data = form_data(form)
        for field_name in WEBAUTHN_RESPONSE_FIELDS:
            if field_name in data:
                data[field_name] = payload
                if field_name == "publicKeyCredential":
                    data["_eventId"] = "proceed"
                elif "_eventId" in data or "_eventId_proceed" in form.get("inputs", {}) or form_has_button(form, "_eventId_proceed"):
                    data["_eventId"] = "proceed"
                if args.verbose:
                    print(f"[WebAuthn] Invio risposta a {action}", file=sys.stderr)
                return session.post(action, data=data, verify=verify, timeout=args.http_timeout, allow_redirects=True)

    if args.verbose:
        print("[WebAuthn] Nessun form risposta trovato, provo POST diretto", file=sys.stderr)
    return session.post(
        res.url,
        data={"publicKeyCredential": payload, "_eventId": "proceed"},
        verify=verify,
        timeout=args.http_timeout,
        allow_redirects=True,
    )


def handle_webauthn_entrypoint(session, res, args, verify):
    entrypoint = find_webauthn_entrypoint(res.text, res.url)
    if not entrypoint:
        return None
    if entrypoint["type"] == "link":
        if args.verbose:
            print(f"[WebAuthn] Trovato link: {entrypoint['url']}", file=sys.stderr)
        return session.get(entrypoint["url"], verify=verify, timeout=args.http_timeout, allow_redirects=True)
    if args.verbose:
        print(f"[Passkey] Submit form a {entrypoint['url']}", file=sys.stderr)
    return post_or_get_form(
        session,
        entrypoint["url"],
        entrypoint.get("method", "POST"),
        entrypoint.get("data", {}),
        verify,
        args.http_timeout,
    )


def handle_login_form(session, res, parser, args, verify):
    login_form = find_login_form(parser.forms)
    if not login_form:
        return None

    action = urljoin(res.url, login_form.get("action", "")) if login_form.get("action") else res.url
    data = form_data(login_form)

    for field in LOGIN_USERNAME_FIELDS:
        if field in data:
            data[field] = args.user if args.user else input("Username: ")
            break

    for field in LOGIN_PASSWORD_FIELDS:
        if field in data:
            data[field] = getpass("Password: ")
            break

    if args.verbose:
        print(f"[Login] Invio credenziali a {action}", file=sys.stderr)
    return post_or_get_form(session, action, login_form.get("method", "POST"), data, verify, args.http_timeout)


def extract_gp_auth_result(res: requests.Response, verbose: int) -> dict[str, str]:
    result = {}
    for header, value in res.headers.items():
        h_lower = header.lower()
        if h_lower == "prelogin-cookie":
            result["prelogin-cookie"] = value
        elif h_lower == "saml-username":
            result["saml-username"] = value
        elif h_lower == "portal-userauthcookie":
            result["portal-userauthcookie"] = value

    if not result.get("prelogin-cookie") and not result.get("portal-userauthcookie"):
        if verbose > 1:
            print("[SAML] Cookie non trovato negli header, cerco nel body...", file=sys.stderr)
        for comment in re.findall(r"<!--(.+?)-->", res.text, re.DOTALL):
            try:
                xmlroot = ET.fromstring(f"<root>{comment}</root>")
            except ET.ParseError:
                continue
            for elem in xmlroot:
                tag = elem.tag.lower()
                if tag == "prelogin-cookie":
                    result["prelogin-cookie"] = elem.text or ""
                elif tag == "saml-username":
                    result["saml-username"] = elem.text or ""
                elif tag == "portal-userauthcookie":
                    result["portal-userauthcookie"] = elem.text or ""
        if verbose > 1 and result:
            print(f"[SAML] Trovato nei commenti XML: {list(result.keys())}", file=sys.stderr)
    return result


def print_openconnect_result(result: dict[str, str], args):
    interface = args.interface
    cookie_name = "prelogin-cookie" if "prelogin-cookie" in result else "portal-userauthcookie"
    cookie_value = result[cookie_name]
    username = result.get("saml-username", args.user or "unknown")

    if args.execute:
        import subprocess

        cmd = [
            "sudo",
            "openconnect",
            "--protocol=gp",
            "--useragent=PAN GlobalProtect",
            f"--user={username}",
            f"--os={args.clientos.lower()}",
            f"--usergroup={interface}:{cookie_name}",
            "--passwd-on-stdin",
            args.server,
        ]
        if args.allow_insecure_crypto:
            cmd.insert(2, "--allow-insecure-crypto")

        print(f"\nEseguo: {' '.join(quote(c) for c in cmd)}", file=sys.stderr)
        print("(con cookie come password)", file=sys.stderr)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
        proc.communicate(input=cookie_value)
        sys.exit(proc.returncode)

    print(f"\nHOST=https://{args.server}/{interface}:{cookie_name}")
    print(f"USER={username}")
    print(f"COOKIE={cookie_value}")
    print("\nPer connetterti:")
    openconnect_args = [
        "sudo",
        "openconnect",
        "--protocol=gp",
        "--useragent=PAN GlobalProtect",
        f"--user={username}",
        f"--os={args.clientos.lower()}",
        f"--usergroup={interface}:{cookie_name}",
        "--passwd-on-stdin",
        args.server,
    ]
    print(
        f"  printf '%s\\n' {quote(cookie_value)} | "
        f"{' '.join(quote(arg) for arg in openconnect_args)}"
    )


def handle_saml_response(session, res, parser, args, verify):
    saml_form = find_saml_response_form(parser.forms)
    if not saml_form:
        return None

    action = urljoin(res.url, saml_form.get("action", "")) if saml_form.get("action") else res.url
    data = form_data(saml_form)
    if args.verbose:
        print(f"[SAML] Invio SAMLResponse a {action}", file=sys.stderr)

    saml_res = session.post(action, data=data, verify=verify, timeout=args.http_timeout, allow_redirects=False)
    if args.verbose > 1:
        print(f"[SAML] Risposta {saml_res.status_code}", file=sys.stderr)
        for header, value in saml_res.headers.items():
            h_lower = header.lower()
            if h_lower.startswith("saml-") or h_lower.startswith("prelogin") or h_lower in {
                "set-cookie",
                "portal-userauthcookie",
            }:
                print(f"[SAML] Header {header}: {safe_header_value(header, value)[:120]}", file=sys.stderr)

    result = extract_gp_auth_result(saml_res, args.verbose)
    if result.get("prelogin-cookie") or result.get("portal-userauthcookie"):
        print("\nAutenticazione completata!", file=sys.stderr)
        print_openconnect_result(result, args)
        sys.exit(0)

    if saml_res.is_redirect:
        location = saml_res.headers.get("Location", "")
        if location:
            return session.get(
                urljoin(saml_res.url, location),
                verify=verify,
                timeout=args.http_timeout,
                allow_redirects=True,
            )
    return saml_res


def handle_proceed_link(session, res, args, verify):
    match = re.search(r'href=["\']([^"\']*(?:proceed|continue|next)[^"\']*)["\']', res.text, re.I)
    if not match:
        return None
    link = urljoin(res.url, match.group(1))
    if args.verbose:
        print(f"[Proceed] {link}", file=sys.stderr)
    return session.get(link, verify=verify, timeout=args.http_timeout, allow_redirects=True)


def run_auth_flow(session, res, args, verify):
    handlers = (
        (handle_webauthn_page, True),
        (handle_webauthn_entrypoint, False),
        (handle_login_form, True),
        (handle_saml_response, True),
        (handle_proceed_link, False),
    )

    for step in range(args.max_steps):
        if args.verbose > 1:
            print(f"[Step {step}] URL: {res.url} status={res.status_code}", file=sys.stderr)
        parser = parse_html(res.text)

        for handler, needs_parser in handlers:
            if needs_parser:
                next_res = handler(session, res, parser, args, verify)
            else:
                next_res = handler(session, res, args, verify)
            if next_res is not None:
                res = next_res
                break
        else:
            raise FlowFailed("pagina senza azioni riconosciute", res)

    raise FlowFailed(f"raggiunto limite massimo step ({args.max_steps})", res)


def build_arg_parser():
    parser = argparse.ArgumentParser(description="GlobalProtect SAML + FIDO2 authentication")
    parser.add_argument("server", help="GlobalProtect server (es: vpn.example.com)")
    parser.add_argument("-u", "--user", help="Username (se richiesto prima di WebAuthn)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-v, -vv, -vvv)")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Ignora errori certificato SSL (disabilita verifica TLS)",
    )
    parser.add_argument("-x", "-e", "--execute", action="store_true", help="Esegui openconnect automaticamente")
    parser.add_argument("--clientos", default="Linux", choices=["Linux", "Windows", "Mac"], help="Client OS da simulare")
    parser.add_argument("--allow-insecure-crypto", action="store_true", help="Passa --allow-insecure-crypto a openconnect")
    parser.add_argument("--max-steps", type=int, default=10, help="Numero massimo di step nel flusso SAML/FIDO2")
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=HTTP_TIMEOUT_DEFAULT,
        help="Timeout HTTP in secondi per le richieste al portal/IdP",
    )

    iface_group = parser.add_mutually_exclusive_group()
    iface_group.add_argument(
        "-g",
        "--gateway",
        dest="interface",
        action="store_const",
        const="gateway",
        help="Usa gateway interface (ssl-vpn/prelogin.esp)",
    )
    iface_group.add_argument(
        "-p",
        "--portal",
        dest="interface",
        action="store_const",
        const="portal",
        help="Usa portal interface (global-protect/prelogin.esp) [default]",
    )
    parser.set_defaults(interface="portal")
    return parser


def main():
    args = build_arg_parser().parse_args()
    if args.max_steps < 1:
        print("Errore: --max-steps deve essere >= 1", file=sys.stderr)
        sys.exit(2)
    if args.http_timeout <= 0:
        print("Errore: --http-timeout deve essere > 0 secondi", file=sys.stderr)
        sys.exit(2)

    session, verify = setup_session(args)
    last_response = None
    try:
        prelogin_res = start_gp_prelogin(session, args, verify)
        last_response = prelogin_res
        saml_url, saml_method, saml_html = extract_saml_request(prelogin_res)
        if args.verbose:
            print(f"[2] SAML URL/Method: {saml_url} / {saml_method}", file=sys.stderr)
        if not saml_url:
            raise GpSamlError("SAML URL assente nel form iniziale")

        res = follow_initial_saml(session, saml_url, saml_html, verify, args.http_timeout)
        last_response = res
        if args.verbose:
            print(f"[3] Pagina IdP: {res.url}", file=sys.stderr)
        run_auth_flow(session, res, args, verify)
    except requests.RequestException as exc:
        print(f"\nErrore HTTP: {exc}", file=sys.stderr)
        if getattr(exc, "response", None) is not None:
            print_failure_context(exc.response, args.verbose, "richiesta HTTP fallita")
        sys.exit(1)
    except GpSamlError as exc:
        failure_response = getattr(exc, "response", None) or last_response
        if failure_response is not None:
            print_failure_context(failure_response, args.verbose, str(exc))
        else:
            print(f"\nErrore: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
