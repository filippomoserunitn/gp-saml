import importlib.util
import pathlib
import types
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "gp-saml-fido2-cli.py"
SPEC = importlib.util.spec_from_file_location("gp_saml_fido2_cli", MODULE_PATH)
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class HelperTests(unittest.TestCase):
    def test_base64url_roundtrip_without_padding(self):
        raw = b"hello world?"
        encoded = cli.b64encode_nopadding(raw)
        self.assertNotIn("=", encoded)
        self.assertEqual(cli.b64decode_padding(encoded), raw)

    def test_parse_html_forms_inputs_buttons_and_links(self):
        html = """
        <form action="/login" method="post">
          <input type="hidden" name="csrf" value="abc">
          <input type="text" name="username">
          <input type="password" name="password">
          <button name="_eventId_runFlow_WebAuthn" type="submit">Entra con passkey</button>
        </form>
        <a href="/webauthn/start"><img alt="WebAuthn"></a>
        """
        parser = cli.parse_html(html)
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0]["action"], "/login")
        self.assertIn("csrf", parser.forms[0]["inputs"])
        self.assertEqual(parser.forms[0]["buttons"][0]["attrs"]["name"], "_eventId_runFlow_WebAuthn")
        self.assertEqual(parser.links[0]["href"], "/webauthn/start")

    def test_extract_webauthn_options_from_multiline_variable_with_trailing_commas(self):
        html = """
        <script>
          const pkCredRequestOptions = {
            "publicKey": {
              "challenge": "YWJj",
              "rpId": "idp.example.org",
              "allowCredentials": [
                {"type": "public-key", "id": "ZGVm",},
              ],
            },
          };
        </script>
        """
        options = cli.extract_webauthn_options(html)
        self.assertEqual(options["challenge"], "YWJj")
        self.assertEqual(options["rpId"], "idp.example.org")
        self.assertEqual(options["allowCredentials"][0]["id"], "ZGVm")

    def test_extract_webauthn_options_from_navigator_credentials_get(self):
        html = """
        <script>
          navigator.credentials.get({
            publicKey: {challenge: 'Y2hhbA', rpId: "login.example.test"}
          });
        </script>
        """
        options = cli.extract_webauthn_options(html)
        self.assertEqual(options["challenge"], "Y2hhbA")
        self.assertEqual(options["rpId"], "login.example.test")

    def test_find_webauthn_link_and_button(self):
        link = cli.find_webauthn_entrypoint(
            '<a href="/idp/webauthn">Security Key</a>',
            "https://idp.example.org/login",
        )
        self.assertEqual(link["type"], "link")
        self.assertEqual(link["url"], "https://idp.example.org/idp/webauthn")

        button = cli.find_webauthn_entrypoint(
            """
            <form action="/login" method="post">
              <input name="csrf" value="1">
              <button name="_eventId_runFlow_WebAuthn" type="submit">Entra con passkey</button>
            </form>
            """,
            "https://idp.example.org/start",
        )
        self.assertEqual(button["type"], "form")
        self.assertEqual(button["data"]["_eventId"], "runFlow_WebAuthn")

    def test_mask_cookie_header(self):
        masked = cli.mask_cookie_header("GPSESSIONID=abcdef1234567890; Path=/; other=value")
        self.assertIn("GPSESSIONID=abcd...7890", masked)
        self.assertNotIn("abcdef1234567890", masked)
        self.assertIn("other=value", masked)

        self.assertEqual(cli.safe_header_value("prelogin-cookie", "abcdef1234567890"), "abcd...7890")

    def test_webauthn_public_key_credential_posts_proceed_event(self):
        html = """
        <script>
          const pkCredRequestOptions = {"publicKey": {"challenge": "YWJj", "rpId": "idp.example.org"}};
        </script>
        <form action="/webauthn" method="post">
          <input name="csrf" value="token">
          <input name="publicKeyCredential" value="">
        </form>
        """

        class FakeSession:
            def __init__(self):
                self.posted = None

            def post(self, url, data, verify, allow_redirects):
                self.posted = {
                    "url": url,
                    "data": data,
                    "verify": verify,
                    "allow_redirects": allow_redirects,
                }
                return "next-response"

        original_auth = cli.do_fido2_auth
        try:
            cli.do_fido2_auth = lambda options, origin: {"id": "credential"}
            response = types.SimpleNamespace(
                text=html,
                url="https://idp.example.org/login",
                status_code=200,
            )
            parser = cli.parse_html(html)
            args = types.SimpleNamespace(verbose=0)
            session = FakeSession()

            result = cli.handle_webauthn_page(session, response, parser, args, True)

            self.assertEqual(result, "next-response")
            self.assertEqual(session.posted["url"], "https://idp.example.org/webauthn")
            self.assertEqual(session.posted["data"]["_eventId"], "proceed")
            self.assertIn("publicKeyCredential", session.posted["data"])
        finally:
            cli.do_fido2_auth = original_auth


if __name__ == "__main__":
    unittest.main()
