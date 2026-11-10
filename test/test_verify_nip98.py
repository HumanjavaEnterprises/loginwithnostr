import base64
import json
import sys
import unittest
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "python"))

from nostrkey.events import UnsignedEvent, sign_event  # noqa: E402
from nostrkey.keys import generate_keypair  # noqa: E402
from verify_nip98 import verify_nip98  # noqa: E402

URL = "https://example.com/api/auth/nostr"
NOW = 1_800_000_000


def make(kind=27235, tags=None, created_at=NOW):
    priv, pub = _keys()
    ev = sign_event(priv, UnsignedEvent(kind=kind, content="",
                                        tags=tags or [["u", URL], ["method", "POST"]],
                                        created_at=created_at))
    return pub, asdict(ev)


def _keys():
    kp = generate_keypair()
    if isinstance(kp, tuple):
        return kp[0], kp[1]
    return kp.private_key_hex, kp.public_key_hex


def enc(d):
    return "Nostr " + base64.b64encode(json.dumps(d).encode()).decode()


class VerifyNip98(unittest.TestCase):
    def test_valid_once_then_replay(self):
        pub, ev = make()
        self.assertEqual(verify_nip98(enc(ev), URL, "POST", NOW), pub)
        with self.assertRaisesRegex(ValueError, "already used"):
            verify_nip98(enc(ev), URL, "POST", NOW)

    def test_future_dated_replay(self):
        _, ev = make(created_at=NOW + 60)
        verify_nip98(enc(ev), URL, "POST", NOW)
        with self.assertRaisesRegex(ValueError, "already used"):
            verify_nip98(enc(ev), URL, "POST", NOW + 61)

    def test_tampered(self):
        _, ev = make()
        ev["content"] = "x"
        with self.assertRaisesRegex(ValueError, "bad signature"):
            verify_nip98(enc(ev), URL, "POST", NOW)

    def test_other_key(self):
        _, ev = make()
        other, _ = make()
        ev["pubkey"] = other
        with self.assertRaisesRegex(ValueError, "bad signature"):
            verify_nip98(enc(ev), URL, "POST", NOW)

    def test_wrong_fields(self):
        _, ev = make()
        with self.assertRaisesRegex(ValueError, "url"):
            verify_nip98(enc(ev), URL + "/other", "POST", NOW)
        _, ev = make()
        with self.assertRaisesRegex(ValueError, "method"):
            verify_nip98(enc(ev), URL, "GET", NOW)
        _, ev = make(kind=1)
        with self.assertRaisesRegex(ValueError, "kind"):
            verify_nip98(enc(ev), URL, "POST", NOW)
        _, ev = make()
        with self.assertRaisesRegex(ValueError, "expired"):
            verify_nip98(enc(ev), URL, "POST", NOW + 61)

    def test_malformed(self):
        for h in (None, "Bearer x", "Nostr !!!"):
            with self.assertRaises(ValueError):
                verify_nip98(h, URL, "POST", NOW)


if __name__ == "__main__":
    unittest.main()
