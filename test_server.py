import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import app as server


class LicenseServerTests(unittest.TestCase):
    def setUp(self):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_patch = patch.object(server, 'PUBLIC', self.private.public_key())
        self.public_patch.start()
        pem = self.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        self.env = patch.dict(os.environ, {'OWNER_PRIVATE_KEY_PEM': pem, 'VERCEL': '1'})
        self.env.start()
        self.client = TestClient(server.app)
        self.request = {'deviceId': 'A' * 32, 'key': '', 'nonce': 'b' * 32, 'macAddresses': ['02:AB:CD:EF:12:34']}
        self.now = datetime.now(timezone.utc)
        self.db = {'status': 200, 'serverUtc': self.now.isoformat(), 'expiresUtc': (self.now + timedelta(days=7)).isoformat()}

    def tearDown(self):
        self.env.stop()
        self.public_patch.stop()

    def call(self):
        return self.client.post('/v1/authorize', json=self.request, headers={'x-forwarded-for': '203.0.113.5'})

    def paid(self, device=None):
        expiry = (self.now + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S') + '.1234567+00:00'
        claims = {'Kind': 'subscription', 'DeviceId': device or self.request['deviceId'], 'LicenseId': 'paid_test', 'ExpiresUtc': expiry}
        self.request['key'] = server.sign(claims, self.private)
        return claims

    def test_trial_signature_nonce_mac_and_ip_hash(self):
        with patch.object(server, 'authorize_db', return_value=self.db) as db:
            result = self.call()
        self.assertEqual(result.status_code, 200)
        grant = server.verify(result.json()['token'])
        self.assertEqual(grant['Nonce'], self.request['nonce'])
        self.assertEqual(grant['Kind'], 'trial')
        self.assertEqual(grant['LeaseSeconds'], 180)
        self.assertEqual(db.call_args.args[0]['p_macs'], ['02ABCDEF1234'])
        self.assertEqual(len(db.call_args.args[0]['p_ip_hash']), 64)

    def test_paid_expiry_preserves_dotnet_precision(self):
        claims = self.paid()
        with patch.object(server, 'authorize_db', return_value=self.db):
            result = self.call()
        self.assertEqual(server.verify(result.json()['token'])['ExpiresUtc'], claims['ExpiresUtc'])

    def test_wrong_pc_rejected_before_database(self):
        self.paid('C' * 32)
        with patch.object(server, 'authorize_db') as db:
            self.assertEqual(self.call().status_code, 403)
            db.assert_not_called()

    def test_tampered_key(self):
        self.paid()
        parts = self.request['key'].split('.')
        parts[1] = server.b64(b'{}')
        self.request['key'] = '.'.join(parts)
        self.assertEqual(self.call().status_code, 403)

    def test_revoked_expired_or_exhausted_trial(self):
        for error in ['Revoked', 'Expired', 'Trial ended']:
            with patch.object(server, 'authorize_db', return_value={'status': 403, 'error': error}):
                self.assertEqual(self.call().status_code, 403)

    def test_rate_limit(self):
        with patch.object(server, 'authorize_db', return_value={'status': 429, 'error': 'Rate limited'}):
            self.assertEqual(self.call().status_code, 429)

    def test_database_failure_returns_unavailable(self):
        with patch.object(server, 'authorize_db', side_effect=OSError('private endpoint data')):
            result = self.call()
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('private', result.text)

    def test_wrong_signing_authority_fails_before_database(self):
        with patch.object(server, 'PUBLIC', rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()), patch.object(server, 'authorize_db') as db:
            self.assertEqual(self.call().status_code, 503)
            db.assert_not_called()

    def test_invalid_device_and_mac_list(self):
        self.request['deviceId'] = 'wrong'
        self.assertEqual(self.call().status_code, 400)
        self.request['deviceId'] = 'A' * 32
        self.request['macAddresses'] = ['02ABCDEF1234'] * 17
        self.assertEqual(self.call().status_code, 400)

    def test_size_limit(self):
        self.assertEqual(self.client.post('/v1/authorize', content='x' * 16385).status_code, 413)

    def test_ip_missing_or_ambiguous(self):
        for value in ['', '203.0.113.5, 203.0.113.6']:
            self.assertEqual(self.client.post('/v1/authorize', json=self.request, headers={'x-forwarded-for': value}).status_code, 400)

    def test_local_socket_ignores_spoofed_forwarded_header(self):
        from starlette.requests import Request
        req = Request({'type': 'http', 'headers': [(b'x-forwarded-for', b'8.8.8.8')], 'client': ('127.0.0.1', 10)})
        with patch.dict(os.environ, {'VERCEL': '0'}):
            self.assertEqual(server.requester_ip(req), '127.0.0.1')


if __name__ == '__main__':
    unittest.main()
