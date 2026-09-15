"""Hermetic unit tests for BaseAudit Oracle."""

import unittest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

import server
from server import app, USDC_ASSET

client = TestClient(app)


class BaseAuditServerTests(unittest.TestCase):
    def test_root_discovery(self):
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("BaseAudit Oracle", data["service"])
        self.assertEqual(data["payee"], server.PAYEE_ADDRESS)

    def test_health_check(self):
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)

    def test_self_test(self):
        resp = client.get("/self-test")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("sample"))
        self.assertIn("audit", data)

    def test_well_known_x402(self):
        resp = client.get("/.well-known/x402")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["x402Version"], 2)
        self.assertEqual(data["payment"]["payTo"], server.PAYEE_ADDRESS)
        self.assertEqual(len(data["resources"]), 2)

    def test_audit_402_challenge_get(self):
        resp = client.get("/v1/audit")
        self.assertEqual(resp.status_code, 402)
        data = resp.json()
        self.assertEqual(data["x402Version"], 2)
        self.assertEqual(data["accepts"][0]["payTo"], server.PAYEE_ADDRESS)
        self.assertEqual(data["accepts"][0]["amount"], server.PRICE_ATOMIC)
        self.assertIn("bazaar", data["extensions"])

    def test_audit_402_challenge_post(self):
        resp = client.post("/v1/audit", json={"address": USDC_ASSET})
        self.assertEqual(resp.status_code, 402)
        data = resp.json()
        self.assertEqual(data["x402Version"], 2)
        self.assertEqual(data["accepts"][0]["payTo"], server.PAYEE_ADDRESS)

    def test_proxy_402_challenge(self):
        resp = client.get("/v1/proxy")
        self.assertEqual(resp.status_code, 402)
        data = resp.json()
        self.assertEqual(data["x402Version"], 2)

    def test_audit_with_mock_payment_success(self):
        headers = {"X-Payment": "valid_signed_eip3009_payload"}
        resp = client.post("/v1/audit", json={"address": USDC_ASSET}, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["payment_processed"])
        self.assertIn("audit", data)
        audit = data["audit"]
        self.assertTrue(audit["is_contract"])
        self.assertGreater(audit["bytecode_size_bytes"], 0)
        self.assertIn("risk_score", audit)


if __name__ == "__main__":
    unittest.main()
