"""Hermetic BaseAudit data-quality and payment-boundary regressions."""
import asyncio
import json
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
import httpx
import pytest

import server

TARGET = "0x1111111111111111111111111111111111111111"
IMPL = "0x2222222222222222222222222222222222222222"
BEACON = "0x3333333333333333333333333333333333333333"
ZERO_SLOT = "0x" + "00" * 32


def slot(address):
    return "0x" + "00" * 12 + address[2:]


def rpc_fixture(*, code="0x60006000f4", implementation=None, beacon=None, chain="0x2105"):
    async def rpc(method, params):
        if method == "eth_chainId":
            return chain
        if method == "eth_blockNumber":
            return "0x1234"
        if method == "eth_getCode":
            return code
        if method == "eth_getStorageAt":
            values = {server.EIP1967_IMPL_SLOT: slot(implementation) if implementation else ZERO_SLOT,
                      server.EIP1967_ADMIN_SLOT: ZERO_SLOT,
                      server.EIP1967_BEACON_SLOT: slot(beacon) if beacon else ZERO_SLOT}
            return values[params[1]]
        raise AssertionError("Unexpected RPC method: " + method)
    return AsyncMock(side_effect=rpc)


def analyze(**kwargs):
    rpc = rpc_fixture(**kwargs)
    with patch.object(server, "rpc_call", rpc):
        result = asyncio.run(server.analyze_contract(TARGET))
    return result, rpc


@pytest.mark.parametrize("path", ["/", "/health", "/self-test", "/.well-known/x402", "/openapi.json"])
def test_public_routes_do_not_fetch_paid_analysis(path):
    with patch.object(server, "rpc_call", AsyncMock()) as rpc, patch.object(server, "analyze_contract", AsyncMock()) as business:
        with TestClient(server.app) as client:
            response = client.get(path)
    assert response.status_code == 200
    rpc.assert_not_awaited()
    business.assert_not_awaited()
    if path == "/self-test":
        assert response.json()["check_type"] == "configuration_only"
        assert "audit" not in response.json()


@pytest.mark.parametrize("path", ["/v1/audit", "/v1/proxy"])
@pytest.mark.parametrize("method", ["GET", "POST", "HEAD"])
@pytest.mark.parametrize("header", ["Authorization", "X-Payment", "Payment-Receipt", "Payment-Response"])
def test_fake_header_does_not_unlock_resource(path, method, header):
    with patch.object(server, "analyze_contract", AsyncMock()) as business, patch.object(server, "rpc_call", AsyncMock()) as rpc, patch.object(server.payment.facilitator, "verify", AsyncMock()) as verify:
        with TestClient(server.app) as client:
            kwargs = {"json": {"address": TARGET}} if method == "POST" else {"params": {"address": TARGET}}
            result = client.request(method, path, headers={header: "Payment pretend-this-is-paid"}, **kwargs)
    assert result.status_code == 402
    assert "PAYMENT-REQUIRED" in result.headers
    assert "PAYMENT-RESPONSE" not in result.headers
    business.assert_not_awaited()
    rpc.assert_not_awaited()
    verify.assert_not_awaited()


def test_discovery_exposes_only_canonical_get_operations():
    with TestClient(server.app) as client:
        manifest = client.get("/.well-known/x402").json()
        schema = client.get("/openapi.json").json()
    assert {(item["method"], item["path"]) for item in manifest["resources"]} == {
        ("GET", "/v1/audit"), ("GET", "/v1/proxy")}
    for path in ("/v1/audit", "/v1/proxy"):
        assert set(schema["paths"][path]) == {"get"}
    assert all(item["accepts"][0]["amount"] == "20000" for item in manifest["resources"])


@pytest.mark.parametrize("width", [1, 2, 4, 20, 32])
def test_opcode_bytes_inside_push_operands_are_not_instructions(width):
    operand = (b"\xff\xf4" * 16)[:width]
    result = server.inspect_bytecode(bytes([0x5F + width]) + operand + b"\x00")
    assert result["has_selfdestruct"] is False
    assert result["has_delegatecall"] is False
    assert result["disassembly_complete"] is True


def test_real_opcode_offsets_after_push_are_preserved():
    result = server.inspect_bytecode(bytes.fromhex("61fff4fff4"))
    assert result["opcode_offsets"] == {"SELFDESTRUCT": [3], "DELEGATECALL": [4]}
    assert result["has_selfdestruct"] is True
    assert result["has_delegatecall"] is True


def test_truncated_push_operand_does_not_create_false_opcode():
    result = server.inspect_bytecode(bytes.fromhex("7ffff4"))
    assert result["has_selfdestruct"] is False
    assert result["has_delegatecall"] is False
    assert result["disassembly_complete"] is False
    assert result["security_findings"][0]["code"] == "truncated_push_operand"


def test_selectors_are_only_push4_hints_not_confirmed_interfaces():
    data = bytes.fromhex("67a9059cbb000000006370a0823100")
    result = server.inspect_bytecode(data)
    assert [item["selector"] for item in result["selector_hints"]] == ["0x70a08231"]
    assert result["standards_confirmed"] == []


def test_empty_runtime_does_not_receive_a_safe_score_or_eoa_claim():
    result, rpc = analyze(code="0x")
    assert result["is_contract"] is False
    assert result["risk_score"] is None
    assert result["risk_level"] == "NOT_ASSESSED"
    assert result["is_proxy"] is None
    assert rpc.await_count == 3
    assert "Externally Owned Account" not in json.dumps(result)


def test_eip1967_implementation_is_reported_as_unanalyzed_pointer():
    result, rpc = analyze(implementation=IMPL)
    assert result["is_proxy"] is True
    assert result["implementation_address"] == IMPL
    assert result["implementation_analysis"] == "not_performed"
    assert result["analysis_scope"] == "proxy_runtime_only"
    assert result["proxy_type"] == "EIP-1967 implementation slot"
    code_calls = [call.args for call in rpc.await_args_list if call.args[0] == "eth_getCode"]
    assert code_calls == [("eth_getCode", [TARGET, "0x1234"])]
    assert result["risk_score"] is None


def test_beacon_address_is_not_fabricated_as_implementation():
    result, rpc = analyze(beacon=BEACON)
    assert result["beacon_address"] == BEACON
    assert result["implementation_address"] is None
    assert result["beacon_implementation_resolution"] == "not_supported"
    assert result["analysis_scope"] == "proxy_runtime_only"
    assert all(call.args[0] != "eth_call" for call in rpc.await_args_list)


def test_conflicting_implementation_and_beacon_slots_are_disclosed():
    result, _ = analyze(implementation=IMPL, beacon=BEACON)
    assert "conflicting_proxy_slots" in [item["code"] for item in result["security_findings"]]


def test_empty_proxy_slots_do_not_prove_non_proxy():
    result, _ = analyze()
    assert result["is_proxy"] is None
    assert result["proxy_detection"] == "no_eip1967_proxy_slot_observed"
    assert result["analysis_type"] == "static_onchain_heuristic"
    assert result["confidence"] == "limited"


def test_code_and_slots_use_one_numbered_block():
    result, rpc = analyze()
    assert result["block_number"] == 0x1234
    state_calls = [call.args for call in rpc.await_args_list if call.args[0] in ("eth_getCode", "eth_getStorageAt")]
    assert len(state_calls) == 4
    assert all(params[-1] == "0x1234" for _, params in state_calls)
    assert result["data_sources"]


@pytest.mark.parametrize("chain", ["0x1", "0x2106", None, "0x", 8453])
def test_wrong_or_malformed_chain_fails_before_bytecode(chain):
    rpc = rpc_fixture(chain=chain)
    with patch.object(server, "rpc_call", rpc), pytest.raises(server.UpstreamUnavailable):
        asyncio.run(server.analyze_contract(TARGET))
    assert not any(call.args[0] == "eth_getCode" for call in rpc.await_args_list)


@pytest.mark.parametrize("word", [None, "0x", "0x0", "0xzz", "0x" + "0" * 63, "0x" + "ff" * 32])
def test_malformed_storage_word_is_not_silently_absent(word):
    with pytest.raises(server.UpstreamUnavailable):
        server.parse_address_from_slot(word)


@pytest.mark.parametrize("code", [None, "0x0", "0xzz", "6000", "0x" + "00" * (server.MAX_BYTECODE_BYTES + 1)],
                         ids=["missing", "odd_length", "non_hex", "no_prefix", "oversized"])
def test_bytecode_validation_is_bounded(code):
    with pytest.raises(server.UpstreamUnavailable):
        server.decode_bytecode(code)


@pytest.mark.parametrize("address", ["", "0x1234", TARGET + "\n", None, "0x" + "g" * 40])
def test_invalid_address_never_calls_rpc(address):
    with patch.object(server, "rpc_call", AsyncMock()) as rpc, pytest.raises(ValueError):
        asyncio.run(server.analyze_contract(address))
    rpc.assert_not_awaited()


def test_rpc_failure_is_sanitized_not_a_successful_empty_report():
    with patch.object(server, "analyze_contract", AsyncMock(side_effect=ValueError("provider-secret-raw-body"))):
        result = asyncio.run(server._observe(TARGET))
    assert result.status_code == 502
    assert json.loads(result.body)["error"]["code"] == "upstream_unavailable"
    assert b"provider-secret" not in result.body


@pytest.mark.parametrize("value", [[], {"jsonrpc": "2.0", "id": 1}, {"jsonrpc": "2.0", "id": True, "result": "0x1"},
                                   {"jsonrpc": "2.0", "id": 1, "error": {"message": "private-provider-data"}}])
def test_rpc_envelope_validation(value):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=value))
    real_client = httpx.AsyncClient
    with patch.object(server.httpx, "AsyncClient", side_effect=lambda **kwargs: real_client(transport=transport, **kwargs)):
        with pytest.raises(server.UpstreamUnavailable, match="Base RPC is unavailable"):
            asyncio.run(server.rpc_call("eth_chainId", []))


def test_rpc_response_size_is_bounded():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b" " * (server.MAX_RPC_RESPONSE_BYTES + 1)))
    real_client = httpx.AsyncClient
    with patch.object(server.httpx, "AsyncClient", side_effect=lambda **kwargs: real_client(transport=transport, **kwargs)):
        with pytest.raises(server.UpstreamUnavailable):
            asyncio.run(server.rpc_call("eth_chainId", []))
