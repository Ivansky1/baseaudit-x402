"""Bounded, read-only Base bytecode observations behind a verified x402 gate."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
import re
from typing import Annotated

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, ConfigDict, Field

from x402_payment import NETWORK, USDC_ASSET, PaidOperation, PaymentGate, configured_payee

PAYEE_ADDRESS = configured_payee()
PRICE_ATOMIC = "20000"
CHAIN_ID = NETWORK
BASE_RPC_URL = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
ADDRESS_PATTERN = r"^0x[0-9a-fA-F]{40}$"
MAX_BYTECODE_BYTES = 65536
MAX_RPC_RESPONSE_BYTES = 150000
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
FUNCTION_SELECTORS = {
    "a9059cbb": ("transfer(address,uint256)", "ERC-20"),
    "23b872dd": ("transferFrom(address,address,uint256)", "ERC-20/ERC-721"),
    "70a08231": ("balanceOf(address)", "ERC-20/ERC-721"),
    "095ea7b3": ("approve(address,uint256)", "ERC-20/ERC-721"),
    "18160ddd": ("totalSupply()", "ERC-20/ERC-721"),
    "6352211e": ("ownerOf(uint256)", "ERC-721"),
    "42842e0e": ("safeTransferFrom(address,address,uint256)", "ERC-721"),
    "40c10f19": ("mint(address,uint256)", "Mintable"),
    "a0712d68": ("mint(uint256)", "Mintable"),
    "8456cb59": ("pause()", "Pausable"),
    "3f4ba63a": ("unpause()", "Pausable"),
    "8da5cb5b": ("owner()", "Ownable"),
    "f2fde38b": ("transferOwnership(address)", "Ownable"),
    "3659cfe6": ("upgradeTo(address)", "Upgradeable"),
}
LIMITATIONS = [
    "Static observations are not a security audit, simulation, or safety guarantee.",
    "Linear disassembly skips PUSH operands but does not prove reachability; embedded data or metadata can resemble instructions.",
    "PUSH4 selector matches do not prove that a function exists, is callable, or implements an interface.",
    "Implementation code, permissions, control flow, and storage invariants are not analyzed.",
    "Only EIP-1967 storage slots are checked; an empty slot does not rule out other proxy designs.",
    "A numbered block is used consistently; RPC trust and chain reorganizations remain limitations.",
]

app = FastAPI(title="BaseAudit Oracle x402", version="2.0.0", redirect_slashes=False,
              description="Static Base runtime bytecode and EIP-1967 slot observations. Not a security audit.")


class UpstreamUnavailable(ValueError):
    """RPC data is unavailable or does not meet the expected schema."""


async def rpc_call(method: str, params: list):
    """A bounded JSON-RPC read; provider bodies never become client errors."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=3.0),
                                     follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", BASE_RPC_URL, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
            }) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RPC_RESPONSE_BYTES:
                        raise UpstreamUnavailable("RPC response exceeds the limit")
                result = json.loads(body)
        if (not isinstance(result, dict) or result.get("jsonrpc") != "2.0"
                or type(result.get("id")) is not int or result["id"] != 1
                or "error" in result or "result" not in result):
            raise UpstreamUnavailable("Invalid RPC response")
        return result["result"]
    except (httpx.HTTPError, ValueError, TypeError, RecursionError):
        raise UpstreamUnavailable("Base RPC is unavailable") from None


def rpc_quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})", value):
        raise UpstreamUnavailable("Invalid RPC quantity")
    return int(value, 16)


def parse_address_from_slot(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise UpstreamUnavailable("Invalid storage word")
    if int(value[2:26], 16) != 0:
        raise UpstreamUnavailable("Storage word is not a padded address")
    return "0x" + value[-40:].lower() if int(value, 16) else None


def decode_bytecode(value):
    if (not isinstance(value, str) or len(value) > 2 + MAX_BYTECODE_BYTES * 2
            or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value)):
        raise UpstreamUnavailable("Invalid runtime bytecode")
    return bytes.fromhex(value[2:])


def inspect_bytecode(code: bytes):
    """Linear EVM decoding: PUSH1..PUSH32 immediate data is never an opcode."""
    offsets = {"SELFDESTRUCT": [], "DELEGATECALL": []}
    selectors = set()
    pc, truncated = 0, False
    while pc < len(code):
        offset, opcode = pc, code[pc]
        pc += 1
        if 0x60 <= opcode <= 0x7F:
            width = opcode - 0x5F
            if pc + width > len(code):
                truncated = True
                break
            if width == 4:
                selector = code[pc:pc + width].hex()
                if selector in FUNCTION_SELECTORS:
                    selectors.add(selector)
            pc += width
        elif opcode == 0xFF:
            offsets["SELFDESTRUCT"].append(offset)
        elif opcode == 0xF4:
            offsets["DELEGATECALL"].append(offset)
    hints = [{"selector": "0x" + selector, "function": FUNCTION_SELECTORS[selector][0],
              "interface_hint": FUNCTION_SELECTORS[selector][1]} for selector in sorted(selectors)]
    findings = []
    if offsets["SELFDESTRUCT"]:
        findings.append({"code": "selfdestruct_instruction", "severity": "review",
                         "message": "SELFDESTRUCT instruction observed; reachability and effects are unverified. Modern EVM rules restrict code deletion."})
    if offsets["DELEGATECALL"]:
        findings.append({"code": "delegatecall_instruction", "severity": "review",
                         "message": "DELEGATECALL instruction observed; the target and access controls are unverified."})
    if truncated:
        findings.append({"code": "truncated_push_operand", "severity": "info",
                         "message": "Runtime ends within a PUSH operand; disassembly is incomplete."})
    return {"has_selfdestruct": bool(offsets["SELFDESTRUCT"]),
            "has_delegatecall": bool(offsets["DELEGATECALL"]),
            "opcode_offsets": offsets, "selector_hints": hints,
            "standards_confirmed": [], "disassembly_complete": not truncated,
            "security_findings": findings}


async def analyze_contract(address: str):
    if not isinstance(address, str) or not re.fullmatch(ADDRESS_PATTERN, address):
        raise ValueError("Invalid address")
    address = address.lower()
    chain, block = await asyncio.gather(rpc_call("eth_chainId", []), rpc_call("eth_blockNumber", []))
    if rpc_quantity(chain) != 8453:
        raise UpstreamUnavailable("Unexpected RPC chain")
    block_number = rpc_quantity(block)
    block_tag = hex(block_number)
    code = decode_bytecode(await rpc_call("eth_getCode", [address, block_tag]))
    result = {
        "address": address, "network": NETWORK, "chain_id": 8453, "block_number": block_number,
        "timestamp": datetime.now(timezone.utc).isoformat(), "analysis_type": "static_onchain_heuristic",
        "analysis_scope": "queried_address_runtime_only", "confidence": "limited",
        "is_contract": bool(code), "bytecode_size_bytes": len(code), "risk_score": None,
        "risk_level": "NOT_ASSESSED", "is_proxy": None, "proxy_type": None,
        "implementation_address": None, "admin_address": None, "beacon_address": None,
        "implementation_analysis": "not_performed", "beacon_implementation_resolution": "not_applicable",
        "proxy_detection": "not_checked", "limitations": list(LIMITATIONS),
        "data_sources": [{"provider": "configured_base_rpc", "method": "eth_chainId"},
                         {"provider": "configured_base_rpc", "method": "eth_blockNumber"},
                         {"provider": "configured_base_rpc", "method": "eth_getCode", "block": block_tag}],
        **inspect_bytecode(code),
    }
    if not code:
        result["proxy_detection"] = "no_runtime_bytecode"
        result["security_findings"].append({"code": "no_runtime_bytecode", "severity": "info",
                                           "message": "No runtime code at the observed block; this does not establish account type or safety."})
        return result
    slots = [EIP1967_IMPL_SLOT, EIP1967_ADMIN_SLOT, EIP1967_BEACON_SLOT]
    values = await asyncio.gather(*(rpc_call("eth_getStorageAt", [address, slot, block_tag]) for slot in slots))
    impl, admin, beacon = [parse_address_from_slot(value) for value in values]
    result.update(implementation_address=impl, admin_address=admin, beacon_address=beacon,
                  proxy_detection="eip1967_slot_observed" if impl or beacon else "no_eip1967_proxy_slot_observed")
    result["data_sources"].extend({"provider": "configured_base_rpc", "method": "eth_getStorageAt",
                                   "slot": slot, "block": block_tag} for slot in slots)
    if impl or beacon:
        result["is_proxy"] = True
        result["proxy_type"] = "EIP-1967 implementation slot" if impl else "EIP-1967 beacon slot"
        result["analysis_scope"] = "proxy_runtime_only"
        result["security_findings"].append({"code": "proxy_slot_observed", "severity": "info",
                                           "message": "EIP-1967 address observed. Proxy behavior and implementation code are not verified."})
    if beacon:
        result["beacon_implementation_resolution"] = "not_supported"
        result["limitations"].append("Beacon implementation() is not called; the beacon's implementation is unresolved.")
    if impl and beacon:
        result["security_findings"].append({"code": "conflicting_proxy_slots", "severity": "review",
                                           "message": "Both implementation and beacon slots are populated; active delegation is not established."})
    return result


def upstream_error():
    return JSONResponse(status_code=502, content={"success": False, "error": {
        "code": "upstream_unavailable", "message": "Base bytecode data is unavailable."}})


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(min_length=42, max_length=42, pattern=ADDRESS_PATTERN)


AddressQuery = Annotated[str, Query(min_length=42, max_length=42, pattern=ADDRESS_PATTERN)]


async def _observe(address, *, proxy_only=False):
    try:
        audit = await analyze_contract(address)
    except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError):
        return upstream_error()
    if proxy_only:
        keys = ("address", "network", "block_number", "is_contract", "is_proxy", "proxy_type",
                "implementation_address", "admin_address", "beacon_address", "proxy_detection",
                "implementation_analysis", "beacon_implementation_resolution", "analysis_type",
                "analysis_scope", "confidence", "limitations", "data_sources", "timestamp")
        return {"success": True, **{key: audit.get(key) for key in keys}}
    return {"success": True, "oracle": "BaseAudit Oracle", "audit": audit}


@app.get("/v1/audit", summary="Observe Base runtime bytecode and proxy slots")
async def audit_endpoint(address: AddressQuery):
    return await _observe(address)


@app.api_route("/v1/audit", methods=["POST", "HEAD"], include_in_schema=False)
async def audit_compat(payload: AuditRequest):
    return await _observe(payload.address)


@app.get("/v1/proxy", summary="Read Base EIP-1967 address slots")
async def proxy_endpoint(address: AddressQuery):
    return await _observe(address, proxy_only=True)


@app.api_route("/v1/proxy", methods=["POST", "HEAD"], include_in_schema=False)
async def proxy_compat(payload: AuditRequest):
    return await _observe(payload.address, proxy_only=True)


@app.get("/")
async def root():
    return {"service": "BaseAudit Oracle x402", "version": "2.0.0", "network": NETWORK,
            "description": "Static bytecode and EIP-1967 slot observations; not a security audit.",
            "price_usdc": "0.02", "payee": PAYEE_ADDRESS, "docs": "/docs", "manifest": "/.well-known/x402"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "baseaudit-x402", "check_type": "process_only"}


@app.get("/self-test")
async def self_test():
    return {"status": "configured", "check_type": "configuration_only", "network": NETWORK,
            "facilitator_configured": bool(os.getenv("X402_FACILITATOR_URL")), "payee": PAYEE_ADDRESS}


@app.get("/.well-known/x402")
async def manifest(request: Request):
    return payment.manifest(request)


INPUT_SCHEMA = AuditRequest.model_json_schema()
OUTPUT_SCHEMA = {"type": "object", "required": ["success"], "properties": {"success": {"type": "boolean"}}}
payment = PaymentGate(service="BaseAudit", payee=PAYEE_ADDRESS, amount=PRICE_ATOMIC, operations=[
    PaidOperation(method="GET", path="/v1/audit", description="Static Base runtime bytecode observations; no safety guarantee or implementation audit.",
                  input_schema=INPUT_SCHEMA, output_schema=OUTPUT_SCHEMA, example={"address": USDC_ASSET}),
    PaidOperation(method="GET", path="/v1/proxy", description="Read EIP-1967 address slots; beacon implementation resolution is unsupported.",
                  input_schema=INPUT_SCHEMA, output_schema=OUTPUT_SCHEMA, example={"address": USDC_ASSET}),
])
payment.install(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
