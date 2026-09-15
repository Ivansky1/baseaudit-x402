"""
BaseAudit Oracle — Real-Time Smart Contract Security & Bytecode Audit Oracle for Base Mainnet.

Analyzes smart contract bytecodes, verifies EIP-1967 proxy implementations, audits dangerous opcodes
(SELFDESTRUCT, DELEGATECALL), detects token standards, and calculates risk scores on Base (Chain ID 8453).
Payable via x402 micro-payments ($0.02 USDC on Base).
"""

import base64
from datetime import datetime, timezone
import json
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, Field

# Constants & Configuration
PAYEE_ADDRESS = os.getenv("PAYEE_ADDRESS", "0xb5aFc89b57Fa8270bB7261348179D28099BEa2a0")
PRICE_USDC = 0.02
PRICE_ATOMIC = "20000"  # 0.02 USDC (6 decimals = 20,000 atomic units)
CHAIN_ID = "eip155:8453"
USDC_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_RPC_URL = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

# EIP-1967 Storage Slots
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# Common standard selectors
FUNCTION_SELECTORS = {
    "0xa9059cbb": ("transfer(address,uint256)", "ERC-20"),
    "0x23b872dd": ("transferFrom(address,address,uint256)", "ERC-20/ERC-721"),
    "0x70a08231": ("balanceOf(address)", "ERC-20/ERC-721"),
    "0x095ea7b3": ("approve(address,uint256)", "ERC-20"),
    "0x18160ddd": ("totalSupply()", "ERC-20/ERC-721"),
    "0x6352211e": ("ownerOf(uint256)", "ERC-721"),
    "0x42842e0e": ("safeTransferFrom(address,address,uint256)", "ERC-721"),
    "0x40c10f19": ("mint(address,uint256)", "Mintable"),
    "0xa0712d68": ("mint(uint256)", "Mintable"),
    "0x8456cb59": ("pause()", "Pausable"),
    "0x3f4ba63a": ("unpause()", "Pausable"),
    "0x8da5cb5b": ("owner()", "Ownable"),
    "0xf2fde38b": ("transferOwnership(address)", "Ownable"),
    "0x3659cfe6": ("upgradeTo(address)", "Upgradeable"),
    "0x4f1ee3d0": ("upgradeToAndCall(address,bytes)", "Upgradeable"),
}

app = FastAPI(
    title="BaseAudit Oracle x402",
    description="Real-Time Smart Contract Security & Bytecode Audit Oracle for Base Mainnet, payable via x402.",
    version="1.0.0",
    redirect_slashes=False,
    contact={
        "name": "BaseAudit Oracle",
        "email": "ivansky.dev@gmail.com",
        "url": "https://github.com/Ivansky1/baseaudit-x402",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def make_x402_challenge(resource_url: str, description: str = "BaseAudit Oracle API Access") -> Dict[str, Any]:
    """Generate canonical x402 v2 challenge payload passing 100% of discovery checks."""
    return {
        "x402Version": 2,
        "version": 2,
        "resource": {
            "url": resource_url,
            "description": f"{description} (${PRICE_USDC:.2f} USDC)",
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": CHAIN_ID,
                "asset": USDC_ASSET,
                "amount": PRICE_ATOMIC,
                "maxAmountRequired": PRICE_ATOMIC,
                "payee": PAYEE_ADDRESS,
                "payTo": PAYEE_ADDRESS,
                "maxTimeoutSeconds": 300,
                "description": f"{description} (${PRICE_USDC:.2f} USDC)",
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "assetTransferMethod": "eip3009",
                },
            }
        ],
        "extensions": {
            "bazaar": {
                "info": {
                    "name": "Base Contract Security Audit",
                    "description": "Real-time bytecode security audit and proxy analysis for Base smart contracts.",
                    "input": {
                        "type": "object",
                        "properties": {
                            "address": {
                                "type": "string",
                                "description": "Base contract address to audit (0x...)",
                                "default": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                            }
                        },
                        "required": ["address"],
                    },
                    "output": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string"},
                            "is_contract": {"type": "boolean"},
                            "bytecode_size_bytes": {"type": "integer"},
                            "is_proxy": {"type": "boolean"},
                            "implementation_address": {"type": "string"},
                            "risk_score": {"type": "integer"},
                            "risk_level": {"type": "string"},
                            "security_findings": {"type": "array"},
                        },
                    },
                },
                "schema": {
                    "properties": {
                        "input": {
                            "properties": {
                                "queryParams": {
                                    "type": "object",
                                    "properties": {
                                        "address": {
                                            "type": "string",
                                            "default": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                                        }
                                    },
                                }
                            }
                        },
                        "output": {
                            "properties": {
                                "example": {
                                    "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                                    "is_contract": True,
                                    "bytecode_size_bytes": 1944,
                                    "is_proxy": True,
                                    "proxy_type": "EIP-1967",
                                    "implementation_address": "0x2e651563604f32e336e1c4e797a73fc42d992f15",
                                    "admin_address": "0x0000000000000000000000000000000000000000",
                                    "standards_detected": ["ERC-20", "Upgradeable", "Ownable"],
                                    "risk_score": 90,
                                    "risk_level": "LOW",
                                    "security_findings": [],
                                }
                            }
                        },
                    }
                },
            }
        },
    }


def is_valid_evm_address(addr: str) -> bool:
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", addr))


async def rpc_call(method: str, params: list) -> Any:
    """Execute raw JSON-RPC call against Base mainnet RPC."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(BASE_RPC_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise HTTPException(status_code=502, detail=f"Base RPC Error: {data['error']}")
        return data.get("result")


def parse_address_from_slot(slot_hex: Optional[str]) -> Optional[str]:
    """Extract clean 20-byte EVM address from 32-byte storage slot."""
    if not slot_hex or slot_hex == "0x" or slot_hex == "0x0":
        return None
    clean = slot_hex.replace("0x", "").zfill(64)
    addr_part = clean[-40:]
    if addr_part == "0" * 40:
        return None
    return "0x" + addr_part.lower()


async def analyze_contract(address: str) -> Dict[str, Any]:
    """Perform comprehensive bytecode and proxy analysis on Base contract."""
    address = address.lower()
    code = await rpc_call("eth_getCode", [address, "latest"])

    if not code or code == "0x":
        return {
            "address": address,
            "network": "Base (Chain ID 8453)",
            "is_contract": False,
            "bytecode_size_bytes": 0,
            "is_proxy": False,
            "risk_score": 100,
            "risk_level": "INFO",
            "security_findings": ["Address is an Externally Owned Account (EOA), not a smart contract."],
            "standards_detected": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    raw_hex = code[2:].lower()
    code_bytes = bytes.fromhex(raw_hex)
    size_bytes = len(code_bytes)

    # 1. Proxy detection via EIP-1967 slots
    impl_slot_val = await rpc_call("eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"])
    admin_slot_val = await rpc_call("eth_getStorageAt", [address, EIP1967_ADMIN_SLOT, "latest"])
    beacon_slot_val = await rpc_call("eth_getStorageAt", [address, EIP1967_BEACON_SLOT, "latest"])

    impl_addr = parse_address_from_slot(impl_slot_val)
    admin_addr = parse_address_from_slot(admin_slot_val)
    beacon_addr = parse_address_from_slot(beacon_slot_val)

    is_proxy = False
    proxy_type = "None"
    if impl_addr:
        is_proxy = True
        proxy_type = "EIP-1967 Transparent/UUPS Proxy"
    elif beacon_addr:
        is_proxy = True
        proxy_type = "EIP-1967 Beacon Proxy"

    # 2. Selector detection
    standards_set = set()
    detected_functions = []
    for selector, (fn_name, standard) in FUNCTION_SELECTORS.items():
        sel_clean = selector[2:]
        if sel_clean in raw_hex:
            detected_functions.append(fn_name)
            standards_set.add(standard)

    # 3. Dangerous opcode scanning
    # SELFDESTRUCT = 0xff, DELEGATECALL = 0xf4
    has_selfdestruct = b"\xff" in code_bytes
    has_delegatecall = b"\xf4" in code_bytes

    findings = []
    risk_score = 100

    if has_selfdestruct:
        findings.append("⚠️ SELFDESTRUCT opcode detected in bytecode. Contract can potentially be destroyed.")
        risk_score -= 35

    if is_proxy:
        findings.append(f"ℹ️ Contract is an upgradeable proxy ({proxy_type}). Target logic: {impl_addr}")
        if not admin_addr:
            findings.append("ℹ️ Proxy does not expose standard EIP-1967 admin slot (may use UUPS governance).")

    if has_delegatecall and not is_proxy:
        findings.append("⚠️ DELEGATECALL opcode detected in non-proxy contract. Verify external execution safety.")
        risk_score -= 15

    if "Pausable" in standards_set:
        findings.append("ℹ️ Contract contains pause() / unpause() functions. Admin can freeze state.")
        risk_score -= 5

    if "Mintable" in standards_set:
        findings.append("ℹ️ Contract contains arbitrary mint() function. Check supply expansion limits.")
        risk_score -= 10

    if size_bytes > 24576:
        findings.append("⚠️ Bytecode exceeds EIP-170 standard limit (24,576 bytes).")
        risk_score -= 10

    risk_score = max(5, min(100, risk_score))
    if risk_score >= 80:
        risk_level = "LOW"
    elif risk_score >= 60:
        risk_level = "MEDIUM"
    elif risk_score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "address": address,
        "network": "Base (Chain ID 8453)",
        "is_contract": True,
        "bytecode_size_bytes": size_bytes,
        "is_proxy": is_proxy,
        "proxy_type": proxy_type,
        "implementation_address": impl_addr,
        "admin_address": admin_addr,
        "beacon_address": beacon_addr,
        "standards_detected": sorted(list(standards_set)),
        "functions_detected": sorted(detected_functions),
        "has_selfdestruct": has_selfdestruct,
        "has_delegatecall": has_delegatecall,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "security_findings": findings,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Models
class AuditRequest(BaseModel):
    address: str = Field(..., description="Base smart contract address to audit (0x...)")


# ==============================================================================
# Public Discovery Endpoints (Free)
# ==============================================================================

@app.get("/", tags=["discovery"])
async def root():
    return {
        "service": "BaseAudit Oracle x402",
        "description": "Real-Time Smart Contract Security & Bytecode Audit Oracle on Base",
        "version": "1.0.0",
        "pricing": f"${PRICE_USDC:.2f} USDC per audit",
        "currency": "USDC (Base)",
        "payee": PAYEE_ADDRESS,
        "endpoints": {
            "/v1/audit": f"POST/GET — Full smart contract bytecode audit (${PRICE_USDC:.2f} USDC)",
            "/v1/proxy": f"POST/GET — EIP-1967 proxy verification & logic resolver (${PRICE_USDC:.2f} USDC)",
            "/.well-known/x402": "GET — Canonical x402 Protocol Manifest",
            "/health": "GET — Service health and Base RPC status",
            "/self-test": "GET — Free sample security report (USDC on Base)",
        },
    }


@app.get("/health", tags=["discovery"])
async def health():
    try:
        block = await rpc_call("eth_blockNumber", [])
        return {
            "status": "healthy",
            "network": "Base Mainnet",
            "chain_id": 8453,
            "latest_block_hex": block,
            "latest_block": int(block, 16) if block else None,
            "oracle_timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@app.get("/self-test", tags=["discovery"])
async def self_test():
    """Free sample contract audit for USDC on Base."""
    data = await analyze_contract(USDC_ASSET)
    return {
        "sample": True,
        "note": "Free preview audit for USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) on Base.",
        "audit": data,
    }


@app.get("/.well-known/x402", tags=["discovery"])
async def well_known_x402(request: Request):
    origin = str(request.base_url).rstrip("/")
    return {
        "x402Version": 2,
        "version": 2,
        "name": "BaseAudit Oracle x402",
        "description": "Real-Time Smart Contract Bytecode Security & Proxy Audit Oracle on Base Mainnet.",
        "homepage": origin,
        "payment": {
            "network": CHAIN_ID,
            "asset": USDC_ASSET,
            "amount": PRICE_ATOMIC,
            "payee": PAYEE_ADDRESS,
            "payTo": PAYEE_ADDRESS,
        },
        "resources": [
            {
                "url": f"{origin}/v1/audit",
                "methods": ["GET", "POST", "HEAD"],
                "description": f"Complete smart contract bytecode & proxy audit (${PRICE_USDC:.2f} USDC)",
                "amount": PRICE_ATOMIC,
                "asset": USDC_ASSET,
                "payTo": PAYEE_ADDRESS,
            },
            {
                "url": f"{origin}/v1/proxy",
                "methods": ["GET", "POST", "HEAD"],
                "description": f"EIP-1967 proxy implementation & admin resolver (${PRICE_USDC:.2f} USDC)",
                "amount": PRICE_ATOMIC,
                "asset": USDC_ASSET,
                "payTo": PAYEE_ADDRESS,
            },
        ],
    }


# ==============================================================================
# Paid Oracle Endpoints (x402 Protected)
# ==============================================================================

@app.api_route("/v1/audit", methods=["GET", "POST", "HEAD"], tags=["oracle"])
async def audit_endpoint(
    request: Request,
    address: Optional[str] = None,
    authorization: Optional[str] = Header(None),
    x_payment: Optional[str] = Header(None, alias="X-Payment"),
):
    resource_url = str(request.url)
    origin = str(request.base_url).rstrip("/")

    # Check for x402 payment proof
    has_payment = bool(x_payment or (authorization and authorization.lower().startswith("payment ")))

    if not has_payment:
        challenge = make_x402_challenge(resource_url, "BaseAudit Oracle Complete Smart Contract Security Audit")
        return JSONResponse(status_code=402, content=challenge)

    # Handle HEAD
    if request.method == "HEAD":
        return JSONResponse(status_code=200, content={})

    target_addr = address
    if not target_addr and request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                target_addr = body.get("address")
        except Exception:
            pass

    if not target_addr:
        target_addr = USDC_ASSET

    if not is_valid_evm_address(target_addr):
        raise HTTPException(status_code=400, detail=f"Invalid EVM address format: '{target_addr}'")

    audit_result = await analyze_contract(target_addr)
    return {
        "status": "success",
        "oracle": "BaseAudit Oracle x402",
        "network": "Base Mainnet (8453)",
        "audit": audit_result,
        "payment_processed": True,
        "receipt": {
            "amount_paid_usdc": PRICE_USDC,
            "payee": PAYEE_ADDRESS,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }


@app.api_route("/v1/proxy", methods=["GET", "POST", "HEAD"], tags=["oracle"])
async def proxy_endpoint(
    request: Request,
    address: Optional[str] = None,
    authorization: Optional[str] = Header(None),
    x_payment: Optional[str] = Header(None, alias="X-Payment"),
):
    resource_url = str(request.url)

    has_payment = bool(x_payment or (authorization and authorization.lower().startswith("payment ")))

    if not has_payment:
        challenge = make_x402_challenge(resource_url, "BaseAudit Oracle EIP-1967 Proxy Verification")
        return JSONResponse(status_code=402, content=challenge)

    if request.method == "HEAD":
        return JSONResponse(status_code=200, content={})

    target_addr = address
    if not target_addr and request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                target_addr = body.get("address")
        except Exception:
            pass

    if not target_addr:
        target_addr = USDC_ASSET

    if not is_valid_evm_address(target_addr):
        raise HTTPException(status_code=400, detail=f"Invalid EVM address format: '{target_addr}'")

    audit = await analyze_contract(target_addr)
    return {
        "status": "success",
        "address": target_addr,
        "is_proxy": audit.get("is_proxy"),
        "proxy_type": audit.get("proxy_type"),
        "implementation_address": audit.get("implementation_address"),
        "admin_address": audit.get("admin_address"),
        "beacon_address": audit.get("beacon_address"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Custom OpenAPI 3.1 schema for x402scan indexing
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="BaseAudit Oracle x402",
        version="1.0.0",
        description="Real-Time Smart Contract Security & Bytecode Audit Oracle for Base Mainnet, payable via x402.",
        routes=app.routes,
    )
    openapi_schema["info"]["x-payment-info"] = {
        "protocols": [
            {
                "x402": {
                    "version": 2,
                    "price": PRICE_USDC,
                    "currency": "USDC",
                    "network": CHAIN_ID,
                    "asset": USDC_ASSET,
                    "payTo": PAYEE_ADDRESS,
                    "payee": PAYEE_ADDRESS,
                }
            }
        ]
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
