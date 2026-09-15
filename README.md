# BaseAudit Oracle x402

> Real-Time Smart Contract Security & Bytecode Audit Oracle for Base Mainnet.

Analyzes smart contract bytecodes, verifies EIP-1967 proxy implementations, audits dangerous opcodes (SELFDESTRUCT, DELEGATECALL), detects token standards, and calculates risk scores on Base (Chain ID 8453).

Payable per-request via the **x402** protocol ($0.02 USDC on Base).

## Features
- **EIP-1967 Proxy Verification**: Resolves transparent and beacon proxy implementations via storage slots.
- **Bytecode Vulnerability Scanner**: Checks for `SELFDESTRUCT` (0xff) and unhandled `DELEGATECALL` (0xf4) opcodes.
- **Token Standard Detection**: Automatically parses function selectors for ERC-20, ERC-721, Ownable, and Pausable interfaces.
- **Risk Scoring**: Returns 0-100 security risk rating and actionable warning flags.
- **$0 Maintenance / Autonomous**: Backed directly by public Base RPC (`https://mainnet.base.org`).
- **x402 v2 Protocol Compliant**: 100% compliant with Coinbase x402 v2 & bazaar discovery specifications.

## Endpoints
- `GET /` — Service capabilities and pricing.
- `GET /health` — Real-time Base RPC block height and service health.
- `GET /self-test` — Free sample security report for USDC on Base.
- `GET /.well-known/x402` — Canonical x402 Protocol Manifest.
- `POST/GET /v1/audit` — Complete smart contract bytecode & proxy audit ($0.02 USDC).
- `POST/GET /v1/proxy` — EIP-1967 proxy logic and admin verification ($0.02 USDC).

## Payment Destination
All payments route directly to: `0xb5aFc89b57Fa8270bB7261348179D28099BEa2a0` on Base.
