import base64
import hmac
import hashlib
import logging
import os
from decimal import Decimal, ROUND_DOWN
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from web3 import Web3
from eth_account import Account

# Azure Key Vault
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ballx-svc")

app = FastAPI(title="BALLX Distributor Service")

# ===== ABIs (mínimos) =====
ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
]

AUTHORITY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "bytes32", "name": "refId", "type": "bytes32"},
            {"internalType": "string", "name": "reason", "type": "string"},
        ],
        "name": "distribute",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

# ===== Models =====
class DistributePayload(BaseModel):
    to_address: str = Field(..., description="Recipient EVM address")
    amount_ballx: Decimal = Field(..., gt=Decimal("0"))
    order_id: str = Field(..., min_length=1)
    reason: Optional[str] = Field(default="")
    refid_hex: Optional[str] = Field(default=None, description="0x-prefixed 32-byte hex; overrides order_id hash")

# ===== Key Vault / Settings =====
class Settings:
    def __init__(self):
        self.kv_uri = os.getenv("KEYVAULT_URI")
        self._kv_client = None
        if self.kv_uri:
            cred = DefaultAzureCredential()
            self._kv_client = SecretClient(vault_url=self.kv_uri, credential=cred)

    def _get_kv(self, name: str) -> Optional[str]:
        if not self._kv_client:
            return None
        try:
            return self._kv_client.get_secret(name).value
        except Exception as e:
            logger.error(f"KeyVault get_secret failed for {name}: {e}")
            return None

    def get(self, name: str, env_fallback: Optional[str] = None) -> Optional[str]:
        # Try Key Vault first, then env var
        val = self._get_kv(name)
        if val:
            return val
        if env_fallback:
            return os.getenv(env_fallback)
        return None

settings = Settings()

# Secret names (change here if you used different names in Key Vault)
KV_S_OPERATOR_PK = "BALLX-OperatorPrivateKey"
KV_S_RPC_URL     = "PolygonRpcUrl"
KV_S_TOKEN_ADDR  = "BallxTokenAddress"
KV_S_AUTH_ADDR   = "BallxAuthorityAddress"
KV_S_WEBHOOK     = "WebhookSecret"

# Non-secret tuning
GAS_LIMIT = int(os.getenv("GAS_LIMIT", "300000"))
MAX_FEE_GWEI = Decimal(os.getenv("MAX_FEE_GWEI", "60"))
MAX_PRIORITY_FEE_GWEI = Decimal(os.getenv("MAX_PRIORITY_FEE_GWEI", "40"))

# ===== Utils =====

def checksum(addr: str) -> str:
    if not Web3.is_address(addr):
        raise ValueError("Invalid EVM address")
    return Web3.to_checksum_address(addr)


def to_wei_ballx(amount: Decimal, decimals: int) -> int:
    q = (amount.quantize(Decimal(1) / (Decimal(10) ** decimals), rounding=ROUND_DOWN))
    return int(q * (Decimal(10) ** decimals))


def make_refid(order_id: str) -> bytes:
    return Web3.keccak(text=order_id)


def parse_refid(refid_hex: Optional[str], order_id: str) -> bytes:
    if refid_hex:
        if not refid_hex.startswith("0x") or len(refid_hex) != 66:
            raise ValueError("refid_hex must be 0x + 64 hex chars (32 bytes)")
        return bytes.fromhex(refid_hex[2:])
    return make_refid(order_id)


def verify_wc_signature(raw_body: bytes, provided_sig: Optional[str]) -> bool:
    secret = settings.get(KV_S_WEBHOOK, env_fallback="WEBHOOK_SECRET")
    if not secret:
        logger.warning("No webhook secret configured; skipping signature verification.")
        return True
    if not provided_sig:
        return False
    # WooCommerce: Base64(HMAC_SHA256(body, secret)) in X-WC-Webhook-Signature
    expected = base64.b64encode(hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(expected, provided_sig)


# ===== On-chain wiring =====

def get_web3_and_contracts():
    rpc_url = settings.get(KV_S_RPC_URL, env_fallback="RPC_URL")
    token_addr = settings.get(KV_S_TOKEN_ADDR, env_fallback="TOKEN_ADDRESS")
    auth_addr = settings.get(KV_S_AUTH_ADDR, env_fallback="AUTHORITY_ADDRESS")
    operator_pk = settings.get(KV_S_OPERATOR_PK, env_fallback="OPERATOR_PRIVATE_KEY")

    if not all([rpc_url, token_addr, auth_addr, operator_pk]):
        raise RuntimeError("Missing RPC/addresses/operator PK from Key Vault or env vars")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError("Failed to connect to Polygon RPC")

    token = w3.eth.contract(address=Web3.to_checksum_address(token_addr), abi=ERC20_ABI)
    auth = w3.eth.contract(address=Web3.to_checksum_address(auth_addr), abi=AUTHORITY_ABI)
    acct = Account.from_key(operator_pk)
    return w3, token, auth, acct


@app.post("/distribute")
async def distribute(request: Request):
    raw = await request.body()
    sig = request.headers.get("x-wc-webhook-signature") or request.headers.get("X-WC-Webhook-Signature")
    if not verify_wc_signature(raw, sig):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    try:
        data = await request.json()
        payload = DistributePayload(**data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")

    try:
        w3, token, auth, acct = get_web3_and_contracts()
        sender = acct.address

        decimals = token.functions.decimals().call()
        to = checksum(payload.to_address)
        amount_wei = to_wei_ballx(payload.amount_ballx, decimals)
        refid_b32 = parse_refid(payload.refid_hex, payload.order_id)

        bal_before = token.functions.balanceOf(auth.address).call()
        if bal_before < amount_wei:
            raise HTTPException(status_code=400, detail="Authority has insufficient BALLX balance")

        chain_id = w3.eth.chain_id
        nonce = w3.eth.get_transaction_count(sender)
        max_fee = w3.to_wei(str(MAX_FEE_GWEI), "gwei")
        max_priority = w3.to_wei(str(MAX_PRIORITY_FEE_GWEI), "gwei")

        tx = auth.functions.distribute(to, amount_wei, refid_b32, payload.reason or "").build_transaction({
            "from": sender,
            "nonce": nonce,
            "gas": GAS_LIMIT,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority,
            "chainId": chain_id,
        })

        signed = w3.eth.account.sign_transaction(tx, private_key=acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

        bal_after = token.functions.balanceOf(auth.address).call()

        return {
            "ok": bool(receipt.status == 1),
            "order_id": payload.order_id,
            "to": to,
            "amount_ballx": str(payload.amount_ballx),
            "decimals": decimals,
            "amount_wei": str(amount_wei),
            "tx_hash": tx_hash,
            "status": receipt.status,
            "blockNumber": receipt.blockNumber,
            "gasUsed": receipt.gasUsed,
            "authority_balance_before": str(Decimal(bal_before) / (Decimal(10) ** decimals)),
            "authority_balance_after": str(Decimal(bal_after) / (Decimal(10) ** decimals)),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Distribution failed")
        raise HTTPException(status_code=500, detail=f"Distribution failed: {e}")


@app.get("/healthz")
def healthz():
    return {"ok": True}