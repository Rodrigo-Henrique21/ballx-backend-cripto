import json
import hmac
import hashlib
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from web3 import Web3
from send_ballx_prod import send_ballx, get_secret_reader


load_dotenv()

app = FastAPI()

HEADER_SIGNATURE = "X-WP-Signature"


def verify_signature(body: bytes, header_sig: str, secret: str) -> bool:
    computed = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, header_sig)


@app.post("/webhook")
async def handle_webhook(request: Request):
    body = await request.body()
    header_sig = request.headers.get(HEADER_SIGNATURE)
    get = get_secret_reader()
    secret = get("WEBHOOK_SECRET")
    if not header_sig or not verify_signature(body, header_sig, secret):
        raise HTTPException(status_code=401, detail="assinatura inválida")

    payload = json.loads(body)
    wallet = payload.get("wallet") or payload.get("wallet_address")
    amount = payload.get("amount")
    if not wallet or not Web3.is_address(wallet):
        raise HTTPException(status_code=400, detail="carteira inválida")
    if amount is None:
        raise HTTPException(status_code=400, detail="amount requerido")

    tipo = payload.get("tipo", "INV")
    reason = payload.get("reason")
    idemp = payload.get("order_id") or payload.get("idempotency_key")

    result = send_ballx(wallet, amount, tipo=tipo, reason=reason, idempotency_key=idemp)
    return result


@app.get("/")
async def healthcheck():
    return {"status": "ok"}
