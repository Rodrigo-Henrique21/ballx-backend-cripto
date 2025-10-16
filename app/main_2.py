# ============================================================
# main_v2.py — BALLX Transfer System (Seller → Buyer)
# ============================================================
# Função: Realiza transferências diretas entre carteiras
#         seller (time) → buyer (torcedor/investidor)
#         com assinatura e gás pagos pela Oriah.
# ============================================================

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from decimal import Decimal, getcontext
from web3 import Web3
import os
import logging

# ------------------------------------------------------------
# CONFIGURAÇÕES GERAIS
# ------------------------------------------------------------

app = FastAPI(title="BALLX Transfer API v2")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ballx_v2")

# RPC da Polygon Mainnet (ou troque por testnet para teste)
RPC_URL = "https://polygon-rpc.com"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Endereço do contrato do token BALLX
TOKEN_ADDRESS = Web3.toChecksumAddress("0x63F9d0990ab6d742c3FF1E4a83675566b2B0244D")

# ABI mínima ERC20 (balanceOf, allowance, transferFrom, decimals)
TOKEN_ABI = [
    {"inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
     "name": "balanceOf", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "decimals", "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "owner", "type": "address"},
                {"internalType": "address", "name": "spender", "type": "address"}],
     "name": "allowance", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "from", "type": "address"},
                {"internalType": "address", "name": "to", "type": "address"},
                {"internalType": "uint256", "name": "amount", "type": "uint256"}],
     "name": "transferFrom", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
]

token = w3.eth.contract(address=TOKEN_ADDRESS, abi=TOKEN_ABI)

# Carteira da ORIAH (Authority / pagadora de gás)
ORIAH_ADDRESS = Web3.toChecksumAddress("0x2f8c2527385a100A74474D9C66b7d8d5eB473ed7")

# 🔒 A chave privada da ORIAH deve vir de variável de ambiente segura (Azure ou .env)
ORIAH_PRIVATE_KEY = os.getenv("ORIAH_PRIVATE_KEY")

# Parâmetros padrão de gas
GAS_LIMIT = 350000
MAX_FEE_GWEI = 100
MAX_PRIORITY_FEE_GWEI = 2

getcontext().prec = 50


# ------------------------------------------------------------
# Funções auxiliares
# ------------------------------------------------------------

def to_wei_ballx(amount_ballx, decimals):
    """Converte quantidade de BALLX para WEI"""
    a = Decimal(str(amount_ballx))
    scale = Decimal(10) ** int(decimals)
    return int((a * scale).to_integral_value())


def checksum(address):
    """Valida e converte endereço para checksum"""
    if not Web3.isAddress(address):
        raise HTTPException(status_code=400, detail=f"Endereço inválido: {address}")
    return Web3.toChecksumAddress(address)


# ------------------------------------------------------------
# ENDPOINT PRINCIPAL
# ------------------------------------------------------------

@app.post("/distribute")
async def distribute(request: Request):
    """
    Realiza transferência direta (seller → buyer)
    usando a Oriah como operadora.
    """
    try:
        data = await request.json()
        logger.info(f"Payload recebido: {data}")

        # 🟢 Captura dados do front-end
        seller_wallet = data.get("seller_wallet")   # saída (time)
        buyer_wallet = data.get("to_address")       # entrada (comprador)
        amount_ballx = data.get("amount_ballx")     # quantidade em BALLX

        if not seller_wallet or not buyer_wallet or not amount_ballx:
            raise HTTPException(status_code=400, detail="Campos obrigatórios: seller_wallet, to_address, amount_ballx")

        seller = checksum(seller_wallet)
        buyer = checksum(buyer_wallet)

        # 🔢 Converter BALLX para WEI
        decimals = token.functions.decimals().call()
        amount_wei = to_wei_ballx(Decimal(amount_ballx), decimals)

        # 1️⃣ Verifica saldo do vendedor
        seller_balance = token.functions.balanceOf(seller).call()
        if seller_balance < amount_wei:
            raise HTTPException(status_code=400, detail="Saldo insuficiente do vendedor")

        # 2️⃣ Verifica autorização (approve)
        allowance = token.functions.allowance(seller, ORIAH_ADDRESS).call()
        if allowance < amount_wei:
            raise HTTPException(status_code=400, detail="Vendedor precisa aprovar a Oriah para movimentar tokens")

        # 3️⃣ Monta transação transferFrom(seller → buyer)
        chain_id = w3.eth.chain_id
        nonce = w3.eth.get_transaction_count(ORIAH_ADDRESS)
        max_fee = w3.to_wei(str(MAX_FEE_GWEI), "gwei")
        max_priority = w3.to_wei(str(MAX_PRIORITY_FEE_GWEI), "gwei")

        tx = token.functions.transferFrom(seller, buyer, amount_wei).build_transaction({
            "from": ORIAH_ADDRESS,
            "nonce": nonce,
            "gas": GAS_LIMIT,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority,
            "chainId": chain_id,
        })

        # 4️⃣ Assina e envia a transação
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=ORIAH_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction).hex()

        # Aguarda receipt (confirmação)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

        # 5️⃣ Verifica saldo após
        seller_balance_after = token.functions.balanceOf(seller).call()

        # ✅ Retorno final
        return JSONResponse(content={
            "success": True,
            "seller": seller,
            "buyer": buyer,
            "amount_ballx": str(amount_ballx),
            "amount_wei": str(amount_wei),
            "tx_hash": tx_hash,
            "status": receipt.status,
            "blockNumber": receipt.blockNumber,
            "seller_balance_before": str(Decimal(seller_balance) / (Decimal(10) ** decimals)),
            "seller_balance_after": str(Decimal(seller_balance_after) / (Decimal(10) ** decimals)),
        })

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.exception("Erro durante a transferência BALLX")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


# ------------------------------------------------------------
# Endpoint simples de teste
# ------------------------------------------------------------

@app.get("/")
async def root():
    return {"message": "BALLX Transfer API v2 ativa"}


# ============================================================
# FIM DO ARQUIVO
# ============================================================
