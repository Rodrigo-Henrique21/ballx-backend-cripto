# send_ballx_prod.py
import os, json, time, logging, argparse
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone
from typing import Optional

from web3 import Web3, Account
from web3.exceptions import ContractLogicError, TimeExhausted
from web3.types import TxParams

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

CHAIN_ID = 137  # Polygon
APP_NAME = "BALLX-Distributor"

logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(APP_NAME)

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name":"","type":"uint8"}], "type":"function"},
    {"constant": True, "inputs": [{"name":"owner","type":"address"}],
     "name":"balanceOf", "outputs":[{"name":"","type":"uint256"}], "type":"function"},
    {"constant": True, "inputs": [{"name":"owner","type":"address"},{"name":"spender","type":"address"}],
     "name":"allowance", "outputs":[{"name":"","type":"uint256"}], "type":"function"},
]

AUTHORITY_ABI = [
    {"inputs":[
        {"internalType":"address","name":"to","type":"address"},
        {"internalType":"uint256","name":"amount","type":"uint256"},
        {"internalType":"bytes32","name":"refId","type":"bytes32"},
        {"internalType":"string","name":"reason","type":"string"},
    ],
     "name":"distribute","outputs":[],"stateMutability":"nonpayable","type":"function"}
]

# ---------- Key Vault ----------
def get_secret_reader():
    use_kv = os.getenv("BALLX_DISABLE_KV") not in ("1","true","True")
    # usa kv-ballx-backend por padrão se VAULT_URL não estiver definido
    vault_url = os.getenv("VAULT_URL", "https://kv-ballx-backend.vault.azure.net/")
    client = None
    if use_kv:
        cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        client = SecretClient(vault_url=vault_url, credential=cred)
    cache = {}
    def _get(name: str, required=True) -> Optional[str]:
        if name in cache: return cache[name]
        val = None
        if client:
            try:
                val = client.get_secret(name).value
            except Exception as e:
                log.warning(f"KV: segredo {name} não lido do KV: {e}")
        if val is None:
            val = os.getenv(name)
        if required and (not val or not str(val).strip()):
            raise RuntimeError(f"Segredo {name} não encontrado (KV/ENV).")
        cache[name] = val
        return val
    return _get

# ---------- Utils ----------
def to_checksum(a:str)->str: return Web3.to_checksum_address(a)
def polygonscan_tx_url(h:str)->str: return f"https://polygonscan.com/tx/{h}"
def now_utc()->datetime: return datetime.now(timezone.utc)

def make_human_refid(tipo:str, wallet:str, now:datetime, nonce4:str)->str:
    stamp = now.astimezone().strftime("%Y%m%dT%H%M%S")
    last6 = wallet[-6:].lower()
    return f"{tipo}-{stamp}-{last6}-{nonce4}"

def to_bytes32_ascii(s:str)->str:
    b = s.encode("utf-8")[:32]
    b += b"\x00" * (32 - len(b))
    return "0x" + b.hex()

def human_to_amount18(human: str|float|Decimal, decimals:int)->int:
    d = Decimal(str(human)).quantize(Decimal("1.000000000000000000"), rounding=ROUND_DOWN)
    return int((d * (Decimal(10) ** decimals)).to_integral_value(rounding=ROUND_DOWN))

def suggest_fees(w3: Web3, priority_gwei:int=40, headroom:float=1.2):
    blk = w3.eth.get_block("latest")
    base = blk.get("baseFeePerGas")
    if base is None:
        return None, None, w3.eth.gas_price
    prio = w3.to_wei(priority_gwei, "gwei")
    maxf = int(base * headroom + prio)
    return maxf, prio, None

def ensure_gas_and_estimate(w3: Web3, from_addr:str, tx:TxParams)->int:
    gas_limit = w3.eth.estimate_gas(tx)
    fee_per_gas = tx.get("maxFeePerGas") or tx.get("gasPrice")
    if fee_per_gas is None:
        tx["gasPrice"] = w3.eth.gas_price
        fee_per_gas = tx["gasPrice"]
    fee_wei = gas_limit * fee_per_gas
    bal_wei = w3.eth.get_balance(from_addr)
    if bal_wei < fee_wei:
        raise RuntimeError("Saldo insuficiente de MATIC para gas.")
    return gas_limit

def backoff_sleep(i:int):
    time.sleep(min(1 * (2**i), 10))

# ---------- Idempotência (arquivo simples) ----------
IDEMP_STORE = os.getenv("BALLX_IDEMP_STORE", ".ballx_idem.json")

def was_processed(key:str)->Optional[str]:
    try:
        if not os.path.exists(IDEMP_STORE): return None
        with open(IDEMP_STORE,"r",encoding="utf-8") as f:
            data = json.load(f)
        return data.get(key)
    except Exception:
        return None

def mark_processed(key:str, tx_hash:str):
    try:
        data = {}
        if os.path.exists(IDEMP_STORE):
            with open(IDEMP_STORE,"r",encoding="utf-8") as f:
                data = json.load(f)
        data[key] = tx_hash
        with open(IDEMP_STORE,"w",encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.warning(f"Falha ao persistir idempotência: {e}")

# ---------- Core ----------
def send_ballx(
    to: str,
    amount,
    *,
    tipo: str = "INV",
    reason: Optional[str] = None,
    human_refid: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    wait: bool = False,
    wait_timeout: int = 180,
    priority_gwei: int = 40,
):
    get = get_secret_reader()
    RPC_URL           = get("BALLX_RPC_URL")
    OPERATOR_PK       = get("BALLX_OPERATOR_PK")
    AUTHORITY_ADDRESS = get("BALLX_AUTHORITY_ADDRESS")
    TOKEN_ADDRESS     = get("BALLX_TOKEN_ADDRESS")
    RESERVE_ADDRESS   = get("BALLX_RESERVE_ADDRESS")

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise RuntimeError("Falha ao conectar no RPC.")

    operator = Account.from_key(OPERATOR_PK if OPERATOR_PK.startswith("0x") else "0x"+OPERATOR_PK)
    operator_addr = to_checksum(operator.address)
    to_addr = to_checksum(to)

    token     = w3.eth.contract(address=to_checksum(TOKEN_ADDRESS), abi=ERC20_ABI)
    authority = w3.eth.contract(address=to_checksum(AUTHORITY_ADDRESS), abi=AUTHORITY_ABI)

    decimals = token.functions.decimals().call()
    amount18 = human_to_amount18(amount, decimals)

    reserve_bal = token.functions.balanceOf(to_checksum(RESERVE_ADDRESS)).call()
    allowance   = token.functions.allowance(to_checksum(RESERVE_ADDRESS), to_checksum(AUTHORITY_ADDRESS)).call()
    if reserve_bal < amount18:
        raise RuntimeError("Reserva sem saldo suficiente.")
    if allowance < amount18:
        raise RuntimeError("Allowance Reserva→Authority insuficiente (faça approve).")

    now = now_utc()
    if human_refid:
        human_ref = human_refid.strip()
    else:
        # refId = TIPO-YYYYMMDDTHHMMSS-last6-XXXX
        nonce4 = f"{int(time.time()*1_000_000)%10000:04d}"
        human_ref = make_human_refid(tipo, to_addr, now, nonce4)
    if len(human_ref.encode("utf-8")) > 32:
        raise ValueError("human_refid > 32 bytes. Encurte TIPO/format.")
    ref_b32 = to_bytes32_ascii(human_ref)
    reason  = reason or f"{tipo} - BALLX"

    # Idempotência
    if idempotency_key:
        prev = was_processed(idempotency_key)
        if prev:
            log.info(f"idempotency-key já processada. tx={prev}")
            return {"idempotency_key": idempotency_key, "tx_hash": prev}

    # Taxas
    max_fee, prio, gp = suggest_fees(w3, priority_gwei)
    tx_base = {
        "from": operator_addr,
        "nonce": w3.eth.get_transaction_count(operator_addr),
        "chainId": CHAIN_ID,
    }
    if gp:
        tx_base["gasPrice"] = gp
    else:
        tx_base["maxFeePerGas"] = max_fee
        tx_base["maxPriorityFeePerGas"] = prio

    # Build + estimate + send com retries
    last_err = None
    for i in range(5):
        try:
            tx = authority.functions.distribute(to_addr, amount18, ref_b32, reason).build_transaction(tx_base)
            tx["gas"] = ensure_gas_and_estimate(w3, operator_addr, tx)
            signed = w3.eth.account.sign_transaction(tx, OPERATOR_PK if OPERATOR_PK.startswith("0x") else "0x"+OPERATOR_PK)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
            log.info(f"tx enviada: {tx_hash} {polygonscan_tx_url(tx_hash)}")
            if idempotency_key:
                mark_processed(idempotency_key, tx_hash)
            result = {
                "app": APP_NAME,
                "to": to_addr,
                "amount18": str(amount18),
                "decimals": decimals,
                "human_refid": human_ref,
                "refid_bytes32": ref_b32,
                "reason": reason,
                "tx_hash": tx_hash,
                "explorer": polygonscan_tx_url(tx_hash),
                "timestamp": now.isoformat(),
            }
            if wait:
                rc = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=wait_timeout)
                result["confirmation"] = {"confirmed": rc.status == 1, "blockNumber": rc.blockNumber}
            return result
        except (ContractLogicError, TimeExhausted):
            raise
        except Exception as e:
            last_err = e
            log.warning(f"tentativa {i+1}/5 falhou: {e}")
            backoff_sleep(i)
    raise RuntimeError(f"Falha ao enviar transação após retries: {last_err}")

def run(args):
    return send_ballx(
        args.to,
        args.amount,
        tipo=args.tipo,
        reason=args.reason,
        human_refid=args.human_refid,
        idempotency_key=args.idempotency_key,
        wait=args.wait,
        wait_timeout=args.wait_timeout,
        priority_gwei=args.priority_gwei,
    )

def parse_args():
    p = argparse.ArgumentParser(description="BALLX • Distribute via Authority (Key Vault + Prod)")
    p.add_argument("--to", required=True, help="Carteira destino (0x...)")
    p.add_argument("--amount", required=True, help="Quantidade humana (ex.: 10000)")
    p.add_argument("--tipo", default="INV", help="INV|PRE|EMB|DOA|CLB (para refId)")
    p.add_argument("--reason", default=None, help="Motivo curto on-chain")
    p.add_argument("--human-refid", default=None, help="Fornecer refId manual (<=32 bytes)")
    p.add_argument("--idempotency-key", default=None, help="Chave única para evitar duplicidade (ex.: order_id)")
    p.add_argument("--wait", action="store_true", help="Aguardar confirmação")
    p.add_argument("--wait-timeout", type=int, default=180, help="Timeout confirmação (s)")
    p.add_argument("--priority-gwei", type=int, default=40, help="EIP-1559 priority fee")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
