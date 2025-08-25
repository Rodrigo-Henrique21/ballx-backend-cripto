## 1) Visão geral

- **De onde sai**: a Reserva (Oriah) **não assina** — ela apenas faz `approve(Authority, limite)` do token BALLX.
- **Quem envia**: o **operador** do Authority assina a transação `distribute(...)`.
- **O que vai on-chain**: `to`, `amount(18d)`, `refId(bytes32)`, `reason(string)`.
- **De onde vêm os segredos**: `DefaultAzureCredential` → Managed Identity (nuvem) ou Azure CLI / Service Principal (local).
- **Pontos de robustez**: EIP-1559 com fallback, checagem de saldo da Reserva/allowance, verificação de MATIC para gas, idempotência opcional.

---

## 2) Pré-requisitos

- Python 3.10+ (recomendado 3.11+)
- Azure Key Vault criado
- Identidade com permissão **Key Vault Secrets User** no Key Vault:
  - **Produção (Azure Functions/VM/App Service)** → **Managed Identity** do recurso
  - **Local** → Azure CLI logado **OU** Service Principal (ENV)

Instale as dependências:
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
