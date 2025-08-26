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
```

### Execução local sem Key Vault

Para testes locais é possível usar apenas variáveis de ambiente definidas em um arquivo `.env`.

1. Copie `.env.example` para `.env` e preencha os valores.
2. Defina `BALLX_USE_KV=0` para evitar o acesso ao Key Vault.
3. Execute o script ou o servidor normalmente; os valores serão carregados do `.env`.

## 3) Deploy em contêiner (ACR + ACI)

1. **Build** da imagem local:
   ```bash
   docker build -t ballx:latest .
   ```
2. **Login** e push no Azure Container Registry (ACR):
   ```bash
   az acr login -n <registry>
   docker tag ballx:latest <registry>.azurecr.io/ballx:latest
   docker push <registry>.azurecr.io/ballx:latest
   ```
3. **Executar** no Azure Container Instances (ACI) usando o Key Vault `kv-ballx-backend`:
   ```bash
   az container create \
     -g <resource-group> \
     -n ballx-distributor \
     --image <registry>.azurecr.io/ballx:latest \
     --assign-identity \
     --environment-variables VAULT_URL=https://kv-ballx-backend.vault.azure.net/ \
     --secure-environment-variables \
       BALLX_RPC_URL=<rpc> \
       BALLX_OPERATOR_PK=<pk> \
       BALLX_AUTHORITY_ADDRESS=<addr> \
       BALLX_TOKEN_ADDRESS=<addr> \
       BALLX_RESERVE_ADDRESS=<addr>
   ```

   A identidade gerenciada atribuída deve ter permissão **Key Vault Secrets User** no cofre `kv-ballx-backend`.

Um exemplo de variáveis de ambiente necessárias está em `.env.example`.

---

## 4) Receptor de Webhook HTTP

O contêiner expõe um serviço FastAPI na porta **8000** com endpoint `POST /webhook`.

- O WordPress deve enviar um JSON com `wallet` (ou `wallet_address`), `amount`,
  `tipo` opcional, `reason` opcional e `order_id`.
- A requisição deve conter o cabeçalho `X-WP-Signature` com o **HMAC SHA256** do corpo usando `WEBHOOK_SECRET`.
- Variáveis de ambiente:
  - `WEBHOOK_SECRET` – segredo compartilhado para validar o webhook.
  - Demais variáveis de blockchain (`BALLX_RPC_URL`, `BALLX_OPERATOR_PK`, etc.).

Exemplo de execução local:
```bash
uvicorn app:app --reload
# então teste:
curl -X POST http://localhost:8000/webhook \
  -H "X-WP-Signature: $(printf 'payload' | openssl dgst -sha256 -hmac $WEBHOOK_SECRET -hex | sed 's/^.* //')" \
  -d '{"wallet":"0x...","amount":10}'
```

O container em Azure Container Instances deve ter a porta 8000 exposta e receber o `WEBHOOK_SECRET` via Key Vault.
