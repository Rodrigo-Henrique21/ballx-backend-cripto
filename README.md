# BALLX Backend Distributor

## Visão Geral

O BALLX Backend Distributor é um serviço robusto e seguro desenvolvido em Python para gerenciar a distribuição automatizada de tokens BALLX na rede Polygon. Este serviço atua como uma ponte entre sistemas Web2 e Web3, permitindo a distribuição programática de tokens através de um endpoint webhook HTTP seguro.

### Principais Características

- **Arquitetura Segura**: Integração com Azure Key Vault para gerenciamento seguro de chaves e secrets
- **Webhook HTTP**: Endpoint RESTful para integração com sistemas externos
- **Validação Criptográfica**: Assinatura HMAC SHA256 para garantir a autenticidade das requisições
- **Smart Contract Integration**: Interação direta com contratos ERC20 e Authority na Polygon
- **Containerização**: Suporte completo a Docker para fácil deploy e escalabilidade
- **Monitoramento**: Logging detalhado para rastreamento de operações
- **Resiliência**: Implementação de EIP-1559 com fallback para transações blockchain

## Arquitetura

### Fluxo de Distribuição
1. Sistema externo (ex: WordPress) envia requisição webhook
2. Backend valida a assinatura HMAC do payload
3. Serviço interage com Smart Contracts na Polygon:
   - Verifica saldo e allowance do token BALLX
   - Executa distribuição através do contrato Authority
   - Monitora status da transação

### Componentes
- **FastAPI**: Framework web de alta performance
- **Web3.py**: Interface com blockchain
- **Azure Identity**: Gerenciamento de credenciais
- **Azure Key Vault**: Armazenamento seguro de secrets

## Pré-requisitos

- Python 3.11+ 
- Azure Key Vault configurado
- Acesso à rede Polygon
- Docker (opcional)

### Configuração de Ambiente

1. **Instalação Local**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Variáveis de Ambiente**:
   - Copie `.env.example` para `.env`
   - Configure as variáveis necessárias
   - Para desenvolvimento local, defina `BALLX_USE_KV=0`

### Permissões Azure

- **Produção**: Managed Identity com role "Key Vault Secrets User"
- **Desenvolvimento**: Azure CLI ou Service Principal

## Deploy

### Container (Azure Container Instances)

1. **Build da Imagem**:
   ```bash
   docker build -t ballx:latest .
   ```

2. **Push para Azure Container Registry**:
   ```bash
   az acr login -n <registry>
   docker tag ballx:latest <registry>.azurecr.io/ballx:latest
   docker push <registry>.azurecr.io/ballx:latest
   ```

3. **Deploy em ACI**:
   ```bash
   az container create \
     -g <resource-group> \
     -n ballx-distributor \
     --image <registry>.azurecr.io/ballx:latest \
     --assign-identity \
     --environment-variables KEYVAULT_URI=https://kv-ballx-backend.vault.azure.net/
   ```

## API Webhook

### Endpoint: `POST /webhook`

**Headers**:
- `X-WP-Signature`: HMAC SHA256 do payload usando `WEBHOOK_SECRET`

**Payload**:
```json
{
  "wallet": "0x...",
  "amount": 10.5,
  "order_id": "ORD123",
  "reason": "Reward",
  "tipo": "bonus"
}
```

### Segurança
- Validação HMAC SHA256 obrigatória
- Rate limiting
- Validação de endereços Ethereum
- Verificação de saldo

### Exemplo de Teste Local:
```bash
uvicorn app:app --reload --port 8000
```

## Monitoramento e Manutenção

- Logs estruturados com níveis INFO/ERROR
- Métricas de gas e transações
- Alertas de saldo baixo
- Monitoramento de falhas de transação

## Variáveis de Configuração

### Blockchain
- `RPC_URL`: URL do node Polygon
- `OPERATOR_PK`: Chave privada do operador
- `AUTHORITY_ADDRESS`: Endereço do contrato Authority
- `TOKEN_ADDRESS`: Endereço do contrato BALLX

### Segurança
- `WEBHOOK_SECRET`: Secret para validação HMAC
- `KEYVAULT_URI`: URI do Azure Key Vault

### Performance
- `GAS_LIMIT`: Limite de gas (default: 300000)
- `MAX_FEE_GWEI`: Fee máximo (default: 60)
- `MAX_PRIORITY_FEE_GWEI`: Priority fee máximo (default: 40)
