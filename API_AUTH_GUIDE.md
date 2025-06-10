# API Authentication 获取指南

本项目实现了符合 [MCP Authorization 规范](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-10-third-party-authorization-flow) 的OAuth 2.0 + PKCE认证流程。以下是通过API获取Authentication的完整指南。

## 认证架构概述

这个系统使用Azure API Management作为OAuth授权服务器，实现了三方授权流程：
- **MCP客户端** → **Azure API Management (OAuth服务器)** → **Azure Entra ID** → **Azure Functions (MCP服务器)**

## API端点

部署后，你的API Management服务会提供以下端点：

```
https://<apim-servicename>.azure-api.net/oauth/.well-known/oauth-authorization-server
https://<apim-servicename>.azure-api.net/oauth/authorize
https://<apim-servicename>.azure-api.net/oauth/token
https://<apim-servicename>.azure-api.net/oauth/register
https://<apim-servicename>.azure-api.net/mcp/sse
https://<apim-servicename>.azure-api.net/mcp/message
```

## 完整认证流程

### 1. 发现OAuth服务器配置

首先获取OAuth服务器的配置信息：

```bash
curl -X GET "https://<apim-servicename>.azure-api.net/oauth/.well-known/oauth-authorization-server"
```

**响应示例：**
```json
{
    "issuer": "https://<apim-servicename>.azure-api.net",
    "service_documentation": "https://microsoft.com/",
    "authorization_endpoint": "https://<apim-servicename>.azure-api.net/oauth/authorize",
    "token_endpoint": "https://<apim-servicename>.azure-api.net/oauth/token",
    "revocation_endpoint": "https://<apim-servicename>.azure-api.net/oauth/revoke",
    "registration_endpoint": "https://<apim-servicename>.azure-api.net/oauth/register",
    "response_types_supported": ["code"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["none"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "revocation_endpoint_auth_methods_supported": ["client_secret_post"]
}
```

### 2. 生成PKCE参数

在开始OAuth流程之前，客户端需要生成PKCE参数：

```python
import base64
import hashlib
import secrets
import urllib.parse

# 生成 code_verifier
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# 生成 code_challenge
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

code_challenge_method = "S256"
```

或者使用项目提供的脚本：

```bash
python generate_pkce.py
```

### 3. 客户端注册 (可选)

如果需要动态注册客户端：

```bash
curl -X POST "https://<apim-servicename>.azure-api.net/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["https://myclient.example.com/callback"],
    "application_type": "native"
  }'
```

### 4. 启动授权流程

构建授权URL并在浏览器中打开：

```bash
# 构建授权URL
AUTHORIZE_URL="https://<apim-servicename>.azure-api.net/oauth/authorize"
CLIENT_ID="your-client-id"
REDIRECT_URI="https://myclient.example.com/callback"
STATE="random-state-value"

AUTH_URL="${AUTHORIZE_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&state=${STATE}"

# 在浏览器中打开这个URL
echo $AUTH_URL
```

**URL示例：**
```
https://<apim-servicename>.azure-api.net/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=https://myclient.example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=random-state
```

### 5. 用户同意流程

用户将被重定向到同意页面，确认是否授权客户端访问。同意后，用户会被重定向到你的redirect_uri，并附带授权码：

```
https://myclient.example.com/callback?code=generated-authorization-code&state=random-state
```

### 6. 交换访问令牌

使用授权码和code_verifier获取访问令牌：

```bash
curl -X POST "https://<apim-servicename>.azure-api.net/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=generated-authorization-code&code_verifier=${CODE_VERIFIER}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}"
```

**响应示例：**
```json
{
    "access_token": "encrypted-session-key",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### 7. 使用访问令牌访问MCP API

获得访问令牌后，可以访问MCP服务器：

**建立SSE连接：**
```bash
curl -X GET "https://<apim-servicename>.azure-api.net/mcp/sse" \
  -H "Authorization: Bearer encrypted-session-key" \
  -H "Accept: text/event-stream"
```

**发送MCP消息：**
```bash
curl -X POST "https://<apim-servicename>.azure-api.net/mcp/message" \
  -H "Authorization: Bearer encrypted-session-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

## 安全机制

### 多层安全模型

1. **OAuth 2.0/PKCE认证**
   - 防止授权码拦截攻击
   - 用户同意管理
   - 持久化偏好设置

2. **会话密钥加密**
   - 访问令牌不会暴露给MCP客户端
   - 加密的会话密钥提供有时限的访问
   - 在APIM中使用AES加密进行安全密钥管理

3. **Function级别安全**
   - Function主机密钥保护对Azure Functions的直接访问
   - 托管身份确保安全的服务间通信

4. **Azure平台安全**
   - 所有流量使用TLS加密
   - 通过托管身份访问存储
   - 通过Application Insights进行审计日志记录

### 会话密钥加密详情

系统使用AES加密来保护会话密钥：

- 访问令牌存储在APIM缓存中
- 返回给客户端的是加密的会话密钥
- 每次API调用时解密并验证会话密钥

## 错误处理

### 常见错误响应

**401 未授权：**
```json
{
    "error": "invalid_token",
    "error_description": "The access token provided is invalid"
}
```

**400 错误请求：**
```json
{
    "error": "invalid_request",
    "error_description": "Missing required parameter: code_challenge"
}
```

**403 禁止访问：**
```json
{
    "error": "access_denied",
    "error_description": "User denied the authorization request"
}
```

## 示例：完整的Python客户端

```python
import requests
import secrets
import base64
import hashlib
import webbrowser
from urllib.parse import urlparse, parse_qs

class MCPClient:
    def __init__(self, base_url, client_id, redirect_uri):
        self.base_url = base_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.access_token = None
        
    def generate_pkce(self):
        """生成PKCE参数"""
        self.code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        self.code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return self.code_challenge
    
    def get_authorization_url(self):
        """构建授权URL"""
        code_challenge = self.generate_pkce()
        self.state = secrets.token_urlsafe(32)
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': self.state
        }
        
        url = f"{self.base_url}/oauth/authorize"
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{url}?{query_string}"
    
    def exchange_code_for_token(self, authorization_code):
        """交换授权码为访问令牌"""
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'code_verifier': self.code_verifier,
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri
        }
        
        response = requests.post(
            f"{self.base_url}/oauth/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data['access_token']
            return token_data
        else:
            raise Exception(f"Token exchange failed: {response.text}")
    
    def call_mcp_api(self, endpoint, data=None):
        """调用MCP API"""
        if not self.access_token:
            raise Exception("No access token available")
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.base_url}/mcp/{endpoint}"
        
        if data:
            response = requests.post(url, json=data, headers=headers)
        else:
            response = requests.get(url, headers=headers)
        
        return response.json()

# 使用示例
if __name__ == "__main__":
    client = MCPClient(
        base_url="https://<apim-servicename>.azure-api.net",
        client_id="your-client-id",
        redirect_uri="https://myclient.example.com/callback"
    )
    
    # 1. 获取授权URL
    auth_url = client.get_authorization_url()
    print(f"请在浏览器中打开: {auth_url}")
    
    # 2. 用户授权后，从回调URL中获取授权码
    callback_url = input("请输入完整的回调URL: ")
    parsed_url = urlparse(callback_url)
    auth_code = parse_qs(parsed_url.query)['code'][0]
    
    # 3. 交换访问令牌
    token_data = client.exchange_code_for_token(auth_code)
    print(f"访问令牌获取成功: {token_data}")
    
    # 4. 调用MCP API
    tools = client.call_mcp_api("message", {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    })
    print(f"可用工具: {tools}")
```

## 疑难排解

### 检查部署状态
```bash
azd env get-values
```

### 查看日志
```bash
# 获取函数应用日志
az functionapp logs tail --name <function-app-name> --resource-group <resource-group>

# 获取API Management日志
az monitor activity-log list --resource-group <resource-group>
```

### 测试端点
```bash
# 测试OAuth元数据端点
curl -s "https://<apim-servicename>.azure-api.net/oauth/.well-known/oauth-authorization-server" | jq

# 测试MCP端点（需要有效token）
curl -H "Authorization: Bearer <your-token>" \
     "https://<apim-servicename>.azure-api.net/mcp/sse"
```

## 注意事项

1. **安全性**：始终使用HTTPS进行生产部署
2. **令牌管理**：访问令牌有过期时间，需要适当的刷新机制
3. **错误处理**：实现适当的重试和错误处理逻辑
4. **CORS**：如果从浏览器应用调用，确保正确配置CORS
5. **速率限制**：注意API调用的速率限制

这个认证系统提供了企业级的安全性，同时保持了与MCP规范的兼容性。

# VS Code 专用简化流程 🆕

如果你只是想在VS Code中使用MCP服务器，可以使用我们提供的一键认证工具：

## 一键获取Auth Code

```bash
# 方法1: 使用便捷脚本（推荐）
./get_auth_code.sh

# 方法2: 直接使用Python脚本
python vscode_mcp_auth.py https://your-apim.azure-api.net

# 方法3: 自动检测APIM URL
python vscode_mcp_auth.py $(azd env get-value APIM_GATEWAY_URL)
```

## 流程说明

1. **自动检测** - 脚本会自动检测你的APIM部署URL
2. **浏览器授权** - 自动打开浏览器进行OAuth授权
3. **本地回调** - 启动本地服务器接收授权码
4. **配置生成** - 自动生成VS Code MCP配置
5. **测试验证** - 可选：运行测试确保配置正确

## 验证配置

```bash
# 测试生成的认证配置
python test_mcp_auth.py
```

详细说明请参考：[VS Code MCP 认证指南](VSCODE_MCP_AUTH_GUIDE.md)

---
