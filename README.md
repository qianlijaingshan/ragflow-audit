# ragflow-audit

RAGFlow 三洞审计工具（CVE-2026-28797 / CVE-2026-24770 / CVE-2025-69286）

- **ssti**：检测并利用 StringTransform / Message 组件的 SSTI -> RCE
- **zipslip**：离线检测 zip 条目的路径穿越（Zip Slip）
- **apikey**：从分享链接 beta 推导 API key（uuid1 时间戳枚举）

纯 Python 标准库，无第三方依赖，Python 3.8+ 可直接运行。

## 用法

```
python3 ragflow-audit.py [-h] {ssti,zipslip,apikey} ...
```

### ssti

```
python3 ragflow-audit.py ssti --url http://TARGET:9380 --auth "AUTH_HEADER" [--component StringTransform|Message] [--newline]
```

- `--url`：RAGFlow Web 地址
- `--auth`：登录响应头 Authorization 的完整值
- `--component`：目标组件，默认 StringTransform
- `--newline`：使用换行绕过 payload（绕过 `_is_jinjia2` 正则检测）

流程：构造恶意 canvas DSL -> `POST /v1/canvas/set` 创建画布 -> `POST /v1/canvas/completion` 触发执行 -> 匹配输出中的 `uid=` 判断 RCE 是否成功。

### zipslip

```
python3 ragflow-audit.py zipslip --zip evil.zip [--extract-dir /tmp/out]
```

离线检查 zip 条目，标记三类危险：路径穿越（`..`）、绝对路径、符号链接。

### apikey

```
python3 ragflow-audit.py apikey --beta "分享链接token" --node "攻击者user_id后12位"
```

从公开分享链接的 beta token 恢复 uuid1 主体，枚举 time_low，输出候选 token。真实利用时对候选 token 逐个调用需要认证的 API（200 命中 / 401 继续）。

## 认证说明

RAGFlow 的登录凭证在 **登录响应头 Authorization** 里，不是 body 里的 `access_token`。body 里的 access_token 只是 UUID，调 API 会 401。

```
curl -i -X POST http://TARGET:9380/v1/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"x@x.com","password":"<RSA加密后的密码>"}'
```

取响应头 `authorization:` 的值作为 `--auth` 参数。

注意：注册/登录的密码需要先 RSA 加密（公钥在 `/ragflow/conf/public.pem`，PKCS1_v1_5，加密对象是 base64 之后的明文），直接传明文密码会报错。

## 漏洞背景

| CVE | 类型 | 影响版本 | 修复版本 |
|-----|------|----------|----------|
| CVE-2026-28797 | SSTI（StringTransform/Message 组件） | 全版本 | 未修复 |
| CVE-2026-24770 | MinerU 解析器 Zip Slip | < 0.23.1 | 0.23.1 |
| CVE-2025-69286 | API key 可推导（uuid1 + tenant_id 密钥） | < 0.22.0 | 0.22.0 |

## 免责声明

本工具仅用于授权的安全测试与漏洞研究。未经授权对他人系统使用本工具造成的后果由使用者自行承担。
