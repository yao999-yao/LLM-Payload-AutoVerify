#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM-Payload-AutoVerify
======================

基于大语言模型（DeepSeek Harness / DeepSeek API）批量生成 Web 漏洞 Payload，
并仅在本地 DVWA 靶场上自动提交、自动判定、自动落盘 CSV 的验证框架。

设计边界（重要）
----------------
1. 目标地址被硬性限制为回环地址（127.0.0.1 / localhost），启动即校验；
2. 每条 Payload 中出现的 URL 都会被解析并校验主机，任何非本地地址直接被拒绝，
   不会发出请求（见 ScopeGuard）；
3. 不做目录爆破、不做账号爆破、不并发压测，全部请求串行且带间隔；
4. 仅用于本地靶场学习与研究。

用法
----
    python main.py --gen dataset                  # 使用内置 Payload 数据集
    python main.py --gen harness                  # 使用 harness_task 产出的候选集
    python main.py --gen auto --limit 20          # 数据集 + harness + API（有 key 时）
    python main.py --only-type sqli --security medium
    python main.py --dry-run                      # 只做加载与校验，不发包

作者：<你的名字>
"""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import logging
import random
import re
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# =============================================================================
# 1. 配置区：唯一需要按本机环境修改的地方
# =============================================================================

# --- 1.1 靶场 ---
DVWA_BASE_URL: str = "http://127.0.0.1/dvwa"
DVWA_SECURITY_LEVEL: str = "low"          # low / medium / high / impossible

# --- 1.1b SSRF 靶点（官方 DVWA 不含 SSRF 模块，此处使用自建的本地演示页） ---
# 部署：把项目里的 lab/index.php 复制到 D:\tool\xampp\htdocs\ssrf-lab\index.php
# 若你不想跑 SSRF，把 SSRF_LAB_ENABLED 改成 False 即可
SSRF_LAB_URL: str = "http://127.0.0.1/ssrf-lab/"
SSRF_LAB_ENABLED: bool = True

# --- 1.2 登录凭据（优先使用 DVWA_COOKIE；留空则自动登录） ---
DVWA_COOKIE: str = ""                      # 例：PHPSESSID=abcd1234; security=low
DVWA_USERNAME: str = "admin"
DVWA_PASSWORD: str = "password"
DVWA_AUTO_LOGIN: bool = True

# --- 1.3 LLM（DeepSeek）生成端：仅在 --gen api 时使用，留空则跳过 ---
HARNESS_API_BASE: str = "https://api.deepseek.com/v1"
HARNESS_API_KEY: str = ""                  # 从环境变量 DEEPSEEK_API_KEY 读取亦可
HARNESS_MODEL: str = "deepseek-chat"
HARNESS_PAYLOAD_FILE: str = "../harness_task/output/payloads_out.jsonl"

# --- 1.4 范围守卫：目标主机白名单（仅回环地址及其等价写法） ---
LOCAL_HOST_ALLOWLIST: Tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "::1",
    "127.1",
    "2130706433",
)
ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")

# --- 1.5 发包节奏与容量（本地靶场，串行、限速） ---
REQUEST_TIMEOUT: float = 15.0              # 秒；需大于 time-based 用例的 SLEEP
REQUEST_INTERVAL: float = 0.25             # 每次请求之间的强制间隔（秒）
MAX_RETRIES: int = 2
BATCH_LIMIT_PER_TYPE: int = 60             # 单类漏洞单次运行的最大用例数
TIME_DELAY_THRESHOLD_MS: int = 800         # 响应耗时超过该值且载荷含 SLEEP() 判为时间盲注
DRY_RUN: bool = False

# --- 1.6 路径（全部相对脚本所在目录，脚本可在任意工作目录启动） ---
PROJECT_ROOT: Path = Path(__file__).resolve().parent
RESULT_DIR: Path = PROJECT_ROOT / "result"
CSV_PATH: Path = RESULT_DIR / "payload_result.csv"
LOG_PATH: Path = RESULT_DIR / "log.txt"
PAYLOAD_LIBRARY: Path = PROJECT_ROOT / "payloads" / "payload_library.jsonl"
CASE_SNAPSHOT: Path = RESULT_DIR / "cases_snapshot.jsonl"


# =============================================================================
# 2. 常量与数据结构
# =============================================================================

VULN_TYPES: Tuple[str, ...] = ("xss_r", "sqli", "ssrf")

ENDPOINTS: Dict[str, str] = {
    "xss_r": "vulnerabilities/xss_r/",
    "sqli": "vulnerabilities/sqli/",
    "ssrf": SSRF_LAB_URL,          # 绝对地址；官方 DVWA 无 SSRF 模块
}

# 判定为“漏洞成立”的结论集合，用于与人工标注比对
POSITIVE_VERDICTS: Dict[str, frozenset] = {
    "xss_r": frozenset({"REFLECTED_UNESCAPED"}),
    "sqli": frozenset({"SQL_ERROR", "UNION_MARKER", "TIME_DELAY", "BOOLEAN_DIFF"}),
    "ssrf": frozenset({"SSRF_CONFIRMED", "CONTENT_DIFF"}),
}

SQLI_ERROR_SIGNATURES: Tuple[str, ...] = (
    "You have an error in your SQL syntax",
    "check the manual that corresponds to your",
    "Warning: mysqli",
    "Warning: mysql",
    "supplied argument is not a valid MySQL",
    "mysqli_fetch_array() expects parameter",
    "mysqli_sql_exception",
    "Uncaught mysqli_sql_exception",
    "XPATH syntax error",
    "Unknown column",
    "SQL syntax",
)

SSRF_FAIL_SIGNATURES: Tuple[str, ...] = (
    "failed to open stream",
    "php_network_getaddresses",
    "Connection refused",
    "No route to host",
    "getaddrinfo failed",
    "A connection attempt failed",
)

SQLI_HINT_RE = re.compile(
    r"(?i)(--|#|/\*|union|select|sleep\s*\(|benchmark\s*\(|information_schema"
    r"|or\s+['\"\d]|and\s+['\"\d]|updatexml|extractvalue|order\s+by)"
)

DANGEROUS_XSS_TOKENS: Tuple[str, ...] = (
    "<script",
    "<svg",
    "<iframe",
    "<body",
    "<img",
    "onerror",
    "onload",
    "onbegin",
    "ontoggle",
    "onfocus",
    "onmouseover",
    "onclick",
    "javascript:",
)

CSV_HEADER: Tuple[str, ...] = (
    "序号",
    "时间戳",
    "漏洞类型",
    "用例ID",
    "载荷",
    "请求端点",
    "HTTP状态",
    "判定结果",
    "置信度",
    "证据",
    "响应长度",
    "耗时ms",
    "人工标注",
    "标注一致性",
    "来源",
    "备注",
)

NONCE_PLACEHOLDER = "{{NONCE}}"


class ScopeError(RuntimeError):
    """目标或载荷超出本地靶场范围时抛出。"""


@dataclass(frozen=True)
class PayloadCase:
    """一条待验证的 Payload 用例。"""

    case_id: str
    vuln_type: str
    payload: str
    source: str = "dataset"
    expected: str = ""        # vuln / clean / ""（未标注）
    severity: str = "medium"
    note: str = ""


@dataclass
class HttpResult:
    ok: bool
    status: int
    text: str
    length: int
    elapsed_ms: int
    error: str = ""
    url: str = ""

    @property
    def snippet(self) -> str:
        return re.sub(r"\s+", " ", self.text)[:160]


@dataclass
class Outcome:
    verdict: str
    confidence: str
    evidence: str
    status: int = 0
    length: int = 0
    latency_ms: int = 0


@dataclass
class SqliBaseline:
    length: int = 0
    has_row: bool = False
    rows: int = 0


# =============================================================================
# 3. 范围守卫：只允许本地回环目标
# =============================================================================

_URL_WITH_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15})://([^/\s'\"<>?#]+)")
_PROTO_RELATIVE = re.compile(r"(?<![:/\w])//([^/\s'\"<>?#]+)")
_SCHEME_PREFIX = re.compile(r"(?i)(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]{1,15}):")

# 这些协议一律禁止出现在载荷里：它们能让服务端读取本地文件或访问非 HTTP 资源
BLOCKED_SCHEMES: Tuple[str, ...] = (
    "file", "gopher", "dict", "ftp", "ftps", "jar", "netdoc",
    "tftp", "smb", "ldap", "php", "expect", "telnet", "scp",
)


def split_host_port(host: str) -> str:
    """从 host[:port] / [::1]:port 中取出纯主机部分。"""
    text = (host or "").strip()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def host_is_local(host: str) -> bool:
    """主机名或 IP 是否属于本机回环。"""
    name = split_host_port(host).strip().lower().rstrip(".")
    if not name:
        return False
    if name in LOCAL_HOST_ALLOWLIST:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def assert_target_is_local(url: str) -> None:
    """校验靶场地址。"""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise ScopeError(f"不支持的协议：{parts.scheme!r}，仅允许 http/https")
    if not host_is_local(parts.hostname or ""):
        raise ScopeError(
            f"目标主机 {parts.hostname!r} 不在本地回环白名单内，"
            f"本框架拒绝向非本机地址发送任何请求"
        )


def assert_payload_is_local(payload: str) -> None:
    """校验 Payload 文本中出现的所有 URL 是否指向本机。

    这是本框架最重要的安全约束：即使数据集或大模型生成了指向外部主机的
    SSRF 载荷，此处也会在发包前直接拦截。
    """
    for scheme, host in _URL_WITH_SCHEME.findall(payload):
        if scheme.lower() not in ALLOWED_SCHEMES:
            raise ScopeError(f"载荷包含不允许的协议：{scheme}://（{payload[:60]}）")
        if not host_is_local(host):
            raise ScopeError(f"载荷指向非本机主机：{host}（{payload[:60]}）")
    for host in _PROTO_RELATIVE.findall(payload):
        if not host_is_local(host):
            raise ScopeError(f"载荷指向非本机主机：{host}（{payload[:60]}）")
    for scheme in _SCHEME_PREFIX.findall(payload):
        if scheme.lower() in BLOCKED_SCHEMES:
            raise ScopeError(f"载荷包含被禁止的协议：{scheme}:（{payload[:60]}）")


def guard_cases(cases: Sequence[PayloadCase], logger: logging.Logger) -> List[PayloadCase]:
    """逐条过守卫，丢弃越界用例并记录。"""
    kept: List[PayloadCase] = []
    for case in cases:
        try:
            assert_payload_is_local(case.payload)
        except ScopeError as exc:
            logger.warning("用例 %s 被范围守卫拦截：%s", case.case_id, exc)
            continue
        kept.append(case)
    return kept


# =============================================================================
# 4. DVWA 客户端
# =============================================================================

class DVWAClient:
    """封装 DVWA 的会话、登录、安全等级与串行请求。"""

    def __init__(
        self,
        base_url: str,
        security_level: str,
        cookie: str,
        username: str,
        password: str,
        timeout: float,
        interval: float,
        retries: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.security_level = security_level
        self.cookie = cookie
        self.username = username
        self.password = password
        self.timeout = timeout
        self.interval = interval

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "LLM-Payload-AutoVerify/1.0 (local-lab; DVWA only)",
                "Accept": "text/html,application/xhtml+xml",
            }
        )
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=retries,
                backoff_factor=0.3,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset({"GET", "POST"}),
            )
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if cookie:
            for chunk in cookie.split(";"):
                chunk = chunk.strip()
                if "=" in chunk:
                    key, value = chunk.split("=", 1)
                    self.session.cookies.set(key.strip(), value.strip())

    # -- 基础 ---------------------------------------------------------------
    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs) -> HttpResult:
        if path.lower().startswith(("http://", "https://")):
            assert_target_is_local(path)      # 绝对地址同样必须落在本机
            target = path
        else:
            target = self.url(path)
        if self.interval > 0:
            time.sleep(self.interval)
        started = time.perf_counter()
        try:
            resp = self.session.request(
                method, target, timeout=self.timeout, **kwargs
            )
        except requests.exceptions.RequestException as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return HttpResult(False, 0, "", 0, elapsed, str(exc)[:200], target)
        elapsed = int((time.perf_counter() - started) * 1000)
        return HttpResult(
            True, resp.status_code, resp.text, len(resp.text), elapsed, "", resp.url
        )

    def get_absolute(self, url: str) -> HttpResult:
        """按绝对地址抓取（仅本机），用于生成内容指纹。"""
        return self.request("GET", url, allow_redirects=True)

    def get(self, path: str, params: Optional[Dict[str, str]] = None) -> HttpResult:
        return self.request("GET", path, params=params)

    def post(self, path: str, data: Dict[str, str]) -> HttpResult:
        return self.request("POST", path, data=data)

    # -- 登录与配置 ---------------------------------------------------------
    @staticmethod
    def _token_from(text: str) -> str:
        match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-zA-Z]+)", text)
        return match.group(1) if match else ""

    def _user_token(self, path: str) -> str:
        result = self.request("GET", path, allow_redirects=True)
        return self._token_from(result.text) if result.ok else ""

    def login(self, logger: logging.Logger) -> bool:
        token = self._user_token("login.php")
        result = self.post(
            "login.php",
            {
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": token,
            },
        )
        if not result.ok:
            logger.error("登录请求失败：%s", result.error)
            return False
        if 'name="password"' in result.text:
            logger.error("登录失败：请检查 DVWA_USERNAME / DVWA_PASSWORD")
            return False
        logger.info("DVWA 登录成功（%s）", self.username)
        return True

    def set_security(self, logger: logging.Logger) -> None:
        # 注意：user_token 必须从 security.php 自己的表单里取。
        # DVWA 2.x 默认等级是 impossible，取错 token 会导致 CSRF 校验失败、
        # 等级停留在 impossible，而页面里的下拉选项文本仍包含 "low"，
        # 只看文本会误判为设置成功。
        token = self._user_token("security.php")
        result = self.post(
            "security.php",
            {
                "security": self.security_level,
                "seclev_submit": "Submit",
                "user_token": token,
            },
        )
        if not result.ok:
            logger.error("设置安全等级失败：%s", result.error)
            return
        match = re.search(r'<option value="([a-z]+)"\s+selected', result.text)
        current = match.group(1) if match else ""
        if current == self.security_level:
            logger.info("安全等级已设置为 %s", self.security_level)
        else:
            logger.warning(
                "安全等级未生效（当前 %s），判定结果可能偏离预期，请手动检查 dvwa/security.php",
                current or "未知",
            )
        # DVWA 的 security Cookie 作用域是 /dvwa/，SSRF 靶点在 /ssrf-lab/ 读不到，
        # 这里额外下发一个同名等级的 lab_level Cookie（path=/），让靶点跟随同一等级。
        self.session.cookies.set("lab_level", self.security_level, path="/")

    def ensure_authenticated(self, logger: logging.Logger) -> bool:
        probe = self.request("GET", "index.php", allow_redirects=True)
        if not probe.ok:
            logger.error("无法访问 DVWA：%s", probe.error)
            return False
        need_login = "login.php" in probe.url or 'name="password"' in probe.text
        if need_login:
            if not DVWA_AUTO_LOGIN:
                logger.error("DVWA 要求登录，但未开启自动登录；请填写 DVWA_COOKIE")
                return False
            if not self.login(logger):
                return False
        self.set_security(logger)
        return True

    # -- 基线 ---------------------------------------------------------------
    def sqli_fetch(self, ident: str) -> HttpResult:
        """按当前安全等级选择 SQLi 的正确提交方式。

        DVWA 的 SQLi 模块会随等级更换取参方式：
          low        -> GET  ?id=
          medium     -> POST id=      （mysqli_real_escape_string 后仍拼进无引号数值位）
          high       -> 先 POST session-input.php 写入 $_SESSION['id']，再 GET 页面
          impossible -> GET  ?id=      （预处理语句，理论上无效）
        """
        level = self.security_level
        if level == "medium":
            return self.post(ENDPOINTS["sqli"], {"id": ident, "Submit": "Submit"})
        if level == "high":
            self.post(
                "vulnerabilities/sqli/session-input.php",
                {"id": ident, "Submit": "Submit"},
            )
            return self.get(ENDPOINTS["sqli"])
        return self.get(ENDPOINTS["sqli"], {"id": ident, "Submit": "Submit"})

    def sqli_baseline(self) -> SqliBaseline:
        result = self.sqli_fetch("1")
        if not result.ok:
            return SqliBaseline()
        rows = result.text.count("First name")
        return SqliBaseline(length=result.length, has_row=rows > 0, rows=rows)

    def ssrf_control(self) -> HttpResult:
        """控制组：向本机一个未监听端口发起请求，作为失败基线。"""
        return self.get(
            ENDPOINTS["ssrf"],
            {"url": "http://127.0.0.1:1/", "Submit": "Submit"},
        )


# =============================================================================
# 5. Payload 来源：数据集 / harness_task 产物 / DeepSeek API
# =============================================================================

def _normalise_case(raw: Dict[str, object], default_source: str) -> Optional[PayloadCase]:
    vuln_type = str(raw.get("type") or raw.get("vuln_type") or "").strip()
    payload = str(raw.get("payload") or "").strip()
    if vuln_type not in VULN_TYPES or not payload:
        return None
    case_id = str(raw.get("id") or raw.get("case_id") or "").strip()
    if not case_id:
        case_id = f"{vuln_type}_{abs(hash(payload)) % 100000:05d}"
    return PayloadCase(
        case_id=case_id,
        vuln_type=vuln_type,
        payload=payload,
        source=str(raw.get("source") or default_source),
        expected=str(raw.get("expected") or "").strip().lower(),
        severity=str(raw.get("severity") or "medium"),
        note=str(raw.get("note") or ""),
    )


def load_jsonl(path: Path, default_source: str, logger: logging.Logger) -> List[PayloadCase]:
    if not path.is_file():
        logger.warning("未找到用例文件：%s", path)
        return []
    cases: List[PayloadCase] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("%s 第 %d 行解析失败：%s", path.name, lineno, exc)
                continue
            case = _normalise_case(raw, default_source)
            if case:
                cases.append(case)
    logger.info("从 %s 载入 %d 条用例", path.name, len(cases))
    return cases


def dedupe(cases: Iterable[PayloadCase]) -> List[PayloadCase]:
    seen: set = set()
    result: List[PayloadCase] = []
    for case in cases:
        key = (case.vuln_type, case.payload)
        if key in seen:
            continue
        seen.add(key)
        result.append(case)
    return result


_GEN_SYSTEM_PROMPT = """你是 Web 安全实验助教，只服务于本地 DVWA 靶场（http://127.0.0.1/dvwa）的
合法教学研究。请针对指定漏洞类型生成绕过 Payload 候选。

硬性要求：
1. 所有载荷只能指向 127.0.0.1 / localhost，禁止出现任何公网或内网第三方主机名、IP、域名；
2. 只输出 JSON，格式为 {"items":[{"type":"xss_r|sqli|ssrf","payload":"...","note":"绕过思路","severity":"low|medium|high"}]}；
3. 载荷中需要唯一标记的位置一律写作 {{NONCE}}，运行时由程序替换为随机串；
4. 不要输出任何扫描、爆破、批量发包逻辑，不要解释，不要 Markdown 代码块。"""

_GEN_USER_PROMPT = """漏洞类型：{vuln_type}（{desc}）
目标参数：{param}
生成 {count} 条互不重复的绕过候选。

覆盖维度参考：
- XSS：标签变形、大小写混淆、事件属性、闭合绕过、嵌套标签、伪协议、HTML 实体；
- SQL 注入：布尔、报错、联合查询、时间盲注、注释符、引号闭合、函数变形；
- SSRF：回环地址等价写法、端口变化、指向靶场内部页面、协议相对写法。

所有 URL 必须落在本机，例如 http://127.0.0.1/dvwa/ 。"""

_GEN_PARAM_DESC = {
    "xss_r": ("name", "反射型 XSS，参数被原样回显"),
    "sqli": ("id", "数字型 SQL 注入，2 列查询"),
    "ssrf": ("url", "服务端请求伪造，参数被服务端抓取"),
}


def generate_with_api(
    vuln_types: Sequence[str], per_type: int, logger: logging.Logger
) -> List[PayloadCase]:
    """调用 DeepSeek 兼容接口生成候选载荷（可选能力，失败不影响主流程）。"""
    api_key = HARNESS_API_KEY or ""
    if not api_key:
        logger.info("未配置 HARNESS_API_KEY，跳过 API 生成")
        return []

    cases: List[PayloadCase] = []
    for vuln_type in vuln_types:
        param, desc = _GEN_PARAM_DESC[vuln_type]
        body = {
            "model": HARNESS_MODEL,
            "temperature": 0.9,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _GEN_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": _GEN_USER_PROMPT.format(
                        vuln_type=vuln_type,
                        desc=desc,
                        param=param,
                        count=per_type,
                    ),
                },
            ],
        }
        try:
            resp = requests.post(
                f"{HARNESS_API_BASE.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=90,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            items = json.loads(content).get("items", [])
        except (requests.exceptions.RequestException, KeyError, ValueError) as exc:
            logger.warning("API 生成 %s 失败：%s", vuln_type, exc)
            continue

        for index, item in enumerate(items, 1):
            item = dict(item)
            item.setdefault("type", vuln_type)
            item.setdefault("source", "deepseek-api")
            item["id"] = f"{vuln_type}_api_{index:02d}"
            case = _normalise_case(item, "deepseek-api")
            if case:
                cases.append(case)
        logger.info("API 生成 %s 候选 %d 条", vuln_type, len(items))

    return dedupe(cases)


# =============================================================================
# 6. 三类漏洞的判定逻辑
# =============================================================================

def check_xss(client: DVWAClient, effective: str, token: str) -> Outcome:
    """反射型 XSS：以“随机标记是否原样回显”为核心判定。"""
    result = client.get(
        ENDPOINTS["xss_r"], {"name": effective, "Submit": "Submit"}
    )
    if not result.ok:
        return Outcome("REQUEST_FAILED", "low", result.error or "请求异常")

    text = result.text
    if token not in text:
        return Outcome(
            "NOT_REFLECTED", "high", "响应中未出现本轮随机标记，载荷未被回显",
            result.status, result.length, result.elapsed_ms,
        )
    if effective in text:
        raw_dangerous = any(flag in effective.lower() for flag in DANGEROUS_XSS_TOKENS)
        if raw_dangerous:
            return Outcome(
                "REFLECTED_UNESCAPED", "high",
                "随机标记原样回显且保留可执行结构，响应中存在未转义的脚本注入面",
                result.status, result.length, result.elapsed_ms,
            )
        return Outcome(
            "REFLECTED_PLAIN", "medium",
            "随机标记原样回显，但载荷不含可执行结构，仅证明回显未过滤",
            result.status, result.length, result.elapsed_ms,
        )
    if html.escape(effective, quote=True) in text or "&lt;script" in text:
        return Outcome(
            "REFLECTED_ESCAPED", "medium",
            "标记存在但 < > \" 已被转义（htmlspecialchars 类处理），未构成注入",
            result.status, result.length, result.elapsed_ms,
        )
    return Outcome(
        "REFLECTED_MODIFIED", "low", "标记存在但载荷被截断或改写",
        result.status, result.length, result.elapsed_ms,
    )


def check_sqli(
    client: DVWAClient, effective: str, token: str, baseline: SqliBaseline
) -> Outcome:
    """SQL 注入：报错 > 联合查询标记 > 时间盲注 > 布尔差异 的优先级判定。"""
    result = client.sqli_fetch(effective)
    if not result.ok:
        return Outcome("REQUEST_FAILED", "low", result.error or "请求异常")

    text = result.text
    # 只有载荷里真的带了 SQL 语法特征（引号、注释符、关键字）时，报错才算注入证据。
    # 否则像 id=abc 这种普通非法输入也会触发 "Unknown column"，造成误报。
    has_sql_hint = bool(SQLI_HINT_RE.search(effective))
    if has_sql_hint:
        for signature in SQLI_ERROR_SIGNATURES:
            if signature in text:
                return Outcome(
                    "SQL_ERROR", "high", f"响应出现数据库报错特征：{signature}",
                    result.status, result.length, result.elapsed_ms,
                )

    if token and token in text:
        return Outcome(
            "UNION_MARKER", "high", "联合查询标记出现在结果集中，注入点可回显数据",
            result.status, result.length, result.elapsed_ms,
        )

    if "sleep(" in effective.lower() and result.elapsed_ms >= TIME_DELAY_THRESHOLD_MS:
        return Outcome(
            "TIME_DELAY", "high",
            f"响应延迟 {result.elapsed_ms}ms（阈值 {TIME_DELAY_THRESHOLD_MS}ms），疑似时间盲注生效",
            result.status, result.length, result.elapsed_ms,
        )

    if has_sql_hint:
        rows_now = text.count("First name")
        if baseline.has_row and rows_now != baseline.rows:
            return Outcome(
                "BOOLEAN_DIFF", "medium",
                f"结果行数由基线 {baseline.rows} 变为 {rows_now}，存在布尔逻辑差异",
                result.status, result.length, result.elapsed_ms,
            )

        if baseline.length and abs(result.length - baseline.length) > 300:
            return Outcome(
                "BOOLEAN_DIFF", "medium",
                f"响应长度与基线相差 {abs(result.length - baseline.length)} 字节",
                result.status, result.length, result.elapsed_ms,
            )

    return Outcome(
        "NO_EFFECT", "low", "未观测到报错、标记、延迟或长度差异",
        result.status, result.length, result.elapsed_ms,
    )


def check_ssrf(
    client: DVWAClient, effective: str, token: str, control: HttpResult
) -> Outcome:
    """SSRF：以“服务端是否抓取到本机内部资源”为判定依据。"""
    result = client.get(
        ENDPOINTS["ssrf"], {"url": effective, "Submit": "Submit"}
    )
    if not result.ok:
        return Outcome("REQUEST_FAILED", "low", result.error or "请求异常")

    text = result.text
    # 目标页可能把提交的 url 原样回显到表单里，此时单次出现不足以证明“服务端抓取成功”，
    # 需要至少两次（回显 + 抓取回来的页面内容）才算数；页面不回显时一次即可。
    token_hits = text.count(token) if token else 0
    reflected_input = bool(token) and effective in text
    if token and (token_hits >= 2 or (token_hits >= 1 and not reflected_input)):
        return Outcome(
            "SSRF_CONFIRMED", "high",
            "目标页面的随机标记经服务端抓取后出现在响应中，SSRF 成立",
            result.status, result.length, result.elapsed_ms,
        )

    for signature in SSRF_FAIL_SIGNATURES:
        if signature in text:
            return Outcome(
                "FETCH_FAILED", "medium", f"服务端抓取失败：{signature}",
                result.status, result.length, result.elapsed_ms,
            )

    # 内容指纹：先用本机直接抓取同一地址，取其正文片段，再确认它是否出现在
    # SSRF 响应里。命中即说明“服务端替我们抓到了这个内部页面”。
    if control.ok:
        control_compact = re.sub(r"\s+", "", control.text)
        response_compact = re.sub(r"\s+", "", text)
        direct = client.get_absolute(effective)
        if direct.ok:
            for window in _content_windows(direct.text):
                if window in response_compact and window not in control_compact:
                    return Outcome(
                        "SSRF_CONFIRMED", "medium",
                        "响应包含目标页面的内容指纹，服务端确实抓取了内部资源",
                        result.status, result.length, result.elapsed_ms,
                    )

    if control.ok and result.length > control.length + 200:
        return Outcome(
            "CONTENT_DIFF", "medium",
            f"响应体比失败控制组多 {result.length - control.length} 字节，疑似回显内部资源",
            result.status, result.length, result.elapsed_ms,
        )

    return Outcome(
        "NO_EFFECT", "low", "未观测到内部资源回显",
        result.status, result.length, result.elapsed_ms,
    )


def _content_windows(text: str, size: int = 24, limit: int = 8) -> List[str]:
    """从页面正文中抽取若干固定长度片段，作为内容指纹候选。"""
    compact = re.sub(r"\s+", "", text)
    if len(compact) < size + 2:
        return []
    span = len(compact) - size
    step = max(1, span // limit)
    return [compact[i:i + size] for i in range(0, span, step)][:limit]


def evaluate_expected(vuln_type: str, expected: str, verdict: str) -> str:
    """与人工标注比对，返回 一致 / 不一致 / 未标注。"""
    if expected not in ("vuln", "clean") or verdict == "DRY_RUN":
        return "未标注"
    positive = verdict in POSITIVE_VERDICTS.get(vuln_type, frozenset())
    return "一致" if (expected == "vuln") == positive else "不一致"


# =============================================================================
# 7. 报告与日志
# =============================================================================

def prepare_environment() -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("autoverify")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    file_handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


class ReportWriter:
    """逐行落盘，进程中断也不会丢失已完成用例。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = path.open("w", newline="", encoding="utf-8-sig")
        self.writer = csv.writer(self.handle)
        self.writer.writerow(CSV_HEADER)

    def write(self, row: Sequence[object]) -> None:
        self.writer.writerow(row)
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()


def new_token() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "nx" + "".join(random.choice(alphabet) for _ in range(8))


def write_snapshot(cases: Sequence[PayloadCase]) -> None:
    with CASE_SNAPSHOT.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(
                json.dumps(
                    {
                        "id": case.case_id,
                        "type": case.vuln_type,
                        "payload": case.payload,
                        "source": case.source,
                        "expected": case.expected,
                        "severity": case.severity,
                        "note": case.note,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def print_summary(rows: Sequence[Sequence[object]], logger: logging.Logger) -> None:
    total = len(rows)
    if not total:
        logger.info("没有产生任何结果")
        return

    by_type: Dict[str, Dict[str, int]] = {}
    match_count = {"一致": 0, "不一致": 0, "未标注": 0}
    for row in rows:
        vuln_type = str(row[2])
        verdict = str(row[7])
        by_type.setdefault(vuln_type, {}).setdefault(verdict, 0)
        by_type[vuln_type][verdict] += 1
        match_count[str(row[13])] = match_count.get(str(row[13]), 0) + 1

    lines = ["", "=" * 66, "验证结果汇总", "=" * 66]
    for vuln_type in VULN_TYPES:
        if vuln_type not in by_type:
            continue
        lines.append(f"[{vuln_type}]")
        for verdict, count in sorted(by_type[vuln_type].items(), key=lambda kv: -kv[1]):
            lines.append(f"    {verdict:<22} {count:>3}")
    lines.append("-" * 66)
    lines.append(f"用例总数：{total}")
    labelled = match_count["一致"] + match_count["不一致"]
    if labelled:
        rate = match_count["一致"] / labelled * 100
        lines.append(f"与人工标注一致率：{rate:.1f}% （{match_count['一致']}/{labelled}）")
    lines.append(f"结果文件：{CSV_PATH.relative_to(PROJECT_ROOT)}")
    lines.append(f"运行日志：{LOG_PATH.relative_to(PROJECT_ROOT)}")
    lines.append("=" * 66)
    logger.info("\n".join(lines))


# =============================================================================
# 8. 主流程
# =============================================================================

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="本地 DVWA 靶场 Payload 自动生成与验证框架（仅限 127.0.0.1）",
    )
    parser.add_argument(
        "--gen",
        choices=("dataset", "harness", "api", "auto"),
        default="auto",
        help="载荷来源：dataset=内置数据集，harness=harness_task 产物，api=DeepSeek 生成，auto=全部可用来源",
    )
    parser.add_argument(
        "--only-type",
        default=",".join(VULN_TYPES),
        help="只跑指定漏洞类型，逗号分隔，如 xss_r,sqli",
    )
    parser.add_argument("--limit", type=int, default=BATCH_LIMIT_PER_TYPE, help="单类漏洞用例上限")
    parser.add_argument("--base-url", default=DVWA_BASE_URL, help="DVWA 根地址")
    parser.add_argument(
        "--security", default=DVWA_SECURITY_LEVEL, choices=("low", "medium", "high", "impossible")
    )
    parser.add_argument("--dry-run", action="store_true", help="只加载与校验，不发送请求")
    parser.add_argument("--snapshot-cases", action="store_true", help="导出本次使用的用例快照")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    return parser.parse_args(argv)


def collect_cases(args: argparse.Namespace, logger: logging.Logger) -> List[PayloadCase]:
    types = [t.strip() for t in args.only_type.split(",") if t.strip()]
    unknown = [t for t in types if t not in VULN_TYPES]
    if unknown:
        raise SystemExit(f"未知漏洞类型：{unknown}，可选 {VULN_TYPES}")

    cases: List[PayloadCase] = []
    if args.gen in ("dataset", "auto"):
        cases.extend(load_jsonl(PAYLOAD_LIBRARY, "dataset", logger))
    if args.gen in ("harness", "auto"):
        harness_path = (PROJECT_ROOT / HARNESS_PAYLOAD_FILE).resolve()
        cases.extend(load_jsonl(harness_path, "harness", logger))
    if args.gen in ("api", "auto"):
        api_types = types if args.gen == "api" else []
        if api_types:
            cases.extend(generate_with_api(api_types, min(args.limit, 10), logger))

    cases = [c for c in dedupe(cases) if c.vuln_type in types]
    cases = guard_cases(cases, logger)

    limited: List[PayloadCase] = []
    for vuln_type in types:
        bucket = [c for c in cases if c.vuln_type == vuln_type][: args.limit]
        limited.extend(bucket)
    return limited


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    prepare_environment()
    logger = setup_logging(args.verbose)
    logger.info("=" * 66)
    logger.info("LLM-Payload-AutoVerify 启动：%s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        assert_target_is_local(args.base_url)
    except ScopeError as exc:
        logger.error("范围校验失败，已退出：%s", exc)
        return 2
    logger.info("目标地址校验通过：%s（安全等级 %s）", args.base_url, args.security)

    try:
        cases = collect_cases(args, logger)
    except SystemExit as exc:
        logger.error("%s", exc)
        return 3
    if not SSRF_LAB_ENABLED:
        cases = [case for case in cases if case.vuln_type != "ssrf"]
        logger.info("SSRF 靶点未启用（SSRF_LAB_ENABLED=False），已跳过 ssrf 用例")
    if not cases:
        logger.error("没有可执行的用例，请检查 payloads/ 与 harness_task/output/")
        return 3
    logger.info("本次计划执行 %d 条用例（dry-run=%s）", len(cases), args.dry_run)

    if args.snapshot_cases:
        write_snapshot(cases)
        logger.info("用例快照已导出：%s", CASE_SNAPSHOT.relative_to(PROJECT_ROOT))

    baseline = SqliBaseline()
    control = HttpResult(False, 0, "", 0, 0, "dry-run")
    client: Optional[DVWAClient] = None
    if not args.dry_run:
        client = DVWAClient(
            base_url=args.base_url,
            security_level=args.security,
            cookie=DVWA_COOKIE,
            username=DVWA_USERNAME,
            password=DVWA_PASSWORD,
            timeout=REQUEST_TIMEOUT,
            interval=REQUEST_INTERVAL,
            retries=MAX_RETRIES,
        )
        if not client.ensure_authenticated(logger):
            logger.error("DVWA 未就绪，已退出。请确认 XAMPP 的 Apache/MySQL 已启动")
            return 4
        baseline = client.sqli_baseline()
        control = client.ssrf_control()
        logger.info(
            "SQLi 基线长度 %d（含结果行=%s），SSRF 控制组长度 %d",
            baseline.length,
            baseline.has_row,
            control.length,
        )

    writer = ReportWriter(CSV_PATH)
    rows: List[Sequence[object]] = []
    started = time.perf_counter()
    try:
        for index, case in enumerate(cases, 1):
            token = new_token()
            effective = case.payload.replace(NONCE_PLACEHOLDER, token)

            if args.dry_run:
                outcome = Outcome("DRY_RUN", "-", "未发送请求（dry-run）")
            elif case.vuln_type == "xss_r":
                outcome = check_xss(client, effective, token)
            elif case.vuln_type == "sqli":
                outcome = check_sqli(client, effective, token, baseline)
            else:
                outcome = check_ssrf(client, effective, token, control)

            match = evaluate_expected(case.vuln_type, case.expected, outcome.verdict)
            row = (
                index,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                case.vuln_type,
                case.case_id,
                effective,
                ENDPOINTS.get(case.vuln_type, ""),
                outcome.status,
                outcome.verdict,
                outcome.confidence,
                outcome.evidence,
                outcome.length,
                outcome.latency_ms,
                case.expected or "未标注",
                match,
                case.source,
                case.note,
            )
            writer.write(row)
            rows.append(row)
            logger.info(
                "[%d/%d] %-6s %-12s %-20s (%s) %5dms  %s",
                index, len(cases), case.vuln_type, case.case_id,
                outcome.verdict, outcome.confidence, outcome.latency_ms,
                outcome.evidence[:60],
            )
    finally:
        writer.close()

    elapsed = time.perf_counter() - started
    logger.info("全部用例执行完毕，用时 %.1f 秒", elapsed)
    print_summary(rows, logger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
