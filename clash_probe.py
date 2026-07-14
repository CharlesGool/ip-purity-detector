"""Probe the real egress IP of a Clash/Mihomo proxy node.

Rather than reimplementing VLESS/Trojan/Reality/etc protocol logic, this
shells out to the actual `mihomo` (Clash Meta) core: it spins up a throwaway
config containing just the one node, points a local mixed HTTP/SOCKS port at
it, and asks a public IP-echo service what IP is visible through that tunnel.
"""
import contextlib
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import requests
import yaml

MIHOMO_BIN = (
    os.environ.get("MIHOMO_BIN")
    or shutil.which("mihomo")
    or str(Path(__file__).parent / "bin" / "mihomo")
)

STARTUP_TIMEOUT = 8.0
PROBE_TIMEOUT = 12.0
MAX_BATCH_NODES = 1000

IP_ECHO_URLS = [
    "https://api.ipify.org",
    "https://api.ip.sb/ip",
    "https://ipinfo.io/ip",
]


class NodeProbeError(Exception):
    pass


def _is_node(obj: Any) -> bool:
    return isinstance(obj, dict) and "server" in obj and "type" in obj


def _parse_structured(raw: str) -> list:
    """Try parsing `raw` as well-formed YAML and pull node dicts out of it."""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return []

    candidates: list = []
    if isinstance(data, dict):
        if isinstance(data.get("proxies"), list) and data["proxies"]:
            candidates = data["proxies"]
        elif _is_node(data):
            candidates = [data]
    elif isinstance(data, list):
        candidates = data

    return [n for n in candidates if _is_node(n)]


def _extract_flow_blobs(raw: str) -> list:
    """Pull out every balanced top-level `{ ... }` chunk in `raw`, ignoring
    braces inside quoted strings.

    Users often paste node lists assembled from several different sources
    (converters, subscription tools, hand-edited snippets), each using its
    own indentation/quoting conventions. That breaks YAML's block-sequence
    parser (which is strict about indentation) even though every individual
    `- { ... }` entry is itself perfectly valid flow-style YAML. Scanning
    for balanced braces sidesteps indentation entirely and tolerates that
    kind of copy-paste mess, including entries whose flow mapping happens
    to be wrapped across multiple lines.
    """
    blobs = []
    depth = 0
    start = None
    quote = None
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if quote:
            if quote == '"' and c == "\\":
                i += 2
                continue
            if quote == "'" and c == "'" and i + 1 < n and raw[i + 1] == "'":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue

        if c in ("'", '"'):
            quote = c
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    blobs.append(raw[start : i + 1])
                    start = None
        i += 1
    return blobs


def _parse_flow_fallback(raw: str) -> list:
    """Recover nodes from non-standard/invalid YAML by extracting individual
    flow-style `{ ... }` mappings and parsing each on its own."""
    nodes = []
    for blob in _extract_flow_blobs(raw):
        try:
            obj = yaml.safe_load(blob)
        except yaml.YAMLError:
            continue
        if _is_node(obj):
            nodes.append(obj)
    return nodes


def parse_nodes(raw: str) -> list:
    """Parse one or many Clash proxy nodes out of pasted YAML.

    Accepts: a single flow-style node (`- { ... }` or `{ ... }`), a
    multi-line list of nodes, or a full config containing a `proxies:`
    list. Returns every well-formed node found (i.e. dicts with both
    `type` and `server`), skipping anything else in the list silently.

    Also tolerant of non-standard input that isn't strictly valid YAML
    (e.g. pasted-together node lines with inconsistent indentation) as
    long as each node is still a recognizable flow-style `{ ... }` mapping
    — see `_parse_flow_fallback`.
    """
    raw = (raw or "").strip()
    if not raw:
        raise NodeProbeError("请输入 Clash 节点配置")

    nodes = _parse_structured(raw)
    if not nodes:
        nodes = _parse_flow_fallback(raw)

    if not nodes:
        raise NodeProbeError(
            "无法从输入中解析出有效的 Clash 节点（需要包含 type / server 等字段）"
        )
    if len(nodes) > MAX_BATCH_NODES:
        raise NodeProbeError(
            f"一次最多支持检测 {MAX_BATCH_NODES} 个节点（本次输入了 {len(nodes)} 个）"
        )
    return nodes


def parse_node(raw: str) -> dict:
    return parse_nodes(raw)[0]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_config(node: dict, mixed_port: int) -> str:
    name = node.get("name") or "probe-node"
    node = {**node, "name": name}
    config = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "proxies": [node],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [name]}],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def _wait_port(port: int, timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.15)
    raise NodeProbeError("mihomo 未能在预期时间内启动本地代理端口")


_LOG_MSG_RE = re.compile(r'msg="([^"]+)"')
_NOISY_SUBSTRINGS = ("shutting down", "shutdown")


def _clean_log_line(line: str) -> str:
    m = _LOG_MSG_RE.search(line)
    return m.group(1) if m else line


def _last_meaningful_log_line(out: str) -> str:
    if not out:
        return ""
    lines = [l.strip() for l in out.splitlines() if l.strip()]

    # Prefer actual dial/connect failures over generic shutdown noise.
    for l in reversed(lines):
        low = l.lower()
        if "dial" in low and "error" in low and not any(n in low for n in _NOISY_SUBSTRINGS):
            return _clean_log_line(l)
    for l in reversed(lines):
        low = l.lower()
        if ("error" in low or "warn" in low) and not any(n in low for n in _NOISY_SUBSTRINGS):
            return _clean_log_line(l)
    return _clean_log_line(lines[-1]) if lines else ""


class NodeProxyHandle:
    """A running mihomo instance proxying through a single node.

    Kept alive across the egress-IP probe and any follow-up checks (e.g. a
    WebRTC leak test tunneled through the same local port) so callers don't
    pay mihomo's startup cost twice. Must be closed via `.close()`.
    """

    def __init__(self, proc: subprocess.Popen, tmpdir: str, mixed_port: int):
        self.proc = proc
        self.tmpdir = tmpdir
        self.mixed_port = mixed_port

    def close(self):
        with contextlib.suppress(Exception):
            self.proc.terminate()
            self.proc.wait(timeout=3)
        with contextlib.suppress(Exception):
            self.proc.kill()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


def start_node_proxy(node: dict) -> NodeProxyHandle:
    """Blocking. Launch mihomo with a single-node config and wait for its
    local mixed (HTTP/SOCKS) port to come up. Call via asyncio.to_thread."""
    if not Path(MIHOMO_BIN).exists():
        raise NodeProbeError(
            f"未找到 mihomo 可执行文件: {MIHOMO_BIN}（请运行 scripts/fetch_mihomo.sh 安装）"
        )

    mixed_port = _free_port()
    tmpdir = tempfile.mkdtemp(prefix="ipdetect-mihomo-")
    config_path = Path(tmpdir) / "config.yaml"
    config_path.write_text(_build_config(node, mixed_port), encoding="utf-8")

    proc = subprocess.Popen(
        [MIHOMO_BIN, "-f", str(config_path), "-d", tmpdir],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_port(mixed_port, STARTUP_TIMEOUT)
    except NodeProbeError:
        out = _drain(proc)
        detail = _last_meaningful_log_line(out)
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise NodeProbeError(f"mihomo 启动失败: {detail or '未知原因'}")

    return NodeProxyHandle(proc, tmpdir, mixed_port)


def fetch_egress_ip(handle: NodeProxyHandle, node: dict, timeout: float = PROBE_TIMEOUT) -> dict:
    """Blocking. Ask a public IP-echo service what IP is visible through an
    already-running node proxy. Call via asyncio.to_thread."""
    proxies = {
        "http": f"http://127.0.0.1:{handle.mixed_port}",
        "https": f"http://127.0.0.1:{handle.mixed_port}",
    }
    last_err: Optional[Exception] = None
    for url in IP_ECHO_URLS:
        try:
            resp = requests.get(url, proxies=proxies, timeout=timeout)
            resp.raise_for_status()
            ip = resp.text.strip()
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            socket.inet_pton(family, ip)
            return {
                "egress_ip": ip,
                "node_name": node.get("name"),
                "node_type": node.get("type"),
                "node_server": node.get("server"),
                "node_port": node.get("port"),
            }
        except Exception as e:  # noqa: BLE001 - tried next echo service below
            last_err = e
            continue

    out = _drain(handle.proc)
    detail = _last_meaningful_log_line(out) or str(last_err)
    raise NodeProbeError(f"无法通过该节点访问外网: {detail}")


def probe_node_egress_ip(node: dict, timeout: float = PROBE_TIMEOUT) -> dict:
    """Blocking. Launch mihomo with a single-node config, return the egress
    IP visible through it plus basic node metadata, then tear it down. Call
    via asyncio.to_thread from async code.

    Thin convenience wrapper around start_node_proxy + fetch_egress_ip for
    callers that don't need the proxy kept alive afterwards.
    """
    handle = start_node_proxy(node)
    try:
        return fetch_egress_ip(handle, node, timeout=timeout)
    finally:
        handle.close()


def _drain(proc: subprocess.Popen) -> str:
    with contextlib.suppress(Exception):
        proc.terminate()
    try:
        out, _ = proc.communicate(timeout=2)
        return out or ""
    except subprocess.TimeoutExpired:
        return ""
