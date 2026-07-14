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

IP_ECHO_URLS = [
    "https://api.ipify.org",
    "https://api.ip.sb/ip",
    "https://ipinfo.io/ip",
]


class NodeProbeError(Exception):
    pass


def parse_node(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        raise NodeProbeError("请输入 Clash 节点配置")

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise NodeProbeError(f"节点配置不是合法的 YAML: {e}")

    node: Optional[Any] = None
    if isinstance(data, dict):
        if isinstance(data.get("proxies"), list) and data["proxies"]:
            node = data["proxies"][0]
        elif "server" in data and "type" in data:
            node = data
    elif isinstance(data, list) and data:
        node = data[0]

    if not isinstance(node, dict) or "server" not in node or "type" not in node:
        raise NodeProbeError(
            "无法从输入中解析出有效的 Clash 节点（需要包含 type / server 等字段）"
        )
    return node


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


def probe_node_egress_ip(node: dict, timeout: float = PROBE_TIMEOUT) -> dict:
    """Blocking. Launch mihomo with a single-node config, return the egress
    IP visible through it plus basic node metadata. Call via
    asyncio.to_thread from async code."""
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
        try:
            _wait_port(mixed_port, STARTUP_TIMEOUT)
        except NodeProbeError:
            out = _drain(proc)
            detail = _last_meaningful_log_line(out)
            raise NodeProbeError(f"mihomo 启动失败: {detail or '未知原因'}")

        proxies = {
            "http": f"http://127.0.0.1:{mixed_port}",
            "https": f"http://127.0.0.1:{mixed_port}",
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

        out = _drain(proc)
        detail = _last_meaningful_log_line(out) or str(last_err)
        raise NodeProbeError(f"无法通过该节点访问外网: {detail}")
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=3)
        with contextlib.suppress(Exception):
            proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


def _drain(proc: subprocess.Popen) -> str:
    with contextlib.suppress(Exception):
        proc.terminate()
    try:
        out, _ = proc.communicate(timeout=2)
        return out or ""
    except subprocess.TimeoutExpired:
        return ""
