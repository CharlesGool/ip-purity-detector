#!/usr/bin/env python3
"""Command-line client for the IP purity detector service.

Talks to the already-running web service over HTTP (same server the web UI
uses), so it reuses its warm browser/mihomo instances instead of booting
its own for every invocation.

Examples:
    ./cli.py ip 8.8.8.8
    ./cli.py ip example.com --json
    ./cli.py node -f node.yaml                      # single or many nodes
    cat nodes.yaml | ./cli.py node                   # batch, piped in
    ./cli.py node "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, ... }"
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests

DEFAULT_URL = os.environ.get("IPDETECT_URL", "http://127.0.0.1:8000")

COLOR_BY_LABEL = {
    "极度纯净": "\033[32m",
    "纯净": "\033[32m",
    "中性": "\033[33m",
    "轻度风险": "\033[33m",
    "中度风险": "\033[38;5;208m",
    "极度风险": "\033[31m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def colorize(text: str, code: str) -> str:
    if not supports_color():
        return text
    return f"{code}{text}{RESET}"


def print_kv(rows: list[tuple[str, str]]):
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {k.ljust(width)} : {v}")


def print_ip_result(data: dict):
    label = data.get("ippure_label")
    color = COLOR_BY_LABEL.get(label, "") if label else ""
    score_display = data.get("ippure_raw") or "暂不可用"
    if color:
        score_display = colorize(score_display, color)

    print(colorize("IP 纯净度检测结果", BOLD))
    print_kv([
        ("输入", data.get("input", "-")),
        ("出口 IP", data.get("resolved_ip", "-")),
        ("IP 来源", data.get("ip_source") or "未知"),
        ("IP 属性", data.get("ip_attribute") or "未知"),
        ("IPPure 系数", score_display),
    ])


def print_node_result(data: dict):
    label = data.get("ippure_label")
    color = COLOR_BY_LABEL.get(label, "") if label else ""
    score_display = data.get("ippure_raw") or "暂不可用"
    if color:
        score_display = colorize(score_display, color)

    print(colorize("Clash 节点纯净度检测结果", BOLD))
    print_kv([
        ("节点名称", data.get("node_name") or "-"),
        ("协议类型", data.get("node_type") or "-"),
        ("节点服务器", f"{data.get('node_server')}:{data.get('node_port')}"),
        ("出口 IP", data.get("egress_ip", "-")),
        ("IP 来源", data.get("ip_source") or "未知"),
        ("IP 属性", data.get("ip_attribute") or "未知"),
        ("IPPure 系数", score_display),
    ])


def _truncate(s: str, width: int) -> str:
    return s if len(s) <= width else s[: width - 1] + "…"


def print_nodes_table(data: dict):
    results = data["results"]
    print(colorize(f"Clash 节点批量检测结果  ({data['success_count']}/{data['total']} 成功)", BOLD))
    print()

    cols = [
        ("节点名称", 22),
        ("协议", 8),
        ("出口 IP", 16),
        ("IP 来源", 10),
        ("IP 属性", 10),
        ("IPPure 系数", 14),
    ]
    header = "  ".join(_truncate(name, w).ljust(w) for name, w in cols)
    print(header)
    print("-" * len(header))

    for r in results:
        name = _truncate(r.get("node_name") or "-", cols[0][1])
        proto = _truncate(r.get("node_type") or "-", cols[1][1])
        if not r.get("success"):
            row = f"{name.ljust(cols[0][1])}  {proto.ljust(cols[1][1])}  " + colorize(
                _truncate("失败: " + (r.get("error") or "未知错误"), 60), "\033[31m"
            )
            print(row)
            continue

        ip = _truncate(r.get("egress_ip") or "-", cols[2][1])
        source = _truncate(r.get("ip_source") or "未知", cols[3][1])
        attr = _truncate(r.get("ip_attribute") or "未知", cols[4][1])
        score_display = r.get("ippure_raw") or "暂不可用"
        label = r.get("ippure_label")
        color = COLOR_BY_LABEL.get(label, "") if label else ""
        score_cell = colorize(_truncate(score_display, cols[5][1]), color) if color else _truncate(score_display, cols[5][1])

        row = "  ".join([
            name.ljust(cols[0][1]),
            proto.ljust(cols[1][1]),
            ip.ljust(cols[2][1]),
            source.ljust(cols[3][1]),
            attr.ljust(cols[4][1]),
            score_cell,
        ])
        print(row)


def request(url: str, path: str, payload: dict, timeout: float) -> dict:
    try:
        resp = requests.post(f"{url.rstrip('/')}{path}", json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError:
        print(
            f"错误: 无法连接到服务 {url}\n"
            f"请确认服务已启动（例如 docker compose up -d），或用 --url 指定正确地址。",
            file=sys.stderr,
        )
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"错误: 请求超时（{timeout}s）", file=sys.stderr)
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError:
        print(f"错误: 服务返回了非预期内容 (HTTP {resp.status_code})", file=sys.stderr)
        sys.exit(1)

    if not resp.ok:
        print(f"错误: {data.get('detail', resp.text)}", file=sys.stderr)
        sys.exit(1)

    return data


def cmd_ip(args):
    data = request(args.url, "/api/detect", {"target": args.target}, timeout=args.timeout)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_ip_result(data)


def cmd_node(args):
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.config:
        text = args.config
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print(
            "错误: 需要提供节点配置（位置参数 / -f 文件 / 标准输入管道三选一）",
            file=sys.stderr,
        )
        sys.exit(1)

    data = request(args.url, "/api/detect-nodes", {"nodes": text}, timeout=args.timeout)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif data["total"] == 1:
        result = data["results"][0]
        if not result.get("success"):
            print(f"错误: {result.get('error')}", file=sys.stderr)
            sys.exit(1)
        print_node_result(result)
    else:
        print_nodes_table(data)


def main():
    parser = argparse.ArgumentParser(
        prog="ipdetect",
        description="IP 纯净度检测命令行工具（连接到本地/远程运行中的检测服务）",
    )

    # --url/--json/--timeout must come after the subcommand, e.g.
    # `cli.py ip 8.8.8.8 --json` (argparse subparsers don't reliably merge
    # flags placed before the subcommand into the shared namespace).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=DEFAULT_URL, help=f"服务地址，默认 {DEFAULT_URL}（可用环境变量 IPDETECT_URL 设置）")
    common.add_argument("--json", action="store_true", help="输出原始 JSON 而非表格")
    common.add_argument("--timeout", type=float, default=180.0, help="请求超时时间（秒），默认 180（批量检测节点较慢，需要更长超时）")

    sub = parser.add_subparsers(dest="cmd", required=True)

    ip_p = sub.add_parser("ip", help="检测 IP 或域名的纯净度", parents=[common])
    ip_p.add_argument("target", help="IP 地址或域名")
    ip_p.set_defaults(func=cmd_ip)

    node_p = sub.add_parser("node", help="检测 Clash 节点出口 IP 的纯净度", parents=[common])
    node_p.add_argument("config", nargs="?", help="Clash 节点 YAML 文本")
    node_p.add_argument("-f", "--file", help="从文件读取节点配置")
    node_p.set_defaults(func=cmd_node)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
