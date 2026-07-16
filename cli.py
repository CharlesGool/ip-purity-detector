#!/usr/bin/env python3
"""Command-line client for the IP purity detector service.

Talks to the already-running web service over HTTP (same server the web UI
uses), so it reuses its warm browser/mihomo instances instead of booting
its own for every invocation.

Examples:
    ./cli.py ip 8.8.8.8
    ./cli.py ip example.com --json
    ./cli.py ip "8.8.8.8, example.com"               # batch, comma-separated
    ./cli.py ip -f targets.txt                       # batch, one per line
    ./cli.py node -f node.yaml                      # single or many nodes
    cat nodes.yaml | ./cli.py node                   # batch, piped in
    ./cli.py node "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, ... }"
"""
import argparse
import json
import os
import re
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


def _detail_rows(data: dict) -> list[tuple[str, str]]:
    """Rows shared by the single IP result and single node result views:
    ASN/位置/人机流量比/两个系数/WebRTC 泄露, mirroring ippure.com's own layout."""
    rows = []

    asn = data.get("asn")
    if asn:
        rows.append(("ASN", asn))
    if data.get("as_domain"):
        rows.append(("AS域名", data["as_domain"]))
    if data.get("ip_range"):
        rows.append(("IP范围", data["ip_range"]))
    if data.get("human_pct") is not None or data.get("bot_pct") is not None:
        h = data.get("human_pct")
        b = data.get("bot_pct")
        rows.append((
            "人机流量比",
            f"human {h}% / bot {b}%" if h is not None and b is not None else "-",
        ))

    for source, loc in (data.get("locations") or {}).items():
        rows.append((f"位置({source})", loc))

    rows.append(("IP 来源", data.get("ip_source") or "未知"))
    rows.append(("IP 属性", data.get("ip_attribute") or "未知"))

    label = data.get("ippure_label")
    color = COLOR_BY_LABEL.get(label, "") if label else ""
    score_display = data.get("ippure_raw") or "暂不可用"
    rows.append(("IPPure 系数", colorize(score_display, color) if color else score_display))

    cf_label = data.get("cloudflare_label")
    cf_color = COLOR_BY_LABEL.get(cf_label, "") if cf_label else ""
    cf_display = data.get("cloudflare_raw") or "暂不可用"
    rows.append(("Cloudflare 系数", colorize(cf_display, cf_color) if cf_color else cf_display))

    leak = data.get("webrtc_leak") or {}
    if leak.get("leaked") is True:
        leak_display = colorize(f"泄露 -> {leak.get('ip') or '?'} ({leak.get('location') or '未知位置'})", "\033[31m")
    elif leak.get("leaked") is False:
        leak_display = colorize("未检测到泄露", "\033[32m")
    else:
        leak_display = leak.get("error") or "未检测"
    rows.append(("WebRTC 泄露", leak_display))

    return rows


def print_ip_result(data: dict):
    print(colorize("IP 纯净度检测结果", BOLD))
    print_kv([
        ("输入", data.get("input", "-")),
        ("出口 IP", data.get("resolved_ip", "-")),
        *_detail_rows(data),
    ])


def print_node_result(data: dict):
    print(colorize("Clash 节点纯净度检测结果", BOLD))
    print_kv([
        ("节点名称", data.get("node_name") or "-"),
        ("协议类型", data.get("node_type") or "-"),
        ("节点服务器", f"{data.get('node_server')}:{data.get('node_port')}"),
        ("出口 IP", data.get("egress_ip", "-")),
        *_detail_rows(data),
    ])


def print_nodes_table(data: dict):
    results = data["results"]
    print(colorize(f"Clash 节点批量检测结果  ({data['success_count']}/{data['total']} 成功)", BOLD))

    for i, r in enumerate(results, 1):
        print()
        print(colorize(f"[{i}/{len(results)}] {r.get('node_name') or '-'}", BOLD))
        if not r.get("success"):
            print(colorize(f"  失败: {r.get('error') or '未知错误'}", "\033[31m"))
            continue

        print_kv([
            ("协议类型", r.get("node_type") or "-"),
            ("节点服务器", f"{r.get('node_server')}:{r.get('node_port')}"),
            ("出口 IP", r.get("egress_ip", "-")),
            *_detail_rows(r),
        ])


def print_targets_table(data: dict):
    results = data["results"]
    print(colorize(f"IP / 域名批量检测结果  ({data['success_count']}/{data['total']} 成功)", BOLD))

    for i, r in enumerate(results, 1):
        print()
        print(colorize(f"[{i}/{len(results)}] {r.get('input') or '-'}", BOLD))
        if not r.get("success"):
            print(colorize(f"  失败: {r.get('error') or '未知错误'}", "\033[31m"))
            continue

        print_kv([
            ("出口 IP", r.get("resolved_ip", "-")),
            *_detail_rows(r),
        ])


def render_progress(done: int, total: int):
    """Draw an in-place progress bar on stderr (stdout is reserved for the
    table/JSON output), so batches don't sit silent for the whole run."""
    if not total or not sys.stderr.isatty():
        return
    width = 30
    pct = max(0, min(1, done / total))
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    sys.stderr.write(f"\r检测进度 [{bar}] {done}/{total}")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\n")
        sys.stderr.flush()


def request_stream(url: str, path: str, payload: dict, timeout: float, on_progress=None) -> dict:
    """POST to a streaming NDJSON endpoint, calling on_progress(done, total)
    for each progress line, and returning the final `done` event's payload
    (same shape as the non-streaming batch endpoints)."""
    try:
        resp = requests.post(f"{url.rstrip('/')}{path}", json=payload, timeout=timeout, stream=True)
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

    if not resp.ok:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        print(f"错误: {detail}", file=sys.stderr)
        sys.exit(1)

    final = None
    try:
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            event = json.loads(line)
            if event.get("type") == "progress":
                if on_progress:
                    on_progress(event.get("done", 0), event.get("total", 0))
            elif event.get("type") == "done":
                final = {k: v for k, v in event.items() if k != "type"}
    except requests.exceptions.ChunkedEncodingError as e:
        print(f"错误: 连接中断: {e}", file=sys.stderr)
        sys.exit(1)

    if final is None:
        print("错误: 服务未返回完整结果", file=sys.stderr)
        sys.exit(1)
    return final


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
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.target:
        text = args.target
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print(
            "错误: 需要提供 IP/域名（位置参数 / -f 文件 / 标准输入管道三选一）",
            file=sys.stderr,
        )
        sys.exit(1)

    targets = [t.strip() for t in re.split(r"[\n,，]+", text) if t.strip()]
    if not targets:
        print("错误: 未解析出任何 IP/域名", file=sys.stderr)
        sys.exit(1)

    if len(targets) == 1:
        data = request(args.url, "/api/detect", {"target": targets[0]}, timeout=args.timeout)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_ip_result(data)
    else:
        data = request_stream(
            args.url, "/api/detect-batch-stream", {"targets": text},
            timeout=args.timeout, on_progress=render_progress,
        )
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_targets_table(data)


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

    data = request_stream(
        args.url, "/api/detect-nodes-stream", {"nodes": text},
        timeout=args.timeout, on_progress=render_progress,
    )
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

    ip_p = sub.add_parser("ip", help="检测 IP 或域名的纯净度（支持逗号/换行分隔的多个目标）", parents=[common])
    ip_p.add_argument("target", nargs="?", help="IP 地址或域名，多个用逗号或换行分隔")
    ip_p.add_argument("-f", "--file", help="从文件读取 IP/域名列表")
    ip_p.set_defaults(func=cmd_ip)

    node_p = sub.add_parser("node", help="检测 Clash 节点出口 IP 的纯净度", parents=[common])
    node_p.add_argument("config", nargs="?", help="Clash 节点 YAML 文本")
    node_p.add_argument("-f", "--file", help="从文件读取节点配置")
    node_p.set_defaults(func=cmd_node)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
