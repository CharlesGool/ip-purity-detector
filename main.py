import asyncio
import ipaddress
import re
import socket
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from playwright.async_api import async_playwright, Browser, Playwright

import clash_probe

IPPURE_URL = "https://ippure.com/?ip={ip}"
IPPURE_HOME_URL = "https://ippure.com/"
NAV_TIMEOUT_MS = 20000
SELECTOR_TIMEOUT_MS = 15000
MAX_CONCURRENCY = 3
MAX_RETRIES = 2
MAX_NODE_CONCURRENCY = 2
MAX_BATCH_TARGETS = 1000
WEBRTC_CHECK_TIMEOUT_MS = 15000

# Resource types that only slow down the page without affecting the
# text content we scrape (map tiles, ad images, fonts, etc).
BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}

# Shared helpers used by both extraction scripts below. ippure's detail
# table mixes two DOM shapes: a `.info-key` <span> sitting next to its
# `.info-value` sibling (IP来源/IP属性), and a `.info-key` <div> whose
# *entire value block* is the next sibling element (位置/泄露检测/the two
# colormap score bars). scoreFor/asnInfo/locations/webrtcLeak below each
# target one of those shapes.
_JS_HELPERS = """
    function textOf(el) {
        return el ? el.textContent.replace(/\\s+/g, ' ').trim() : null;
    }
    function findKey(label) {
        return Array.from(document.querySelectorAll('.info-key'))
            .find(el => el.textContent.trim() === label) || null;
    }
    function simpleValue(label) {
        const key = findKey(label);
        if (!key) return null;
        const valueEl = key.parentElement.querySelector('.info-value');
        return valueEl ? textOf(valueEl) : null;
    }
    function scoreFor(label) {
        const key = findKey(label);
        if (!key) return null;
        const container = key.parentElement.nextElementSibling;
        if (!container) return null;
        const valEl = container.querySelector('.colormap-indicator-value');
        return valEl ? textOf(valEl) : null;
    }
    function asnInfo() {
        const key = findKey('ASN');
        if (!key) return {};
        const row = key.parentElement;
        const mainVal = row.querySelector('.info-value');
        const sub = {};
        row.querySelectorAll('.ip-subtitle').forEach((subKey) => {
            const label = textOf(subKey);
            const valEl = subKey.parentElement.querySelector('.info-value');
            sub[label] = valEl ? textOf(valEl) : null;
        });
        return {
            asn: mainVal ? textOf(mainVal) : null,
            as_domain: sub['AS域名'] || null,
            ip_range: sub['IP范围'] || null,
            bot_ratio_raw: sub['人机流量比'] || null,
        };
    }
    function locations() {
        const key = findKey('位置');
        if (!key) return {};
        const container = key.nextElementSibling;
        const out = {};
        if (container) {
            Array.from(container.children).forEach((row) => {
                const src = row.querySelector && row.querySelector('.geo-source');
                const val = row.querySelector && row.querySelector('.info-value');
                if (src && val) out[textOf(src)] = textOf(val);
            });
        }
        return out;
    }
    function webrtcLeak() {
        const key = findKey('泄露检测');
        if (!key) return null;
        const container = key.nextElementSibling;
        if (!container) return null;
        const row = Array.from(container.children).find((r) => {
            const src = r.querySelector && r.querySelector('.geo-source');
            return src && textOf(src) === 'WebRTC泄露';
        });
        if (!row) return null;
        const values = Array.from(row.querySelectorAll('.info-value')).map(textOf).filter(Boolean);
        if (values.length === 0 || values[0].includes('未检测到')) {
            return { leaked: false, ip: null, location: null };
        }
        return { leaked: true, ip: values[0] || null, location: values[1] || null };
    }
"""

# Full detail-table extraction: IP来源/IP属性/IPPure系数 plus everything
# revealed by the "显示扩展" toggle (ASN/AS域名/IP范围/人机流量比, the
# per-provider 位置 table, Cloudflare系数, and the WebRTC leak check).
EXTRACT_JS = (
    "() => {"
    + _JS_HELPERS
    + """
    const asn = asnInfo();
    return {
        source: simpleValue('IP来源'),
        attribute: simpleValue('IP属性'),
        scoreText: scoreFor('IPPure系数'),
        cloudflareScoreText: scoreFor('Cloudflare系数'),
        asn: asn.asn,
        as_domain: asn.as_domain,
        ip_range: asn.ip_range,
        bot_ratio_raw: asn.bot_ratio_raw,
        locations: locations(),
        webrtcLeak: webrtcLeak(),
    };
}
"""
)

# Narrow extraction used for the tunnel-routed node WebRTC leak check: we
# only care whether browsing through the node's proxy leaks a real IP.
WEBRTC_LEAK_JS = "() => {" + _JS_HELPERS + "return webrtcLeak();}"

_state: dict = {"playwright": None, "browser": None}
_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
_node_semaphore = asyncio.Semaphore(MAX_NODE_CONCURRENCY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pw: Playwright = await async_playwright().start()
    browser: Browser = await pw.chromium.launch(
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            # Without a configured proxy this blocks WebRTC from leaking our
            # own server's IP on plain (non-tunneled) lookups. With a
            # per-context SOCKS5 proxy (node WebRTC leak check below) it
            # forces WebRTC media to go through that proxy instead of
            # bypassing it over a direct UDP interface, which is the whole
            # point of testing for a leak.
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]
    )
    _state["playwright"] = pw
    _state["browser"] = browser
    yield
    await browser.close()
    await pw.stop()


app = FastAPI(title="IP Pure Detector", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class DetectRequest(BaseModel):
    target: str


class DetectBatchRequest(BaseModel):
    targets: str


class NodeDetectRequest(BaseModel):
    node: str


class NodesDetectRequest(BaseModel):
    nodes: str


def resolve_to_ip(target: str) -> str:
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"无法解析域名: {target}")

    if not infos:
        raise HTTPException(status_code=400, detail=f"无法解析域名: {target}")

    # Prefer IPv4 results, fall back to whatever was returned first.
    for family_pref in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family_pref:
                return info[4][0]
    return infos[0][4][0]


def parse_targets(raw: str) -> list:
    """Split pasted IP/domain text into individual targets. Accepts one per
    line, comma-separated (half- or full-width), or a mix of both."""
    raw = (raw or "").strip()
    if not raw:
        return []
    parts = re.split(r"[\n,，]+", raw)
    return [p.strip() for p in parts if p.strip()]


async def _block_heavy_resources(route):
    if route.request.resource_type in BLOCKED_RESOURCE_TYPES:
        await route.abort()
    else:
        await route.continue_()


async def fetch_purity(ip: str) -> dict:
    browser: Browser = _state["browser"]
    async with _semaphore:
        context = await browser.new_context(locale="zh-CN")
        try:
            page = await context.new_page()
            await page.route("**/*", _block_heavy_resources)
            await page.goto(
                IPPURE_URL.format(ip=ip),
                timeout=NAV_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            # IP来源/IP属性 always render once the main lookup resolves. The
            # IPPure系数 bar depends on extra geo/bot APIs that can fail for
            # some inputs (e.g. IPv6 hits CORS errors on their end) and never
            # appear, so it's waited for separately and treated as optional.
            await page.wait_for_function(
                """
                () => {
                    const keys = Array.from(document.querySelectorAll('.info-key'));
                    const key = keys.find(el => el.textContent.trim() === 'IP来源');
                    return !!(key && key.parentElement.querySelector('.info-value')
                        && key.parentElement.querySelector('.info-value').textContent.trim());
                }
                """,
                timeout=SELECTOR_TIMEOUT_MS,
            )
            try:
                await page.wait_for_selector(".colormap-indicator-value", timeout=5000)
            except Exception:
                pass
            # Cloudflare系数/位置详情/泄露检测 sit behind a "显示扩展" toggle.
            # Best-effort: a missing/unclickable button just means those
            # fields come back empty, same as any other optional field.
            try:
                await page.click(".expand-btn-container", timeout=3000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass
            return await page.evaluate(EXTRACT_JS)
        finally:
            await context.close()


def parse_score(score_text: Optional[str]):
    if not score_text:
        return None, None
    m = re.match(r"(\d+)%\s*(.*)", score_text)
    if not m:
        return None, score_text
    return int(m.group(1)), m.group(2).strip()


def parse_bot_ratio(raw: Optional[str]):
    if not raw:
        return None, None
    hm = re.search(r"human\s*([\d.]+)%", raw)
    bm = re.search(r"bot\s*([\d.]+)%", raw)
    human = float(hm.group(1)) if hm else None
    bot = float(bm.group(1)) if bm else None
    return human, bot


def build_detail_fields(data: dict) -> dict:
    """Map raw scraped ippure fields onto the API's response shape. Shared
    by /api/detect and node detection since both go through fetch_purity."""
    score, label = parse_score(data.get("scoreText"))
    cf_score, cf_label = parse_score(data.get("cloudflareScoreText"))
    human_pct, bot_pct = parse_bot_ratio(data.get("bot_ratio_raw"))
    return {
        "ip_source": data.get("source"),
        "ip_attribute": data.get("attribute"),
        "ippure_score": score,
        "ippure_label": label,
        "ippure_raw": data.get("scoreText"),
        "cloudflare_score": cf_score,
        "cloudflare_label": cf_label,
        "cloudflare_raw": data.get("cloudflareScoreText"),
        "asn": data.get("asn"),
        "as_domain": data.get("as_domain"),
        "ip_range": data.get("ip_range"),
        "human_pct": human_pct,
        "bot_pct": bot_pct,
        "locations": data.get("locations") or {},
    }


async def check_node_webrtc_leak(mixed_port: int) -> dict:
    """Browse through the node's own local proxy port and see whether
    WebRTC leaks a real IP instead of staying inside the tunnel. Routed
    through a per-context SOCKS5 proxy so mihomo (with udp: true on the
    node) can relay the STUN traffic; the browser-wide
    disable_non_proxied_udp policy (see lifespan) stops WebRTC from just
    going out directly and bypassing the tunnel."""
    browser: Browser = _state["browser"]
    try:
        context = await browser.new_context(
            locale="zh-CN",
            proxy={"server": f"socks5://127.0.0.1:{mixed_port}"},
        )
    except Exception as e:  # noqa: BLE001 - surfaced to the client as "unknown"
        return {"leaked": None, "error": f"无法创建代理浏览器上下文: {e}"}

    try:
        page = await context.new_page()
        await page.route("**/*", _block_heavy_resources)
        await page.goto(
            IPPURE_HOME_URL,
            timeout=WEBRTC_CHECK_TIMEOUT_MS,
            wait_until="domcontentloaded",
        )
        await page.wait_for_selector(".info-key", timeout=WEBRTC_CHECK_TIMEOUT_MS)
        try:
            await page.click(".expand-btn-container", timeout=3000)
        except Exception:
            pass
        await page.wait_for_timeout(2500)
        result = await page.evaluate(WEBRTC_LEAK_JS)
        return result if result is not None else {"leaked": None}
    except Exception as e:  # noqa: BLE001 - best-effort, never fails the node probe
        return {"leaked": None, "error": f"WebRTC 泄露检测失败: {e}"}
    finally:
        await context.close()


async def get_purity_with_retry(ip: str) -> dict:
    last_error: Optional[Exception] = None
    data = None
    for _ in range(MAX_RETRIES):
        try:
            data = await fetch_purity(ip)
            if data.get("source") or data.get("attribute") or data.get("scoreText"):
                break
        except Exception as e:  # noqa: BLE001 - surfaced to the client below
            last_error = e
            data = None

    if not data or not (data.get("source") or data.get("attribute") or data.get("scoreText")):
        detail = f"检测失败: {last_error}" if last_error else "未能获取检测结果，请稍后重试"
        raise HTTPException(status_code=502, detail=detail)

    return data


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/detect")
async def detect(req: DetectRequest):
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="请输入IP或域名")

    ip = resolve_to_ip(req.target)
    data = await get_purity_with_retry(ip)

    return {
        "input": req.target.strip(),
        "resolved_ip": ip,
        **build_detail_fields(data),
        # Reflects our own server's browsing path (no proxy configured on
        # this context), not the queried IP itself — see check_node_webrtc_leak
        # for the version that actually matters, tunneled through a node.
        "webrtc_leak": data.get("webrtcLeak"),
    }


async def _detect_single_target(target: str) -> dict:
    base = {"input": target}
    try:
        ip = resolve_to_ip(target)
    except HTTPException as e:
        return {**base, "success": False, "error": str(e.detail)}

    base["resolved_ip"] = ip

    try:
        data = await get_purity_with_retry(ip)
    except HTTPException as e:
        return {**base, "success": False, "error": str(e.detail)}

    return {
        **base,
        "success": True,
        **build_detail_fields(data),
        "webrtc_leak": data.get("webrtcLeak"),
    }


@app.post("/api/detect-batch")
async def detect_batch(req: DetectBatchRequest):
    targets = parse_targets(req.targets)
    if not targets:
        raise HTTPException(status_code=400, detail="请输入至少一个 IP 或域名（支持换行或逗号分隔）")
    if len(targets) > MAX_BATCH_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"一次最多支持检测 {MAX_BATCH_TARGETS} 个（本次输入了 {len(targets)} 个）",
        )

    results = await asyncio.gather(*(_detect_single_target(t) for t in targets))
    return {
        "total": len(results),
        "success_count": sum(1 for r in results if r.get("success")),
        "results": results,
    }


async def _detect_single_node(node: dict) -> dict:
    base = {
        "node_name": node.get("name"),
        "node_type": node.get("type"),
        "node_server": node.get("server"),
        "node_port": node.get("port"),
    }

    async with _node_semaphore:
        try:
            handle = await asyncio.to_thread(clash_probe.start_node_proxy, node)
        except clash_probe.NodeProbeError as e:
            return {**base, "success": False, "error": str(e)}

        try:
            try:
                probe = await asyncio.to_thread(clash_probe.fetch_egress_ip, handle, node)
            except clash_probe.NodeProbeError as e:
                return {**base, "success": False, "error": str(e)}

            ip = probe["egress_ip"]
            base["node_name"] = probe.get("node_name")
            base["egress_ip"] = ip

            try:
                data = await get_purity_with_retry(ip)
            except HTTPException as e:
                return {**base, "success": False, "error": str(e.detail)}

            webrtc_leak = await check_node_webrtc_leak(handle.mixed_port)
        finally:
            await asyncio.to_thread(handle.close)

    return {
        **base,
        "success": True,
        **build_detail_fields(data),
        "webrtc_leak": webrtc_leak,
    }


@app.post("/api/detect-node")
async def detect_node(req: NodeDetectRequest):
    try:
        node = clash_probe.parse_node(req.node)
    except clash_probe.NodeProbeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await _detect_single_node(node)
    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "检测失败"))
    return result


@app.post("/api/detect-nodes")
async def detect_nodes(req: NodesDetectRequest):
    try:
        nodes = clash_probe.parse_nodes(req.nodes)
    except clash_probe.NodeProbeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    results = await asyncio.gather(*(_detect_single_node(n) for n in nodes))
    return {
        "total": len(results),
        "success_count": sum(1 for r in results if r.get("success")),
        "results": results,
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")
