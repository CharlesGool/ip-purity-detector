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
NAV_TIMEOUT_MS = 20000
SELECTOR_TIMEOUT_MS = 15000
MAX_CONCURRENCY = 3
MAX_RETRIES = 2
MAX_NODE_CONCURRENCY = 2

# Resource types that only slow down the page without affecting the
# text content we scrape (map tiles, ad images, fonts, etc).
BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}

EXTRACT_JS = """
() => {
    function infoValue(label) {
        const keys = Array.from(document.querySelectorAll('.info-key'));
        const key = keys.find(el => el.textContent.trim() === label);
        if (!key) return null;
        const row = key.parentElement;
        const valueEl = row.querySelector('.info-value');
        return valueEl ? valueEl.textContent.trim() : null;
    }
    const scoreEl = document.querySelector('.colormap-indicator-value');
    return {
        source: infoValue('IP来源'),
        attribute: infoValue('IP属性'),
        scoreText: scoreEl ? scoreEl.textContent.trim() : null,
    };
}
"""

_state: dict = {"playwright": None, "browser": None}
_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
_node_semaphore = asyncio.Semaphore(MAX_NODE_CONCURRENCY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pw: Playwright = await async_playwright().start()
    browser: Browser = await pw.chromium.launch(
        args=["--no-sandbox", "--disable-dev-shm-usage"]
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
    score, label = parse_score(data.get("scoreText"))

    return {
        "input": req.target.strip(),
        "resolved_ip": ip,
        "ip_source": data.get("source"),
        "ip_attribute": data.get("attribute"),
        "ippure_score": score,
        "ippure_label": label,
        "ippure_raw": data.get("scoreText"),
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
            probe = await asyncio.to_thread(clash_probe.probe_node_egress_ip, node)
        except clash_probe.NodeProbeError as e:
            return {**base, "success": False, "error": str(e)}

    ip = probe["egress_ip"]
    base["node_name"] = probe.get("node_name")
    base["egress_ip"] = ip

    try:
        data = await get_purity_with_retry(ip)
    except HTTPException as e:
        return {**base, "success": False, "error": str(e.detail)}

    score, label = parse_score(data.get("scoreText"))
    return {
        **base,
        "success": True,
        "ip_source": data.get("source"),
        "ip_attribute": data.get("attribute"),
        "ippure_score": score,
        "ippure_label": label,
        "ippure_raw": data.get("scoreText"),
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
