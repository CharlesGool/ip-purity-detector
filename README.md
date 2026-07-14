# IP 纯净度检测

输入 IP / 域名 / Clash 代理节点配置，检测其出口 IP 的纯净度。驱动一个真实的无头浏览器打开
`https://ippure.com/?ip=x.x.x.x`，抓取页面上的三项结果：

- **IP 来源**
- **IP 属性**
- **IPPure 系数**

支持三种使用方式：Web UI、HTTP API、命令行工具（`cli.py`）。

## 为什么用无头浏览器而不是直接调用接口

ippure.com 的数据接口做了签名/加密（HMAC + AES）防止被脚本直接调用，且逻辑在混淆过的前端
JS 里，逆向成本高、还会随对方前端更新随时失效。本工具改为像真实用户一样用 Chromium 打开
页面、等待其自身发起请求渲染完成后，再从固定的 CSS class（`info-key` / `info-value` /
`colormap-indicator-value`）里读取结果，稳定性和可维护性都更好。

## Clash 节点检测是怎么做的

同样不重新实现 VLESS / Trojan / Reality 等各种协议——那样既复杂又脆弱。而是直接调用
[mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta 换皮后的正式名字，协议支持最全、
更新最活跃的开源 Clash 内核）：

1. 把粘贴进来的单个节点配置包进一个临时的 mihomo 配置文件，起一个本地混合代理端口；
2. 通过这个本地端口访问一个 IP 回显服务（`api.ipify.org` 等），得到的就是流量真正从这个节点
   出去时对外呈现的公网 IP；
3. 把这个出口 IP 丢进和上面一样的 ippure.com 检测流程；
4. 检测完立刻杀掉这个 mihomo 子进程、清理临时目录。

这样理论上 mihomo 支持的所有协议（vless/vmess/trojan/ss/hysteria2/reality/...）都能直接用，
不需要我们逐个协议维护解析逻辑。

## 本机运行（已部署）

代码在 `/root/ipdetect/`，已用 Docker 构建验证可用。默认监听 `8000` 端口。

```bash
cd /root/ipdetect
docker compose up -d --build
```

打开浏览器访问 `http://<本机IP>:8000` 即可使用。

## 部署到其他电脑

只需要目标机器装有 Docker（含 `docker compose`），把 `/root/ipdetect` 整个目录拷贝过去，
不需要额外安装 Python、浏览器或任何依赖——都在镜像构建时自动装好。

```bash
# 把目录拷到目标机器后
cd ipdetect
docker compose up -d --build
```

默认对外暴露 `8000` 端口，如需换端口修改 `docker-compose.yml` 里的 `ports` 映射，例如
`"9000:8000"`。

### 不用 Docker，直接跑（不推荐，但可行）

```bash
cd ipdetect
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install --with-deps chromium   # 自动装浏览器及系统依赖
scripts/fetch_mihomo.sh ./bin/mihomo      # 装 mihomo，用于检测 Clash 节点
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 命令行工具

`cli.py` 是个瘦客户端，通过 HTTP 连接到已经在跑的服务（本机或远程都行），复用服务里已经
热好的浏览器/mihomo，不用每次都重新起一遍。

```bash
# 装依赖（如果不在 venv 里，至少需要 requests）
pip install requests

# 检测 IP / 域名
python3 cli.py ip 8.8.8.8
python3 cli.py ip example.com --json          # 输出原始 JSON

# 检测 Clash 节点（三种传参方式任选）
python3 cli.py node "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, ... }"
python3 cli.py node -f node.yaml
cat node.yaml | python3 cli.py node

# 连接远程部署的服务
python3 cli.py ip 8.8.8.8 --url http://192.168.1.10:8000
# 或者：export IPDETECT_URL=http://192.168.1.10:8000
```

注意 `--url` / `--json` / `--timeout` 这些参数要放在子命令（`ip`/`node`）**后面**，
例如 `cli.py ip 8.8.8.8 --json` 可以，`cli.py --json ip 8.8.8.8` 不行。

## 接口说明

### 检测 IP / 域名

```
POST /api/detect
Content-Type: application/json

{ "target": "8.8.8.8" }        // 或域名，如 "example.com"
```

返回：

```json
{
  "input": "8.8.8.8",
  "resolved_ip": "8.8.8.8",
  "ip_source": "原生IP",
  "ip_attribute": "机房IP",
  "ippure_score": 7,
  "ippure_label": "极度纯净",
  "ippure_raw": "7% 极度纯净"
}
```

- `resolved_ip`：输入若为域名，这里是 DNS 解析出的出口 IP；输入本身是 IP 则原样返回。
- 个别 IPv6 地址上，ippure.com 自身的地理/风控接口会跨域失败，导致纯净度系数这部分
  渲染不出来；此时 `ippure_score`/`ippure_label`/`ippure_raw` 会是 `null`，但
  `ip_source`/`ip_attribute` 仍正常返回。前端会显示为“暂不可用”。

### 检测 Clash 节点

```
POST /api/detect-node
Content-Type: application/json

{ "node": "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, uuid: ..., ... }" }
```

`node` 字段可以是：单个节点的 flow-style YAML（如上）、多行 YAML 节点、或者一整份包含
`proxies:` 列表的 Clash 配置（此时只探测第一个节点）。

返回：

```json
{
  "node_name": "sg",
  "node_type": "vless",
  "node_server": "1.2.3.4",
  "node_port": 443,
  "egress_ip": "185.xx.xx.xx",
  "ip_source": "原生IP",
  "ip_attribute": "机房IP",
  "ippure_score": 12,
  "ippure_label": "纯净",
  "ippure_raw": "12% 纯净"
}
```

若节点连不通（服务器不可达、握手失败、协议参数缺失等），会返回 502，`detail` 里带上
mihomo 自身报出的具体原因，例如：

```json
{ "detail": "无法通过该节点访问外网: [TCP] dial PROXY ... connect error: context deadline exceeded" }
```

## 已知限制

- 依赖 ippure.com 的可用性和页面结构，如果对方大改版（class 名变化）需要同步更新
  `main.py` 里 `EXTRACT_JS` 的选择器。
- 默认最多 3 个请求并发跑浏览器（`MAX_CONCURRENCY`），最多 2 个并发跑节点探测
  （`MAX_NODE_CONCURRENCY`），避免机器资源被打满；如需调高，改 `main.py` 顶部的常量。
- 单次 IP/域名检测耗时约 3～5 秒，节点检测因为要等真实握手/超时，耗时可能到 10～20 秒，
  都属正常现象。
- Clash 节点检测只探测输入里的第一个节点，不会批量跑一整份订阅。
