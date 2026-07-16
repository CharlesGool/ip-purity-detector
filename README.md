# IP 纯净度检测

输入 IP / 域名 / Clash 代理节点配置，检测其出口 IP 的纯净度。驱动一个真实的无头浏览器打开
`https://ippure.com/?ip=x.x.x.x`，抓取页面上完整的一份报告（和 ippure.com 网页本身展示的
内容对齐）：

- **ASN / AS域名 / IP范围 / 人机流量比**
- **位置**：Cloudflare / IP2Location / DB-IP / MaxMind / IPInfo.io / Bilibili 等各家的地理位置判断
- **IP 来源**、**IP 属性**
- **IPPure 系数**、**Cloudflare 系数**（两套风险打分）
- **WebRTC 泄露检测**

支持三种使用方式：Web UI、HTTP API、命令行工具（`cli.py`），且 IP/域名、Clash 节点都支持
单个查询和批量查询（最多各 1000 个），批量时每一项返回的信息和单个查询完全一样多。批量查询
时 Web UI 和 CLI 都会实时显示进度条（已完成/总数），不用干等到全部跑完才有反馈。

## 为什么用无头浏览器而不是直接调用接口

ippure.com 的数据接口做了签名/加密（HMAC + AES）防止被脚本直接调用，且逻辑在混淆过的前端
JS 里，逆向成本高、还会随对方前端更新随时失效。本工具改为像真实用户一样用 Chromium 打开
页面、等待其自身发起请求渲染完成、点开页面上的「显示扩展」按钮，再从固定的 CSS class
（`info-key` / `info-value` / `colormap-indicator-value` / `geo-source` / `ip-subtitle`
等）里读取结果，稳定性和可维护性都比逆向接口好。

## Clash 节点检测是怎么做的

同样不重新实现 VLESS / Trojan / Reality 等各种协议——那样既复杂又脆弱。而是直接调用
[mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta 换皮后的正式名字，协议支持最全、
更新最活跃的开源 Clash 内核）：

1. 把粘贴进来的单个节点配置包进一个临时的 mihomo 配置文件，起一个本地混合代理端口；
2. 通过这个本地端口访问一个 IP 回显服务（`api.ipify.org` 等），得到的就是流量真正从这个节点
   出去时对外呈现的公网 IP；
3. 把这个出口 IP 丢进和上面一样的 ippure.com 检测流程；
4. 额外用一个配置了该节点本地代理端口（SOCKS5）的浏览器上下文访问 ippure.com，专门检测这个
   节点的隧道本身是否会被 WebRTC 绕过而泄露真实 IP（`disable_non_proxied_udp` 策略强制
   WebRTC 走配置的代理，不走则视为没有可用的代理通道，不会误报泄露）；
5. 检测完立刻杀掉这个 mihomo 子进程、清理临时目录。

这样理论上 mihomo 支持的所有协议（vless/vmess/trojan/ss/hysteria2/reality/anytls/...）都能
直接用，不需要我们逐个协议维护解析逻辑。

节点解析对粘贴格式有一定容错：优先按标准 YAML 解析，如果因为缩进不规范（比如把多个不同来源、
不同缩进习惯的节点粘到一起）导致解析失败，会自动退化为逐个提取 `{ ... }` 这样的 flow-style
节点单独解析，不需要手动整理缩进。

## 本机运行（已部署）

代码在 `/root/ipdetect/`，已用 Docker 构建验证可用。默认监听 `8000` 端口。

```bash
cd /root/ipdetect
docker compose up -d --build
```

打开浏览器访问 `http://<本机IP>:8000` 即可使用。

## 在一台全新的 Linux 电脑上从零部署

假设是一台干净的服务器/虚拟机（以 Ubuntu/Debian 为例），既没装 Docker，也没有这份代码，
从头走一遍：

### 1. 装 Docker

用官方安装脚本，主流发行版（Ubuntu/Debian/CentOS/Fedora 等）通用：

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
```

验证装好了、且自带新版 `docker compose`（不是老的独立 `docker-compose` 命令）：

```bash
docker --version
docker compose version
```

如果 `docker compose version` 报"找不到命令"，说明装的版本没带 compose 插件，参考
[Docker 官方文档](https://docs.docker.com/compose/install/) 单独装一下。

（可选）把当前用户加进 `docker` 组，之后就不用每条命令都 `sudo`：

```bash
sudo usermod -aG docker $USER
newgrp docker   # 或者退出重新登录一次让分组生效
```

### 2. 从 GitHub 拉代码

大多数发行版自带 `git`，没有的话先装一下（`sudo apt install -y git` 或对应发行版的包管理器）：

```bash
git clone https://github.com/CharlesGool/ip-purity-detector.git
cd ip-purity-detector
```

### 3. 构建并启动

```bash
docker compose up -d --build
```

首次构建会在镜像里自动装好 Chromium（Playwright）和 mihomo，不需要额外操作，看网速可能要
几分钟。

### 4. 访问

浏览器打开 `http://<这台服务器的IP>:8000`。如果是云服务器，记得在安全组/防火墙（`ufw` 等）
里放行 `8000` 端口；如果不想直接暴露这个端口，可以把 `docker-compose.yml` 里的 `ports`
改成只绑本机（`"127.0.0.1:8000:8000"`），再自行套一层反向代理。

### 5. 常用运维命令

```bash
docker compose logs -f          # 看实时日志
docker compose ps               # 看容器状态
docker compose down             # 停止服务（不会删代码或镜像）
```

以后更新代码：

```bash
git pull
docker compose up -d --build    # 重新构建镜像并重启容器
```

### 换一个端口

默认对外暴露 `8000` 端口，如需换端口，改 `docker-compose.yml` 里的 `ports` 映射，例如把
`"8000:8000"` 改成 `"9000:8000"`（宿主机 9000 端口对外，容器内部仍是 8000）。

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

# 检测 IP / 域名（单个）
python3 cli.py ip 8.8.8.8
python3 cli.py ip example.com --json          # 输出原始 JSON

# 检测 IP / 域名（批量，一行一个或逗号分隔，三种传参方式任选）
python3 cli.py ip "8.8.8.8, example.com, 1.1.1.1"
python3 cli.py ip -f targets.txt              # 文件里一行一个
cat targets.txt | python3 cli.py ip           # 管道输入

# 检测 Clash 节点（单个或批量都行，三种传参方式任选）
python3 cli.py node "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, ... }"
python3 cli.py node -f nodes.yaml          # 文件里可以是一个节点，也可以是一整份节点列表
cat nodes.yaml | python3 cli.py node       # 批量、单个都会走完整详情视图，只是批量会挨个打印

# 连接远程部署的服务
python3 cli.py ip 8.8.8.8 --url http://192.168.1.10:8000
# 或者：export IPDETECT_URL=http://192.168.1.10:8000
```

注意 `--url` / `--json` / `--timeout` 这些参数要放在子命令（`ip`/`node`）**后面**，
例如 `cli.py ip 8.8.8.8 --json` 可以，`cli.py --json ip 8.8.8.8` 不行。

批量检测数量多时终端输出会很长，建议加 `--json` 配合脚本/`jq` 处理，而不是人工翻屏读。

批量检测（`ip`/`node` 传入多个目标时）会在终端显示一个实时进度条（`检测进度 [###---] 3/10`），
输出到 stderr，不影响 `--json` 或表格输出的内容；非终端环境（管道/重定向）下自动不显示。

## 接口说明

### 检测 IP / 域名（单个）

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
  "ippure_raw": "7% 极度纯净",
  "cloudflare_score": 15,
  "cloudflare_label": "纯净",
  "cloudflare_raw": "15% 纯净",
  "asn": "AS15169 - Google LLC",
  "as_domain": "google.com",
  "ip_range": "8.8.8.0 - 8.8.8.255",
  "human_pct": 2.66,
  "bot_pct": 97.34,
  "locations": {
    "IP2Location": "United States, California, Mountain View",
    "DB-IP": "United States, California, Mountain View",
    "MaxMind": "United States",
    "Bilibili": "GOOGLE.COM, GOOGLE.COM"
  },
  "webrtc_leak": { "leaked": false, "ip": null, "location": null }
}
```

- `resolved_ip`：输入若为域名，这里是 DNS 解析出的出口 IP；输入本身是 IP 则原样返回。
- 以上每个字段都可能因为 ippure.com 那边某个数据源没返回而缺失（`null` 或该 key 不在
  `locations` 里），前端会显示为"暂不可用"，不代表出错。
- `webrtc_leak` 这里反映的是**本服务自己的浏览器**有没有走漏 IP（没配代理的情况下，靠
  `disable_non_proxied_udp` 策略基本恒为 `false`），不是查询目标 IP 的属性；节点检测里的
  `webrtc_leak` 才是真正有意义的、走该节点隧道测出来的结果（见下）。

### 批量检测多个 IP / 域名

```
POST /api/detect-batch
Content-Type: application/json

{ "targets": "8.8.8.8, example.com\n1.1.1.1" }
```

`targets` 支持换行、半角逗号、全角逗号混用分隔，每次最多 1000 个（超过直接 400 拒绝）。
并发跑（受 `MAX_CONCURRENCY` 限制，默认 3），单个失败不影响其他：

```json
{
  "total": 3,
  "success_count": 2,
  "results": [
    { "input": "8.8.8.8", "resolved_ip": "8.8.8.8", "success": true, "...": "同上单个查询的全部字段" },
    { "input": "example.com", "success": false, "error": "无法解析域名: example.com" }
  ]
}
```

#### 流式版本（带进度）：`/api/detect-batch-stream`

请求体一样，但响应是 `application/x-ndjson`（每行一个 JSON 对象，而不是一次性返回一个大
JSON）：每完成一项就立刻推一行 `{"type": "progress", "done": N, "total": T, "index": i,
"result": {...}}`（`index` 是该项在原始输入里的顺序，方便客户端按输入顺序而不是完成顺序摆
放结果），全部跑完后再推最后一行 `{"type": "done", "total": T, "success_count": S,
"results": [...]}`，`results` 已经按输入顺序排好，字段和上面的 `/api/detect-batch` 完全一样。
Web UI 和 `cli.py` 都是靠这个接口驱动进度条的。

### 检测单个 Clash 节点

```
POST /api/detect-node
Content-Type: application/json

{ "node": "- { name: 'sg', type: vless, server: 1.2.3.4, port: 443, uuid: ..., ... }" }
```

`node` 字段可以是：单个节点的 flow-style YAML（如上）、多行 YAML 节点、或者一整份包含
`proxies:` 列表的 Clash 配置（此时只探测第一个节点）；缩进不规范的粘贴内容也能容错解析。

返回（字段和 `/api/detect` 一样全，外加节点自身信息和出口 IP）：

```json
{
  "node_name": "sg",
  "node_type": "vless",
  "node_server": "1.2.3.4",
  "node_port": 443,
  "egress_ip": "185.xx.xx.xx",
  "success": true,
  "ip_source": "原生IP",
  "ip_attribute": "机房IP",
  "ippure_score": 12,
  "ippure_label": "纯净",
  "ippure_raw": "12% 纯净",
  "cloudflare_score": 18,
  "cloudflare_label": "纯净",
  "cloudflare_raw": "18% 纯净",
  "asn": "...", "as_domain": "...", "ip_range": "...",
  "human_pct": 80.1, "bot_pct": 19.9,
  "locations": { "...": "..." },
  "webrtc_leak": { "leaked": false, "ip": null, "location": null }
}
```

这里的 `webrtc_leak` 是真正走该节点自己的本地代理端口测出来的：`leaked: true` 时
`ip`/`location` 是通过 WebRTC 泄露出去的真实 IP 和大致位置，说明这个节点不适合用来隐藏真实
出口；`leaked: false` 说明没测到绕过隧道的泄露（也可能是该节点/协议不支持 UDP 转发导致
WebRTC 干脆连不上，保守地不算作泄露）。

若节点连不通（服务器不可达、握手失败、协议参数缺失等），会返回 502，`detail` 里带上
mihomo 自身报出的具体原因，例如：

```json
{ "detail": "无法通过该节点访问外网: [TCP] dial PROXY ... connect error: context deadline exceeded" }
```

### 批量检测多个 Clash 节点

```
POST /api/detect-nodes
Content-Type: application/json

{ "nodes": "- { name: 'sg', ... }\n- { name: 'uk', ... }\n- { name: 'jp', ... }" }
```

`nodes` 字段接受一份多行的节点列表（YAML list，也支持一整份带 `proxies:` 的 Clash 配置，
此时会探测其中全部节点）。每次最多 1000 个（`MAX_BATCH_NODES`），按
`MAX_NODE_CONCURRENCY`（默认 2）的并发度逐个探测，单个节点失败不影响其他节点，
返回结果里每条都带 `success` 标记，成功的条目字段和单个节点检测完全一样：

```json
{
  "total": 5,
  "success_count": 2,
  "results": [
    { "node_name": "uk", "node_type": "anytls", "node_server": "...", "node_port": 40251,
      "success": false, "error": "无法通过该节点访问外网: ..." },
    { "node_name": "ar", "node_type": "anytls", "node_server": "...", "node_port": 40254,
      "egress_ip": "103.xx.xx.xx", "success": true,
      "ip_source": "原生IP", "ip_attribute": "机房IP",
      "ippure_score": 81, "ippure_label": "极度风险", "ippure_raw": "81% 极度风险",
      "cloudflare_score": 76, "cloudflare_label": "极度风险", "cloudflare_raw": "76% 极度风险",
      "webrtc_leak": { "leaked": false, "ip": null, "location": null } }
  ]
}
```

#### 流式版本（带进度）：`/api/detect-nodes-stream`

和 `/api/detect-batch-stream` 是同一套协议（`application/x-ndjson`，逐行 `progress` 事件
+ 最后一行 `done` 事件），只是跑的是节点探测。节点检测本身耗时更长（20～40 秒/个），进度条
在这里尤其有用。

Web UI 的两个页面（「IP / 域名检测」「Clash 节点检测」）都会自动识别：输入单个显示详情卡片，
输入多个则会对每一项都展开同样完整的详情卡片、依次堆叠展示（不是精简表格）。

## 已知限制

- 依赖 ippure.com 的可用性和页面结构，如果对方大改版（class 名变化）需要同步更新
  `main.py` 里 `EXTRACT_JS` / `WEBRTC_LEAK_JS` 的选择器。
- 默认最多 3 个请求并发跑浏览器（`MAX_CONCURRENCY`），最多 2 个并发跑节点探测
  （`MAX_NODE_CONCURRENCY`），避免机器资源被打满；如需调高，改 `main.py` 顶部的常量。
- 单次 IP/域名检测耗时约 3～5 秒；节点检测因为要等真实握手/超时，再加上一次 WebRTC 隧道
  检测，耗时可能到 20～40 秒。批量检测时是并发跑的，总耗时约等于
  `数量 / 并发数` 个单条耗时，都属正常现象。
- 批量检测（IP/域名、Clash 节点）一次最多各 1000 个，超过会直接报错拒绝，不做分批自动处理；
  数量大时网页会展示很长的堆叠列表，建议改用 CLI 的 `--json` 输出配脚本处理。
- Cloudflare 系数是会话动态打分，同一个 IP 多次检测分数会有正常波动，不代表检测不稳定。
- 节点 WebRTC 泄露检测依赖该节点/mihomo 支持 UDP 转发（节点配置里通常要有 `udp: true`），
  不支持时会保守地判定为"未检测到泄露"而不是报错。
