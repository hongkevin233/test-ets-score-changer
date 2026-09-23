# 测试 ETS 改分程序

基于 mitmproxy 的语音评测（ETS/讯飞 ISE）打分自动化测试工具。作为中间人代理捕获服务端下发的 WebSocket 帧，
将评测分数字段替换为指定区间内的随机值，用于测试客户端对不同分数的展示与逻辑反应。

> 仅限授权范围内的自动化测试使用，请勿用于其他用途。

## 功能

- 拦截服务端 → 客户端的 WebSocket 下行帧，正则匹配并随机替换打分字段：
  `total_score / accuracy_score / fluency_score / integrity_score / standard_score`
- 三种替换模式（GUI 滑块操作，替换值固定保留 6 位小数，满分 5.000000）：
  - 随机区间：双滑块（一个滑槽两个把手）拖动确定分数上下限，区间内随机取值
  - 手动改分：勾选后切换为单滑块，所有字段替换为滑块指定的固定值
  - 分项改分：三个滑块分别设置 accuracy / fluency / integrity，总分自动 = 三者平均
    （启用后统一改分滑块禁用）
- 域名过滤：仅检测指定域名的 WS 流量（`;` 分隔，留空检测全部，支持子域名匹配）
- 二进制帧自动按 latin-1 强制解码后参与匹配（可无损还原字节）
- 自动导出 mitmproxy CA 根证书到指定目录（默认 `D:/cert`）
- 图形化界面（Tkinter）：参数设置、启动/停止、实时日志（含流量摘要）、一键导出证书
- 启动时自动设置 Windows 系统代理，停止/退出时自动还原
- 停止代理时自动清理：显式关闭 mitmproxy 11 遗留的监听服务（修复反复启停后端口被本进程占死的问题），
  若端口仍被其他进程占用则自动结束该进程；启动时端口被占会先尝试自动释放再继续启动
- 设置自动持久化到程序目录 `score_mitm_settings.json`

## 使用方法

### 方式一：直接运行 exe（推荐）

1. 到 [Releases](../../releases) 下载 `score_proxy.exe`（或自行构建，见下文）
2. 双击运行，按需修改参数后点击「启动代理」
3. 首次使用点击「导出 CA 证书」，将 `D:\cert\mitmproxy-ca-cert.cer` 安装到被测设备/系统的
   「受信任的根证书颁发机构」（不装证书 WSS 握手会失败，抓不到帧）
4. 客户端流量走本机代理端口（默认 8080；勾选系统代理时本机流量自动接管，手机设备请手动配置 Wi-Fi 代理）

### 方式二：源码运行

```powershell
pip install mitmproxy
python score_mitm_gui.py
```

也可以纯命令行使用核心脚本：

```powershell
mitmdump -s score_mitm.py -p 8080 --set score_min=3.000000 --set score_max=5.000000 --set watch_domains=eduaiplat.com --set ssl_insecure=true
```

## 参数说明

| 参数 | 说明 | 默认值 |
|---|---|---|
| 随机区间 | 双滑块确定 `score_min` ~ `score_max`，区间内随机（含边界） | `3.000000` ~ `5.000000` |
| 手动改分 | 勾选后单滑块指定固定值，替换所有 5 个字段 | 关（`4.500000`） |
| 监听端口 | 代理监听端口 | `8080` |
| 监控域名 | 仅检测这些域名，`;` 分隔，留空全部 | 空（全部） |
| 证书导出目录 | CA 根证书导出位置 | `D:/cert` |
| `ssl_insecure` | 不校验上游服务器证书（测试环境建议开） | 开 |
| 系统代理 | 启动时自动设置 Windows 系统代理 | 开 |

## 构建 exe

```powershell
pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name score_proxy `
  --collect-all mitmproxy --collect-data certifi --collect-data publicsuffix2 `
  score_mitm_gui.py
```

产物在 `dist\score_proxy.exe`。

## 文件结构

```
score_mitm.py       # mitmproxy 插件：WS 帧捕获 + 分数随机替换 + CA 证书导出
score_mitm_gui.py   # 图形化界面：参数设置/启停/日志/系统代理/设置持久化
```

## 注意事项

- 分数替换值固定 6 位小数格式，缺少小数位可能导致被测客户端解析报错
- 程序被强杀（而非点窗口 X）时系统代理可能残留，需手动到 Windows 设置关闭
- 同一帧内多个命中的字段各自独立随机取值
