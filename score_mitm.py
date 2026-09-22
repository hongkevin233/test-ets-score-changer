"""mitmproxy 测试脚本：拦截服务端 -> 客户端的 WebSocket 帧并随机替换打分字段。

用法：
    mitmdump -s D:\\test\\test\\score_mitm.py -p 8080 --set score_min=70 --set score_max=100 --set watch_domains=api.example.com;foo.bar.com --set ssl_insecure=true

功能：
    1. 自动导出 mitmproxy CA 根证书到 D:/cert（.cer / .pem / .p12）
    2. 仅检测 watch_domains 指定域名的 WS 流量（; 分隔，留空检测全部）
    3. 匹配正则 (total_score|accuracy_score|fluency_score|integrity_score|standard_score)="[\\d.]+"
       并替换为 score_min ~ score_max 区间内的随机数（保留 6 位小数）
    4. 二进制帧强制按 latin-1 解码后同样参与匹配
"""

import os
import re
import shutil
import random

from mitmproxy import ctx, http

SCORE_PATTERN = re.compile(
    r'(total_score|accuracy_score|fluency_score|integrity_score|standard_score)="[\d.]+"'
)

CA_FILES = ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.p12")


class ScoreRewriteAddon:
    def load(self, loader):
        loader.add_option(
            name="score_min",
            typespec=str,
            default="3.000000",
            help="随机替换分数的最小值（含），满分 5.000000，固定 6 位小数",
        )
        loader.add_option(
            name="score_max",
            typespec=str,
            default="5.000000",
            help="随机替换分数的最大值（含），满分 5.000000，固定 6 位小数",
        )
        loader.add_option(
            name="cert_export_dir",
            typespec=str,
            default="D:/cert",
            help="mitmproxy CA 根证书导出目录",
        )
        loader.add_option(
            name="watch_domains",
            typespec=str,
            default="",
            help="仅检测这些域名的 WS 流量，以;分隔，留空检测全部",
        )

    def configure(self, updated):
        self._domains = [
            d.strip().lower()
            for d in ctx.options.watch_domains.split(";")
            if d.strip()
        ]
        if self._domains:
            ctx.log.info(f"[score-mitm] 域名过滤: {', '.join(self._domains)}")
        self._export_ca()

    def running(self):
        self._export_ca()

    def tls_clienthello(self, data):
        self._export_ca()

    def _export_ca(self):
        export_dir = ctx.options.cert_export_dir
        confdir = os.path.abspath(ctx.options.confdir)
        try:
            os.makedirs(export_dir, exist_ok=True)
            for name in CA_FILES:
                src = os.path.join(confdir, name)
                if os.path.isfile(src):
                    shutil.copy2(src, os.path.join(export_dir, name))
                    ctx.log.info(f"[score-mitm] 已导出证书: {src} -> {export_dir}")
        except Exception as e:
            ctx.log.warn(f"[score-mitm] 导出证书失败: {e}")

    def _random_score(self):
        lo = float(ctx.options.score_min)
        hi = float(ctx.options.score_max)
        if hi < lo:
            lo, hi = hi, lo
        return f"{random.uniform(lo, hi):.6f}"

    def _domain_allowed(self, flow) -> bool:
        if not self._domains:
            return True
        request = getattr(flow, "request", None)
        if request is not None:
            host = (request.pretty_host or "").lower()
        else:
            server = getattr(flow, "server_conn", None)
            host = (server.address[0] if server and server.address else "").lower()
        return any(host == d or host.endswith("." + d) for d in self._domains)

    @staticmethod
    def _decode(content: bytes):
        """优先 utf-8；二进制/非 utf-8 帧强制按 latin-1 解码（可无损还原字节）。"""
        try:
            return content.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            return content.decode("latin-1"), "latin-1"

    def websocket_message(self, flow):
        # 新版(>=11)传 WebSocketFlow，消息在 flow.messages；旧版传 HTTPFlow，在 flow.websocket.messages
        messages = getattr(flow, "messages", None)
        if messages is None:
            messages = flow.websocket.messages
        message = messages[-1]
        if message.from_client:
            return
        if not self._domain_allowed(flow):
            return
        text, codec = self._decode(message.content)

        def _replace(m: re.Match) -> str:
            val = self._random_score()
            ctx.log.info(f'[score-mitm] 命中: {m.group(0)} -> {m.group(1)}="{val}"')
            return f'{m.group(1)}="{val}"'

        new_text, count = SCORE_PATTERN.subn(_replace, text)
        if count:
            message.content = new_text.encode(codec)
            ctx.log.info(f"[score-mitm] 本帧共替换 {count} 处分数")


addons = [ScoreRewriteAddon()]
