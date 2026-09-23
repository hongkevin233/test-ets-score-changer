"""mitmproxy 测试脚本：拦截服务端 -> 客户端的 WebSocket 帧并随机替换打分字段。

用法：
    mitmdump -s D:\\test\\test\\score_mitm.py -p 8080 --set score_min=70 --set score_max=100 --set watch_domains=api.example.com;foo.bar.com --set ssl_insecure=true

功能：
    1. 自动导出 mitmproxy CA 根证书到 D:/cert（.cer / .pem / .p12）
    2. 仅检测 watch_domains 指定域名的 WS 流量（; 分隔，留空检测全部）
    3. 匹配正则 (total_score|accuracy_score|fluency_score|integrity_score|standard_score)="[\\d.]+"
       并替换分数：fixed_scores 非空时用其中的固定值，否则用 score_min ~ score_max 区间随机数
       （均保留 6 位小数，满分 5.000000）
    4. 二进制帧强制按 latin-1 解码后同样参与匹配
"""

import os
import re
import shutil
import random

from mitmproxy import ctx, http

SCORE_FIELDS = (
    "total_score",
    "accuracy_score",
    "fluency_score",
    "integrity_score",
    "standard_score",
)

SCORE_PATTERN = re.compile(
    r'(total_score|accuracy_score|fluency_score|integrity_score|standard_score)="[\d.]+"'
)

CA_FILES = ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.p12")


class ScoreRewriteAddon:
    def __init__(self):
        self._fixed = {}  # field -> float

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
        loader.add_option(
            name="fixed_scores",
            typespec=str,
            default="",
            help="手动指定分数，格式 total_score=4.500000;accuracy_score=...; "
                 "非空时对应字段用固定值替换（未列出的字段仍走随机区间），留空全部随机",
        )

    def configure(self, updated):
        self._domains = [
            d.strip().lower()
            for d in ctx.options.watch_domains.split(";")
            if d.strip()
        ]
        if self._domains:
            ctx.log.info(f"[score-mitm] 域名过滤: {', '.join(self._domains)}")
        self._fixed = {}
        for part in ctx.options.fixed_scores.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            field, _, val = part.partition("=")
            field = field.strip()
            if field in SCORE_FIELDS:
                try:
                    self._fixed[field] = float(val)
                except ValueError:
                    ctx.log.warn(f"[score-mitm] 忽略非法固定分值: {part}")
        if self._fixed:
            ctx.log.info(f"[score-mitm] 固定分数模式: "
                         + ", ".join(f"{k}={v:.6f}" for k, v in sorted(self._fixed.items())))
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
            field = m.group(1)
            if field in self._fixed:
                val = f"{self._fixed[field]:.6f}"
            elif (field == "total_score"
                  and "total_score" not in self._fixed
                  and all(f in self._fixed for f in ("accuracy_score", "fluency_score", "integrity_score"))):
                # 分项模式: 总分 = 三个分项的平均数
                avg = (self._fixed["accuracy_score"]
                       + self._fixed["fluency_score"]
                       + self._fixed["integrity_score"]) / 3
                val = f"{avg:.6f}"
            else:
                val = self._random_score()
            ctx.log.info(f'[score-mitm] 命中: {m.group(0)} -> {field}="{val}"')
            return f'{field}="{val}"'

        new_text, count = SCORE_PATTERN.subn(_replace, text)
        if count:
            message.content = new_text.encode(codec)
            ctx.log.info(f"[score-mitm] 本帧共替换 {count} 处分数")


addons = [ScoreRewriteAddon()]
