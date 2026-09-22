"""mitmproxy 打分替换测试工具 - 图形化界面。

用法：
    python D:\\test\\test\\score_mitm_gui.py

功能：
    1. 图形化设置 score_min / score_max / watch_domains / cert_export_dir / 监听端口
    2. 一键启动 / 停止 mitmproxy（工作线程内运行独立事件循环）
    3. 启动时自动设置 Windows 系统代理, 停止/退出时自动关闭
    4. 日志实时显示在窗口（同时保留控制台输出）
    5. 一键导出 CA 根证书（无需启动代理）
    6. 设置自动保存到脚本所在目录 score_mitm_settings.json, 下次启动自动恢复
"""

import asyncio
import ctypes
import inspect
import json
import logging as py_logging
import os
import queue
import shutil
import socket
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

sys.path.insert(0, str(Path(__file__).parent))

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from score_mitm import CA_FILES, ScoreRewriteAddon

# --windowed 打包模式下没有控制台, stdout/stderr 为 None;
# 重定向到空设备, 避免任何库写控制台时崩溃
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115

DEFAULT_CONFDIR = str(Path.home() / ".mitmproxy")
MAX_LOG_LINES = 3000
SETTINGS_FILE = "score_mitm_settings.json"
IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    import winreg

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
INET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def set_system_proxy(enable: bool, proxy: str = ""):
    """开启/关闭 Windows 系统代理 (仅 HKCU, 无需管理员权限)。"""
    if not IS_WINDOWS:
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_SETTINGS_KEY, 0,
                        winreg.KEY_SET_VALUE) as key:
        if enable:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
    # 通知系统代理设置已变化, 立即生效而无需注销
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


class LogSink:
    """把 mitmproxy 日志事件转发到线程安全队列，供 GUI 轮询显示。"""

    def __init__(self, q: queue.Queue):
        self.q = q

    def log(self, entry):
        self.q.put(f"[{entry.level}] {entry.msg}")


class FlowSink:
    """把经过代理的流量摘要（类似 mitmdump 终端输出）推到 GUI 日志。"""

    def __init__(self, q: queue.Queue):
        self.q = q

    @staticmethod
    def _addr(flow) -> str:
        try:
            peer = flow.client_conn.peername
            return f"{peer[0]}:{peer[1]}" if peer else "?"
        except Exception:  # noqa: BLE001
            return "?"

    def response(self, flow):
        try:
            status = flow.response.status_code
            size = len(flow.response.raw_content or b"")
            self.q.put(f"{self._addr(flow)}: {flow.request.method} "
                       f"{flow.request.pretty_url} << {status} {size}b")
        except Exception:  # noqa: BLE001
            pass

    def websocket_message(self, flow):
        try:
            messages = getattr(flow, "messages", None)
            if messages is None:
                messages = flow.websocket.messages
            msg = messages[-1]
            if msg.from_client:
                return
            kind = "text" if getattr(msg, "is_text", True) else "binary"
            self.q.put(f"{self._addr(flow)}: WS {kind} <- "
                       f"{flow.request.pretty_url} {len(msg.content)}b")
        except Exception:  # noqa: BLE001
            pass


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("打分替换测试代理 (mitmproxy)")
        root.geometry("760x560")
        root.minsize(640, 460)

        self.log_q: queue.Queue = queue.Queue()
        self.master: DumpMaster | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.sysproxy_set = False  # 本次会话是否已由本程序开启系统代理
        self.settings = self._load_settings()

        self._build_widgets()
        self.root.after(100, self._poll_log)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- 设置持久化 ----------
    @staticmethod
    def _app_dir() -> Path:
        # PyInstaller --onefile 下 __file__ 在临时解压目录, 冻结模式用 exe 所在目录
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent

    def _settings_path(self) -> Path:
        return self._app_dir() / SETTINGS_FILE

    def _load_settings(self) -> dict:
        try:
            p = self._settings_path()
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                self._log_later(f"[gui] 已从 {p} 恢复上次设置")
                return data
        except Exception as e:  # noqa: BLE001
            self._log_later(f"[error] 读取设置失败: {e}")
        return {}

    def _save_settings(self):
        try:
            data = {
                "score_min": self.e_min.get(),
                "score_max": self.e_max.get(),
                "listen_port": self.e_port.get(),
                "watch_domains": self.e_domains.get(),
                "cert_export_dir": self.e_certdir.get(),
                "ssl_insecure": self.var_insecure.get(),
                "sysproxy": self.var_sysproxy.get(),
            }
            self._settings_path().write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            self._log(f"[gui] 设置已保存到 {self._settings_path()}")
        except Exception as e:  # noqa: BLE001
            self._log(f"[error] 保存设置失败: {e}")

    def _log_later(self, msg: str):
        # 启动早期日志队列还没开始轮询, 先入队, _poll_log 启动后会取出来
        self.log_q.put(msg)

    # ---------- UI ----------
    def _build_widgets(self):
        pad = {"padx": 6, "pady": 4}
        frm = ttk.LabelFrame(self.root, text="参数设置")
        frm.pack(fill="x", **pad)

        ttk.Label(frm, text="分数下限 score_min:").grid(row=0, column=0, sticky="e", **pad)
        self.e_min = ttk.Entry(frm, width=12)
        self.e_min.insert(0, self.settings.get("score_min", "3.000000"))
        self.e_min.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(frm, text="分数上限 score_max:").grid(row=0, column=2, sticky="e", **pad)
        self.e_max = ttk.Entry(frm, width=12)
        self.e_max.insert(0, self.settings.get("score_max", "5.000000"))
        self.e_max.grid(row=0, column=3, sticky="w", **pad)

        ttk.Label(frm, text="监听端口:").grid(row=0, column=4, sticky="e", **pad)
        self.e_port = ttk.Entry(frm, width=8)
        self.e_port.insert(0, str(self.settings.get("listen_port", "8080")))
        self.e_port.grid(row=0, column=5, sticky="w", **pad)

        ttk.Label(frm, text="监控域名 (; 分隔, 留空全部):").grid(row=1, column=0, sticky="e", **pad)
        self.e_domains = ttk.Entry(frm, width=52)
        self.e_domains.insert(0, self.settings.get("watch_domains", ""))
        self.e_domains.grid(row=1, column=1, columnspan=4, sticky="we", **pad)

        ttk.Label(frm, text="证书导出目录:").grid(row=2, column=0, sticky="e", **pad)
        self.e_certdir = ttk.Entry(frm, width=52)
        self.e_certdir.insert(0, self.settings.get("cert_export_dir", "D:/cert"))
        self.e_certdir.grid(row=2, column=1, columnspan=4, sticky="we", **pad)

        self.var_insecure = tk.BooleanVar(value=self.settings.get("ssl_insecure", True))
        ttk.Checkbutton(frm, text="ssl_insecure (不校验上游服务器证书)", variable=self.var_insecure).grid(
            row=3, column=1, columnspan=3, sticky="w", **pad)

        self.var_sysproxy = tk.BooleanVar(value=self.settings.get("sysproxy", True))
        ttk.Checkbutton(frm, text="自动设置系统代理 (启动时开启指向本代理, 停止/退出时自动关闭)",
                        variable=self.var_sysproxy).grid(row=3, column=3, columnspan=3, sticky="w", **pad)

        ttk.Label(
            frm,
            text="提示: 分数满分 5.000000, 替换值自动保留 6 位小数 (如 4.523180), "
                 "缺少 6 位小数会导致客户端程序报错",
            foreground="#b26a00",
        ).grid(row=4, column=0, columnspan=6, sticky="w", **pad)

        frm.columnconfigure(1, weight=1)

        btns = ttk.Frame(self.root)
        btns.pack(fill="x", **pad)
        self.btn_start = ttk.Button(btns, text="启动代理", command=self.start)
        self.btn_start.pack(side="left", padx=6)
        self.btn_stop = ttk.Button(btns, text="停止", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(btns, text="导出 CA 证书", command=self.export_cert).pack(side="left", padx=6)
        ttk.Button(btns, text="清空日志", command=lambda: self.txt_log.delete("1.0", "end")).pack(side="left", padx=6)

        self.lbl_status = ttk.Label(self.root, text="状态: 未启动", foreground="gray")
        self.lbl_status.pack(anchor="w", padx=8)

        ttk.Label(self.root, text="日志:").pack(anchor="w", padx=8)
        self.txt_log = scrolledtext.ScrolledText(self.root, height=18, state="disabled", font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # ---------- 逻辑 ----------
    def _log(self, msg: str):
        self.log_q.put(msg)

    def _poll_log(self):
        lines = []
        while not self.log_q.empty():
            lines.append(self.log_q.get())
        if lines:
            self.txt_log.configure(state="normal")
            self.txt_log.insert("end", "\n".join(lines) + "\n")
            if int(self.txt_log.index("end-1c").split(".")[0]) > MAX_LOG_LINES:
                self.txt_log.delete("1.0", f"{len(lines)}")
            self.txt_log.see("end")
            self.txt_log.configure(state="disabled")
        self.root.after(100, self._poll_log)

    def _set_params_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for w in (self.e_min, self.e_max, self.e_port, self.e_domains, self.e_certdir):
            w.configure(state=state)
        self.btn_start.configure(state=state)
        self.btn_stop.configure(state="normal" if not enabled else "disabled")

    def _validate(self) -> dict | None:
        try:
            lo = float(self.e_min.get())
            hi = float(self.e_max.get())
            port = int(self.e_port.get())
        except ValueError:
            messagebox.showerror("参数错误", "分数和端口必须是数字")
            return None
        if not (0 <= lo <= 5 and 0 <= hi <= 5):
            messagebox.showerror("参数错误", "分数满分 5.000000, 请输入 0~5 之间的数值")
            return None
        if not (1 <= port <= 65535):
            messagebox.showerror("参数错误", "端口范围 1-65535")
            return None
        return {
            "score_min": f"{lo:.6f}",
            "score_max": f"{hi:.6f}",
            "listen_port": port,
            "watch_domains": self.e_domains.get().strip(),
            "cert_export_dir": self.e_certdir.get().strip() or "D:/cert",
        }

    def start(self):
        params = self._validate()
        if params is None:
            return
        if self.thread is not None and self.thread.is_alive():
            self._log("[gui] 等待上一次代理线程退出...")
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self._log("[error] 上一实例尚未退出, 端口仍被占用; 请稍等几秒再启动")
                return
        if not self._port_free(params["listen_port"]):
            self._log(f"[error] 端口 {params['listen_port']} 已被占用: "
                      f"可能还开着其他本程序窗口或旧实例未完全退出, 换个端口或稍后再试")
            self._set_params_state(enabled=True)
            return
        self._set_params_state(enabled=False)
        self.lbl_status.configure(
            text=f"状态: 运行中  0.0.0.0:{params['listen_port']}", foreground="green")
        self.thread = threading.Thread(target=self._run_master, args=(params,), daemon=True)
        self.thread.start()
        self._save_settings()
        if self.var_sysproxy.get():
            try:
                set_system_proxy(True, f"127.0.0.1:{params['listen_port']}")
                self.sysproxy_set = True
                self._log(f"[gui] 已开启系统代理 -> 127.0.0.1:{params['listen_port']}")
            except Exception as e:  # noqa: BLE001
                self._log(f"[error] 设置系统代理失败: {e}")

    def _run_master(self, params: dict):
        """工作线程：创建独立事件循环，在循环内构造 DumpMaster（新版 mitmproxy 要求）。"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop

        async def main():
            opts = Options(
                listen_host="0.0.0.0",
                listen_port=params["listen_port"],
                ssl_insecure=self.var_insecure.get(),
            )
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(ScoreRewriteAddon(), LogSink(self.log_q), FlowSink(self.log_q))
            # addons.add 之后自定义 option 才已注册
            master.options.update(
                score_min=params["score_min"],
                score_max=params["score_max"],
                watch_domains=params["watch_domains"],
                cert_export_dir=params["cert_export_dir"],
            )
            self.master = master
            self._log(f"[gui] 已启动, 监听 0.0.0.0:{params['listen_port']}, 请将客户端代理指向本机该端口")
            # 兼容 run() 为协程或普通方法的版本
            ret = master.run()
            if inspect.iscoroutine(ret):
                await ret

        try:
            loop.run_until_complete(main())
        except Exception as e:  # noqa: BLE001
            self._log(f"[error] mitmproxy 异常退出: {e}")
        finally:
            # 让循环里排队的日志/回调先跑完, 避免关闭后触发 "Event loop is closed"
            try:
                loop.run_until_complete(asyncio.sleep(0.05))
            except Exception:  # noqa: BLE001
                pass
            self._remove_dead_log_handlers(loop)
            loop.close()
            self._log("[gui] mitmproxy 已停止")
            self.root.after(0, self._on_master_stopped)

    def _remove_dead_log_handlers(self, dead_loop):
        """mitmproxy 每次创建 DumpMaster 都会往 root logger 挂指向其事件循环的
        日志 handler; 循环关闭后残留 handler 会在任何日志输出时报
        "Event loop is closed", 这里在退出后清理干净。"""
        root = py_logging.getLogger()
        removed = 0
        for h in list(root.handlers):
            m = getattr(h, "master", None)
            if m is not None and getattr(m, "event_loop", None) is dead_loop:
                root.removeHandler(h)
                removed += 1
        if removed:
            self._log(f"[gui] 已清理 {removed} 个失效日志处理器")

    def _on_master_stopped(self):
        self.master = None
        self.loop = None
        self.thread = None
        if self.sysproxy_set:
            try:
                set_system_proxy(False)
                self._log("[gui] 已关闭系统代理")
            except Exception as e:  # noqa: BLE001
                self._log(f"[error] 关闭系统代理失败: {e}")
            self.sysproxy_set = False
        self._set_params_state(enabled=True)
        self.lbl_status.configure(text="状态: 未启动", foreground="gray")

    def stop(self):
        if self.master is None:
            return
        loop = self.loop
        if loop is None or loop.is_closed():
            return
        self._log("[gui] 正在停止...")

        def _shutdown_on_loop():
            # 必须在代理线程的事件循环内调用 shutdown (内部会 set asyncio.Event,
            # 跨线程直接调用不保证生效), 否则旧实例可能停不掉、端口一直被占
            try:
                ret = self.master.shutdown()
                if inspect.iscoroutine(ret):
                    loop.create_task(ret)
            except Exception as e:  # noqa: BLE001
                self._log(f"[error] 停止失败: {e}")

        try:
            loop.call_soon_threadsafe(_shutdown_on_loop)
        except RuntimeError:
            self._log("[error] 代理事件循环已关闭, 无法发送停止指令")

    @staticmethod
    def _port_free(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return True
            except OSError:
                return False

    def export_cert(self):
        dest = Path(self.e_certdir.get().strip() or "D:/cert")
        try:
            dest.mkdir(parents=True, exist_ok=True)
            found = []
            for name in CA_FILES:
                src = Path(DEFAULT_CONFDIR) / name
                if src.is_file():
                    shutil.copy2(src, dest / name)
                    found.append(name)
            if found:
                self._log(f"[gui] 已导出证书到 {dest}: {', '.join(found)}")
            else:
                self._log(f"[gui] {DEFAULT_CONFDIR} 下未找到 CA 证书, 请先启动一次代理让其生成")
        except Exception as e:  # noqa: BLE001
            self._log(f"[error] 导出证书失败: {e}")

    def _on_close(self):
        # 不做优雅退出: 保存设置、关闭系统代理后直接结束进程,
        # 所有代理线程(mitm)随进程一并终止
        try:
            self._save_settings()
        except Exception:  # noqa: BLE001
            pass
        if self.sysproxy_set:
            try:
                set_system_proxy(False)
            except Exception:  # noqa: BLE001
                pass
        self.root.destroy()
        os._exit(0)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
