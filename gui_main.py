#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络拓扑扫描工具 - CustomTkinter GUI
复用 get_port_neighbors.py 的全部扫描/解析/报表逻辑, 仅做界面壳。
用法: python gui_main.py  (或打包为 exe)
"""
import csv
import io
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
import get_port_neighbors as topo
import updater

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

TREE_COLS = ("端口", "状态", "方向", "对端设备", "对端端口", "对端IP", "对端MAC", "终端识别", "主机名")


def resource_path(relative):
    base = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)
    return Path(base) / relative


class QueueWriter(io.TextIOBase):
    """把 print 输出重定向进队列, 供 UI 实时显示 (扫描线程专用)"""
    def __init__(self, q):
        self.q = q

    def write(self, s):
        if s.strip():
            self.q.put(("log", s.rstrip()))
        return len(s)

    def flush(self):
        pass


class ToolTip:
    """鼠标悬停提示 (Enter显示/Leave消失)"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _=None):
        if self.tip:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 24
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", bg="#2b2b2b", fg="#eeeeee",
                 relief="solid", borderwidth=1, padx=8, pady=5,
                 font=("Microsoft YaHei", 9)).pack()

    def _hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self._set_taskbar_identity()
        self._set_window_icon()
        self.title("网络拓扑扫描工具")
        self.geometry("1120x700")
        self.minsize(900, 560)
        self.q = queue.Queue()
        self.update_q = queue.Queue()
        self.all_data = []
        self.worker = None
        self.scan_cancel = threading.Event()
        self.about_window = None
        self.about_progress = None
        self.about_buttons = None
        self.about_status_var = None
        self._update_checking = False
        self._update_downloading = False
        self._available_update = None
        self.update_badge = None
        self.btn_about = None
        self._build_ui()
        self.after(120, self._poll)
        self.after(800, lambda: self._check_updates(silent=True))

    def _set_taskbar_identity(self):
        if sys.platform != "win32":
            return
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "payne.devices_neighbors"
            )
        except Exception:
            pass

    def _set_window_icon(self):
        ico = resource_path("image/appImage2.ico")
        png = resource_path("image/appImage2.png")
        try:
            if ico.exists():
                self.iconbitmap(default=str(ico))
        except Exception:
            pass
        try:
            if png.exists():
                self._window_icon = tk.PhotoImage(file=str(png))
                self.iconphoto(True, self._window_icon)
        except Exception:
            pass

    # ---------------- UI ----------------
    def _build_ui(self):
        # 连接信息行: 固定宽度, 避免输入框随窗口拉成长条
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(f, text="交换机 IP:", text_color="#c8c8c8").grid(
            row=0, column=0, padx=(0, 6), pady=6, sticky="w"
        )
        self.ip_var = ctk.StringVar(value="")
        self.ip_entry = ctk.CTkEntry(
            f,
            width=140,
            height=30,
            placeholder_text="如 10.175.10.41",
            textvariable=self.ip_var,
        )
        self.ip_entry.grid(row=0, column=1, padx=(0, 12), pady=6, sticky="w")
        ctk.CTkLabel(f, text="用户名:", text_color="#c8c8c8").grid(
            row=0, column=2, padx=(0, 6), pady=6, sticky="w"
        )
        self.user_var = ctk.StringVar(value="")
        self.user_entry = ctk.CTkEntry(
            f,
            width=90,
            height=30,
            placeholder_text="admin",
            textvariable=self.user_var,
        )
        self.user_entry.grid(row=0, column=3, padx=(0, 12), pady=6, sticky="w")
        ctk.CTkLabel(f, text="密码:", text_color="#c8c8c8").grid(
            row=0, column=4, padx=(0, 6), pady=6, sticky="w"
        )
        self.pwd_var = ctk.StringVar(value="")
        self.pwd_entry = ctk.CTkEntry(
            f, width=105, height=30, textvariable=self.pwd_var, show="*"
        )
        self.pwd_entry.grid(row=0, column=5, padx=(0, 12), pady=6, sticky="w")

        self.btn_single = ctk.CTkButton(
            f,
            text="单台扫描",
            width=78,
            height=30,
            command=lambda: self._start_scan(False),
        )
        self.btn_single.grid(row=0, column=6, padx=(0, 6), pady=6)
        self.btn_all = ctk.CTkButton(
            f,
            text="全网扫描",
            width=78,
            height=30,
            fg_color="#2f6f4f",
            hover_color="#3b8661",
            command=lambda: self._start_scan(True),
        )
        self.btn_all.grid(row=0, column=7, padx=(0, 6), pady=6)
        self.btn_stop = ctk.CTkButton(
            f,
            text="停止扫描",
            width=78,
            height=30,
            state="disabled",
            fg_color="#8a3030",
            hover_color="#a43b3b",
            command=self._stop_scan,
        )
        self.btn_stop.grid(row=0, column=8, padx=(0, 6), pady=6)
        ToolTip(self.btn_stop, "停止当前扫描，并保留已经完成的结果")

        # 状态与关于固定在右侧; 关于按钮占固定宽度, 不会被长状态文字挤掉
        f.grid_columnconfigure(9, weight=1)
        self.status_var = ctk.StringVar(value="就绪")
        ctk.CTkLabel(
            f, textvariable=self.status_var, text_color="#8f8f8f", anchor="e"
        ).grid(row=0, column=9, sticky="e", padx=(8, 6), pady=6)
        self.btn_about = ctk.CTkButton(
            f, text="关于", width=60, height=30, command=self._open_about
        )
        self.btn_about.grid(row=0, column=10, sticky="e", pady=6)
        self.update_badge = ctk.CTkLabel(
            self.btn_about,
            text="",
            width=10,
            height=10,
            corner_radius=5,
            fg_color="#ff3b30",
            cursor="hand2",
        )
        self.update_badge.bind("<Button-1>", lambda _event: self._open_about())
        self.update_badge.place_forget()
        ToolTip(self.update_badge, "发现新版本")

        # 常用操作区: 工具与查询同排, 减少纵向占用
        tools = ctk.CTkFrame(self, fg_color="transparent")
        tools.pack(fill="x", padx=12, pady=(2, 4))
        ctk.CTkButton(
            tools, text="导出模板", width=82, height=30, command=self._export_template
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            tools, text="选择 CSV 批量", width=110, height=30, command=self._batch_scan
        ).pack(side="left", padx=(0, 12))
        self.qip_var = ctk.StringVar()
        self.qip_entry = ctk.CTkEntry(
            tools,
            width=130,
            height=30,
            placeholder_text="按 IP 反查",
            textvariable=self.qip_var,
        )
        self.qip_entry.pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            tools, text="反查", width=56, height=30, command=self._query_ip
        ).pack(side="left", padx=(0, 2))
        q1 = ctk.CTkLabel(tools, text=" ? ", text_color="#4a90d9", cursor="question_arrow")
        q1.pack(side="left", padx=(0, 10))
        ToolTip(q1, "反查: 输入设备IP, 查出它插在哪台交换机的哪个物理端口\n例如 10.175.200.240 → YFL-ZXJF-JK-no.1 的 GE0/0/2\n需先扫描过且有数据")
        self.qport_var = ctk.StringVar()
        self.qport_entry = ctk.CTkEntry(
            tools,
            width=150,
            height=30,
            placeholder_text="按端口查询(如GE0/0/49)",
            textvariable=self.qport_var,
        )
        self.qport_entry.pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            tools, text="查询", width=56, height=30, command=self._query_port
        ).pack(side="left", padx=(0, 2))
        q2 = ctk.CTkLabel(tools, text=" ? ", text_color="#4a90d9", cursor="question_arrow")
        q2.pack(side="left", padx=(0, 10))
        ToolTip(q2, "查询: 输入交换机端口, 查看该端口的上下联链路与对端详情\n例如 GE0/0/49 → 上联 CoreSW-INTERNET-01 XGE1/0/2")
        ctk.CTkButton(
            tools, text="导出 CSV 报表", width=110, height=30, command=self._export
        ).pack(side="left")

        # 输入完成后可直接回车执行单台扫描
        for entry in (self.ip_entry, self.user_entry, self.pwd_entry):
            entry.bind("<Return>", lambda _event: self._start_scan(False))
            entry.bind("<KP_Enter>", lambda _event: self._start_scan(False))

        self.log_box = ctk.CTkTextbox(
            self, height=110, font=("Consolas", 12), corner_radius=6
        )
        self.log_box.pack(fill="x", padx=12, pady=(4, 2))

        tf = ctk.CTkFrame(self, fg_color="transparent")
        tf.pack(fill="both", expand=True, padx=12, pady=(2, 10))
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#202020",
            fieldbackground="#202020",
            foreground="#e8e8e8",
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#2c2c2c",
            foreground="#f0f0f0",
            relief="flat",
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=4,
        )
        style.map("Treeview", background=[("selected", "#315d8a")])
        self.tree = ttk.Treeview(tf, columns=TREE_COLS, show="headings", height=12)
        for c in TREE_COLS:
            self.tree.heading(c, text=c, anchor="center")
        widths = {
            "端口": 72,
            "状态": 56,
            "方向": 62,
            "对端设备": 120,
            "对端端口": 96,
            "对端IP": 108,
            "对端MAC": 118,
            "终端识别": 120,
            "主机名": 100,
        }
        for c in TREE_COLS:
            self.tree.column(
                c,
                width=widths.get(c, 100),
                minwidth=widths.get(c, 100),
                stretch=True,
                anchor="w",
            )
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        # 表格列在窗口内自动分配宽度; 缩到最小宽度以下时由横向滚动条承接
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        # 右键菜单: 复制单元格/整行/整列/全部(供 Excel 粘贴)
        self.tree_menu = tk.Menu(self, tearoff=0)
        self.tree_menu.add_command(label="复制单元格", command=self._copy_cell)
        self.tree_menu.add_command(label="复制整行", command=self._copy_row)
        self.tree_menu.add_command(label="复制整列", command=self._copy_col)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="复制全部", command=self._copy_all)
        self._menu_cell = None
        self._menu_col = None
        self.tree.bind("<Button-3>", self._tree_menu_popup)
        self.after(100, self.ip_entry.focus_set)

    # ---------------- 日志 / 轮询 ----------------
    def _log(self, msg):
        self.log_box.insert("end", str(msg) + "\n")
        self.log_box.see("end")

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "done":
                    self.all_data = payload
                    self._fill_tree()
                    self.status_var.set(f"扫描完成: {len(self.all_data)} 台设备")
                    self._set_scan_buttons(True)
                elif kind == "cancelled":
                    self.all_data = payload
                    if self.all_data:
                        self._fill_tree()
                    self._log(f"扫描已停止，保留已完成 {len(self.all_data)} 台设备结果")
                    self.status_var.set(
                        f"扫描已停止: {len(self.all_data)} 台设备"
                    )
                    self._set_scan_buttons(True)
                elif kind == "error":
                    self._log(f"❌ {payload}")
                    messagebox.showerror("错误", str(payload))
                    self.status_var.set("扫描失败")
                    self._set_scan_buttons(True)
        except queue.Empty:
            pass
        self._poll_updates()
        self.after(120, self._poll)

    def _set_scan_buttons(self, enabled):
        state = "normal" if enabled else "disabled"
        self.btn_single.configure(state=state)
        self.btn_all.configure(state=state)
        self.btn_stop.configure(
            state="disabled" if enabled else "normal",
            text="停止扫描",
        )

    # ---------------- 关于 / 更新 ----------------
    def _about_is_open(self):
        return bool(self.about_window and self.about_window.winfo_exists())

    def _set_update_badge(self, visible):
        if not self.update_badge:
            return
        if visible:
            self.update_badge.place(x=0, y=0, anchor="nw")
            self.update_badge.lift()
        else:
            self.update_badge.place_forget()

    def _open_about(self):
        if self._about_is_open():
            self.about_window.lift()
            return

        win = ctk.CTkToplevel(self)
        self.about_window = win
        win.title("关于")
        win.geometry("430x250")
        win.resizable(False, False)
        # 关于窗口不显示标题栏图标: 用全透明 .ico (Tk 的 PhotoImage 会丢 alpha 渲染成黑块,
        # 而 .ico 带 alpha 通道; 调用 iconbitmap 同时会置位 CTk 的标记, 阻止其 200ms 后
        # 覆盖成内置蓝色图标)
        try:
            blank = resource_path("image/blank.ico")
            if blank.exists():
                win.iconbitmap(str(blank))
        except Exception:
            pass
        win.transient(self)
        win.grab_set()
        win.protocol("WM_DELETE_WINDOW", self._close_about)

        ctk.CTkLabel(
            win, text="网络拓扑扫描工具", font=ctk.CTkFont(size=22, weight="bold")
        ).pack(pady=(24, 8))
        ctk.CTkLabel(
            win,
            text=f"版本 v{topo.APP_VERSION}\n作者：payne",
            justify="center",
            text_color="#c8c8c8",
        ).pack(pady=(0, 14))
        if self._available_update:
            about_status = f"发现新版本 v{self._available_update.version}"
        elif self._update_checking:
            about_status = "正在后台检查更新..."
        elif self._update_downloading:
            about_status = "正在下载更新..."
        else:
            about_status = "可检查 GitHub 仓库中的最新版本"
        self.about_status_var = ctk.StringVar(value=about_status)
        ctk.CTkLabel(
            win, textvariable=self.about_status_var, text_color="#9fc5e8"
        ).pack(pady=(0, 12))

        # 下载进度条: 空闲时不显示, 仅下载时 pack 出来 (总大小未知时切换为循环动画)
        self.about_progress = ctk.CTkProgressBar(win, width=340, height=10, mode="determinate")
        self.about_progress.set(0)

        self.about_buttons = ctk.CTkFrame(win, fg_color="transparent")
        self.about_buttons.pack()
        buttons = self.about_buttons
        self.btn_check_update = ctk.CTkButton(
            buttons,
            text="检查更新",
            width=110,
            command=lambda: self._check_updates(silent=False),
        )
        if self._update_checking:
            self.btn_check_update.configure(state="disabled", text="检查中...")
        elif self._update_downloading:
            self.btn_check_update.configure(state="disabled", text="下载中...")
        self.btn_check_update.pack(side="left", padx=5)
        ctk.CTkButton(
            buttons, text="关闭", width=90, fg_color="#555555",
            hover_color="#666666", command=self._close_about
        ).pack(side="left", padx=5)

    def _close_about(self):
        if self.about_window and self.about_window.winfo_exists():
            self.about_window.destroy()
        self.about_window = None
        self.about_progress = None
        self.about_buttons = None

    def _show_progress(self):
        """下载开始时把进度条显示出来 (窗口随之增高, 避开空闲时的空占位)"""
        if not self.about_progress or not self.about_window:
            return
        try:
            if not self.about_progress.winfo_ismapped():
                self.about_window.geometry("430x300")
                self.about_progress.pack(before=self.about_buttons, pady=(0, 12))
        except Exception:
            pass

    def _hide_progress(self):
        """下载结束/失败后收起进度条, 恢复空闲外观"""
        if not self.about_progress or not self.about_window:
            return
        try:
            if self.about_progress.winfo_ismapped():
                self.about_progress.pack_forget()
                self.about_window.geometry("430x250")
        except Exception:
            pass

    def _check_updates(self, silent=False):
        if self._update_checking or self._update_downloading:
            return
        self._update_checking = True
        if self._about_is_open():
            self.about_status_var.set("正在检查更新...")
            self.btn_check_update.configure(state="disabled", text="检查中...")
        threading.Thread(
            target=self._worker_check_update, args=(silent,), daemon=True
        ).start()

    def _worker_check_update(self, silent):
        try:
            info = updater.check_for_update(topo.APP_VERSION)
            self.update_q.put(("check_ok", (info, silent)))
        except Exception as exc:
            self.update_q.put(("check_error", (str(exc), silent)))

    def _start_update_download(self, info):
        if self._update_downloading:
            return
        self._update_downloading = True
        self.about_status_var.set(f"正在下载 v{info.version}...")
        self.btn_check_update.configure(state="disabled", text="下载中...")
        self._show_progress()
        if self.about_progress:
            self.about_progress.stop()
            self.about_progress.configure(mode="determinate")
            self.about_progress.set(0)
        threading.Thread(
            target=self._worker_download_update, args=(info,), daemon=True
        ).start()

    def _worker_download_update(self, info):
        last_bucket = -1

        def report(received, total):
            nonlocal last_bucket
            percent = int(received * 100 / total) if total else 0
            bucket = percent // 2          # 每 2% 推一次, 进度条更平滑
            if bucket != last_bucket:
                last_bucket = bucket
                self.update_q.put(("download_progress", (received, total, percent)))

        try:
            path = updater.download_update(
                info.download_url,
                expected_sha256=info.sha256,
                progress=report,
            )
            self.update_q.put(("download_ok", (info, path)))
        except Exception as exc:
            self.update_q.put(("download_error", str(exc)))

    def _poll_updates(self):
        while True:
            try:
                kind, payload = self.update_q.get_nowait()
            except queue.Empty:
                return
            if kind == "check_ok":
                info, silent = payload
                self._update_checking = False
                self._available_update = info
                self._set_update_badge(info is not None)
            elif kind == "check_error":
                _message, silent = payload
                self._update_checking = False
            elif kind in ("download_ok", "download_error"):
                self._update_downloading = False
            if not self._about_is_open():
                continue
            if kind == "check_ok":
                self.btn_check_update.configure(state="normal", text="检查更新")
                if info is None:
                    self.about_status_var.set("当前已是最新版本")
                    if not silent:
                        messagebox.showinfo(
                            "检查更新", "当前已是最新版本", parent=self.about_window
                        )
                    continue
                self.about_status_var.set(f"发现新版本 v{info.version}")
                if silent:
                    continue
                notes = f"\n\n更新说明：\n{info.notes}" if info.notes else ""
                if messagebox.askyesno(
                    "发现更新",
                    f"当前版本：v{topo.APP_VERSION}\n"
                    f"最新版本：v{info.version}{notes}\n\n是否下载更新？",
                    parent=self.about_window,
                ):
                    self._start_update_download(info)
            elif kind == "check_error":
                self.btn_check_update.configure(state="normal", text="检查更新")
                self.about_status_var.set("检查更新失败")
                if not silent:
                    messagebox.showerror(
                        "检查更新", _message, parent=self.about_window
                    )
            elif kind == "download_progress":
                received, total, percent = payload
                if total:
                    if self.about_progress:
                        self.about_progress.stop()
                        self.about_progress.configure(mode="determinate")
                        self.about_progress.set(min(received / total, 1.0))
                    self.about_status_var.set(
                        f"正在下载：{percent}%  "
                        f"({received / 1024 / 1024:.1f}/{total / 1024 / 1024:.1f} MB)"
                    )
                else:
                    if self.about_progress:
                        self.about_progress.configure(mode="indeterminate")
                        self.about_progress.start()
                    self.about_status_var.set(
                        f"正在下载：{received / 1024 / 1024:.1f} MB"
                    )
            elif kind == "download_ok":
                info, path = payload
                if self.about_progress:
                    self.about_progress.stop()
                    self.about_progress.configure(mode="determinate")
                    self.about_progress.set(1)
                self.btn_check_update.configure(state="normal", text="检查更新")
                self.about_status_var.set(f"v{info.version} 已下载完成")
                if not updater.can_self_update():
                    messagebox.showinfo(
                        "更新已下载",
                        f"开发模式不会自动替换程序。\n下载位置：{path}",
                        parent=self.about_window,
                    )
                    continue
                if messagebox.askyesno(
                    "安装更新",
                    f"v{info.version} 已下载完成。\n是否退出程序并自动安装更新？",
                    parent=self.about_window,
                ):
                    try:
                        updater.launch_updater(path)
                    except Exception as exc:
                        messagebox.showerror(
                            "安装更新", str(exc), parent=self.about_window
                        )
                        continue
                    self.about_status_var.set("正在重启并安装更新...")
                    self.after(300, self.destroy)
            elif kind == "download_error":
                if self.about_progress:
                    self.about_progress.stop()
                    self.about_progress.configure(mode="determinate")
                    self.about_progress.set(0)
                self._hide_progress()
                self.btn_check_update.configure(state="normal", text="检查更新")
                self.about_status_var.set("下载更新失败")
                messagebox.showerror("下载更新", payload, parent=self.about_window)

    # ---------------- 扫描 ----------------
    def _start_scan(self, recursive):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("提示", "扫描进行中, 请先停止当前扫描")
            return
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showwarning("提示", "请输入交换机 IP")
            return
        self.q = queue.Queue()
        self.all_data = []
        self.tree.delete(*self.tree.get_children())
        topo.USERNAME = self.user_var.get().strip() or "admin"
        topo.PASSWORD = self.pwd_var.get()
        topo.TARGET_SWITCH = {"host": ip}
        self.scan_cancel.clear()
        self.status_var.set("扫描中..." + (" (全网递归)" if recursive else " (单台)"))
        self._set_scan_buttons(False)
        self._log(f"开始扫描 {ip} ...")
        self.worker = threading.Thread(target=self._worker_scan, args=(recursive,), daemon=True)
        self.worker.start()

    def _worker_scan(self, recursive):
        old = sys.stdout
        sys.stdout = QueueWriter(self.q)
        try:
            data = topo.scan_network(
                recursive=recursive, cancel_event=self.scan_cancel
            )
            self.q.put(("done", data))
        except topo.ScanCancelled as e:
            self.q.put(("cancelled", e.partial or []))
        except Exception as e:
            self.q.put(("error", f"{type(e).__name__}: {e}"))
        finally:
            sys.stdout = old

    def _stop_scan(self):
        if not self.worker or not self.worker.is_alive():
            return
        if self.scan_cancel.is_set():
            return
        self.scan_cancel.set()
        self.btn_stop.configure(state="disabled", text="停止中...")
        self.status_var.set("正在停止扫描...")
        self._log("正在停止扫描...")
        threading.Thread(
            target=topo.cancel_active_connections, daemon=True
        ).start()

    # ---------------- 批量 ----------------
    def _batch_scan(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("提示", "扫描进行中, 请先停止当前扫描")
            return
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
        except Exception as e:
            messagebox.showerror("错误", f"读取CSV失败: {e}")
            return
        if not rows or "IP" not in rows[0]:
            messagebox.showerror("错误", "CSV 需包含表头: IP,用户名,密码,设备名")
            return
        self.q = queue.Queue()
        self.tree.delete(*self.tree.get_children())
        self.scan_cancel.clear()
        self.status_var.set(f"批量扫描 {len(rows)} 台...")
        self._set_scan_buttons(False)
        self._log(f"批量扫描 {len(rows)} 台, 文件: {path}")
        self._log("提示: 该CSV含明文密码, 请勿提交仓库或外发, 用完后删除")
        self.worker = threading.Thread(target=self._worker_batch, args=(rows,), daemon=True)
        self.worker.start()

    def _worker_batch(self, rows):
        old = sys.stdout
        sys.stdout = QueueWriter(self.q)
        all_data = []
        try:
            for i, row in enumerate(rows, 1):
                if self.scan_cancel.is_set():
                    raise topo.ScanCancelled(all_data)
                ip = (row.get("IP") or "").strip()
                if not ip:
                    continue
                topo.USERNAME = (row.get("用户名") or row.get("username") or "admin").strip()
                topo.PASSWORD = (row.get("密码") or row.get("password") or "").strip()
                topo.TARGET_SWITCH = {"host": ip}
                self.q.put(("log", f"\n[{i}/{len(rows)}] 扫描 {ip} ..."))
                all_data.extend(
                    topo.scan_network(
                        recursive=False, cancel_event=self.scan_cancel
                    )
                )
            self.q.put(("done", all_data))
        except topo.ScanCancelled as e:
            self.q.put(("cancelled", all_data + (e.partial or [])))
        except Exception as e:
            self.q.put(("error", f"{type(e).__name__}: {e}"))
        finally:
            sys.stdout = old

    # ---------------- 结果展示 / 导出 / 查询 ----------------
    def _fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        n = 0
        for d in self.all_data:
            for port, r in sorted(topo.build_records(d).items(), key=lambda x: topo.natural(x[0])):
                self.tree.insert("", "end", values=(
                    r["port"], r["status"], r["dir"], r["remote_dev"], r["remote_port"],
                    r["remote_ip"], r["remote_mac"], r["terminal"], r["hostname"]))
                n += 1
        self._log(f"表格已填充 {n} 个端口")

    # ---------------- 右键复制 ----------------
    def _tree_menu_popup(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region not in ("cell", "tree"):
            return
        self._menu_cell = self.tree.identify_row(event.y)
        col_tag = self.tree.identify_column(event.x)          # "#2" 形式
        self._menu_col = int(col_tag[1:]) - 1 if col_tag else None
        try:
            self.tree_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.tree_menu.grab_release()

    def _copy_cell(self):
        if self._menu_cell and self._menu_col is not None:
            val = self.tree.set(self._menu_cell, self._menu_col)
            self.clipboard_clear()
            self.clipboard_append(str(val or ""))

    def _copy_row(self):
        if not self._menu_cell:
            return
        vals = self.tree.item(self._menu_cell, "values")
        self.clipboard_clear()
        self.clipboard_append("\t".join(str(v or "") for v in vals))

    def _copy_col(self):
        if self._menu_col is None:
            return
        vals = [str(self.tree.set(i, self._menu_col) or "") for i in self.tree.get_children()]
        self.clipboard_clear()
        self.clipboard_append("\n".join(vals))
        self._log(f"已复制列 '{TREE_COLS[self._menu_col]}' 共 {len(vals)} 行")

    def _copy_all(self):
        lines = [self._row_to_tsv(self.tree.item(i, "values")) for i in self.tree.get_children()]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self._log(f"已复制 {len(lines)} 行到剪贴板")

    @staticmethod
    def _row_to_tsv(values):
        return "\t".join(str(v or "") for v in values)

    def _export(self):
        if not self.all_data:
            messagebox.showwarning("提示", "没有扫描数据, 请先扫描")
            return
        try:
            topo.write_reports(self.all_data)
            self._log(f"已导出: {topo.OUTPUT_CSV} / {topo.LINKS_CSV} / {topo.MAC_DETAIL_CSV}")
            messagebox.showinfo("完成", f"已导出报表到当前目录:\n{topo.OUTPUT_CSV}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _export_template(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="devices.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP", "用户名", "密码", "设备名"])
            w.writerow(["10.175.10.1", "admin", "", "示例: YFL-1F"])
        self._log(f"模板已导出: {path}")
        messagebox.showinfo("完成", f"模板已导出:\n{path}\n填写后选择CSV批量扫描\n\n"
                                   "注意: 该文件含明文密码, 请勿提交到仓库或外发")

    def _query_ip(self):
        if not self.all_data:
            messagebox.showwarning("提示", "没有扫描数据, 请先扫描")
            return
        ip = self.qip_var.get().strip()
        if not ip:
            return
        self._log(f"\n--- 反查 {ip} ---")
        self._capture_print(lambda: topo.query_ip(self.all_data, ip))

    def _query_port(self):
        if not self.all_data:
            messagebox.showwarning("提示", "没有扫描数据, 请先扫描")
            return
        port = self.qport_var.get().strip()
        if not port:
            return
        self._log(f"\n--- 查询端口 {port} ---")
        self._capture_print(lambda: topo.query_port(self.all_data, port))

    def _capture_print(self, fn):
        """捕获函数内 print 输出到日志区"""
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            fn()
        except Exception as e:
            self._log(f"❌ {e}")
        finally:
            sys.stdout = old
        for line in buf.getvalue().splitlines():
            self._log(line)


if __name__ == "__main__":
    if updater.run_update_helper(sys.argv):
        sys.exit(0)
    App().mainloop()
