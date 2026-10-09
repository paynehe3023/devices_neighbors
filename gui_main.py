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
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
import get_port_neighbors as topo

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

TREE_COLS = ("端口", "状态", "方向", "对端设备", "对端端口", "对端IP", "对端MAC", "终端识别", "主机名")


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
        self.title("网络拓扑扫描工具")
        self.geometry("980x680")
        self.q = queue.Queue()
        self.all_data = []
        self.worker = None
        self._build_ui()
        self.after(120, self._poll)

    # ---------------- UI ----------------
    def _build_ui(self):
        f = ctk.CTkFrame(self)
        f.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(f, text="交换机IP:").grid(row=0, column=0, padx=4, pady=6)
        self.ip_var = ctk.StringVar(value="")
        ctk.CTkEntry(f, width=150, placeholder_text="如 10.175.10.41", textvariable=self.ip_var).grid(row=0, column=1, padx=4)
        ctk.CTkLabel(f, text="用户名:").grid(row=0, column=2, padx=4)
        self.user_var = ctk.StringVar(value="")
        ctk.CTkEntry(f, width=100, placeholder_text="admin", textvariable=self.user_var).grid(row=0, column=3, padx=4)
        ctk.CTkLabel(f, text="密码:").grid(row=0, column=4, padx=4)
        self.pwd_var = ctk.StringVar(value="")
        ctk.CTkEntry(f, width=120, textvariable=self.pwd_var, show="*").grid(row=0, column=5, padx=4)
        self.btn_single = ctk.CTkButton(f, text="单台扫描", width=90, command=lambda: self._start_scan(False))
        self.btn_single.grid(row=0, column=6, padx=4)
        self.btn_all = ctk.CTkButton(f, text="全网扫描", width=90, fg_color="#2f6f4f", command=lambda: self._start_scan(True))
        self.btn_all.grid(row=0, column=7, padx=4)
        ctk.CTkButton(f, text="导出模板", width=90, command=self._export_template).grid(row=0, column=8, padx=4)
        ctk.CTkButton(f, text="选择CSV批量", width=110, command=self._batch_scan).grid(row=0, column=9, padx=4)

        qf = ctk.CTkFrame(self)
        qf.pack(fill="x", padx=10, pady=4)
        self.qip_var = ctk.StringVar()
        ctk.CTkEntry(qf, width=140, placeholder_text="按IP反查", textvariable=self.qip_var).pack(side="left", padx=4)
        ctk.CTkButton(qf, text="反查", width=60, command=self._query_ip).pack(side="left", padx=4)
        q1 = ctk.CTkLabel(qf, text=" ? ", text_color="#4a90d9", cursor="question_arrow")
        q1.pack(side="left", padx=(0, 10))
        ToolTip(q1, "反查: 输入设备IP, 查出它插在哪台交换机的哪个物理端口\n例如 10.175.200.240 → YFL-ZXJF-JK-no.1 的 GE0/0/2\n需先扫描过且有数据")
        self.qport_var = ctk.StringVar()
        ctk.CTkEntry(qf, width=140, placeholder_text="按端口查询(如GE0/0/49)", textvariable=self.qport_var).pack(side="left", padx=4)
        ctk.CTkButton(qf, text="查询", width=60, command=self._query_port).pack(side="left", padx=4)
        q2 = ctk.CTkLabel(qf, text=" ? ", text_color="#4a90d9", cursor="question_arrow")
        q2.pack(side="left", padx=(0, 10))
        ToolTip(q2, "查询: 输入交换机端口, 查看该端口的上下联链路与对端详情\n例如 GE0/0/49 → 上联 CoreSW-INTERNET-01 XGE1/0/2")
        ctk.CTkButton(qf, text="导出CSV报表", width=110, command=self._export).pack(side="left", padx=4)
        self.status_var = ctk.StringVar(value="就绪")
        ctk.CTkLabel(qf, textvariable=self.status_var, text_color="gray").pack(side="right", padx=6)

        self.log_box = ctk.CTkTextbox(self, height=120, font=("Consolas", 13))
        self.log_box.pack(fill="x", padx=10, pady=4)

        tf = ctk.CTkFrame(self)
        tf.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", fieldbackground="#2b2b2b",
                        foreground="#e8e8e8", rowheight=22)
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="#e8e8e8")
        self.tree = ttk.Treeview(tf, columns=TREE_COLS, show="headings", height=12)
        for c in TREE_COLS:
            self.tree.heading(c, text=c)
        widths = {"端口": 90, "状态": 55, "方向": 80, "对端设备": 160, "对端端口": 110,
                  "对端IP": 130, "对端MAC": 130, "终端识别": 180, "主机名": 140}
        for c in TREE_COLS:
            self.tree.column(c, width=widths.get(c, 100), anchor="w")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
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
                elif kind == "error":
                    self._log(f"❌ {payload}")
                    messagebox.showerror("错误", str(payload))
                    self.status_var.set("扫描失败")
                    self._set_scan_buttons(True)
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _set_scan_buttons(self, enabled):
        state = "normal" if enabled else "disabled"
        self.btn_single.configure(state=state)
        self.btn_all.configure(state=state)

    # ---------------- 扫描 ----------------
    def _start_scan(self, recursive):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("提示", "扫描进行中, 请等待完成")
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
        self.status_var.set("扫描中..." + (" (全网递归)" if recursive else " (单台)"))
        self._set_scan_buttons(False)
        self._log(f"开始扫描 {ip} ...")
        self.worker = threading.Thread(target=self._worker_scan, args=(recursive,), daemon=True)
        self.worker.start()

    def _worker_scan(self, recursive):
        old = sys.stdout
        sys.stdout = QueueWriter(self.q)
        try:
            data = topo.scan_network(recursive=recursive)
            self.q.put(("done", data))
        except Exception as e:
            self.q.put(("error", f"{type(e).__name__}: {e}"))
        finally:
            sys.stdout = old

    # ---------------- 批量 ----------------
    def _batch_scan(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("提示", "扫描进行中, 请等待完成")
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
        self.status_var.set(f"批量扫描 {len(rows)} 台...")
        self._set_scan_buttons(False)
        self._log(f"批量扫描 {len(rows)} 台, 文件: {path}")
        self._log("提示: 该CSV含明文密码, 请勿提交仓库或外发, 用完后删除")
        self.worker = threading.Thread(target=self._worker_batch, args=(rows,), daemon=True)
        self.worker.start()

    def _worker_batch(self, rows):
        old = sys.stdout
        sys.stdout = QueueWriter(self.q)
        try:
            all_data = []
            for i, row in enumerate(rows, 1):
                ip = (row.get("IP") or "").strip()
                if not ip:
                    continue
                topo.USERNAME = (row.get("用户名") or row.get("username") or "admin").strip()
                topo.PASSWORD = (row.get("密码") or row.get("password") or "").strip()
                topo.TARGET_SWITCH = {"host": ip}
                self.q.put(("log", f"\n[{i}/{len(rows)}] 扫描 {ip} ..."))
                all_data.extend(topo.scan_network(recursive=False))
            self.q.put(("done", all_data))
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
    App().mainloop()
