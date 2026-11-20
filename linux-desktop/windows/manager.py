"""Run with Windows Python 3.11+ (Tcl/Tk enabled)."""
import argparse
import os
import queue
import sys
import threading
from pathlib import Path

from runtime import Config, Runtime
from workspaces import Store


class Manager:
    def __init__(self, root, runtime, store):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root, self.runtime, self.store = root, runtime, store
        self.events = queue.Queue()
        self.user = None
        self.busy = set()
        self.statuses = {}
        self.closing = False
        self.exiting = False
        self.notice = tk.StringVar()
        self.area = ttk.Frame(root, padding=20)
        self.area.pack(fill="both", expand=True)
        root.title("OrangeSpace · Linux 沙盒")
        root.geometry("740x460")
        root.minsize(620, 400)
        root.protocol("WM_DELETE_WINDOW", lambda: self.finish(exit_app=True))
        self.login_view()
        root.after(80, self.drain)
        root.after(5000, self.refresh_states)

    def clear(self):
        for widget in self.area.winfo_children():
            widget.destroy()
        self.notice.set("")

    def task(self, key, work, success, failure=None):
        if key in self.busy:
            return
        self.busy.add(key)

        def run():
            try:
                payload = work()
                self.events.put((key, success, payload))
            except Exception as exc:
                self.events.put((key, failure or self.error, str(exc) or type(exc).__name__))
        threading.Thread(target=run, daemon=True).start()

    def drain(self):
        while not self.events.empty():
            key, callback, value = self.events.get()
            self.busy.discard(key)
            callback(value)
            if self.exiting:
                return
        self.root.after(80, self.drain)

    def error(self, message):
        self.notice.set(message)

    def login_view(self):
        self.clear()
        ttk = self.ttk
        title = ttk.Label(self.area, text="OrangeSpace  本地账号", font=("Segoe UI", 20))
        title.pack(anchor="w", pady=(16, 20))
        fields = ttk.Frame(self.area)
        fields.pack(anchor="w")
        name, password = self.tk.StringVar(), self.tk.StringVar()
        for i, (text, value) in enumerate([("账号", name), ("密码", password)]):
            ttk.Label(fields, text=text).grid(row=i, column=0, sticky="w", padx=(0, 12), pady=6)
            entry = ttk.Entry(fields, textvariable=value, width=32, show="●" if i else "")
            entry.grid(row=i, column=1, pady=6)
            if i == 0:
                entry.focus_set()

        def submit(register):
            if self.closing or "account" in self.busy:
                return
            user_name, secret = name.get(), password.get()
            auth = self.store.register if register else self.store.login
            self.notice.set("正在打开账号…")

            def logged_in(user):
                password.set("")
                self.user = user
                self.name = user_name
                self.workspace_view()
            self.task("account", lambda: auth(user_name, secret), logged_in)

        buttons = ttk.Frame(self.area)
        buttons.pack(anchor="w", pady=12)
        ttk.Button(buttons, text="登录", command=lambda: submit(False)).pack(side="left")
        ttk.Button(buttons, text="注册本地账号", command=lambda: submit(True)).pack(side="left", padx=6)
        ttk.Label(self.area, textvariable=self.notice, wraplength=630).pack(anchor="w")
        self.root.bind("<Return>", lambda _: submit(False))

    def workspace_view(self):
        self.clear()
        self.root.unbind("<Return>")
        ttk = self.ttk
        bar = ttk.Frame(self.area)
        bar.pack(fill="x", pady=(0, 12))
        ttk.Label(bar, text=f"{self.name} 的沙盒", font=("Segoe UI", 17)).pack(side="left")
        ttk.Button(bar, text="退出账号", command=lambda: self.finish(False)).pack(side="right")
        ttk.Button(bar, text="导入节点配置", command=self.configure).pack(side="right", padx=8)
        self.tree = ttk.Treeview(self.area, show="headings", columns=("name", "node", "state"),
                                 selectmode="browse", height=9)
        for key, label, width in [("name", "沙盒", 170), ("node", "绑定节点", 170), ("state", "状态", 230)]:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _: self.operate("start"))
        buttons = ttk.Frame(self.area)
        buttons.pack(fill="x", pady=10)
        for text, command in [("新建沙盒", lambda: self.edit(False)), ("打开 / 唤回", lambda: self.operate("start")),
                              ("停止", lambda: self.operate("stop")), ("更换节点", lambda: self.edit(True)),
                              ("沙盒 ID", self.show_id), ("刷新状态", lambda: self.operate("status"))]:
            ttk.Button(buttons, text=text, command=command).pack(side="left", padx=(0, 4))
        ttk.Label(self.area, textvariable=self.notice, wraplength=640).pack(anchor="w")
        self.reload()

    def reload(self):
        selected = self.tree.selection()
        self.rows = {r["id"]: r for r in self.store.list(self.user)}
        for sid, row in self.rows.items():
            state = self.statuses.get(sid, "已停止")
            values = (row["name"], self.runtime.cfg.nodes.get(row["node"], "节点已移除"), state)
            if self.tree.exists(sid):
                self.tree.item(sid, values=values)
            else:
                self.tree.insert("", "end", iid=sid, values=values)
        if selected:
            self.tree.selection_set(selected)

    def selected(self):
        selection = self.tree.selection()
        if not selection:
            self.notice.set("请先选择沙盒")
            return None
        return self.rows[selection[0]]

    def configure(self):
        from tkinter import filedialog
        row = self.selected()
        if not row or self.closing or row["id"] in self.busy:
            return
        if row["id"] in self.runtime.displays:
            self.notice.set("请先停止这个沙盒，再导入节点配置")
            return
        path = filedialog.askopenfilename(parent=self.root, title="导入绑定节点的 TUIC 配置",
                                          filetypes=[("节点 JSON", "*.json")])
        if not path:
            return
        self.notice.set("正在将配置保存到沙盒…")
        def done(result):
            self.update_status(row["id"], result)
            self.notice.set(f"{row['name']} 已保存节点配置，可以打开桌面")
        self.task(row["id"], lambda: self.runtime.configure(row, path), done)

    def show_id(self):
        row = self.selected()
        if not row:
            return
        popup = self.tk.Toplevel(self.root)
        popup.title("沙盒标识")
        popup.transient(self.root)
        frame = self.ttk.Frame(popup, padding=16)
        frame.pack()

        def copy(text):
            popup.clipboard_clear()
            popup.clipboard_append(text)

        for i, (name, value) in enumerate([("账号 UUID", row["user_id"]), ("沙盒 UUID", row["id"]),
                                           ("节点 UUID", row["node"])]):
            self.ttk.Label(frame, text=name).grid(row=i, column=0, sticky="w", padx=4, pady=4)
            var = self.tk.StringVar(master=popup, value=value)
            field = self.ttk.Entry(frame, width=40, textvariable=var, state="readonly")
            field.variable = var
            field.grid(row=i, column=1)
            self.ttk.Button(frame, text="复制", command=lambda v=value: copy(v)).grid(row=i, column=2, padx=4)

    def edit(self, binding):
        if self.closing:
            return
        row = self.selected() if binding else None
        if binding and not row:
            return
        if row and (row["id"] in self.busy or row["id"] in self.runtime.displays):
            self.notice.set("请先停止这个沙盒，再更换节点")
            return
        tk, ttk = self.tk, self.ttk
        popup = tk.Toplevel(self.root)
        popup.title("更换节点" if binding else "新建沙盒")
        popup.transient(self.root)
        popup.grab_set()
        frame = ttk.Frame(popup, padding=18)
        frame.pack()
        name = tk.StringVar(value=row["name"] if row else "")
        if not binding:
            ttk.Label(frame, text="沙盒名称").pack(anchor="w")
            ttk.Entry(frame, textvariable=name, width=42).pack(pady=(4, 10))
        ttk.Label(frame, text="绑定节点").pack(anchor="w")
        nodes = list(self.runtime.cfg.nodes)
        box = ttk.Combobox(frame, state="readonly", width=48,
                           values=[f"{self.runtime.cfg.nodes[n]}  ·  {n}" for n in nodes])
        box.current(nodes.index(row["node"]) if row and row["node"] in nodes else 0)
        box.pack(pady=(4, 10))
        error = tk.StringVar()

        def save():
            try:
                node = nodes[box.current()]
                if binding:
                    self.store.bind(self.user, row["id"], node)
                    sid = row["id"]
                else:
                    sid = self.store.create(self.user, name.get(), node)
                popup.destroy()
                self.reload()
                self.tree.selection_set(sid)
            except ValueError as exc:
                error.set(str(exc))
        ttk.Button(frame, text="保存", command=save).pack(anchor="e")
        ttk.Label(frame, textvariable=error).pack(anchor="w")

    def update_status(self, sid, result):
        if result.get("desktop") == "running":
            state = {"gateway-ready": "运行中 · 网关就绪", "online": "运行中 · 节点在线",
                     "offline": "运行中 · 网络离线"}.get(result.get("network"), "运行中 · 网络状态未知")
        elif result.get("desktop") == "stopped":
            state = "已停止"
        else:
            state = "状态未知"
        self.statuses[sid] = state
        self.reload()

    def operate(self, op, row=None, passive=False):
        row = row or self.selected()
        if not row or self.closing or row["id"] in self.busy:
            return
        sid = row["id"]
        if not passive:
            self.statuses[sid] = {"start": "正在打开…", "stop": "正在停止…", "status": "正在查询…"}[op]
            self.reload()
            self.notice.set("")

        def failure(message):
            self.statuses[sid] = "状态未知，可重试"
            self.notice.set(f"{row['name']} · {message}")
            self.reload()
        self.task(sid, lambda: getattr(self.runtime, op)(row), lambda result: self.update_status(sid, result), failure)

    def refresh_states(self):
        if self.user and not self.closing:
            for sid, row in self.rows.items():
                current = self.runtime.displays.get(sid)
                if current and sid not in self.busy:
                    # Closing the desktop's XWin should stop that desktop and its gateway.
                    op = "stop" if current[1].poll() is not None else "status"
                    self.operate(op, row, passive=True)
        self.root.after(5000, self.refresh_states)

    def finish(self, exit_app):
        if self.closing:
            return
        self.closing = True
        self.notice.set("等待当前操作结束，正在关闭桌面…")
        rows = list(self.rows.values()) if self.user else []

        def finish_when_idle():
            if self.busy:
                self.root.after(100, finish_when_idle)
                return
            self.task("close", lambda: self.runtime.close(rows), complete, failed)

        def complete(_):
            self.user = None
            self.name = ""
            for child in self.root.winfo_children():
                if isinstance(child, self.tk.Toplevel):
                    child.destroy()
            self.statuses.clear()
            self.closing = False
            if exit_app:
                self.exiting = True
                self.root.destroy()
            else:
                self.login_view()

        def failed(message):
            self.closing = False
            self.notice.set(f"关闭尚未完成，请重试。{message}")
        finish_when_idle()


def main():
    parser = argparse.ArgumentParser(description="OrangeSpace 本地 Linux 桌面管理器")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.exit(1, "Windows 11 x64 is required.\n")
    import tkinter as tk
    from tkinter import messagebox
    import winapi
    root = tk.Tk()
    root.withdraw()
    try:
        directory = Path(os.environ["LOCALAPPDATA"]) / "OrangeSpace-Linux-Desktop"
        winapi.private_directory(directory)
        instance = winapi.single_manager(directory)
        job = winapi.own_process_tree()
        runtime = Runtime(Config.load(args.config), directory)
        Manager(root, runtime, Store(directory / "accounts.sqlite3"))
        root.deiconify()
        root.mainloop()
        instance.close()
        # Keep the sole non-inheritable Job handle for the lifetime of this process.
        assert job
    except Exception as exc:
        messagebox.showerror("OrangeSpace", str(exc) or type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
