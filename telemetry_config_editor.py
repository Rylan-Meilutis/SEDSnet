#!/usr/bin/env python3
"""
Telemetry Config Editor (Tkinter)

Key behavior:
- Ctrl+S / Cmd+S saves.
- "Live editing" is in-memory only (no JSON write until Save).
- Debounced apply never writes into the newly-selected item (active edit idx tracked).
- Switching tabs flushes only the tab you're leaving.
- Selection no longer jumps to the top (no listbox rebuild during edits).
- Unsaved-changes prompt is HASH-BASED:
    * We only prompt if current config hash != last-saved/loaded hash.
    * Switching tabs won't mark dirty unless it truly changes config.

"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ModuleNotFoundError as e:
    raise SystemExit(
        "Tkinter is required for telemetry_config_editor.py but is not available in this Python runtime."
    ) from e

DATA_TYPE_OPTIONS = [
    "Float64",
    "Float32",
    "UInt8",
    "UInt16",
    "UInt32",
    "UInt64",
    "UInt128",
    "Int8",
    "Int16",
    "Int32",
    "Int64",
    "Int128",
    "Bool",
    "String",
    "Binary",
    "NoData",
]

MESSAGE_CLASS_OPTIONS = ["Data", "Error", "Warning"]
BROADCAST_MODE_OPTIONS = ["Always", "Never", "Default"]
ELEMENT_KIND_OPTIONS = ["Static", "Dynamic"]
RELIABLE_MODE_OPTIONS = ["None", "Ordered", "Unordered"]
SCHEMA_SCOPE_BASE = "base"
SCHEMA_SCOPE_IPC = "ipc"
MAX_TYPE_PRIORITY = 255


def _is_reserved_telemetry_error(rust: str) -> bool:
    rust = (rust or "").strip()
    if not rust:
        return False
    return rust == "TelemetryError" or rust_ident_to_schema_name(rust) == "TELEMETRY_ERROR"


def _is_valid_rust_ident_input(s: str) -> bool:
    if s == "":
        return True
    return ensure_rust_ident(s)


def find_project_root(start: Path) -> Path:
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while True:
        if (cur / "Cargo.toml").exists():
            return cur
        if cur.parent == cur:
            return start.resolve().parent if start.is_file() else start.resolve()
        cur = cur.parent


def find_schema_json_from_config_rs(config_rs: Path, crate_root: Path) -> Optional[Path]:
    script_root = Path(__file__).resolve().parent
    raw = os.environ.get("SEDSNET_SCHEMA_PATH", "").strip()
    if raw:
        p = Path(raw)
        return (p if p.is_absolute() else (script_root / p)).resolve()
    try:
        text = config_rs.read_text(encoding="utf-8")
    except Exception:
        return None

    rx = re.compile(r'(?s)define_telemetry_schema!\s*\(\s*[^)]*?\bpath\s*=\s*"([^"]+)"')
    caps = list(rx.finditer(text))
    if not caps:
        return None
    rel_paths = [cap.group(1) for cap in caps]
    first = rel_paths[0]
    if any(p != first for p in rel_paths[1:]):
        raise RuntimeError(
            f"Multiple define_telemetry_schema!(path=...) entries found in {config_rs} with different paths"
        )
    return (script_root / first).resolve()


def find_ipc_schema_json() -> Optional[Path]:
    script_root = Path(__file__).resolve().parent
    raw = os.environ.get("SEDSNET_IPC_SCHEMA_PATH", "").strip()
    if not raw:
        return None
    p = Path(raw)
    return (p if p.is_absolute() else (script_root / p)).resolve()


def default_blank_config() -> Dict[str, Any]:
    return {"endpoints": [], "types": []}


def safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        raise RuntimeError(f"JSON parse error in {path}: {e}") from e


def safe_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp.replace(path)


def ensure_rust_ident(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s or ""))


def rust_ident_to_schema_name(rust: str) -> str:
    s = (rust or "").strip()
    if not s:
        return ""
    s = re.sub(r"[\s\-]+", "_", s)
    if "_" in s:
        return re.sub(r"_+", "_", s).strip("_").upper()
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"([A-Z])([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s.upper()


def _endpoint_row_text(ep: Dict[str, Any]) -> str:
    ll = " [LL]" if bool(ep.get("link_local_only", False)) else ""
    return f"{ep.get('rust', '')}  [{ep.get('name', '')}]{ll}"


def _type_row_text(ty: Dict[str, Any]) -> str:
    rel_mode = ty.get("reliable_mode", "")
    if not rel_mode or rel_mode == "None":
        rel = " [R]" if bool(ty.get("reliable", False)) else ""
    else:
        rel = f" [Rel:{rel_mode}]"
    priority = int(ty.get("priority", 0) or 0)
    prio = f" [Prio:{priority}]" if priority > 0 else ""
    return f"{ty.get('rust', '')}  [{ty.get('name', '')}]{rel}{prio}"


def _update_listbox_row(lb: tk.Listbox, idx: int, text: str) -> None:
    if idx < 0 or idx >= lb.size():
        return
    try:
        y0, _y1 = lb.yview()
    except Exception:
        y0 = None

    sel = lb.curselection()
    sel_idx = int(sel[0]) if sel else None

    lb.delete(idx)
    lb.insert(idx, text)

    if sel_idx is not None:
        try:
            lb.selection_clear(0, tk.END)
            lb.selection_set(sel_idx)
        except Exception:
            pass

    if y0 is not None:
        try:
            lb.yview_moveto(y0)
        except Exception:
            pass


def _selected_index(lb: tk.Listbox) -> Optional[int]:
    sel = lb.curselection()
    if not sel:
        return None
    return int(sel[0])


def _lb_all(lb: tk.Listbox) -> List[str]:
    return [lb.get(i) for i in range(lb.size())]


def _lb_selected(lb: tk.Listbox) -> List[str]:
    return [lb.get(i) for i in lb.curselection()]


def _lb_remove_items(lb: tk.Listbox, items: List[str]) -> None:
    if not items:
        return
    s = set(items)
    values = [v for v in _lb_all(lb) if v not in s]
    lb.delete(0, tk.END)
    for v in values:
        lb.insert(tk.END, v)


def _lb_add_unique(lb: tk.Listbox, items: List[str]) -> None:
    if not items:
        return
    existing = set(_lb_all(lb))
    for v in items:
        if v not in existing:
            lb.insert(tk.END, v)
            existing.add(v)


class TelemetryConfigEditor(tk.Tk):
    def __init__(
            self,
            crate_root: Path,
            config_rs: Path,
            base_json_path: Optional[Path],
            ipc_json_path: Optional[Path],
    ):
        super().__init__()
        self.title("Telemetry Config Editor (sedsnet)")
        self.geometry("1200x760")

        self.crate_root = crate_root
        self.config_rs_path = config_rs
        self.scope_var = tk.StringVar(value=SCHEMA_SCOPE_BASE)
        self.config_objs: Dict[str, Dict[str, Any]] = {
            SCHEMA_SCOPE_BASE: default_blank_config(),
            SCHEMA_SCOPE_IPC: default_blank_config(),
        }
        self.json_paths: Dict[str, Optional[Path]] = {
            SCHEMA_SCOPE_BASE: base_json_path,
            SCHEMA_SCOPE_IPC: ipc_json_path,
        }
        self.status_var = tk.StringVar(value="")
        self.base_json_path_var = tk.StringVar(value=self._json_path_display(SCHEMA_SCOPE_BASE))
        self.ipc_json_path_var = tk.StringVar(value=self._json_path_display(SCHEMA_SCOPE_IPC))

        # HASH-BASED dirty state
        self._saved_hashes: Dict[str, str] = {
            SCHEMA_SCOPE_BASE: "",
            SCHEMA_SCOPE_IPC: "",
        }
        self._cur_hashes: Dict[str, str] = {
            SCHEMA_SCOPE_BASE: "",
            SCHEMA_SCOPE_IPC: "",
        }
        self.dirty_map: Dict[str, bool] = {
            SCHEMA_SCOPE_BASE: False,
            SCHEMA_SCOPE_IPC: False,
        }

        # Live-edit bookkeeping
        self._suspend_live = False
        self._ep_live_job: Optional[str] = None
        self._ty_live_job: Optional[str] = None

        # Active edit indices
        self._ep_edit_idx: Optional[int] = None
        self._ty_edit_idx: Optional[int] = None

        self._build_menu()
        self._build_layout()
        self._bind_shortcuts()
        self._setup_live_edit_traces()

        # Track current tab so we can flush only the tab you're leaving
        self._tab_idx_endpoints = self.nb.index(self.endpoints_tab)
        self._tab_idx_types = self.nb.index(self.types_tab)
        self._active_tab_idx = self.nb.index("current")
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Initial load
        self._load_initial_scope(SCHEMA_SCOPE_BASE)
        self._load_initial_scope(SCHEMA_SCOPE_IPC)
        self.refresh_lists()
        self._set_status_for_scope()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(0, self._bring_to_front)  # type: ignore

    # ---------------- Hash + dirty management ----------------

    def _current_scope(self) -> str:
        scope = self.scope_var.get()
        if scope not in (SCHEMA_SCOPE_BASE, SCHEMA_SCOPE_IPC):
            return SCHEMA_SCOPE_BASE
        return scope

    def _active_config(self) -> Dict[str, Any]:
        return self.config_objs[self._current_scope()]

    def _active_path(self) -> Optional[Path]:
        return self.json_paths[self._current_scope()]

    def _set_active_path(self, path: Optional[Path]):
        scope = self._current_scope()
        self.json_paths[scope] = path
        if scope == SCHEMA_SCOPE_BASE:
            self.base_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_BASE))
        else:
            self.ipc_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_IPC))

    def _scope_label(self, scope: Optional[str] = None) -> str:
        scope = self._current_scope() if scope is None else scope
        return "IPC overlay" if scope == SCHEMA_SCOPE_IPC else "base schema"

    def _load_initial_scope(self, scope: str):
        path = self.json_paths[scope]
        if path and path.exists():
            self.load_from_path(scope, path)
            return
        self.config_objs[scope] = default_blank_config()
        self._reset_saved_hash_to_current(scope)

    def _canonical_bytes(self, scope: Optional[str] = None) -> bytes:
        """
        Stable serialization for hashing.
        - sort_keys=True so dict key ordering doesn't matter.
        - separators minimize whitespace differences.
        - keep list order (endpoints/types order is meaningful).
        """
        cfg = self.config_objs[self._current_scope() if scope is None else scope]
        blob = json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return blob.encode("utf-8")

    def _compute_hash(self, scope: Optional[str] = None) -> str:
        return hashlib.sha256(self._canonical_bytes(scope)).hexdigest()

    def _update_hash_state(self, scope: Optional[str] = None, *, set_status: bool = False):
        scope = self._current_scope() if scope is None else scope
        self._cur_hashes[scope] = self._compute_hash(scope)
        self.dirty_map[scope] = self._cur_hashes[scope] != self._saved_hashes[scope]
        if set_status:
            path = self.json_paths[scope]
            if self.dirty_map[scope]:
                if path:
                    self._set_status(f"{self._scope_label(scope).capitalize()} modified — {path}")
                else:
                    self._set_status(f"{self._scope_label(scope).capitalize()} modified — no JSON path yet")
            else:
                if path:
                    self._set_status(f"{self._scope_label(scope).capitalize()} up to date — {path}")
                else:
                    self._set_status(f"{self._scope_label(scope).capitalize()} up to date")

    def _mark_changed(self):
        self._update_hash_state(set_status=True)

    def _reset_saved_hash_to_current(self, scope: Optional[str] = None):
        scope = self._current_scope() if scope is None else scope
        self._cur_hashes[scope] = self._compute_hash(scope)
        self._saved_hashes[scope] = self._cur_hashes[scope]
        self.dirty_map[scope] = False

    # ---------------- Shortcuts ----------------

    def _bind_shortcuts(self):
        self.bind_all("<Control-s>", lambda _e: self.menu_save())
        self.bind_all("<Control-S>", lambda _e: self.menu_save())
        self.bind_all("<Command-s>", lambda _e: self.menu_save())
        self.bind_all("<Command-S>", lambda _e: self.menu_save())

    # ---------------- Tab switching flush (only tab you leave) ----------------

    def _on_tab_changed(self, _e=None):
        new_idx = self.nb.index("current")
        prev_idx = self._active_tab_idx

        if prev_idx == self._tab_idx_endpoints:
            self._flush_endpoint_only()
        elif prev_idx == self._tab_idx_types:
            self._flush_type_only()

        self._active_tab_idx = new_idx

    # ---------------- Live editing wiring ----------------

    def _setup_live_edit_traces(self):
        self.ep_rust_var.trace_add("write", lambda *_: self._schedule_live_endpoint_apply())  # type: ignore
        self.ep_bm_var.trace_add("write", lambda *_: self._schedule_live_endpoint_apply())  # type: ignore
        self.ep_doc_text.bind("<<Modified>>", self._on_ep_doc_modified)

        self.ty_rust_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_class_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_kind_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_dtype_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_count_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_reliable_mode_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_priority_var.trace_add("write", lambda *_: self._schedule_live_type_apply())  # type: ignore
        self.ty_doc_text.bind("<<Modified>>", self._on_ty_doc_modified)

    def _on_ep_doc_modified(self, _e=None):
        try:
            if self.ep_doc_text.edit_modified():
                self.ep_doc_text.edit_modified(False)
                self._schedule_live_endpoint_apply()
        except Exception:
            pass

    def _on_ty_doc_modified(self, _e=None):
        try:
            if self.ty_doc_text.edit_modified():
                self.ty_doc_text.edit_modified(False)
                self._schedule_live_type_apply()
        except Exception:
            pass

    def _flush_endpoint_only(self):
        try:
            if self._ep_live_job:
                self.after_cancel(self._ep_live_job)
                self._ep_live_job = None
        except Exception:
            pass
        self._live_apply_endpoint()

    def _flush_type_only(self):
        try:
            if self._ty_live_job:
                self.after_cancel(self._ty_live_job)
                self._ty_live_job = None
        except Exception:
            pass
        self._live_apply_type()

    def _flush_all_pending(self):
        self._flush_endpoint_only()
        self._flush_type_only()

    def _schedule_live_endpoint_apply(self):
        if self._suspend_live:
            return
        if self._ep_live_job:
            try:
                self.after_cancel(self._ep_live_job)
            except Exception:
                pass
        self._ep_live_job = self.after(150, self._live_apply_endpoint)  # type: ignore

    def _schedule_live_type_apply(self):
        if self._suspend_live:
            return
        if self._ty_live_job:
            try:
                self.after_cancel(self._ty_live_job)
            except Exception:
                pass
        self._ty_live_job = self.after(150, self._live_apply_type)  # type: ignore

    # ---------------- List row updates (no rebuild = no jump) ----------------

    # ---------------- Debounced applies (apply to active edit idx) ----------------

    def _live_apply_endpoint(self):
        self._ep_live_job = None
        if self._suspend_live:
            return
        idx = self._ep_edit_idx
        if idx is None:
            return
        cfg = self._active_config()
        eps = cfg.get("endpoints", [])
        if idx < 0 or idx >= len(eps):
            return

        ep = eps[idx]
        before = self._compute_hash()

        old_rust = str(ep.get("rust", ""))
        new_rust = self.ep_rust_var.get().strip()
        new_bm = (self.ep_bm_var.get() or "Default").strip()
        new_doc = self.ep_doc_text.get("1.0", tk.END).strip()

        if new_rust and _is_reserved_telemetry_error(new_rust):
            self._set_status("TelemetryError endpoint is built-in and cannot be added.")
            self._suspend_live = True
            try:
                self.ep_rust_var.set(old_rust)
            finally:
                self._suspend_live = False
            return
        if new_rust and not ensure_rust_ident(new_rust):
            return
        if new_bm not in BROADCAST_MODE_OPTIONS:
            return

        if new_rust:
            ep["rust"] = new_rust
            ep["name"] = rust_ident_to_schema_name(new_rust)
        ep["doc"] = new_doc
        ep["broadcast_mode"] = new_bm
        if self._current_scope() == SCHEMA_SCOPE_IPC:
            ep["link_local_only"] = True
        else:
            ep.pop("link_local_only", None)

        rename_map = None
        if old_rust and new_rust and old_rust != new_rust:
            rename_map = {old_rust: new_rust}
        self._sync_type_endpoints_to_known(rename_map=rename_map)

        after = self._compute_hash()
        if after != before:
            self._mark_changed()

        _update_listbox_row(self.endpoint_list, idx, _endpoint_row_text(ep))
        self._refresh_type_editor_if_selected()

    def _live_apply_type(self):
        self._ty_live_job = None
        if self._suspend_live:
            return
        idx = self._ty_edit_idx
        if idx is None:
            return
        cfg = self._active_config()
        tys = cfg.get("types", [])
        if idx < 0 or idx >= len(tys):
            return

        ty = tys[idx]
        before = self._compute_hash()

        sel_eps = _lb_all(self.ty_selected_endpoints)
        known_eps = {ep.get("rust", "") for ep in cfg.get("endpoints", []) if ep.get("rust", "")}

        new_rust = self.ty_rust_var.get().strip()
        new_class = (self.ty_class_var.get() or "Data").strip()
        new_kind = (self.ty_kind_var.get() or "Static").strip()
        new_dtype = (self.ty_dtype_var.get() or DATA_TYPE_OPTIONS[0]).strip()
        new_doc = self.ty_doc_text.get("1.0", tk.END).strip()
        new_reliable_mode = (self.ty_reliable_mode_var.get() or "None").strip()
        new_priority_s = (self.ty_priority_var.get() or "0").strip()

        if new_rust and _is_reserved_telemetry_error(new_rust):
            self._set_status("TelemetryError data type is built-in and cannot be added.")
            self._suspend_live = True
            try:
                self.ty_rust_var.set(ty.get("rust", ""))
            finally:
                self._suspend_live = False
            return
        if new_rust and not ensure_rust_ident(new_rust):
            return
        if new_class not in MESSAGE_CLASS_OPTIONS:
            return
        if new_kind not in ELEMENT_KIND_OPTIONS:
            return
        if new_dtype not in DATA_TYPE_OPTIONS:
            return
        if new_reliable_mode not in RELIABLE_MODE_OPTIONS:
            return
        try:
            new_priority = int(new_priority_s)
        except Exception:
            return
        if new_priority < 0 or new_priority > MAX_TYPE_PRIORITY:
            return

        element: Dict[str, Any] = {"kind": new_kind, "data_type": new_dtype}
        if new_kind == "Static":
            cnt_s = self.ty_count_var.get().strip()
            if cnt_s == "":
                return
            try:
                cnt = int(cnt_s)
            except Exception:
                return
            if cnt < 0:
                return
            element["count"] = cnt

        if new_rust:
            ty["rust"] = new_rust
            ty["name"] = rust_ident_to_schema_name(new_rust)
        ty["doc"] = new_doc
        ty["reliable_mode"] = new_reliable_mode
        ty["reliable"] = new_reliable_mode != "None"
        ty["priority"] = new_priority
        ty["class"] = new_class
        ty["element"] = element
        ty["endpoints"] = [e for e in sel_eps if e in known_eps]

        after = self._compute_hash()
        if after != before:
            self._mark_changed()

        _update_listbox_row(self.type_list, idx, _type_row_text(ty))

    # ---------------- Window bring-to-front ----------------

    def _bring_to_front(self):
        try:
            self.lift()
            self.attributes("-topmost", True)
            self.focus_force()
            self.after(100, lambda: self.attributes("-topmost", False))  # type: ignore
        except Exception:
            try:
                self.lift()
                self.focus_force()
            except Exception:
                pass

    def _json_path_display(self, scope: str) -> str:
        path = self.json_paths[scope]
        if path is None:
            return "(not set)"
        return str(path)

    def _set_status_for_scope(self):
        scope = self._current_scope()
        path = self.json_paths[scope]
        if self.dirty_map[scope]:
            if path:
                self._set_status(f"Editing {self._scope_label(scope)} — modified — {path}")
            else:
                self._set_status(f"Editing {self._scope_label(scope)} — modified — no JSON path yet")
            return
        if path:
            self._set_status(f"Editing {self._scope_label(scope)} — {path}")
        else:
            self._set_status(f"Editing {self._scope_label(scope)} — no JSON path yet")

    # ---------------- UI scaffolding ----------------

    def _build_menu(self):
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Open Base JSON…", command=lambda: self.menu_open_json(SCHEMA_SCOPE_BASE))
        filem.add_command(label="Open IPC JSON…", command=lambda: self.menu_open_json(SCHEMA_SCOPE_IPC))
        filem.add_separator()
        filem.add_command(label="Save Current", command=self.menu_save, accelerator="Ctrl/Cmd+S")
        filem.add_command(label="Save Current As…", command=self.menu_save_as)
        filem.add_command(label="Save Base", command=lambda: self.menu_save_scope(SCHEMA_SCOPE_BASE))
        filem.add_command(label="Save IPC", command=lambda: self.menu_save_scope(SCHEMA_SCOPE_IPC))
        filem.add_separator()
        filem.add_command(label="Re-scan base path from config.rs", command=self.menu_rescan_base)
        filem.add_command(label="Re-scan IPC path from env", command=self.menu_rescan_ipc)
        filem.add_separator()
        filem.add_command(label="Quit", command=self.on_close)
        menubar.add_cascade(label="File", menu=filem)
        self.config(menu=menubar)

    def _build_layout(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="both", expand=True)

        hdr = ttk.Frame(top)
        hdr.pack(fill="x")

        ttk.Label(hdr, text="crate root:").pack(side="left")
        ttk.Label(hdr, text=str(self.crate_root), foreground="gray").pack(side="left", padx=(6, 14))

        ttk.Label(hdr, text="config.rs:").pack(side="left")
        ttk.Label(hdr, text=str(self.config_rs_path), foreground="gray").pack(side="left", padx=(6, 14))

        ttk.Label(hdr, text="base json:").pack(side="left")
        ttk.Label(hdr, textvariable=self.base_json_path_var, foreground="gray").pack(
            side="left", padx=(6, 14)
        )

        ttk.Label(hdr, text="ipc json:").pack(side="left")
        ttk.Label(hdr, textvariable=self.ipc_json_path_var, foreground="gray").pack(
            side="left", padx=(6, 14)
        )

        scope = ttk.Frame(top)
        scope.pack(fill="x", pady=(10, 0))
        ttk.Label(scope, text="Editing:").pack(side="left")
        ttk.Radiobutton(
            scope,
            text="Base schema",
            value=SCHEMA_SCOPE_BASE,
            variable=self.scope_var,
            command=self.on_scope_changed,
        ).pack(side="left", padx=(8, 0))
        ttk.Radiobutton(
            scope,
            text="IPC overlay",
            value=SCHEMA_SCOPE_IPC,
            variable=self.scope_var,
            command=self.on_scope_changed,
        ).pack(side="left", padx=(8, 0))

        nb = ttk.Notebook(top)
        nb.pack(fill="both", expand=True, pady=(10, 0))
        self.nb = nb

        self.endpoints_tab = ttk.Frame(nb, padding=10)
        self.types_tab = ttk.Frame(nb, padding=10)
        nb.add(self.endpoints_tab, text="Endpoints")
        nb.add(self.types_tab, text="Data Types")

        self._build_endpoints_tab(self.endpoints_tab)
        self._build_types_tab(self.types_tab)

        status = ttk.Frame(self, padding=(10, 6))
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")

    # ---------------- Endpoints tab ----------------

    def _build_endpoints_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=2)
        parent.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(parent, text="Endpoints", padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        btns = ttk.Frame(left)
        btns.grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Add", command=self.add_endpoint).pack(side="left")
        ttk.Button(btns, text="Delete", command=self.delete_endpoint).pack(side="left", padx=6)

        self.endpoint_list = tk.Listbox(left, exportselection=False)
        self.endpoint_list.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.endpoint_list.bind("<<ListboxSelect>>", lambda _e: self.on_select_endpoint())

        right = ttk.LabelFrame(parent, text="Edit Endpoint (live)", padding=10)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)

        ttk.Label(right, text="Name (PascalCase):").grid(row=0, column=0, sticky="w")
        self.ep_rust_var = tk.StringVar()
        vcmd = (self.register(_is_valid_rust_ident_input), "%P")
        self.ep_rust_entry = ttk.Entry(
            right,
            textvariable=self.ep_rust_var,
            validate="key",
            validatecommand=vcmd,
        )
        self.ep_rust_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        ttk.Label(right, text="Doc (optional):").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.ep_doc_text = tk.Text(right, height=5)
        self.ep_doc_text.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        ttk.Label(right, text="Broadcast mode:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.ep_bm_var = tk.StringVar(value="Default")
        ttk.Combobox(
            right, textvariable=self.ep_bm_var, values=BROADCAST_MODE_OPTIONS, state="readonly"
        ).grid(row=2, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        ttk.Label(
            right,
            text="Link-local scope is derived automatically from the active file.",
            foreground="gray",
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        ttk.Label(
            right,
            text="Edits apply in-memory automatically. Use Ctrl/Cmd+S to write JSON.",
            foreground="gray",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(14, 0))

    # ---------------- Types tab ----------------

    def _build_types_tab(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=2)
        parent.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(parent, text="Data Types", padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        btns = ttk.Frame(left)
        btns.grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Add", command=self.add_type).pack(side="left")
        self.type_delete_btn = ttk.Button(btns, text="Delete", command=self.delete_type)
        self.type_delete_btn.pack(side="left", padx=6)

        self.type_list = tk.Listbox(left, exportselection=False)
        self.type_list.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.type_list.bind("<<ListboxSelect>>", lambda _e: self.on_select_type())

        right = ttk.LabelFrame(parent, text="Edit Data Type (live)", padding=10)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)

        ttk.Label(right, text="Name (PascalCase):").grid(row=0, column=0, sticky="w")
        self.ty_rust_var = tk.StringVar()
        vcmd = (self.register(_is_valid_rust_ident_input), "%P")
        self.ty_rust_entry = ttk.Entry(
            right,
            textvariable=self.ty_rust_var,
            validate="key",
            validatecommand=vcmd,
        )
        self.ty_rust_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        ttk.Label(right, text="Class:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.ty_class_var = tk.StringVar(value="Data")
        self.ty_class_combo = ttk.Combobox(
            right, textvariable=self.ty_class_var, values=MESSAGE_CLASS_OPTIONS, state="readonly"
        )
        self.ty_class_combo.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        ttk.Label(right, text="Element kind:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.ty_kind_var = tk.StringVar(value="Static")
        self.ty_kind_combo = ttk.Combobox(
            right, textvariable=self.ty_kind_var, values=ELEMENT_KIND_OPTIONS, state="readonly"
        )
        self.ty_kind_combo.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=(10, 0))
        self.ty_kind_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_count_visibility())

        ttk.Label(right, text="Element data type:").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.ty_dtype_var = tk.StringVar(value=DATA_TYPE_OPTIONS[0])
        self.ty_dtype_combo = ttk.Combobox(
            right, textvariable=self.ty_dtype_var, values=DATA_TYPE_OPTIONS, state="readonly"
        )
        self.ty_dtype_combo.grid(row=3, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        self.ty_count_label = ttk.Label(right, text="Static count (for Static only):")
        self.ty_count_label.grid(row=4, column=0, sticky="nw", pady=(10, 0))
        self.ty_count_var = tk.StringVar(value="1")
        self.ty_count_entry = ttk.Entry(right, textvariable=self.ty_count_var, width=10)
        self.ty_count_entry.grid(row=4, column=1, sticky="nw", padx=(10, 0), pady=(10, 0))

        ttk.Label(right, text="Reliable mode:").grid(row=5, column=0, sticky="w", pady=(10, 0))
        self.ty_reliable_mode_var = tk.StringVar(value="None")
        self.ty_reliable_mode_combo = ttk.Combobox(
            right,
            textvariable=self.ty_reliable_mode_var,
            values=RELIABLE_MODE_OPTIONS,
            state="readonly",
        )
        self.ty_reliable_mode_combo.grid(
            row=5, column=1, sticky="w", padx=(10, 0), pady=(10, 0)
        )

        ttk.Label(right, text=f"Queue priority (0-{MAX_TYPE_PRIORITY}):").grid(
            row=6, column=0, sticky="w", pady=(10, 0)
        )
        self.ty_priority_var = tk.StringVar(value="0")
        self.ty_priority_entry = ttk.Entry(right, textvariable=self.ty_priority_var, width=10)
        self.ty_priority_entry.grid(row=6, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        ttk.Label(right, text="Doc (optional):").grid(row=7, column=0, sticky="w", pady=(10, 0))
        self.ty_doc_text = tk.Text(right, height=5)
        self.ty_doc_text.grid(row=7, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        epbox = ttk.LabelFrame(right, text="Endpoints for this DataType", padding=8)
        epbox.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=(12, 0))
        epbox.columnconfigure(0, weight=1)
        epbox.columnconfigure(1, weight=0)
        epbox.columnconfigure(2, weight=1)
        epbox.rowconfigure(1, weight=1)

        ttk.Label(epbox, text="Available").grid(row=0, column=0, sticky="w")
        ttk.Label(epbox, text="Selected").grid(row=0, column=2, sticky="w")

        self.ty_available_endpoints = tk.Listbox(epbox, exportselection=False)
        self.ty_available_endpoints.grid(row=1, column=0, sticky="nsew")

        mid_btns = ttk.Frame(epbox)
        mid_btns.grid(row=1, column=1, sticky="ns", padx=8)

        ttk.Button(mid_btns, text="Add →", command=self.type_ep_add).pack(fill="x")
        ttk.Button(mid_btns, text="← Remove", command=self.type_ep_remove).pack(fill="x", pady=(6, 0))
        ttk.Separator(mid_btns, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(mid_btns, text="Add All →", command=self.type_ep_add_all).pack(fill="x")
        ttk.Button(mid_btns, text="← Remove All", command=self.type_ep_remove_all).pack(
            fill="x", pady=(6, 0)
        )

        self.ty_selected_endpoints = tk.Listbox(epbox, exportselection=False)
        self.ty_selected_endpoints.grid(row=1, column=2, sticky="nsew")

        ttk.Label(
            right,
            text="Edits apply in-memory automatically. Use Ctrl/Cmd+S to write JSON.",
            foreground="gray",
        ).grid(row=9, column=0, columnspan=2, sticky="w", pady=(14, 0))

        self._type_lock_widgets = [
            self.ty_rust_entry,
            self.ty_class_combo,
            self.ty_kind_combo,
            self.ty_dtype_combo,
            self.ty_count_entry,
            self.ty_reliable_mode_combo,
            self.ty_priority_entry,
        ]

        self._update_count_visibility()

    def _update_count_visibility(self):
        kind = (self.ty_kind_var.get() or "Static").strip()
        if kind == "Dynamic":
            try:
                self.ty_count_label.grid_remove()
                self.ty_count_entry.grid_remove()
            except Exception:
                pass
            if not self._suspend_live:
                self.ty_count_var.set("")
        else:
            try:
                self.ty_count_label.grid()
                self.ty_count_entry.grid()
            except Exception:
                pass
            if (self.ty_count_var.get() or "").strip() == "":
                self.ty_count_var.set("1")

    # ---------------- Menu actions ----------------

    def on_scope_changed(self):
        self._flush_all_pending()
        self.refresh_lists()
        self._set_status_for_scope()

    def menu_open_json(self, scope: str):
        self._flush_all_pending()
        p = filedialog.askopenfilename(
            title=f"Open {self._scope_label(scope)} JSON",
            initialdir=str(self.crate_root),
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not p:
            return
        self.load_from_path(scope, Path(p).resolve())
        if self._current_scope() == scope:
            self.refresh_lists()

    def menu_save(self):
        if self._active_path() is None:
            self.menu_save_as()
            return
        self.save_to_path(self._current_scope(), self._active_path())

    def menu_save_as(self):
        self._flush_all_pending()
        p = filedialog.asksaveasfilename(
            title=f"Save {self._scope_label()} as…",
            initialdir=str(self.crate_root),
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not p:
            return
        path = Path(p).resolve()
        self.save_to_path(self._current_scope(), path)
        self._set_active_path(path)

    def menu_save_scope(self, scope: str):
        path = self.json_paths[scope]
        if path is None:
            current = self._current_scope()
            try:
                self.scope_var.set(scope)
                self.menu_save_as()
            finally:
                self.scope_var.set(current)
                self.refresh_lists()
            return
        self.save_to_path(scope, path)
        if self._current_scope() == scope:
            self.refresh_lists()

    def menu_rescan_base(self):
        self._flush_all_pending()
        found = find_schema_json_from_config_rs(self.config_rs_path, self.crate_root)
        if found is None:
            self._set_status(
                f"Could not find define_telemetry_schema!(path=...) in {self.config_rs_path}",
            )
            return
        self.json_paths[SCHEMA_SCOPE_BASE] = found
        self.base_json_path_var.set(str(found))
        if found.exists():
            self.load_from_path(SCHEMA_SCOPE_BASE, found)
            if self._current_scope() == SCHEMA_SCOPE_BASE:
                self.refresh_lists()
        else:
            self._set_status(f"Discovered base schema path: {found} (does not exist yet)")

    def menu_rescan_ipc(self):
        self._flush_all_pending()
        found = find_ipc_schema_json()
        self.json_paths[SCHEMA_SCOPE_IPC] = found
        self.ipc_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_IPC))
        if found is None:
            self._set_status("SEDSNET_IPC_SCHEMA_PATH is not set")
            return
        if found.exists():
            self.load_from_path(SCHEMA_SCOPE_IPC, found)
            if self._current_scope() == SCHEMA_SCOPE_IPC:
                self.refresh_lists()
        else:
            self.config_objs[SCHEMA_SCOPE_IPC] = default_blank_config()
            self._reset_saved_hash_to_current(SCHEMA_SCOPE_IPC)
            if self._current_scope() == SCHEMA_SCOPE_IPC:
                self.refresh_lists()
            self._set_status(f"Discovered IPC overlay path: {found} (does not exist yet)")

    # ---------------- Load / save ----------------

    def _normalize_schema_names(self) -> bool:
        changed = False
        cfg = self._active_config()
        for ep in cfg.get("endpoints", []) or []:
            rust = str(ep.get("rust", "")).strip()
            expected = rust_ident_to_schema_name(rust)
            if ep.get("name") != expected:
                ep["name"] = expected
                changed = True
            if self._current_scope() == SCHEMA_SCOPE_IPC:
                if ep.get("link_local_only") is not True:
                    ep["link_local_only"] = True
                    changed = True
            elif "link_local_only" in ep:
                ep.pop("link_local_only", None)
                changed = True

        for ty in cfg.get("types", []) or []:
            rust = str(ty.get("rust", "")).strip()
            expected = rust_ident_to_schema_name(rust)
            if ty.get("name") != expected:
                ty["name"] = expected
                changed = True
        return changed

    def _sync_type_endpoints_to_known(self, rename_map: Optional[Dict[str, str]] = None) -> bool:
        cfg = self._active_config()
        known = {ep.get("rust", "") for ep in cfg.get("endpoints", []) if ep.get("rust", "")}
        changed = False
        for ty in cfg.get("types", []) or []:
            eps = ty.get("endpoints", []) or []
            if not isinstance(eps, list):
                ty["endpoints"] = []
                changed = True
                continue
            new_eps: List[str] = []
            for e in eps:
                if not isinstance(e, str):
                    continue
                mapped = rename_map.get(e, e) if rename_map else e
                if mapped in known and mapped not in new_eps:
                    new_eps.append(mapped)
            if new_eps != eps:
                ty["endpoints"] = new_eps
                changed = True
        return changed

    def load_from_path(self, scope: str, path: Path):
        self._flush_all_pending()
        obj = safe_read_json(path)
        if obj is None:
            self.config_objs[scope] = default_blank_config()
            self.json_paths[scope] = path
            self.base_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_BASE))
            self.ipc_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_IPC))
            if self._current_scope() == scope:
                self.refresh_lists()
            self._reset_saved_hash_to_current(scope)
            self._set_status(f"{self._scope_label(scope).capitalize()} file does not exist: {path}. Starting blank.")
            return

        saved_hash_original = hashlib.sha256(
            json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        prev_scope = self._current_scope()
        self.scope_var.set(scope)
        self.config_objs[scope] = obj
        self.json_paths[scope] = path
        self.base_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_BASE))
        self.ipc_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_IPC))

        # normalize/enforce (may change config)
        self._normalize_schema_names()
        self._sync_type_endpoints_to_known()

        if prev_scope == scope:
            self.refresh_lists()
        self.scope_var.set(prev_scope)

        # baseline is the *loaded file state* (but we normalized/enforced already),
        # so if normalization changed anything, it should be considered unsaved.
        # Achieve that by:
        #  - saved_hash = hash of the ORIGINAL file content
        #  - current_hash = hash after normalize/enforce
        self._saved_hashes[scope] = saved_hash_original
        self._update_hash_state(scope, set_status=False)

        if self.dirty_map[scope]:
            self._set_status(
                f"Loaded {self._scope_label(scope)} {path} (normalized/enforced invariants; please Save)"
            )
        elif self._current_scope() == scope:
            self._set_status(f"Loaded {self._scope_label(scope)} {path}")

    def save_to_path(self, scope: str, path: Path):
        self._flush_all_pending()
        prev_scope = self._current_scope()
        self.scope_var.set(scope)
        self._normalize_schema_names()
        self._sync_type_endpoints_to_known()

        try:
            self.validate_current_config(scope)
        except Exception as e:
            self.scope_var.set(prev_scope)
            messagebox.showerror("Validation error", str(e))
            return

        safe_write_json(path, self._active_config())
        self.json_paths[scope] = path
        self.base_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_BASE))
        self.ipc_json_path_var.set(self._json_path_display(SCHEMA_SCOPE_IPC))

        # after actual save, baseline becomes current
        self._reset_saved_hash_to_current(scope)
        self.scope_var.set(prev_scope)
        self._set_status(f"Saved {self._scope_label(scope)} {path}")

    # ---------------- Helpers ----------------

    def _set_status(self, msg: str):
        self.status_var.set(msg)

    def on_close(self):
        self._flush_all_pending()
        self._update_hash_state(SCHEMA_SCOPE_BASE, set_status=False)
        self._update_hash_state(SCHEMA_SCOPE_IPC, set_status=False)
        if any(self.dirty_map.values()):
            if not messagebox.askyesno("Unsaved changes", "You have unsaved changes. Quit anyway?"):
                return
        self.destroy()

    def validate_current_config(self, scope: Optional[str] = None):
        scope = self._current_scope() if scope is None else scope
        obj = self.config_objs[scope]
        other_scope = SCHEMA_SCOPE_IPC if scope == SCHEMA_SCOPE_BASE else SCHEMA_SCOPE_BASE
        other_obj = self.config_objs[other_scope]
        if "endpoints" not in obj or "types" not in obj:
            raise RuntimeError("JSON must contain top-level keys: endpoints, types")

        other_endpoint_rust = {str(ep.get("rust", "")).strip() for ep in other_obj.get("endpoints", [])}
        other_endpoint_name = {str(ep.get("name", "")).strip() for ep in other_obj.get("endpoints", [])}
        other_type_rust = {str(ty.get("rust", "")).strip() for ty in other_obj.get("types", [])}
        other_type_name = {str(ty.get("name", "")).strip() for ty in other_obj.get("types", [])}

        for i, ep in enumerate(obj["endpoints"]):
            rust = str(ep.get("rust", "")).strip()
            if not ensure_rust_ident(rust):
                raise RuntimeError(f"endpoints[{i}].rust must be Rust ident/PascalCase, got {rust!r}")
            if rust == "TelemetryError":
                raise RuntimeError("TelemetryError endpoint is built-in and must not be defined in the schema")

            expected = rust_ident_to_schema_name(rust)
            name = str(ep.get("name", "")).strip()
            if name != expected:
                raise RuntimeError(
                    f"endpoints[{i}].name must match generated name from rust ({expected!r}), got {name!r}"
                )
            if name == "TELEMETRY_ERROR":
                raise RuntimeError("TelemetryError endpoint is built-in and must not be defined in the schema")
            if rust in other_endpoint_rust:
                raise RuntimeError(
                    f"endpoints[{i}].rust collides with {self._scope_label(other_scope)} endpoint {rust!r}"
                )
            if name in other_endpoint_name:
                raise RuntimeError(
                    f"endpoints[{i}].name collides with {self._scope_label(other_scope)} endpoint {name!r}"
                )

            bm = ep.get("broadcast_mode", "Default")
            if bm not in BROADCAST_MODE_OPTIONS:
                raise RuntimeError(
                    f"endpoints[{i}].broadcast_mode must be one of {BROADCAST_MODE_OPTIONS}, got {bm!r}"
                )
            ll = ep.get("link_local_only", False)
            if "link_local_only" in ep and not isinstance(ll, bool):
                raise RuntimeError(
                    f"endpoints[{i}].link_local_only must be boolean, got {ll!r}"
                )
            if scope == SCHEMA_SCOPE_IPC and ll is not True:
                raise RuntimeError(
                    f"endpoints[{i}] ({rust}) in the IPC overlay must set link_local_only=true"
                )
            if scope == SCHEMA_SCOPE_BASE and "link_local_only" in ep:
                raise RuntimeError(
                    f"endpoints[{i}] ({rust}) in the base schema must not set link_local_only"
                )

        endpoint_rust_set = {ep.get("rust", "") for ep in obj["endpoints"]}
        endpoint_rust_set.add("TelemetryError")

        for i, ty in enumerate(obj["types"]):
            rust = str(ty.get("rust", "")).strip()
            if not ensure_rust_ident(rust):
                raise RuntimeError(f"types[{i}].rust must be Rust ident/PascalCase, got {rust!r}")
            if rust == "TelemetryError":
                raise RuntimeError("TelemetryError is built-in and must not be defined in the schema")

            expected = rust_ident_to_schema_name(rust)
            name = str(ty.get("name", "")).strip()
            if name != expected:
                raise RuntimeError(
                    f"types[{i}].name must match generated name from rust ({expected!r}), got {name!r}"
                )
            if name == "TELEMETRY_ERROR":
                raise RuntimeError("TelemetryError is built-in and must not be defined in the schema")
            if rust in other_type_rust:
                raise RuntimeError(
                    f"types[{i}].rust collides with {self._scope_label(other_scope)} type {rust!r}"
                )
            if name in other_type_name:
                raise RuntimeError(
                    f"types[{i}].name collides with {self._scope_label(other_scope)} type {name!r}"
                )

            cls = ty.get("class", "")
            if cls not in MESSAGE_CLASS_OPTIONS:
                raise RuntimeError(f"types[{i}].class must be one of {MESSAGE_CLASS_OPTIONS}, got {cls!r}")

            el = ty.get("element", {}) or {}
            kind = el.get("kind", "")
            if kind not in ELEMENT_KIND_OPTIONS:
                raise RuntimeError(f"types[{i}].element.kind must be one of {ELEMENT_KIND_OPTIONS}, got {kind!r}")

            dt = el.get("data_type", "")
            if dt not in DATA_TYPE_OPTIONS:
                raise RuntimeError(f"types[{i}].element.data_type must be one of DATA_TYPE_OPTIONS, got {dt!r}")

            if kind == "Static":
                cnt = el.get("count", None)
                if cnt is None:
                    raise RuntimeError(f"types[{i}].element.count is required for Static")
                cnti = int(cnt)
                if cnti < 0:
                    raise RuntimeError(f"types[{i}].element.count must be >= 0, got {cnti}")

            if "reliable" in ty and not isinstance(ty.get("reliable"), bool):
                raise RuntimeError(f"types[{i}].reliable must be a boolean")
            if "reliable_mode" in ty:
                rm = ty.get("reliable_mode")
                if not isinstance(rm, str) or rm not in RELIABLE_MODE_OPTIONS:
                    raise RuntimeError(
                        f"types[{i}].reliable_mode must be one of {RELIABLE_MODE_OPTIONS}, got {rm!r}"
                    )
            priority = ty.get("priority", 0)
            try:
                priority_i = int(priority)
            except Exception:
                raise RuntimeError(f"types[{i}].priority must be an integer, got {priority!r}")
            if priority_i < 0 or priority_i > MAX_TYPE_PRIORITY:
                raise RuntimeError(
                    f"types[{i}].priority must be in 0..={MAX_TYPE_PRIORITY}, got {priority_i}"
                )

            eps = ty.get("endpoints", [])
            if not isinstance(eps, list):
                raise RuntimeError(f"types[{i}].endpoints must be list of endpoint rust names")
            for epr in eps:
                if epr not in endpoint_rust_set:
                    raise RuntimeError(
                        f"types[{i}] ({rust}) references unknown endpoint {epr!r}. "
                        f"Known endpoints: {sorted(endpoint_rust_set)}"
                    )
            used_eps = [ep for ep in obj["endpoints"] if ep.get("rust", "") in eps]
            has_link_local = scope == SCHEMA_SCOPE_IPC and bool(used_eps)
            has_non_link_local = scope == SCHEMA_SCOPE_BASE and bool(used_eps)
            if has_link_local and has_non_link_local:
                raise RuntimeError(
                    f"types[{i}] ({rust}) mixes link-local-only and normal endpoints; split it into separate types"
                )

    def refresh_lists(self):
        cfg = self._active_config()
        self._ep_edit_idx = None
        self._ty_edit_idx = None
        self.endpoint_list.delete(0, tk.END)
        for ep in cfg.get("endpoints", []):
            self.endpoint_list.insert(tk.END, _endpoint_row_text(ep))

        self.type_list.delete(0, tk.END)
        for ty in cfg.get("types", []):
            self.type_list.insert(tk.END, _type_row_text(ty))

        self.ty_available_endpoints.delete(0, tk.END)
        for ep in cfg.get("endpoints", []):
            r = ep.get("rust", "")
            if r:
                self.ty_available_endpoints.insert(tk.END, r)

        self.ty_selected_endpoints.delete(0, tk.END)
        self._suspend_live = True
        try:
            self.ep_rust_var.set("")
            self.ep_doc_text.delete("1.0", tk.END)
            self.ep_doc_text.edit_modified(False)
            self.ep_bm_var.set("Default")
            self.ty_rust_var.set("")
            self.ty_class_var.set("Data")
            self.ty_kind_var.set("Static")
            self.ty_dtype_var.set(DATA_TYPE_OPTIONS[0])
            self.ty_count_var.set("1")
            self.ty_reliable_mode_var.set("None")
            self.ty_priority_var.set("0")
            self.ty_doc_text.configure(state="normal")
            self.ty_doc_text.delete("1.0", tk.END)
            self.ty_doc_text.edit_modified(False)
            self._update_count_visibility()
        finally:
            self._suspend_live = False

    # ---------------- Endpoints actions ----------------

    def add_endpoint(self):
        self._flush_endpoint_only()
        rust = "NewEndpoint"
        self._active_config().setdefault("endpoints", []).append(
            {
                "rust": rust,
                "name": rust_ident_to_schema_name(rust),
                "doc": "",
                "broadcast_mode": "Default",
                **({"link_local_only": True} if self._current_scope() == SCHEMA_SCOPE_IPC else {}),
            }
        )
        self.refresh_lists()
        self.endpoint_list.selection_clear(0, tk.END)
        self.endpoint_list.selection_set(tk.END)
        self.on_select_endpoint()
        self._mark_changed()
        self._refresh_type_editor_if_selected()

    def delete_endpoint(self):
        self._flush_endpoint_only()
        idx = _selected_index(self.endpoint_list)
        if idx is None:
            return
        cfg = self._active_config()
        ep = cfg["endpoints"][idx]
        if not messagebox.askyesno("Delete endpoint", f"Delete endpoint {ep.get('rust')}?"):
            return

        removed_rust = ep.get("rust", "")
        del cfg["endpoints"][idx]

        self._sync_type_endpoints_to_known(rename_map={removed_rust: ""})
        self.refresh_lists()
        self._mark_changed()
        self._refresh_type_editor_if_selected()

    def on_select_endpoint(self):
        self._flush_endpoint_only()

        idx = _selected_index(self.endpoint_list)
        if idx is None:
            self._ep_edit_idx = None
            return

        self._ep_edit_idx = idx
        ep = self._active_config()["endpoints"][idx]

        self._suspend_live = True
        try:
            self.ep_rust_var.set(ep.get("rust", ""))
            self.ep_doc_text.delete("1.0", tk.END)
            self.ep_doc_text.insert("1.0", ep.get("doc", "") or "")
            self.ep_doc_text.edit_modified(False)
            self.ep_bm_var.set(ep.get("broadcast_mode", "Default") or "Default")
        finally:
            self._suspend_live = False

    # ---------------- Types actions ----------------

    def add_type(self):
        self._flush_type_only()
        rust = "NewType"
        self._active_config().setdefault("types", []).append(
            {
                "rust": rust,
                "name": rust_ident_to_schema_name(rust),
                "doc": "",
                "reliable": False,
                "reliable_mode": "None",
                "priority": 0,
                "class": "Data",
                "element": {"kind": "Static", "data_type": "Float32", "count": 1},
                "endpoints": [],
            }
        )
        self.refresh_lists()
        self.type_list.selection_clear(0, tk.END)
        self.type_list.selection_set(tk.END)
        self.on_select_type()
        self._mark_changed()

    def delete_type(self):
        self._flush_type_only()
        idx = _selected_index(self.type_list)
        if idx is None:
            idx = self._ty_edit_idx
        if idx is None:
            return
        cfg = self._active_config()
        if idx < 0 or idx >= len(cfg.get("types", [])):
            return
        ty = cfg["types"][idx]
        if not messagebox.askyesno("Delete type", f"Delete type {ty.get('rust')}?"):
            return
        del cfg["types"][idx]
        self.refresh_lists()
        self._mark_changed()

    def on_select_type(self):
        self._flush_type_only()

        idx = _selected_index(self.type_list)
        if idx is None:
            self._ty_edit_idx = None
            return

        self._ty_edit_idx = idx
        cfg = self._active_config()
        ty = cfg["types"][idx]

        self._suspend_live = True
        try:
            self.ty_rust_var.set(ty.get("rust", ""))
            self.ty_class_var.set(ty.get("class", "Data") or "Data")

            el = ty.get("element", {}) or {}
            kind = el.get("kind", "Static") or "Static"
            dt = el.get("data_type", DATA_TYPE_OPTIONS[0]) or DATA_TYPE_OPTIONS[0]
            self.ty_kind_var.set(kind if kind in ELEMENT_KIND_OPTIONS else "Static")
            self.ty_dtype_var.set(dt if dt in DATA_TYPE_OPTIONS else DATA_TYPE_OPTIONS[0])
            reliable_mode = ty.get("reliable_mode", "")
            if not reliable_mode:
                reliable_mode = "Ordered" if bool(ty.get("reliable", False)) else "None"
            if reliable_mode not in RELIABLE_MODE_OPTIONS:
                reliable_mode = "None"
            self.ty_reliable_mode_var.set(reliable_mode)
            self.ty_priority_var.set(str(int(ty.get("priority", 0) or 0)))

            if kind == "Static":
                self.ty_count_var.set(str(el.get("count", 1)))
            else:
                self.ty_count_var.set("")

            self.ty_doc_text.configure(state="normal")
            self.ty_doc_text.delete("1.0", tk.END)
            self.ty_doc_text.insert("1.0", ty.get("doc", "") or "")
            self.ty_doc_text.edit_modified(False)

            self._update_count_visibility()

            selected = ty.get("endpoints", []) or []
            selected_set = set(selected)
            all_eps = [ep.get("rust", "") for ep in cfg.get("endpoints", []) if ep.get("rust", "")]
            available = [e for e in all_eps if e not in selected_set]

            self.ty_available_endpoints.delete(0, tk.END)
            for e in available:
                self.ty_available_endpoints.insert(tk.END, e)

            self.ty_selected_endpoints.delete(0, tk.END)
            for e in selected:
                self.ty_selected_endpoints.insert(tk.END, e)

        finally:
            self._suspend_live = False

    def _refresh_type_editor_if_selected(self):
        if self._ty_edit_idx is None:
            return
        if self._ty_edit_idx < 0 or self._ty_edit_idx >= len(self._active_config().get("types", [])):
            return
        idx = self._ty_edit_idx
        try:
            self.type_list.selection_clear(0, tk.END)
            self.type_list.selection_set(idx)
        except Exception:
            pass
        self.on_select_type()

    # ---------------- Dual listbox helpers ----------------

    def _type_endpoints_changed(self):
        if self._suspend_live:
            return
        self._schedule_live_type_apply()

    def type_ep_add(self):
        items = _lb_selected(self.ty_available_endpoints)
        _lb_remove_items(self.ty_available_endpoints, items)
        _lb_add_unique(self.ty_selected_endpoints, items)
        self._type_endpoints_changed()

    def type_ep_remove(self):
        items = _lb_selected(self.ty_selected_endpoints)
        _lb_remove_items(self.ty_selected_endpoints, items)
        _lb_add_unique(self.ty_available_endpoints, items)
        self._type_endpoints_changed()

    def type_ep_add_all(self):
        items = _lb_all(self.ty_available_endpoints)
        self.ty_available_endpoints.delete(0, tk.END)
        _lb_add_unique(self.ty_selected_endpoints, items)
        self._type_endpoints_changed()

    def type_ep_remove_all(self):
        items = _lb_all(self.ty_selected_endpoints)
        self.ty_selected_endpoints.delete(0, tk.END)
        _lb_add_unique(self.ty_available_endpoints, items)
        self._type_endpoints_changed()


def main():
    start = Path(__file__).resolve().parent
    crate_root = find_project_root(start)

    config_rs = crate_root / "src" / "config.rs"
    if not config_rs.exists():
        if len(sys.argv) >= 2:
            config_rs = Path(sys.argv[1]).resolve()
            crate_root = find_project_root(config_rs)

    base_json_path = None
    ipc_json_path = find_ipc_schema_json()
    if config_rs.exists():
        try:
            base_json_path = find_schema_json_from_config_rs(config_rs, crate_root)
        except Exception as e:
            print(f"warning: {e}", file=sys.stderr)
            base_json_path = None

    app = TelemetryConfigEditor(
        crate_root=crate_root,
        config_rs=config_rs,
        base_json_path=base_json_path,
        ipc_json_path=ipc_json_path,
    )
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nexiting...")
        exit(0)
    except tk.TclError as e:
        print(f"error: Failed to start Tk UI: {e}", file=sys.stderr)
        print(
            "hint: Ensure a desktop display is available and Tk is properly installed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from e
    except Exception as e:
        print(f"error: Unexpected failure in telemetry config editor: {e}", file=sys.stderr)
        raise SystemExit(1) from e
