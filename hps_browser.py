# hps_browser.py (versão corrigida e otimizada)
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import asyncio
import aiohttp
import socketio
import json
import os
import hashlib
import base64
import time
import threading
import uuid
from pathlib import Path
import mimetypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import tempfile
import webbrowser
from PIL import Image, ImageTk
import io
import logging
import qrcode
from io import BytesIO
import socket
import random
import secrets
from datetime import datetime, timedelta
import math
import struct
import sqlite3
import ssl
import subprocess
import platform
import difflib
import re
import multiprocessing
import queue

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HPS-Browser")

def _leading_zero_bits(h: bytes) -> int:
    count = 0
    for byte in h:
        if byte == 0:
            count += 8
        else:
            count += bin(byte)[2:].zfill(8).index('1')
            break
    return count

def _pow_worker(challenge_bytes: bytes, target_bits: int, start_nonce: int, step: int, stop_event, result_queue):
    nonce = start_nonce
    while not stop_event.is_set():
        data = challenge_bytes + struct.pack(">Q", nonce)
        hash_result = hashlib.sha256(data).digest()
        if _leading_zero_bits(hash_result) >= target_bits:
            try:
                result_queue.put_nowait(nonce)
            except Exception:
                pass
            stop_event.set()
            return
        nonce += step

def create_scrollable_container(parent, padding=None):
    container = ttk.Frame(parent)
    canvas = tk.Canvas(container, highlightthickness=0)
    scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
    h_scrollbar = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=canvas.xview)
    content = ttk.Frame(canvas, padding=padding) if padding else ttk.Frame(canvas)
    content_id = canvas.create_window((0, 0), window=content, anchor="nw")

    canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)

    def can_scroll_y():
        bbox = canvas.bbox("all")
        if not bbox:
            return False
        content_height = bbox[3] - bbox[1]
        return content_height > canvas.winfo_height()

    def can_scroll_x():
        bbox = canvas.bbox("all")
        if not bbox:
            return False
        content_width = bbox[2] - bbox[0]
        return content_width > canvas.winfo_width()

    def update_scrollbars():
        if can_scroll_y():
            scrollbar.state(["!disabled"])
        else:
            scrollbar.state(["disabled"])
            canvas.yview_moveto(0)
        if can_scroll_x():
            h_scrollbar.state(["!disabled"])
        else:
            h_scrollbar.state(["disabled"])
            canvas.xview_moveto(0)

    def on_content_configure(_event):
        canvas.configure(scrollregion=canvas.bbox("all"))
        update_scrollbars()

    def on_canvas_configure(event):
        content_width = max(event.width, content.winfo_reqwidth())
        canvas.itemconfigure(content_id, width=content_width)
        update_scrollbars()

    content.bind("<Configure>", on_content_configure)
    canvas.bind("<Configure>", on_canvas_configure)

    container.columnconfigure(0, weight=1)
    container.rowconfigure(0, weight=1)
    canvas.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
    scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
    h_scrollbar.grid(row=1, column=0, columnspan=2, sticky=(tk.E, tk.W))

    bind_scroll_events(container, canvas, can_scroll_y, can_scroll_x)
    container.after(0, update_scrollbars)
    return container, content

def bind_scroll_events(widget, canvas, can_scroll, can_scroll_x=None):
    def on_mousewheel(event):
        is_shift = bool(getattr(event, "state", 0) & 0x0001)
        if is_shift and can_scroll_x:
            if not can_scroll_x():
                return
            if event.num == 4:
                canvas.xview_scroll(-1, "units")
                return
            if event.num == 5:
                canvas.xview_scroll(1, "units")
                return
            if event.delta:
                canvas.xview_scroll(int(-1 * (event.delta / 120)), "units")
            return
        if not can_scroll():
            return
        if event.num == 4:
            canvas.yview_scroll(-1, "units")
            return
        if event.num == 5:
            canvas.yview_scroll(1, "units")
            return
        if event.delta:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def on_enter(_event):
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_mousewheel)
        canvas.bind_all("<Button-5>", on_mousewheel)

    def on_leave(_event):
        canvas.unbind_all("<MouseWheel>")
        canvas.unbind_all("<Button-4>")
        canvas.unbind_all("<Button-5>")

    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

class ContentSecurityDialog:
    def __init__(self, parent, content_info, browser_instance):
        self.window = tk.Toplevel(parent)
        self.window.title("Verificação de Segurança")
        self.window.geometry("700x600")
        self.window.transient(parent)
        self.window.grab_set()
        self.browser = browser_instance

        if content_info.get('contract_blocked'):
            container, main_frame = create_scrollable_container(self.window, padding="15")
            container.pack(fill=tk.BOTH, expand=True)
            ttk.Label(
                main_frame,
                text="STATUS DE SEGURANCA INDISPONIVEL\nQuebra de contrato detectada.",
                foreground="red",
                font=("Arial", 12, "bold")
            ).pack(pady=20)
            ttk.Button(main_frame, text="Fechar", command=self.window.destroy).pack(pady=10)
            return
        
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Verificação de Segurança do Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=10)
        
        verified = content_info.get('verified', False)
        integrity_ok = content_info.get('integrity_ok', True)
        
        if not integrity_ok:
            status_text = "CONTEÚDO ADULTERADO"
            status_color = "red"
        elif verified:
            status_text = "CONTEÚDO VERIFICADO"
            status_color = "green"
        else:
            status_text = "CONTEÚDO NÃO VERIFICADO"
            status_color = "orange"
            
        ttk.Label(status_frame, text=status_text, foreground=status_color, font=("Arial", 12, "bold")).pack()
        
        details_frame = ttk.LabelFrame(main_frame, text="Detalhes do Conteúdo", padding="10")
        details_frame.pack(fill=tk.X, pady=10)
        
        info_grid = ttk.Frame(details_frame)
        info_grid.pack(fill=tk.X)
        
        details = [
            ("Título:", content_info.get('title', 'N/A')),
            ("Autor:", content_info.get('username', 'N/A')),
            ("Dono:", content_info.get('original_owner') or content_info.get('username', 'N/A')),
            ("Hash:", content_info.get('content_hash', 'N/A')),
            ("Tipo MIME:", content_info.get('mime_type', 'N/A')),
            ("Reputação do Autor:", str(content_info.get('reputation', 100))),
            ("Origem:", "Rede P2P"),
        ]
        
        for i, (label, value) in enumerate(details):
            ttk.Label(info_grid, text=label, font=("Arial", 9, "bold")).grid(row=i, column=0, sticky=tk.W, pady=2, padx=5)
            ttk.Label(info_grid, text=value, font=("Arial", 9)).grid(row=i, column=1, sticky=tk.W, pady=2, padx=5)

        certifier = content_info.get('certifier', '')
        if certifier:
            cert_frame = ttk.Frame(details_frame)
            cert_frame.pack(fill=tk.X, pady=(6, 0))
            ttk.Label(cert_frame, text="Certificador:", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=5)
            cert_button = ttk.Button(cert_frame, text=certifier, command=lambda: self.show_certifier_info(certifier))
            cert_button.pack(side=tk.LEFT, padx=5)
            
        sig_frame = ttk.LabelFrame(main_frame, text="Assinatura Digital", padding="10")
        sig_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(sig_frame, text="Chave Pública do Autor:").pack(anchor=tk.W)
        pub_key_text = scrolledtext.ScrolledText(sig_frame, height=4)
        pub_key_text.pack(fill=tk.X, pady=5)
        pub_key_text.insert(tk.END, content_info.get('public_key', 'N/A'))
        pub_key_text.config(state=tk.DISABLED)
        
        ttk.Label(sig_frame, text="Assinatura:").pack(anchor=tk.W)
        sig_text = scrolledtext.ScrolledText(sig_frame, height=3)
        sig_text.pack(fill=tk.X, pady=5)
        sig_text.insert(tk.END, content_info.get('signature', 'N/A'))
        sig_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Copiar Hash", command=lambda: self.copy_hash(content_info.get('content_hash', ''))).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reportar Conteúdo", command=lambda: self.report_content(content_info)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Abrir com Aplicativo", command=lambda: self.open_with_app(content_info)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

    def copy_hash(self, hash_value):
        self.window.clipboard_clear()
        self.window.clipboard_append(hash_value)
        messagebox.showinfo("Copiado", "Hash copiado para área de transferência")

    def report_content(self, content_info):
        if not self.browser.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar logado para reportar conteúdo.")
            return
            
        if self.browser.reputation < 20:
            messagebox.showwarning("Aviso", "Sua reputação é muito baixa para reportar conteúdo.")
            return
            
        if content_info.get('username') == self.browser.current_user:
            messagebox.showwarning("Aviso", "Você não pode reportar seu próprio conteúdo.")
            return
            
        if messagebox.askyesno("Confirmar Reporte", f"Tem certeza que deseja reportar o conteúdo '{content_info.get('title')}' de '{content_info.get('username')}'?"):
            self.browser.report_content_action(content_info.get('content_hash'), content_info.get('username'))
            self.window.destroy()

    def show_certifier_info(self, certifier):
        messagebox.showinfo(
            "Certificador",
            f"{certifier} certificou este contrato. "
            "Isso significa que houve um problema contratual, mas a situacao foi resolvida "
            "com um novo contrato valido assinado por este certificador."
        )

    def open_with_app(self, content_info):
        try:
            temp_dir = tempfile.gettempdir()
            extension = mimetypes.guess_extension(content_info.get('mime_type', 'application/octet-stream')) or '.dat'
            temp_path = os.path.join(temp_dir, f"{content_info.get('content_hash', 'content')}{extension}")
            
            with open(temp_path, 'wb') as f:
                f.write(content_info['content'])
                
            if platform.system() == "Windows":
                os.startfile(temp_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", temp_path])
            else:
                subprocess.run(["xdg-open", temp_path])
                
            messagebox.showinfo("Sucesso", f"Arquivo aberto com aplicativo padrão")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir arquivo: {e}")

class DomainSecurityDialog:
    def __init__(self, parent, domain_info, browser_instance):
        self.window = tk.Toplevel(parent)
        self.window.title("Seguranca do Dominio")
        self.window.geometry("700x520")
        self.window.transient(parent)
        self.window.update_idletasks()
        try:
            self.window.wait_visibility()
            self.window.grab_set()
        except tk.TclError:
            self.window.after(50, self.window.grab_set)
        self.browser = browser_instance

        if domain_info.get('contract_blocked'):
            container, main_frame = create_scrollable_container(self.window, padding="15")
            container.pack(fill=tk.BOTH, expand=True)
            ttk.Label(
                main_frame,
                text="STATUS DE SEGURANCA INDISPONIVEL\nQuebra de contrato detectada.",
                foreground="red",
                font=("Arial", 12, "bold")
            ).pack(pady=20)
            ttk.Button(main_frame, text="Fechar", command=self.window.destroy).pack(pady=10)
            return

        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Seguranca do Dominio", font=("Arial", 14, "bold")).pack(pady=10)

        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=10)

        verified = domain_info.get('verified', False)
        contract_ok = not domain_info.get('contract_violation', False)
        status_text = "DOMINIO VERIFICADO" if verified and contract_ok else "DOMINIO SEM GARANTIA"
        status_color = "green" if verified and contract_ok else "red"
        ttk.Label(status_frame, text=status_text, foreground=status_color, font=("Arial", 12, "bold")).pack()

        details_frame = ttk.LabelFrame(main_frame, text="Detalhes do Dominio", padding="10")
        details_frame.pack(fill=tk.X, pady=10)

        info_grid = ttk.Frame(details_frame)
        info_grid.pack(fill=tk.X)

        details = [
            ("Dominio:", domain_info.get('domain', 'N/A')),
            ("Hash:", domain_info.get('content_hash', 'N/A')),
            ("Dono:", domain_info.get('original_owner') or domain_info.get('username', 'N/A')),
            ("Certificador:", domain_info.get('certifier', '') or "N/A"),
            ("Verificado:", "Sim" if verified else "Nao"),
        ]

        for i, (label, value) in enumerate(details):
            ttk.Label(info_grid, text=label, font=("Arial", 9, "bold")).grid(row=i, column=0, sticky=tk.W, pady=2, padx=5)
            ttk.Label(info_grid, text=value, font=("Arial", 9)).grid(row=i, column=1, sticky=tk.W, pady=2, padx=5)

        contracts = domain_info.get('contracts', []) or []
        contract_frame = ttk.LabelFrame(main_frame, text="Contratos", padding="10")
        contract_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        contract_text = scrolledtext.ScrolledText(contract_frame, height=8)
        contract_text.pack(fill=tk.BOTH, expand=True)
        if not contracts:
            contract_text.insert(tk.END, "Nenhum contrato encontrado para este dominio.")
        else:
            for contract in contracts:
                contract_text.insert(tk.END, f"- {contract.get('action_type')} | {contract.get('contract_id')}\n")
        contract_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

class ContractBlockedDialog:
    def __init__(self, parent, message):
        self.window = tk.Toplevel(parent)
        self.window.title("Acesso Bloqueado por Contrato")
        self.window.geometry("520x260")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.proceed = False
        self._blink_on = True
        self.message = message

        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Conteudo indisponivel", font=("Arial", 12, "bold")).pack(pady=5)
        self.message_label = ttk.Label(
            main_frame,
            text=message,
            foreground="red",
            font=("Arial", 11, "bold"),
            wraplength=460,
            justify="center"
        )
        self.message_label.pack(pady=15)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Continuar", command=self.confirm).pack(side=tk.LEFT, padx=8)
        ttk.Button(button_frame, text="Fechar", command=self.close).pack(side=tk.LEFT, padx=8)

        self._blink()

    def _blink(self):
        if not self.window.winfo_exists():
            return
        self._blink_on = not self._blink_on
        if self._blink_on:
            self.message_label.config(text=self.message)
        else:
            self.message_label.config(text="")
        self.window.after(1000, self._blink)

    def confirm(self):
        self.proceed = True
        self.window.destroy()

    def close(self):
        self.proceed = False
        self.window.destroy()

class SearchDialog:
    def __init__(self, parent, browser):
        self.browser = browser
        self.window = tk.Toplevel(parent)
        self.window.title("Busca Avançada")
        self.window.geometry("600x500")
        self.window.transient(parent)
        self.window.grab_set()
        self.setup_ui()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Busca Avançada", font=("Arial", 14, "bold")).pack(pady=10)
        
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Termo de busca:").pack(anchor=tk.W)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=("Arial", 11))
        search_entry.pack(fill=tk.X, pady=5)
        search_entry.bind('<Return>', lambda e: self.do_search())
        
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(filter_frame, text="Tipo de conteúdo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.type_var = tk.StringVar(value="all")
        type_combo = ttk.Combobox(filter_frame, textvariable=self.type_var, values=["all", "image", "video", "audio", "document", "text"])
        type_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=10)
        
        ttk.Label(filter_frame, text="Ordenar por:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.sort_var = tk.StringVar(value="reputation")
        sort_combo = ttk.Combobox(filter_frame, textvariable=self.sort_var, values=["reputation", "recent", "popular"])
        sort_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=10)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Buscar", command=self.do_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copiar Hash", command=self.copy_selected_hash).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)
        
        self.results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(self.results_frame, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)
        
        self.results_text.tag_configure("title", font=("Arial", 11, "bold"))
        self.results_text.tag_configure("verified", foreground="green")
        self.results_text.tag_configure("unverified", foreground="orange")
        self.results_text.tag_configure("link", foreground="blue", underline=True)
        self.results_text.bind("<Button-1>", self.handle_result_click)

    def do_search(self):
        query = self.search_var.get().strip()
        if not query:
            messagebox.showwarning("Aviso", "Digite um termo para buscar")
            return
            
        asyncio.run_coroutine_threadsafe(self.browser._search_content(query, self.type_var.get(), self.sort_var.get()), self.browser.loop)
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Buscando por: '{query}'")
        self.results_text.config(state=tk.DISABLED)

    def clear_search(self):
        self.search_var.set("")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)

    def handle_result_click(self, event):
        index = self.results_text.index(f"@{event.x},{event.y}")
        for tag in self.results_text.tag_names(index):
            if tag == "link":
                line_start = self.results_text.index(f"{index} linestart")
                line_end = self.results_text.index(f"{index} lineend")
                line_text = self.results_text.get(line_start, line_end)
                import re
                match = re.search(r'hps://(\S+)', line_text)
                if match:
                    url = f"hps://{match.group(1)}"
                    self.browser.browser_url_var.set(url)
                    self.browser.browser_navigate()
                    self.window.destroy()
                break

    def copy_selected_hash(self):
        try:
            index = self.results_text.index(tk.SEL_FIRST)
            line_start = self.results_text.index(f"{index} linestart")
            line_end = self.results_text.index(f"{index} lineend")
            line_text = self.results_text.get(line_start, line_end)
            import re
            match = re.search(r'Hash: (\S+)', line_text)
            if match:
                hash_value = match.group(1)
                self.window.clipboard_clear()
                self.window.clipboard_append(hash_value)
                messagebox.showinfo("Copiado", "Hash copiado para área de transferência")
        except tk.TclError:
            messagebox.showwarning("Aviso", "Selecione um hash para copiar")

class ContractDialog:
    def __init__(self, parent, contract_text, title_suffix="", signer=None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Contrato {title_suffix}".strip())
        self.window.geometry("900x700")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.template_text = contract_text.strip()
        self.current_text = self.template_text
        self.confirmed = False
        self.signer = signer
        self.signed = False
        self.contract_hash_var = tk.StringVar(value="")
        self.summary_var = tk.StringVar(value="")
        self.accept_var = tk.BooleanVar(value=False)
        
        self.setup_ui()
        self.update_diff()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Revisar e Confirmar Contrato", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(
            main_frame,
            text="Confira as informacoes, assine e confirme. Isso protege voce e registra o que sera feito.",
            font=("Arial", 10)
        ).pack(pady=(0, 10))
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text="Hash do contrato:").pack(side=tk.LEFT)
        ttk.Label(info_frame, textvariable=self.contract_hash_var, font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=5)

        summary_frame = ttk.LabelFrame(main_frame, text="Resumo", padding="10")
        summary_frame.pack(fill=tk.X, pady=(5, 10))
        ttk.Label(summary_frame, textvariable=self.summary_var, justify=tk.LEFT).pack(anchor=tk.W)
        
        ttk.Label(main_frame, text="Contrato (editável):", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        self.contract_text = scrolledtext.ScrolledText(main_frame, height=16)
        self.contract_text.pack(fill=tk.BOTH, expand=False)
        self.contract_text.insert(tk.END, self.template_text)
        self.contract_text.bind("<KeyRelease>", lambda e: self.update_diff())
        
        ttk.Label(main_frame, text="Diff (template vs. atual):", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        self.diff_text = scrolledtext.ScrolledText(main_frame, height=12)
        self.diff_text.pack(fill=tk.BOTH, expand=True)
        self.diff_text.config(state=tk.DISABLED)

        ttk.Checkbutton(
            main_frame,
            text="Li e concordo com os termos deste contrato",
            variable=self.accept_var
        ).pack(anchor=tk.W, pady=(8, 0))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT, padx=5)
        self.confirm_button = ttk.Button(button_frame, text="Confirmar", command=self.confirm)
        self.confirm_button.pack(side=tk.LEFT, padx=5)

    def extract_contract_summary(self, contract_text):
        info = {
            "action": None,
            "user": None,
            "target_type": None,
            "target_id": None,
            "domain": None,
            "content_hash": None,
            "transfer_to": None,
            "app": None,
            "title": None
        }
        current_section = None
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    current_section = line[4:-1].lower()
            elif line.startswith("### :END "):
                current_section = None
            elif line.startswith("# "):
                if current_section == "details" and line.startswith("# ACTION:"):
                    info["action"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# TARGET_TYPE:"):
                    info["target_type"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# TARGET_ID:"):
                    info["target_id"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# DOMAIN:"):
                    info["domain"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# CONTENT_HASH:"):
                    info["content_hash"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# TRANSFER_TO:"):
                    info["transfer_to"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# APP:"):
                    info["app"] = line.split(":", 1)[1].strip()
                elif current_section == "details" and line.startswith("# TITLE:"):
                    info["title"] = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# USER:"):
                    info["user"] = line.split(":", 1)[1].strip()
        summary_lines = []
        if info["action"]:
            summary_lines.append(f"Ação: {info['action']}")
        if info["user"]:
            summary_lines.append(f"Usuário: {info['user']}")
        target = None
        if info["target_type"] and info["target_id"]:
            target = f"{info['target_type']} {info['target_id']}"
        elif info["domain"]:
            target = f"domain {info['domain']}"
        elif info["content_hash"]:
            target = f"content {info['content_hash']}"
        if target:
            summary_lines.append(f"Alvo: {target}")
        if info["transfer_to"]:
            summary_lines.append(f"Transferir para: {info['transfer_to']}")
        if info["app"]:
            summary_lines.append(f"App: {info['app']}")
        if info["title"]:
            summary_lines.append(f"Título: {info['title']}")
        return "\n".join(summary_lines) if summary_lines else "Sem detalhes adicionais."

    def update_diff(self):
        self.current_text = self.contract_text.get(1.0, tk.END).strip()
        contract_hash = hashlib.sha256(self.current_text.encode('utf-8')).hexdigest()
        self.contract_hash_var.set(contract_hash)
        self.summary_var.set(self.extract_contract_summary(self.current_text))
        
        template_lines = self.template_text.splitlines()
        current_lines = self.current_text.splitlines()
        diff_lines = difflib.unified_diff(
            template_lines,
            current_lines,
            fromfile="template",
            tofile="atual",
            lineterm=""
        )
        diff_text = "\n".join(diff_lines)
        
        self.diff_text.config(state=tk.NORMAL)
        self.diff_text.delete(1.0, tk.END)
        self.diff_text.insert(tk.END, diff_text if diff_text else "Sem alterações")
        self.diff_text.config(state=tk.DISABLED)

    def confirm(self):
        if not self.current_text.strip():
            messagebox.showwarning("Aviso", "O contrato não pode ficar vazio.")
            return
        if not self.accept_var.get():
            messagebox.showwarning("Aviso", "Confirme que leu e concorda com o contrato.")
            return
        if self.signer and not self.signed:
            try:
                signed_text = self.signer(self.current_text)
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao assinar contrato: {e}")
                return
            self.contract_text.config(state=tk.NORMAL)
            self.contract_text.delete(1.0, tk.END)
            self.contract_text.insert(tk.END, signed_text)
            self.contract_text.config(state=tk.DISABLED)
            self.signed = True
            self.confirm_button.config(text="Continuar")
            self.update_diff()
            messagebox.showinfo("Contrato Assinado", "Contrato assinado. Revise e confirme para continuar.")
            return
        self.confirmed = True
        self.window.destroy()

    def cancel(self):
        self.confirmed = False
        self.window.destroy()

class ContractAnalyzerDialog:
    def __init__(self, parent, summary_lines, contract_text, title="Analisador de Contratos", allow_proceed=False,
                 integrity_ok=True, verify_callback=None, inter_server_verify_callback=None, reissue_callback=None,
                 certify_callback=None, invalidate_callback=None, transfer_accept_callback=None,
                 transfer_reject_callback=None, transfer_renounce_callback=None):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("900x700")
        self.window.transient(parent)
        self.window.update_idletasks()
        try:
            self.window.wait_visibility()
            self.window.grab_set()
        except tk.TclError:
            self.window.after(50, self.window.grab_set)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.allow_proceed = allow_proceed
        self.proceed = False
        self.verify_callback = verify_callback
        self.inter_server_verify_callback = inter_server_verify_callback
        self.reissue_callback = reissue_callback
        self.certify_callback = certify_callback
        self.invalidate_callback = invalidate_callback
        self.transfer_accept_callback = transfer_accept_callback
        self.transfer_reject_callback = transfer_reject_callback
        self.transfer_renounce_callback = transfer_renounce_callback

        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=title, font=("Arial", 14, "bold")).pack(pady=10)
        status_text = "Contrato verificado" if integrity_ok else "Contrato adulterado ou invalido"
        status_color = "green" if integrity_ok else "red"
        ttk.Label(main_frame, text=status_text, foreground=status_color, font=("Arial", 11, "bold")).pack(pady=(0, 8))
        ttk.Label(
            main_frame,
            text="Este painel explica o contrato associado ao arquivo. Leia antes de continuar.",
            font=("Arial", 10)
        ).pack(pady=(0, 10))

        info_frame = ttk.LabelFrame(main_frame, text="Resumo", padding="10")
        info_frame.pack(fill=tk.X, pady=5)

        info_text = scrolledtext.ScrolledText(info_frame, height=8)
        info_text.pack(fill=tk.BOTH, expand=True)
        info_text.insert(tk.END, "\n".join(summary_lines))
        info_text.config(state=tk.DISABLED)

        ttk.Label(main_frame, text="Contrato completo:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        contract_box = scrolledtext.ScrolledText(main_frame, height=18)
        contract_box.pack(fill=tk.BOTH, expand=True)
        contract_box.insert(tk.END, contract_text or "")
        contract_box.config(state=tk.DISABLED)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        if self.verify_callback:
            ttk.Button(button_frame, text="Verificar Agora", command=self.verify).pack(side=tk.LEFT, padx=5)
        if self.inter_server_verify_callback:
            ttk.Button(
                button_frame,
                text="Verificar Assinatura inter-servidor",
                command=self.verify_inter_server
            ).pack(side=tk.LEFT, padx=5)
        if self.reissue_callback:
            ttk.Button(button_frame, text="Emitir Novo Contrato", command=self.reissue).pack(side=tk.LEFT, padx=5)
        if self.certify_callback:
            ttk.Button(button_frame, text="Certificar Contrato", command=self.certify).pack(side=tk.LEFT, padx=5)
        if self.invalidate_callback:
            ttk.Button(button_frame, text="Invalidar Contrato", command=self.invalidate).pack(side=tk.LEFT, padx=5)
        if self.transfer_accept_callback:
            ttk.Button(button_frame, text="Resolver Transferencia", command=self.accept_transfer).pack(side=tk.LEFT, padx=5)
        if self.transfer_reject_callback:
            ttk.Button(button_frame, text="Rejeitar Transferencia", command=self.reject_transfer).pack(side=tk.LEFT, padx=5)
        if self.transfer_renounce_callback:
            ttk.Button(button_frame, text="Renunciar Transferencia", command=self.renounce_transfer).pack(side=tk.LEFT, padx=5)
        if allow_proceed:
            ttk.Button(button_frame, text="Prosseguir", command=self.confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.close).pack(side=tk.LEFT, padx=5)

    def verify(self):
        try:
            if self.verify_callback:
                self.verify_callback()
        finally:
            messagebox.showinfo("Verificacao", "Verificacao solicitada. O contrato sera reaberto atualizado.")
            self.window.destroy()

    def verify_inter_server(self):
        try:
            if self.inter_server_verify_callback:
                self.inter_server_verify_callback()
        finally:
            self.window.destroy()

    def reissue(self):
        if messagebox.askyesno("Confirmar", "Isso vai apagar o registro no servidor e emitir um novo contrato. Continuar?"):
            if self.reissue_callback:
                self.reissue_callback()
            self.window.destroy()

    def certify(self):
        if messagebox.askyesno(
            "Confirmar",
            "Voce esta prestes a registrar um novo contrato para este arquivo. Continuar?"
        ):
            if self.certify_callback:
                self.certify_callback()
            self.window.destroy()

    def invalidate(self):
        if messagebox.askyesno("Confirmar", "Invalidar este contrato remove o registro no servidor. Continuar?"):
            if self.invalidate_callback:
                self.invalidate_callback()
            self.window.destroy()

    def accept_transfer(self):
        if messagebox.askyesno("Confirmar", "Aceitar esta transferencia requer assinatura e envio do contrato. Continuar?"):
            if self.transfer_accept_callback:
                self.transfer_accept_callback()
            self.window.destroy()

    def reject_transfer(self):
        if messagebox.askyesno(
            "Confirmar",
            "Rejeitar esta transferencia devolve ao dono original e pode ir para a custodia se ele renunciar. Continuar?"
        ):
            if self.transfer_reject_callback:
                self.transfer_reject_callback()
            self.window.destroy()

    def renounce_transfer(self):
        if messagebox.askyesno(
            "Confirmar",
            "Renunciar envia esta transferencia para a custodia imediatamente. Continuar?"
        ):
            if self.transfer_renounce_callback:
                self.transfer_renounce_callback()
            self.window.destroy()

    def confirm(self):
        self.proceed = True
        self.window.destroy()

    def close(self):
        self.window.destroy()

class ApiAppNoticeDialog:
    def __init__(self, parent, app_name, is_latest=True):
        self.window = tk.Toplevel(parent)
        self.window.title("API App")
        self.window.geometry("520x280")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.proceed = False
        self.analyze_versions = False

        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="API App Detectado", font=("Arial", 14, "bold")).pack(pady=10)
        status_text = "Esta e a versao mais recente." if is_latest else "Existe uma versao mais recente deste app."
        ttk.Label(main_frame, text=f"App: {app_name}\n{status_text}", font=("Arial", 10)).pack(pady=10)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Prosseguir", command=self.confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Analisar Versoes", command=self.open_versions).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.close).pack(side=tk.LEFT, padx=5)

    def confirm(self):
        self.proceed = True
        self.window.destroy()

    def open_versions(self):
        self.analyze_versions = True
        self.window.destroy()

    def close(self):
        self.window.destroy()

class ApiAppVersionsDialog:
    def __init__(self, parent, app_name, versions, current_hash):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Versoes do API App - {app_name}")
        self.window.geometry("800x520")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.close)

        self.selected_hash = None
        self.proceed_current = False

        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Versoes Disponiveis", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(main_frame, text=f"App: {app_name}", font=("Arial", 10)).pack(pady=(0, 10))

        self.versions_tree = ttk.Treeview(
            main_frame,
            columns=("version", "hash", "user", "timestamp", "action"),
            show="headings",
            height=10
        )
        self.versions_tree.heading("version", text="Versao")
        self.versions_tree.heading("hash", text="Hash")
        self.versions_tree.heading("user", text="Usuario")
        self.versions_tree.heading("timestamp", text="Data")
        self.versions_tree.heading("action", text="Acao")
        self.versions_tree.column("version", width=80)
        self.versions_tree.column("hash", width=200)
        self.versions_tree.column("user", width=120)
        self.versions_tree.column("timestamp", width=140)
        self.versions_tree.column("action", width=120)
        self.versions_tree.pack(fill=tk.BOTH, expand=True)
        self.versions_tree.bind("<Double-1>", lambda e: self.open_selected())

        for version in versions:
            timestamp = version.get('timestamp')
            if timestamp:
                try:
                    timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    timestamp_str = str(timestamp)
            else:
                timestamp_str = ""
            content_hash = version.get('content_hash') or ""
            label = version.get('version_label') or "Upload"
            if content_hash == current_hash:
                label = f"{label} (atual)"
            self.versions_tree.insert("", tk.END, values=(
                label,
                (content_hash[:16] + "...") if content_hash else "",
                version.get('username', ''),
                timestamp_str,
                version.get('action_type', '')
            ), tags=(content_hash,))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Abrir Selecionada", command=self.open_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Prosseguir com Atual", command=self.proceed).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.close).pack(side=tk.LEFT, padx=5)

    def open_selected(self):
        selection = self.versions_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione uma versao para abrir.")
            return
        item = selection[0]
        tags = self.versions_tree.item(item, 'tags')
        if tags:
            self.selected_hash = tags[0]
            self.window.destroy()

    def proceed(self):
        self.proceed_current = True
        self.window.destroy()

    def close(self):
        self.window.destroy()

class PowPopupWindow:
    def __init__(self, parent, action_type="login"):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Prova de Trabalho - {action_type.title()}")
        self.window.geometry("500x400")
        self.window.transient(parent)
        self._grab_attempts = 0
        self.window.after(0, self._safe_grab)
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.action_type = action_type
        self.cancelled = False
        self.start_time = time.time()
        self.setup_ui()

    def _safe_grab(self):
        if not self.window.winfo_exists():
            return
        if self.window.winfo_viewable():
            try:
                self.window.grab_set()
            except tk.TclError:
                return
        else:
            self._grab_attempts += 1
            if self._grab_attempts < 20:
                self.window.after(50, self._safe_grab)

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=f"Resolvendo Prova de Trabalho", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(main_frame, text=f"Ação: {self.action_type.title()}").pack(pady=5)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.status_var = tk.StringVar(value="Iniciando...")
        ttk.Label(info_frame, textvariable=self.status_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Bits Alvo:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.bits_var = tk.StringVar(value="0")
        ttk.Label(info_frame, textvariable=self.bits_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tempo Decorrido:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.time_var = tk.StringVar(value="0.0s")
        ttk.Label(info_frame, textvariable=self.time_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Hashrate:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.hashrate_var = tk.StringVar(value="0 H/s")
        ttk.Label(info_frame, textvariable=self.hashrate_var).grid(row=3, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tentativas:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.attempts_var = tk.StringVar(value="0")
        ttk.Label(info_frame, textvariable=self.attempts_var).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(pady=15)
        self.progress.start()
        
        ttk.Label(main_frame, text="Detalhes:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10,5))
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_status(self, status, bits=None, elapsed_time=None, hashrate=None, attempts=None):
        self.status_var.set(status)
        if bits is not None:
            self.bits_var.set(str(bits))
        if elapsed_time is not None:
            self.time_var.set(f"{elapsed_time:.2f}s")
        if hashrate is not None:
            self.hashrate_var.set(f"{hashrate:.0f} H/s")
        if attempts is not None:
            self.attempts_var.set(str(attempts))
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class UploadProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Upload em Progresso")
        self.window.geometry("450x300")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando upload...")
        self.cancelled = False
        self.setup_ui()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Upload de Arquivo", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Hash:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="Calculando...")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tamanho:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.size_var = tk.StringVar(value="0 bytes")
        ttk.Label(info_frame, textvariable=self.size_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=6, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar Upload", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, hash_value=None, size=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if hash_value:
            self.hash_var.set(f"{hash_value[:20]}...")
        if size:
            self.size_var.set(self.format_size(size))
        self.window.update_idletasks()

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class DDNSProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Processando DNS")
        self.window.geometry("450x300")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando DNS...")
        self.setup_ui()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Registro de DNS", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Domínio:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.domain_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.domain_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Hash do Conteúdo:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=6, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, domain=None, hash_value=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if domain:
            self.domain_var.set(domain)
        if hash_value:
            self.hash_var.set(f"{hash_value[:20]}...")
        self.window.update_idletasks()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class ReportProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Reportando Conteúdo")
        self.window.geometry("500x350")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando reporte...")
        self.cancelled = False
        self.setup_ui()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Reporte de Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Hash do Conteúdo:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Autor Reportado:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.author_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.author_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Sua Reputação:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.reputation_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.reputation_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar Reporte", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, content_hash=None, author=None, reputation=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if content_hash:
            self.hash_var.set(f"{content_hash[:20]}...")
        if author:
            self.author_var.set(author)
        if reputation is not None:
            self.reputation_var.set(str(reputation))
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class PowSolver:
    def __init__(self, browser):
        self.browser = browser
        self.is_solving = False
        self.current_challenge = None
        self.current_target_bits = 0
        self.solution_found = threading.Event()
        self.nonce_solution = None
        self.hashrate_observed = 0.0
        self.current_popup = None
        self.mp_stop_event = None
        self.mp_processes = []

    def leading_zero_bits(self, h: bytes) -> int:
        count = 0
        for byte in h:
            if byte == 0:
                count += 8
            else:
                count += bin(byte)[2:].zfill(8).index('1')
                break
        return count

    def calibrate_hashrate(self, seconds: float = 1.0) -> float:
        message = secrets.token_bytes(16)
        end = time.time() + seconds
        count = 0
        nonce = 0
        
        while time.time() < end:
            data = message + struct.pack(">Q", nonce)
            _ = hashlib.sha256(data).digest()
            nonce += 1
            count += 1
            
        elapsed = seconds
        return count / elapsed if elapsed > 0 else 0.0

    def solve_challenge(self, challenge: str, target_bits: int, target_seconds: float, action_type: str = "login", use_popup: bool = True):
        if self.is_solving:
            return
            
        self.is_solving = True
        self.solution_found.clear()
        self.nonce_solution = None
        self.current_challenge = challenge
        self.current_target_bits = target_bits
        use_popup = use_popup and action_type != "hps_mint"
        if not use_popup:
            self.current_popup = None
        
        def show_popup():
            if not use_popup:
                return
            self.current_popup = PowPopupWindow(self.browser.root, action_type)
            self.current_popup.log_message(f"Desafio recebido: {target_bits} bits")
            self.current_popup.log_message(f"Tempo alvo: {target_seconds:.1f}s")
            
        self.browser.root.after(0, show_popup)
        
        def solve_thread():
            try:
                challenge_bytes = base64.b64decode(challenge)
                start_time = time.time()
                nonce = 0
                hash_count = 0
                last_update = start_time
                
                hashrate = self.calibrate_hashrate(0.5)
                thread_count = max(1, int(self.browser.pow_threads or 1))
                estimated_hashrate = hashrate * thread_count
                self.hashrate_observed = estimated_hashrate
                
                if self.current_popup and self.current_popup.window.winfo_exists():
                    self.browser.root.after(0, lambda: self.current_popup.update_status(f"Resolvendo PoW - {target_bits} bits", bits=target_bits, hashrate=estimated_hashrate))
                    self.browser.root.after(0, lambda: self.current_popup.log_message(f"Iniciando mineração: {target_bits} bits alvo, hashrate estimado: {estimated_hashrate:.0f} H/s"))
                elif action_type == "hps_mint":
                    self.browser.root.after(0, lambda: self.browser.update_hps_mining_status(
                        f"Minerando {target_bits} bits", bits=target_bits, hashrate=estimated_hashrate, attempts=0
                    ))
                    self.browser.root.after(0, lambda: self.browser.log_hps_mining_message(
                        f"Iniciando mineração: {target_bits} bits alvo, hashrate estimado: {estimated_hashrate:.0f} H/s"
                    ))
                
                current_hashrate = 0.0

                if thread_count <= 1:
                    while self.is_solving and time.time() - start_time < 300:
                        if self.current_popup and self.current_popup.cancelled:
                            self.is_solving = False
                            break
                            
                        data = challenge_bytes + struct.pack(">Q", nonce)
                        hash_result = hashlib.sha256(data).digest()
                        hash_count += 1
                        
                        lzb = self.leading_zero_bits(hash_result)
                        
                        current_time = time.time()
                        elapsed = current_time - start_time
                        
                        if current_time - last_update >= 1.0:
                            current_hashrate = hash_count / (current_time - last_update)
                            if self.current_popup and self.current_popup.window.winfo_exists():
                                self.browser.root.after(0, lambda: self.current_popup.update_status(f"Resolvendo... {nonce:,} tentativas", elapsed_time=elapsed, hashrate=current_hashrate, attempts=nonce))
                            elif action_type == "hps_mint":
                                self.browser.root.after(0, lambda: self.browser.update_hps_mining_status(
                                    "Minerando", elapsed_time=elapsed, hashrate=current_hashrate, attempts=nonce
                                ))
                            last_update = current_time
                            hash_count = 0
                        
                        if lzb >= target_bits:
                            solve_time = current_time - start_time
                            self.nonce_solution = str(nonce)
                            self.hashrate_observed = current_hashrate
                            
                            if self.current_popup and self.current_popup.window.winfo_exists():
                                self.browser.root.after(0, lambda: self.current_popup.log_message(f"Solução encontrada! Nonce: {nonce}, tempo: {solve_time:.2f}s"))
                                self.browser.root.after(0, lambda: self.current_popup.update_status("Solução encontrada! Feche esta janela.", elapsed_time=solve_time, hashrate=current_hashrate, attempts=nonce))
                                self.browser.root.after(0, lambda: self.current_popup.log_message("Solução encontrada! Você pode fechar esta janela."))
                            elif action_type == "hps_mint":
                                self.browser.root.after(0, lambda: self.browser.update_hps_mining_status(
                                    "Solução encontrada", elapsed_time=solve_time, hashrate=current_hashrate, attempts=nonce
                                ))
                                self.browser.root.after(0, lambda: self.browser.log_hps_mining_message(
                                    f"Solução encontrada! Nonce: {nonce}, tempo: {solve_time:.2f}s"
                                ))
                                
                            self.browser.root.after(0, lambda: self.browser.pow_solution_found(nonce, solve_time, current_hashrate))
                            self.solution_found.set()
                            break
                        
                        nonce += 1
                        
                        if nonce % 1000 == 0:
                            time.sleep(0)
                        
                        if nonce % 1000 == 0 and not self.is_solving:
                            break
                else:
                    ctx = multiprocessing.get_context("spawn")
                    self.mp_stop_event = ctx.Event()
                    result_queue = ctx.Queue()
                    self.mp_processes = []
                    for worker_id in range(thread_count):
                        process = ctx.Process(
                            target=_pow_worker,
                            args=(challenge_bytes, target_bits, worker_id, thread_count, self.mp_stop_event, result_queue),
                            daemon=True
                        )
                        process.start()
                        self.mp_processes.append(process)

                    while self.is_solving and time.time() - start_time < 300:
                        if self.current_popup and self.current_popup.cancelled:
                            self.is_solving = False
                            break

                        try:
                            found_nonce = result_queue.get_nowait()
                        except queue.Empty:
                            found_nonce = None

                        current_time = time.time()
                        elapsed = current_time - start_time
                        if current_time - last_update >= 1.0:
                            current_hashrate = estimated_hashrate
                            attempts_estimate = int(elapsed * estimated_hashrate)
                            if self.current_popup and self.current_popup.window.winfo_exists():
                                self.browser.root.after(0, lambda: self.current_popup.update_status(f"Resolvendo... {attempts_estimate:,} tentativas", elapsed_time=elapsed, hashrate=current_hashrate, attempts=attempts_estimate))
                            elif action_type == "hps_mint":
                                self.browser.root.after(0, lambda: self.browser.update_hps_mining_status(
                                    "Minerando", elapsed_time=elapsed, hashrate=current_hashrate, attempts=attempts_estimate
                                ))
                            last_update = current_time

                        if found_nonce is not None:
                            solve_time = current_time - start_time
                            self.nonce_solution = str(found_nonce)
                            self.hashrate_observed = current_hashrate
                            self.mp_stop_event.set()
                            attempts_estimate = int(solve_time * estimated_hashrate)
                            
                            if self.current_popup and self.current_popup.window.winfo_exists():
                                self.browser.root.after(0, lambda: self.current_popup.log_message(f"Solução encontrada! Nonce: {found_nonce}, tempo: {solve_time:.2f}s"))
                                self.browser.root.after(0, lambda: self.current_popup.update_status("Solução encontrada! Feche esta janela.", elapsed_time=solve_time, hashrate=current_hashrate, attempts=attempts_estimate))
                                self.browser.root.after(0, lambda: self.current_popup.log_message("Solução encontrada! Você pode fechar esta janela."))
                            elif action_type == "hps_mint":
                                self.browser.root.after(0, lambda: self.browser.update_hps_mining_status(
                                    "Solução encontrada", elapsed_time=solve_time, hashrate=current_hashrate, attempts=attempts_estimate
                                ))
                                self.browser.root.after(0, lambda: self.browser.log_hps_mining_message(
                                    f"Solução encontrada! Nonce: {found_nonce}, tempo: {solve_time:.2f}s"
                                ))
                                
                            self.browser.root.after(0, lambda: self.browser.pow_solution_found(found_nonce, solve_time, current_hashrate))
                            self.solution_found.set()
                            break

                        time.sleep(0.05)
                        
                if not self.nonce_solution and self.is_solving:
                    if self.current_popup and self.current_popup.window.winfo_exists():
                        self.browser.root.after(0, lambda: self.current_popup.log_message("Tempo limite excedido"))
                        self.browser.root.after(0, lambda: self.current_popup.update_status("Tempo limite excedido"))
                    elif action_type == "hps_mint":
                        self.browser.root.after(0, lambda: self.browser.record_hps_mint_failure("Tempo limite excedido"))
                    self.browser.root.after(0, lambda: self.browser.pow_solution_failed())
                    
            except Exception as e:
                logger.error(f"Erro na mineração PoW: {e}")
                if self.current_popup and self.current_popup.window.winfo_exists():
                    self.current_popup.log_message(f"Erro: {e}")
                elif action_type == "hps_mint":
                    self.browser.root.after(0, lambda: self.browser.record_hps_mint_failure(f"Erro: {e}"))
                self.browser.root.after(0, lambda: self.browser.pow_solution_failed())
            finally:
                if self.mp_stop_event:
                    self.mp_stop_event.set()
                    for process in self.mp_processes:
                        process.join(timeout=1.0)
                        if process.is_alive():
                            process.terminate()
                            process.join(timeout=1.0)
                    self.mp_processes = []
                    self.mp_stop_event = None
                self.is_solving = False
                
        threading.Thread(target=solve_thread, daemon=True).start()

    def stop_solving(self):
        self.is_solving = False
        if self.mp_stop_event:
            self.mp_stop_event.set()
            for process in self.mp_processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=1.0)
            self.mp_processes = []
            self.mp_stop_event = None
        if self.current_popup and self.current_popup.window.winfo_exists():
            self.current_popup.cancelled = True
            self.current_popup.destroy()
            self.current_popup = None

class NetworkSyncDialog:
    def __init__(self, parent, browser):
        self.browser = browser
        self.window = tk.Toplevel(parent)
        self.window.title("Sincronização de Rede")
        self.window.geometry("500x300")
        self.window.transient(parent)
        self.window.grab_set()
        self.cancelled = False
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        self.setup_ui()

    def setup_ui(self):
        container, main_frame = create_scrollable_container(self.window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Sincronização de Rede P2P", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, text="Status da Sincronização:").pack(anchor=tk.W, pady=5)
        self.status_var = tk.StringVar(value="Preparando para sincronizar...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=5)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(pady=15)
        self.progress.start()
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_status(self, status):
        self.status_var.set(status)
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class HPSBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("Navegador P2P Hsyst")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.current_user = None
        self.logged_in = False
        self.main_tabs = {}
        self.main_tab_order = []
        self.allowed_tabs_logged_out = {"Login", "Config", "Servidores", "Stats"}
        self.style = None
        self.private_key = None
        self.public_key_pem = None
        self.session_id = str(uuid.uuid4())
        self.node_id = hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.connected = False
        self.peers = []
        self.content_cache = {}
        self.dns_cache = {}
        self.local_files = {}
        self.history = []
        self.history_index = -1
        self.current_content_hash = None
        self.current_content_info = None
        self.known_servers = []
        self.current_server = None
        self.server_nodes = []
        self.content_verification_cache = {}
        self.node_type = "client"
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.reputation = 100
        self.rate_limits = {}
        self.banned_until = None
        self.client_identifier = self.generate_client_identifier()
        self.upload_blocked_until = 0
        self.login_blocked_until = 0
        self.dns_blocked_until = 0
        self.report_blocked_until = 0
        self.ban_duration = 0
        self.ban_reason = ""
        self.ban_status_message = ""
        self.pow_solver = PowSolver(self)
        self.max_upload_size = 100 * 1024 * 1024
        self.disk_quota = 500 * 1024 * 1024
        self.used_disk_space = 0
        self.private_key_passphrase = None
        self.server_public_keys = {}
        self.session_key = None
        self.server_auth_challenge = None
        self.client_auth_challenge = None
        self.upload_window = None
        self.ddns_window = None
        self.report_window = None
        self.upload_callback = None
        self.dns_callback = None
        self.report_callback = None
        self.hps_mint_callback = None
        self.contract_reset_callback = None
        self.contract_certify_callback = None
        self.contract_transfer_callback = None
        self.usage_contract_callback = None
        self.pending_usage_contract = None
        self.search_dialog = None
        self.sync_dialog = None
        self.ssl_verify = False
        self.use_ssl = False
        self.backup_server = None
        self.auto_reconnect = True
        self.active_section = None
        
        self.stats_data = {
            'session_start': time.time(),
            'data_sent': 0,
            'data_received': 0,
            'content_downloaded': 0,
            'content_uploaded': 0,
            'dns_registered': 0,
            'pow_solved': 0,
            'pow_time': 0,
            'content_reported': 0
        }
        
        self.loop = None
        self.sio = None
        self.network_thread = None
        
        self.contracts_filter_mode = "all"
        self.contracts_filter_value = ""
        self.contracts_pending_details = set()
        self.contracts_results_cache = {}
        self.pending_api_app_requests = {}
        self.pending_contract_analyzer_id = None
        self.reported_contract_issues = set()
        self.contract_alert_active = False
        self.contract_alert_message = ""
        self.contract_alert_blink = False
        self.last_pending_transfer_notice = 0.0
        self.active_contract_violations = {}
        self.pending_missing_contract_target = None
        self.missing_contract_certify_callback = None
        self.current_dns_info = None
        self.pending_contract_reissue = None
        self.pending_transfers = []
        self.pending_transfers_by_contract = {}
        self.pending_transfer_accept_id = None
        self.pending_certify_contract_id = None
        self.hps_vouchers = {}
        self.hps_voucher_offers = {}
        self.hps_balance_var = tk.StringVar(value="0 HPS")
        self.hps_transfer_callback = None
        self.hps_auto_mint_var = tk.BooleanVar(value=False)
        self.hps_auto_mint_job = None
        self.hps_auto_mint_interval = 0.1
        self.last_pow_action_type = None
        self.hps_mint_requested_at = None
        self.pending_hps_mint_voucher_id = None
        self.hps_mining_count = 0
        self.hps_mining_total_time = 0.0
        self.hps_mining_status_var = tk.StringVar(value="Parado")
        self.hps_mining_bits_var = tk.StringVar(value="0")
        self.hps_mining_elapsed_var = tk.StringVar(value="0.0s")
        self.hps_mining_hashrate_var = tk.StringVar(value="0 H/s")
        self.hps_mining_attempts_var = tk.StringVar(value="0")
        self.hps_mining_count_var = tk.StringVar(value="0")
        self.hps_mining_total_time_var = tk.StringVar(value="0s")
        self.hps_mining_log = None
        self.voucher_audit_futures = {}
        self.exchange_trace_futures = {}
        self.monetary_transfer_popups = {}
        self.pending_miner_transfers = {}
        self.pending_invalidation_transfers = set()
        self.audit_override_validated = set()
        self.signature_popups = {}
        self.miner_pending_signatures = 0
        self.miner_pending_var = tk.StringVar(value="0")
        self.miner_signature_blocked = False
        self.miner_debt_status = {}
        self.miner_mint_suspended = False
        self.miner_fine_amount = 0
        self.miner_withheld_var = tk.StringVar(value="0")
        self.miner_withheld_value_var = tk.StringVar(value="0")
        self.miner_signature_monitor_var = tk.BooleanVar(value=False)
        self.miner_signature_auto_var = tk.BooleanVar(value=False)
        self.miner_auto_pay_fine_var = tk.BooleanVar(value=False)
        self.miner_fine_promise_var = tk.BooleanVar(value=False)
        self.miner_fine_request_in_flight = False
        self.miner_fine_request_source = ""
        self.miner_protection_prompted = False
        self.wallet_fraud_check_inflight = False
        self.wallet_fraud_checked = False
        self.current_fraud_report = None
        self.current_fraud_server = ""
        self.server_analysis_in_progress = False
        self.server_analysis_steps = {"wallet": False, "server": False}
        self.server_analysis_popup = None
        self.current_server_address = ""
        self.server_economy_stats = {}
        self.hps_pow_skip_costs = {
            "upload": 4,
            "dns": 4,
            "report": 4,
            "contract_transfer": 4,
            "contract_reset": 4,
            "contract_certify": 4,
            "usage_contract": 4,
            "hps_transfer": 4
        }
        self.hps_pow_skip_labels = {
            "upload": "upload",
            "dns": "registro DNS",
            "report": "reporte",
            "contract_transfer": "transferencia",
            "contract_reset": "invalidação de contrato",
            "contract_certify": "certificacao de contrato",
            "usage_contract": "contrato de uso",
            "hps_transfer": "transferencia HPS"
        }
        
        
        self.crypto_dir = os.path.join(os.path.expanduser("~"), ".hps_browser")
        os.makedirs(self.crypto_dir, exist_ok=True)
        self.db_path = os.path.join(self.crypto_dir, "hps_browser.db")
        self.fraud_reports_path = os.path.join(self.crypto_dir, "fraud_reports.json")
        
        self.init_database()
        self.pow_threads = self.load_setting_int("pow_threads", max(1, os.cpu_count() or 1))
        self.pow_threads_var = tk.StringVar(value=str(self.pow_threads))
        self.load_server_economy_stats()
        self.load_local_vouchers()
        self.load_known_servers()
        self.setup_ui()
        self.setup_cryptography()
        self.start_network_thread()
        self.calculate_disk_usage()

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_network_nodes (
                    node_id TEXT PRIMARY KEY,
                    address TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    reputation INTEGER DEFAULT 100,
                    status TEXT NOT NULL,
                    last_seen REAL NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_dns_records (
                    domain TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    ddns_hash TEXT NOT NULL DEFAULT ''
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_known_servers (
                    server_address TEXT PRIMARY KEY,
                    reputation INTEGER DEFAULT 100,
                    last_connected REAL NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    use_ssl INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_content_cache (
                    content_hash TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    last_accessed REAL NOT NULL,
                    title TEXT,
                    description TEXT,
                    username TEXT,
                    signature TEXT,
                    public_key TEXT,
                    verified INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_ddns_cache (
                    domain TEXT PRIMARY KEY,
                    ddns_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    signature TEXT DEFAULT '',
                    public_key TEXT DEFAULT ''
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_contracts_cache (
                    contract_id TEXT PRIMARY KEY,
                    action_type TEXT NOT NULL,
                    content_hash TEXT,
                    domain TEXT,
                    username TEXT NOT NULL,
                    signature TEXT,
                    timestamp REAL NOT NULL,
                    verified INTEGER DEFAULT 0,
                    contract_content TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_reports (
                    report_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    reported_user TEXT NOT NULL,
                    reporter_user TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_hps_vouchers (
                    voucher_id TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    value INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    payload TEXT NOT NULL,
                    issuer_signature TEXT NOT NULL,
                    owner_signature TEXT NOT NULL,
                    status TEXT NOT NULL,
                    invalidated INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_server_economy (
                    server_address TEXT PRIMARY KEY,
                    multiplier REAL NOT NULL,
                    total_minted REAL NOT NULL,
                    custody_balance REAL NOT NULL,
                    owner_balance REAL NOT NULL,
                    rebate_balance REAL NOT NULL,
                    exchange_fee_rate REAL NOT NULL,
                    exchange_fee_min REAL NOT NULL,
                    last_report_ts REAL NOT NULL,
                    report_payload TEXT,
                    report_signature TEXT
                )
            ''')
            
            try:
                cursor.execute("PRAGMA table_info(browser_dns_records)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'ddns_hash' not in columns:
                    cursor.execute('ALTER TABLE browser_dns_records ADD COLUMN ddns_hash TEXT NOT NULL DEFAULT ""')
            except Exception as e:
                logger.error(f"Error checking/adding ddns_hash column: {e}")
                
            try:
                cursor.execute("PRAGMA table_info(browser_ddns_cache)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'signature' not in columns:
                    cursor.execute('ALTER TABLE browser_ddns_cache ADD COLUMN signature TEXT DEFAULT ""')
                if 'public_key' not in columns:
                    cursor.execute('ALTER TABLE browser_ddns_cache ADD COLUMN public_key TEXT DEFAULT ""')
            except Exception as e:
                logger.error(f"Error checking/adding ddns cache columns: {e}")
                
            conn.commit()

    def load_setting(self, key, default=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM browser_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return row[0]
        return default

    def load_setting_int(self, key, default=0):
        value = self.load_setting(key, None)
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def save_setting(self, key, value):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO browser_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value))
            )
            conn.commit()

    def load_server_economy_stats(self):
        self.server_economy_stats = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT server_address, multiplier, total_minted, custody_balance, owner_balance,
                              rebate_balance, exchange_fee_rate, exchange_fee_min, last_report_ts,
                              report_payload, report_signature
                              FROM browser_server_economy''')
            rows = cursor.fetchall()
        for row in rows:
            self.server_economy_stats[row[0]] = {
                "server_address": row[0],
                "multiplier": row[1],
                "total_minted": row[2],
                "custody_balance": row[3],
                "owner_balance": row[4],
                "rebate_balance": row[5],
                "exchange_fee_rate": row[6],
                "exchange_fee_min": row[7],
                "last_report_ts": row[8],
                "report_payload": row[9],
                "report_signature": row[10]
            }

    def store_server_economy(self, server_address, payload, signature):
        if not server_address or not payload:
            return
        multiplier = float(payload.get("multiplier", 1.0))
        total_minted = float(payload.get("total_minted", 0.0))
        custody_balance = float(payload.get("custody_balance", 0.0))
        owner_balance = float(payload.get("owner_balance", 0.0))
        rebate_balance = float(payload.get("rebate_balance", 0.0))
        exchange_fee_rate = float(payload.get("exchange_fee_rate", 0.02))
        exchange_fee_min = float(payload.get("exchange_fee_min", 1))
        last_report_ts = float(payload.get("timestamp", time.time()))
        report_payload = json.dumps(payload, ensure_ascii=True)
        report_signature = signature or ""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO browser_server_economy
                              (server_address, multiplier, total_minted, custody_balance, owner_balance,
                               rebate_balance, exchange_fee_rate, exchange_fee_min, last_report_ts,
                               report_payload, report_signature)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (server_address, multiplier, total_minted, custody_balance, owner_balance,
                            rebate_balance, exchange_fee_rate, exchange_fee_min, last_report_ts,
                            report_payload, report_signature))
            conn.commit()
        self.server_economy_stats[server_address] = {
            "server_address": server_address,
            "multiplier": multiplier,
            "total_minted": total_minted,
            "custody_balance": custody_balance,
            "owner_balance": owner_balance,
            "rebate_balance": rebate_balance,
            "exchange_fee_rate": exchange_fee_rate,
            "exchange_fee_min": exchange_fee_min,
            "last_report_ts": last_report_ts,
            "report_payload": report_payload,
            "report_signature": report_signature
        }

    def load_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT server_address, use_ssl FROM browser_known_servers WHERE is_active = 1')
            for row in cursor.fetchall():
                self.known_servers.append(row[0])
                if row[1]:
                    self.use_ssl = True
                    
        logger.info(f"Loaded known servers: {len(self.known_servers)}")

    def load_local_vouchers(self):
        self.hps_vouchers = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT voucher_id, issuer, owner, value, reason, issued_at, payload,
                              issuer_signature, owner_signature, status, invalidated
                              FROM browser_hps_vouchers ORDER BY issued_at DESC''')
            for row in cursor.fetchall():
                payload = json.loads(row[6])
                integrity = {
                    "hash": self.compute_voucher_integrity_hash({
                        "payload": payload,
                        "signatures": {"issuer": row[7], "owner": row[8]}
                    }),
                    "algo": "sha256"
                }
                self.hps_vouchers[row[0]] = {
                    "voucher_id": row[0],
                    "issuer": row[1],
                    "owner": row[2],
                    "value": row[3],
                    "reason": row[4],
                    "issued_at": row[5],
                    "payload": payload,
                    "signatures": {"issuer": row[7], "owner": row[8]},
                    "integrity": integrity,
                    "status": row[9],
                    "invalidated": bool(row[10])
                }
        self.update_hps_balance()

    def canonicalize_payload(self, payload):
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def compute_voucher_integrity_hash(self, voucher):
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        data = json.dumps(
            {"payload": payload, "signatures": signatures},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def format_hps_voucher_hsyst(self, voucher):
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        integrity = voucher.get("integrity", {})
        pow_info = payload.get("pow", {})
        conditions = payload.get("conditions", {})
        lines = [
            "# HSYST P2P SERVICE",
            "## HPS VOUCHER:",
            "### DETAILS:",
            f"# VERSION: {payload.get('version', 1)}",
            f"# VOUCHER_ID: {payload.get('voucher_id', '')}",
            f"# VALUE: {payload.get('value', 0)}",
            f"# ISSUER: {payload.get('issuer', '')}",
            f"# ISSUER_PUBLIC_KEY: {payload.get('issuer_public_key', '')}",
            f"# OWNER: {payload.get('owner', '')}",
            f"# OWNER_PUBLIC_KEY: {payload.get('owner_public_key', '')}",
            f"# REASON: {payload.get('reason', '')}",
            f"# ISSUED_AT: {payload.get('issued_at', 0)}",
            f"# POW: {json.dumps(pow_info, ensure_ascii=True)}",
            f"# CONDITIONS: {json.dumps(conditions, ensure_ascii=True)}",
            "### :END DETAILS",
            "### SIGNATURES:",
            f"# OWNER: {signatures.get('owner', '')}",
            f"# ISSUER: {signatures.get('issuer', '')}",
            f"# INTEGRITY_HASH: {integrity.get('hash', '')}",
            f"# INTEGRITY_ALGO: {integrity.get('algo', 'sha256')}",
            "### :END SIGNATURES",
            "## :END HPS VOUCHER"
        ]
        return "\n".join(lines) + "\n"

    def parse_hps_voucher_hsyst(self, text):
        if not text.startswith("# HSYST P2P SERVICE"):
            return None
        details = {}
        signatures = {}
        section = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    section = line[4:-1].lower()
                elif line.startswith("### :END"):
                    section = None
                continue
            if not line.startswith("# "):
                continue
            key_value = line[2:]
            if ":" not in key_value:
                continue
            key, value = key_value.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if section == "details":
                details[key] = value
            elif section == "signatures":
                signatures[key] = value
        if not details:
            return None
        def parse_json_field(value_text):
            try:
                return json.loads(value_text)
            except Exception:
                return {}
        payload = {
            "voucher_type": "HPS",
            "version": int(details.get("version", "1") or 1),
            "voucher_id": details.get("voucher_id", ""),
            "value": int(details.get("value", "0") or 0),
            "issuer": details.get("issuer", ""),
            "issuer_public_key": details.get("issuer_public_key", ""),
            "owner": details.get("owner", ""),
            "owner_public_key": details.get("owner_public_key", ""),
            "reason": details.get("reason", ""),
            "issued_at": float(details.get("issued_at", "0") or 0),
            "pow": parse_json_field(details.get("pow", "{}")),
            "conditions": parse_json_field(details.get("conditions", "{}"))
        }
        return {
            "voucher_type": "HPS",
            "payload": payload,
            "signatures": {
                "owner": signatures.get("owner", ""),
                "issuer": signatures.get("issuer", "")
            },
            "integrity": {
                "hash": signatures.get("integrity_hash", ""),
                "algo": signatures.get("integrity_algo", "sha256")
            }
        }

    def verify_voucher_signatures(self, voucher):
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        owner_sig = signatures.get("owner", "")
        issuer_sig = signatures.get("issuer", "")
        owner_key = payload.get("owner_public_key", "")
        issuer_key = payload.get("issuer_public_key", "")
        if not all([owner_sig, issuer_sig, owner_key, issuer_key]):
            return False
        try:
            owner_public_key = serialization.load_pem_public_key(base64.b64decode(owner_key), backend=default_backend())
            owner_public_key.verify(
                base64.b64decode(owner_sig),
                self.canonicalize_payload(payload).encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            issuer_public_key = serialization.load_pem_public_key(base64.b64decode(issuer_key), backend=default_backend())
            issuer_public_key.verify(
                base64.b64decode(issuer_sig),
                self.canonicalize_payload(payload).encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            integrity = voucher.get("integrity", {})
            expected_hash = integrity.get("hash")
            if expected_hash:
                if self.compute_voucher_integrity_hash(voucher) != expected_hash:
                    return False
            return True
        except Exception:
            return False

    def verify_contract_signature_with_key(self, contract_text, public_key_b64):
        if not contract_text or not public_key_b64:
            return False
        try:
            lines = contract_text.splitlines()
            signed_lines = []
            signature_b64 = ""
            for line in lines:
                if line.strip().startswith("# SIGNATURE:"):
                    signature_b64 = line.split(":", 1)[1].strip()
                    continue
                signed_lines.append(line)
            if not signature_b64:
                return False
            public_key_value = public_key_b64.strip()
            if "BEGIN PUBLIC KEY" in public_key_value:
                key_bytes = public_key_value.encode("utf-8")
            else:
                key_bytes = base64.b64decode(public_key_value)
            public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
            public_key.verify(
                base64.b64decode(signature_b64),
                "\n".join(signed_lines).encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def leading_zero_bits(self, hash_bytes):
        count = 0
        for byte in hash_bytes:
            if byte == 0:
                count += 8
                continue
            for i in range(7, -1, -1):
                if byte & (1 << i):
                    return count
                count += 1
            break
        return count

    def verify_voucher_pow_payload(self, payload):
        pow_info = payload.get("pow", {}) or {}
        challenge = pow_info.get("challenge", "")
        nonce = pow_info.get("nonce", "")
        target_bits = int(pow_info.get("target_bits", 0) or 0)
        action_type = pow_info.get("action_type", "") or ""
        voucher_id = payload.get("voucher_id", "")
        pow_voucher_id = pow_info.get("voucher_id", "")
        details = {
            "challenge": challenge,
            "nonce": nonce,
            "target_bits": target_bits,
            "action_type": action_type,
            "voucher_id_match": pow_voucher_id == voucher_id if pow_voucher_id else False,
            "leading_zero_bits": 0
        }
        if not challenge or nonce == "" or target_bits <= 0:
            return False, "pow_missing", details
        if pow_voucher_id and pow_voucher_id != voucher_id:
            return False, "pow_voucher_mismatch", details
        try:
            challenge_bytes = base64.b64decode(challenge)
            nonce_int = int(nonce)
            data = challenge_bytes + struct.pack(">Q", nonce_int)
            hash_result = hashlib.sha256(data).digest()
            lzb = self.leading_zero_bits(hash_result)
            details["leading_zero_bits"] = lzb
            if lzb < target_bits:
                return False, "pow_invalid", details
        except Exception:
            return False, "pow_invalid", details
        if action_type == "hps_mint":
            try:
                challenge_text = base64.b64decode(challenge).decode("ascii", errors="replace")
            except Exception:
                challenge_text = ""
            if not challenge_text.startswith(f"HPSMINT:{voucher_id}:"):
                return False, "pow_challenge_mismatch", details
        return True, "", details

    def extract_contract_detail_from_text(self, contract_text, key):
        if not contract_text or not key:
            return None
        prefix = f"# {key}:"
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
        return None

    def extract_contract_details_map(self, contract_text):
        details = {}
        if not contract_text:
            return details
        in_details = False
        for line in contract_text.splitlines():
            line = line.strip()
            if line == "### DETAILS:":
                in_details = True
                continue
            if line == "### :END DETAILS":
                break
            if in_details and line.startswith("# "):
                parts = line[2:].split(":", 1)
                if len(parts) == 2:
                    details[parts[0].strip()] = parts[1].strip()
        return details

    def build_server_url_options(self, server_address):
        if not server_address:
            return []
        if server_address.startswith("http://") or server_address.startswith("https://"):
            return [server_address.rstrip("/")]
        primary_scheme = "https" if self.use_ssl_var.get() else "http"
        fallback_scheme = "http" if primary_scheme == "https" else "https"
        return [f"{primary_scheme}://{server_address}", f"{fallback_scheme}://{server_address}"]

    def normalize_public_key(self, key_value):
        if not key_value:
            return ""
        key_value = key_value.strip()
        if "BEGIN PUBLIC KEY" in key_value:
            return key_value
        try:
            decoded = base64.b64decode(key_value).decode("utf-8", errors="ignore").strip()
            if "BEGIN PUBLIC KEY" in decoded:
                return decoded
        except Exception:
            pass
        return key_value

    async def fetch_server_info(self, server_address):
        urls = [f"{base}/server_info" for base in self.build_server_url_options(server_address)]
        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=8) as resp:
                        if resp.status == 200:
                            info = await resp.json()
                            if info and info.get("public_key"):
                                info["public_key"] = self.normalize_public_key(info["public_key"])
                            return info
            except Exception:
                continue
        return None

    async def fetch_contract_from_server(self, server_address, contract_id):
        if not contract_id:
            return None
        urls = [f"{base}/contract/{contract_id}" for base in self.build_server_url_options(server_address)]
        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=12) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            try:
                                return content.decode("utf-8", errors="replace")
                            except Exception:
                                return None
            except Exception:
                continue
        return None

    async def fetch_voucher_audit_direct(self, server_address, voucher_ids):
        if not server_address or not voucher_ids:
            return []
        urls = [f"{base}/voucher/audit" for base in self.build_server_url_options(server_address)]
        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json={"voucher_ids": voucher_ids}, timeout=10) as resp:
                        if resp.status == 200:
                            payload = await resp.json()
                            if payload and payload.get("success"):
                                return payload.get("vouchers", []) or []
            except Exception:
                continue
        return []

    def extract_trace_links_from_contracts(self, trace_contracts):
        links = []
        for contract in trace_contracts or []:
            action_type = contract.get("action_type")
            contract_b64 = contract.get("contract_content") or ""
            if not action_type or not contract_b64:
                continue
            try:
                contract_text = base64.b64decode(contract_b64).decode("utf-8", errors="replace")
            except Exception:
                continue
            contract_hash = hashlib.sha256(contract_text.encode("utf-8")).hexdigest() if contract_text else ""
            contract_id = contract.get("contract_id") or ""
            if action_type in ("hps_spend_refund", "miner_fine_refund", "hps_transfer_custody_refund"):
                raw_list = self.extract_contract_detail_from_text(contract_text, "VOUCHERS")
                if raw_list:
                    try:
                        source_ids = json.loads(raw_list)
                    except Exception:
                        source_ids = []
                    for source_id in source_ids:
                        if source_id:
                            links.append({
                                "source_voucher_id": source_id,
                                "contract_id": contract_id,
                                "contract_hash": contract_hash,
                                "action_type": action_type
                            })
            elif action_type == "hps_transfer_refund":
                source_id = self.extract_contract_detail_from_text(contract_text, "ORIGINAL_VOUCHER_ID")
                if source_id:
                    links.append({
                        "source_voucher_id": source_id,
                        "contract_id": contract_id,
                        "contract_hash": contract_hash,
                        "action_type": action_type
                    })
        return links

    def extract_trace_sources_from_contracts(self, trace_contracts):
        source_ids = [link.get("source_voucher_id") for link in self.extract_trace_links_from_contracts(trace_contracts)]
        source_ids = [vid for vid in source_ids if vid]
        return list(dict.fromkeys(source_ids))

    async def analyze_voucher_pow_trace(self, audit_results, inter_server_evidence=None):
        pow_audit = []
        trace_entries = []
        trace_failures = {}
        trace_missing = {}
        audit_by_id = {info.get("voucher_id"): info for info in audit_results if info.get("voucher_id")}
        trace_source_ids = set()
        issuer_audit_requests = {}
        def is_change_like(payload):
            reason = (payload.get("reason") or "").lower()
            conditions = payload.get("conditions", {}) or {}
            condition_type = str(conditions.get("type", "")).lower()
            if condition_type in ("change", "withheld_change"):
                return True
            if "change" in reason or "refund" in reason:
                return True
            return False
        exchange_contract_hash = ""
        exchange_contract_id = ""
        if inter_server_evidence:
            exchange_contract_hash = inter_server_evidence.get("exchange_contract_hash", "") or ""
            exchange_contract_id = inter_server_evidence.get("exchange_contract_id", "") or ""
        def is_pow_mint_ok(payload):
            pow_ok, _, pow_details = self.verify_voucher_pow_payload(payload)
            return bool(pow_ok) and (pow_details.get("action_type") == "hps_mint")

        def extract_sources_from_info(info):
            payload = info.get("payload", {}) or {}
            links = self.extract_trace_links_from_contracts(info.get("trace_contracts"))
            source_ids = [link.get("source_voucher_id") for link in links if link.get("source_voucher_id")]
            conditions = payload.get("conditions", {}) or {}
            if conditions.get("type") == "exchange" and conditions.get("issuer_voucher_ids"):
                issuer_ids = conditions.get("issuer_voucher_ids", []) or []
                if issuer_ids:
                    if exchange_contract_hash or exchange_contract_id:
                        for source_id in issuer_ids:
                            if not source_id:
                                continue
                            links.append({
                                "source_voucher_id": source_id,
                                "contract_id": exchange_contract_id,
                                "contract_hash": exchange_contract_hash,
                                "action_type": "exchange"
                            })
                    source_ids = issuer_ids
            source_ids = list(dict.fromkeys([vid for vid in source_ids if vid]))
            return source_ids, payload, links
        for info in audit_results:
            voucher_id = info.get("voucher_id", "")
            payload = info.get("payload", {}) or {}
            pow_ok, pow_reason, pow_details = self.verify_voucher_pow_payload(payload)
            pow_audit.append({
                "voucher_id": voucher_id,
                "pow_ok": pow_ok,
                "pow_reason": pow_reason,
                "pow_details": pow_details
            })
            if is_pow_mint_ok(payload):
                continue
            source_ids, payload, _ = extract_sources_from_info(info)
            conditions = payload.get("conditions", {}) or {}
            if conditions.get("type") == "exchange" and conditions.get("issuer_voucher_ids"):
                issuer_addr = conditions.get("issuer") or payload.get("issuer", "")
                issuer_ids = conditions.get("issuer_voucher_ids", []) or []
                if issuer_addr and issuer_ids:
                    issuer_audit_requests.setdefault(issuer_addr, set()).update(issuer_ids)
            if not source_ids and is_change_like(payload) and voucher_id:
                trace_missing[voucher_id] = "trace_missing"
            trace_source_ids.update(source_ids)
        if inter_server_evidence:
            for info in inter_server_evidence.get("issuer_voucher_audit", []) or []:
                vid = info.get("voucher_id")
                if vid:
                    audit_by_id.setdefault(vid, info)
            issuer_ids = inter_server_evidence.get("issuer_voucher_ids", []) or []
            trace_source_ids.update(issuer_ids)
        for issuer_addr, ids in issuer_audit_requests.items():
            missing_for_issuer = [vid for vid in ids if vid not in audit_by_id]
            if not missing_for_issuer:
                continue
            direct_audits = await self.fetch_voucher_audit_direct(issuer_addr, missing_for_issuer)
            for info in direct_audits:
                vid = info.get("voucher_id")
                if vid:
                    audit_by_id.setdefault(vid, info)
        missing_ids = [vid for vid in trace_source_ids if vid not in audit_by_id]
        if missing_ids:
            extra_audits = await self.fetch_voucher_audit(missing_ids)
            for info in extra_audits:
                vid = info.get("voucher_id")
                if vid:
                    audit_by_id.setdefault(vid, info)
        for _ in range(4):
            expand_ids = set()
            for info in list(audit_by_id.values()):
                sources, payload, _ = extract_sources_from_info(info)
                if self.verify_voucher_pow_payload(payload)[0]:
                    continue
                for source_id in sources:
                    if source_id and source_id not in audit_by_id:
                        expand_ids.add(source_id)
            if not expand_ids:
                break
            extra_audits = await self.fetch_voucher_audit(list(expand_ids))
            for info in extra_audits:
                vid = info.get("voucher_id")
                if vid:
                    audit_by_id.setdefault(vid, info)
        def trace_has_pow(voucher_id, visited, depth):
            if depth <= 0:
                return False, True
            info = audit_by_id.get(voucher_id)
            if not info:
                return False, True
            payload = info.get("payload", {}) or {}
            if is_pow_mint_ok(payload):
                return True, False
            sources, _, _ = extract_sources_from_info(info)
            if not sources:
                return False, is_change_like(payload)
            missing = False
            for source_id in sources:
                if not source_id or source_id in visited:
                    continue
                visited.add(source_id)
                ok, missing_child = trace_has_pow(source_id, visited, depth - 1)
                if missing_child:
                    missing = True
                if ok:
                    return True, False
            return False, missing
        trace_links_map = {}
        for info in audit_by_id.values():
            voucher_id = info.get("voucher_id", "")
            if not voucher_id:
                continue
            _, _, links = extract_sources_from_info(info)
            trace_links_map[voucher_id] = links

        def build_trace_chain(voucher_id, visited, depth):
            chain = []
            if depth <= 0 or not voucher_id or voucher_id in visited:
                return chain
            info = audit_by_id.get(voucher_id)
            if not info:
                return chain
            visited.add(voucher_id)
            chain.append(voucher_id)
            payload = info.get("payload", {}) or {}
            if self.verify_voucher_pow_payload(payload)[0]:
                return chain
            source_ids, _, _ = extract_sources_from_info(info)
            for source_id in source_ids:
                chain.extend(build_trace_chain(source_id, visited, depth - 1))
            return chain

        def build_trace_contract_chain(voucher_id, visited, depth):
            chain = []
            if depth <= 0 or not voucher_id or voucher_id in visited:
                return chain
            info = audit_by_id.get(voucher_id)
            if not info:
                return chain
            visited.add(voucher_id)
            links = trace_links_map.get(voucher_id, []) or []
            for link in links:
                source_id = link.get("source_voucher_id")
                if not source_id or source_id in visited:
                    continue
                chain.append({
                    "voucher_id": voucher_id,
                    "source_voucher_id": source_id,
                    "contract_id": link.get("contract_id", ""),
                    "contract_hash": link.get("contract_hash", ""),
                    "action_type": link.get("action_type", "")
                })
                chain.extend(build_trace_contract_chain(source_id, visited, depth - 1))
            return chain
        for info in audit_results:
            voucher_id = info.get("voucher_id", "")
            payload = info.get("payload", {}) or {}
            pow_ok, _, _ = self.verify_voucher_pow_payload(payload)
            source_ids, payload, _ = extract_sources_from_info(info)
            source_audits = []
            trace_ok = bool(pow_ok) and is_pow_mint_ok(payload)
            for source_id in source_ids:
                source_info = audit_by_id.get(source_id)
                if not source_info:
                    continue
                source_payload = source_info.get("payload", {}) or {}
                source_signatures = source_info.get("signatures", {}) or {}
                source_pow_ok, source_pow_reason, source_pow_details = self.verify_voucher_pow_payload(source_payload)
                source_audits.append({
                    "voucher_id": source_id,
                    "payload": source_payload,
                    "signatures": source_signatures,
                    "pow_ok": source_pow_ok,
                    "pow_reason": source_pow_reason,
                    "pow_details": source_pow_details
                })
                if source_pow_ok and source_pow_details.get("action_type") == "hps_mint":
                    trace_ok = True
            if not trace_ok and voucher_id:
                trace_ok, missing = trace_has_pow(voucher_id, {voucher_id}, 5)
                if not trace_ok:
                    if missing or voucher_id in trace_missing:
                        trace_failures[voucher_id] = "trace_missing"
                    else:
                        trace_failures[voucher_id] = "trace_invalid"
            trace_chain = build_trace_chain(voucher_id, set(), 6) if voucher_id else []
            trace_contract_chain = build_trace_contract_chain(voucher_id, set(), 6) if voucher_id else []
            trace_contract_links = trace_links_map.get(voucher_id, []) or []
            trace_entries.append({
                "voucher_id": voucher_id,
                "trace_ok": trace_ok,
                "source_vouchers": source_ids,
                "source_audits": source_audits,
                "trace_chain": trace_chain,
                "trace_contract_links": trace_contract_links,
                "trace_contract_chain": trace_contract_chain
            })
        return pow_audit, trace_entries, trace_failures

    def evaluate_voucher_audit(self, audit_results):
        failures = {}
        summary = []
        for info in audit_results:
            voucher_id = info.get("voucher_id", "")
            payload = info.get("payload", {}) or {}
            signatures = info.get("signatures", {}) or {}
            status = info.get("status", "")
            invalidated = bool(info.get("invalidated"))
            issue_contract_b64 = info.get("issue_contract", "") or ""
            issue_contract_text = ""
            if issue_contract_b64:
                try:
                    issue_contract_text = base64.b64decode(issue_contract_b64).decode("utf-8", errors="replace")
                except Exception:
                    issue_contract_text = ""
            issuer_server_key = info.get("issuer_server_key") or ""
            issuer_address = payload.get("issuer", "")
            server_key = issuer_server_key or self.server_public_keys.get(issuer_address, "") or self.server_public_keys.get(self.current_server, "")
            voucher = {
                "payload": payload,
                "signatures": signatures,
                "integrity": {
                    "hash": self.compute_voucher_integrity_hash({"payload": payload, "signatures": signatures}),
                    "algo": "sha256"
                }
            }
            signatures_ok = self.verify_voucher_signatures(voucher)
            contract_ok = self.verify_contract_signature_with_key(issue_contract_text, server_key)
            contract_id = self.extract_contract_detail_from_text(issue_contract_text, "VOUCHER_ID")
            contract_owner = self.extract_contract_detail_from_text(issue_contract_text, "OWNER")
            contract_issuer = self.extract_contract_detail_from_text(issue_contract_text, "ISSUER")
            contract_value = self.extract_contract_detail_from_text(issue_contract_text, "VALUE")
            contract_matches = True
            if contract_id and contract_id != voucher_id:
                contract_matches = False
            if contract_owner and contract_owner != payload.get("owner", ""):
                contract_matches = False
            if contract_issuer and contract_issuer != payload.get("issuer", ""):
                contract_matches = False
            if contract_value is not None and str(contract_value) != str(payload.get("value", "")):
                contract_matches = False
            pow_info = payload.get("pow", {}) or {}
            pow_ok, pow_reason, pow_details = self.verify_voucher_pow_payload(payload)
            if invalidated or status == "invalid":
                failures[voucher_id] = "voucher_invalidated"
            elif not signatures_ok:
                failures[voucher_id] = "voucher_signature_invalid"
            elif not issue_contract_text:
                failures[voucher_id] = "missing_issue_contract"
            elif not contract_ok:
                failures[voucher_id] = "issue_contract_signature_invalid"
            elif not contract_matches:
                failures[voucher_id] = "issue_contract_mismatch"
            summary.append({
                "voucher_id": voucher_id,
                "owner": payload.get("owner", ""),
                "issuer": payload.get("issuer", ""),
                "value": payload.get("value", 0),
                "reason": payload.get("reason", ""),
                "status": status,
                "invalidated": invalidated,
                "signatures_ok": signatures_ok,
                "issue_contract_ok": contract_ok,
                "issue_contract_matches": contract_matches,
                "pow": pow_info,
                "pow_ok": pow_ok,
                "pow_reason": pow_reason,
                "pow_details": pow_details,
                "trace_contracts": info.get("trace_contracts", []) or []
            })
        return summary, failures

    async def fetch_voucher_audit(self, voucher_ids, transfer_id=None):
        if not self.connected:
            return []
        request_id = str(uuid.uuid4())
        future = self.loop.create_future()
        self.voucher_audit_futures[request_id] = future
        await self.sio.emit('request_voucher_audit', {
            'request_id': request_id,
            'voucher_ids': voucher_ids,
            'transfer_id': transfer_id
        })
        try:
            result = await asyncio.wait_for(future, timeout=5.0)
        except Exception:
            result = []
        finally:
            self.voucher_audit_futures.pop(request_id, None)
        if result:
            return result
        server_address = self.current_server_address or self.current_server
        if server_address and voucher_ids:
            direct = await self.fetch_voucher_audit_direct(server_address, voucher_ids)
            return direct or []
        return []

    async def fetch_exchange_trace(self, voucher_ids):
        if not self.connected:
            return []
        request_id = str(uuid.uuid4())
        future = self.loop.create_future()
        self.exchange_trace_futures[request_id] = future
        await self.sio.emit('request_exchange_trace', {
            'request_id': request_id,
            'voucher_ids': voucher_ids
        })
        try:
            result = await asyncio.wait_for(future, timeout=6.0)
        except Exception:
            result = []
        finally:
            self.exchange_trace_futures.pop(request_id, None)
        return result or []

    def load_fraud_reports(self):
        if not self.fraud_reports_path or not os.path.exists(self.fraud_reports_path):
            return []
        try:
            with open(self.fraud_reports_path, "r", encoding="ascii") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            return []
        return []

    def save_fraud_reports(self, reports):
        if not self.fraud_reports_path:
            return
        try:
            with open(self.fraud_reports_path, "w", encoding="ascii") as f:
                json.dump(reports, f, ensure_ascii=True)
        except Exception:
            return

    def append_fraud_report(self, report):
        reports = self.load_fraud_reports()
        reports.append(report)
        self.save_fraud_reports(reports)

    def get_fraud_report_for_server(self, server_address):
        if not server_address:
            return None
        reports = self.load_fraud_reports()
        matches = [r for r in reports if r.get("server_address") == server_address]
        if not matches:
            return None
        matches.sort(key=lambda r: float(r.get("detected_at", 0) or 0), reverse=True)
        return matches[0]

    def set_active_fraud_report(self, report):
        if not report:
            self.current_fraud_report = None
            self.current_fraud_server = ""
            return
        self.current_fraud_report = report
        self.current_fraud_server = report.get("server_address", "") or self.current_server or ""

    def format_fraud_warning_message(self, report, action_label=None):
        base_message = (
            "O servidor que você conectou é fraudulento.\n"
            "A cobrança pode ser indevida, o câmbio para este servidor pode causar perdas, "
            "e arquivos ou vouchers neste servidor podem ser perdidos.\n"
        )
        if action_label:
            base_message += f"\nAção: {action_label}\n"
        contract_id = report.get("contract_id") or ""
        reasons = report.get("failures") or {}
        if contract_id:
            base_message += f"\nContrato relacionado: {contract_id}\n"
        if reasons:
            sample = list(reasons.items())[:5]
            details = ", ".join([f"{vid}:{why}" for vid, why in sample])
            base_message += f"\nEvidências: {details}\n"
        base_message += "\nVocê pode prosseguir, mas os riscos permanecem."
        return base_message

    def show_fraud_contract_analyzer(self, report):
        contract_b64 = report.get("contract_content") or ""
        if not contract_b64:
            return
        try:
            contract_text = base64.b64decode(contract_b64).decode("utf-8", errors="replace")
        except Exception:
            return
        contract_info = {
            "contract_id": report.get("contract_id", ""),
            "action_type": report.get("action_type", "voucher_invalidate"),
            "content_hash": "",
            "domain": "",
            "username": report.get("server_address", ""),
            "signature": "",
            "timestamp": report.get("detected_at", time.time()),
            "verified": True,
            "integrity_ok": True,
            "contract_content": contract_text
        }
        self.show_contract_analyzer(contract_info, title="Analisador de Contratos (Fraude)", allow_proceed=True)

    def warn_fraud_report(self, report, action_label=None, show_analyzer=True):
        if not report:
            return True
        message = self.format_fraud_warning_message(report, action_label=action_label)
        if action_label:
            proceed = messagebox.askyesno("Servidor fraudulento", message)
        else:
            messagebox.showwarning("Servidor fraudulento", message)
            proceed = True
        if show_analyzer:
            self.show_fraud_contract_analyzer(report)
        return proceed

    def confirm_fraud_action(self, action_label, auto=False):
        report = self.get_fraud_report_for_server(self.current_server_address or self.current_server)
        if report:
            self.set_active_fraud_report(report)
        if not report:
            return True
        if auto:
            self.log_hps_mining_message("Alerta: servidor fraudulento detectado. Operações podem ser indevidas.")
            return True
        return self.warn_fraud_report(report, action_label=action_label, show_analyzer=False)

    async def fetch_contracts_by_type_http(self, server_address, action_type, limit=100):
        if not server_address or not action_type:
            return []
        params = f"type={action_type}&limit={int(limit)}"
        urls = [f"{base}/sync/contracts?{params}" for base in self.build_server_url_options(server_address)]
        for url in urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            payload = await resp.json()
                            if isinstance(payload, list):
                                return payload
            except Exception:
                continue
        return []

    async def audit_server_integrity(self):
        server_address = self.current_server_address or self.current_server
        if not server_address:
            self.mark_server_analysis_done("server")
            return
        contracts = await self.fetch_contracts_by_type_http(server_address, "voucher_invalidate", limit=100)
        for contract in contracts or []:
            contract_content_b64 = contract.get("contract_content") or ""
            if not contract_content_b64:
                continue
            try:
                contract_text = base64.b64decode(contract_content_b64).decode("utf-8", errors="replace")
            except Exception:
                continue
            if "ACTION: voucher_invalidate" not in contract_text:
                continue
            voucher_list_raw = self.extract_contract_detail_from_text(contract_text, "VOUCHERS")
            if not voucher_list_raw:
                continue
            try:
                voucher_ids = json.loads(voucher_list_raw)
            except Exception:
                continue
            if not voucher_ids:
                continue
            audits = await self.fetch_voucher_audit_direct(server_address, voucher_ids)
            invalidated_ok = all(bool(item.get("invalidated")) for item in audits or [])
            if not invalidated_ok:
                report = {
                    "server_address": server_address,
                    "contract_id": contract.get("contract_id", ""),
                    "action_type": contract.get("action_type", "voucher_invalidate"),
                    "voucher_ids": voucher_ids,
                    "contract_content": contract_content_b64,
                    "detected_at": time.time()
                }
                self.append_fraud_report(report)
                self.set_active_fraud_report(report)
                self.root.after(0, lambda: self.warn_fraud_report(report, show_analyzer=True))
                self.mark_server_analysis_done("server")
                return
        self.mark_server_analysis_done("server")

    async def submit_fraud_reports(self):
        reports = self.load_fraud_reports()
        if not reports:
            return
        await self.sio.emit('submit_fraud_report', {'reports': reports})

    async def audit_wallet_vouchers_for_fraud(self, vouchers):
        if self.wallet_fraud_checked:
            return
        server_address = self.current_server_address or self.current_server
        if not server_address or not vouchers:
            self.mark_server_analysis_done("wallet")
            return
        voucher_ids = []
        for voucher in vouchers:
            payload = voucher.get("payload", {}) or {}
            voucher_id = payload.get("voucher_id")
            if voucher_id:
                voucher_ids.append(voucher_id)
        if not voucher_ids:
            self.mark_server_analysis_done("wallet")
            return
        audit_results = await self.fetch_voucher_audit(voucher_ids)
        if not audit_results:
            self.mark_server_analysis_done("wallet")
            return
        audit_summary, failures = self.evaluate_voucher_audit(audit_results)
        pow_audit, trace_entries, trace_failures = await self.analyze_voucher_pow_trace(audit_results)
        if trace_failures:
            filtered = {vid: why for vid, why in trace_failures.items() if why != "trace_missing"}
            failures.update(filtered)
        if not failures:
            self.wallet_fraud_checked = True
            self.mark_server_analysis_done("wallet")
            return
        report = {
            "server_address": server_address,
            "contract_id": "",
            "voucher_ids": voucher_ids,
            "failures": failures,
            "audit": audit_summary,
            "pow_audit": pow_audit,
            "trace": trace_entries,
            "detected_at": time.time()
        }
        self.append_fraud_report(report)
        self.wallet_fraud_checked = True
        self.set_active_fraud_report(report)
        self.root.after(0, lambda: self.warn_fraud_report(report, show_analyzer=False))
        self.mark_server_analysis_done("wallet")

    def store_voucher_record(self, voucher):
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        voucher_id = payload.get("voucher_id")
        if not voucher_id:
            return
        integrity = voucher.get("integrity") or {
            "hash": self.compute_voucher_integrity_hash(voucher),
            "algo": "sha256"
        }
        signatures_ok = self.verify_voucher_signatures(voucher)
        status = voucher.get("status", "valid") if signatures_ok else "invalid"
        invalidated = 1 if voucher.get("invalidated") else 0
        if status != "valid":
            invalidated = 1
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO browser_hps_vouchers
                              (voucher_id, issuer, owner, value, reason, issued_at, payload,
                               issuer_signature, owner_signature, status, invalidated)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (voucher_id,
                            payload.get("issuer", ""),
                            payload.get("owner", ""),
                            int(payload.get("value", 0)),
                            payload.get("reason", ""),
                            float(payload.get("issued_at", time.time())),
                            self.canonicalize_payload(payload),
                            signatures.get("issuer", ""),
                            signatures.get("owner", ""),
                            status,
                            invalidated))
            conn.commit()
        self.hps_vouchers[voucher_id] = {
            "voucher_id": voucher_id,
            "issuer": payload.get("issuer", ""),
            "owner": payload.get("owner", ""),
            "value": int(payload.get("value", 0)),
            "reason": payload.get("reason", ""),
            "issued_at": float(payload.get("issued_at", time.time())),
            "payload": payload,
            "signatures": signatures,
            "integrity": integrity,
            "status": status,
            "invalidated": bool(invalidated)
        }
        self.save_voucher_to_storage(voucher_id, voucher)
        self.update_hps_balance()

    def save_voucher_to_storage(self, voucher_id, voucher):
        voucher_dir = os.path.join(self.crypto_dir, "vouchers")
        os.makedirs(voucher_dir, exist_ok=True)
        voucher_path = os.path.join(voucher_dir, f"{voucher_id}.hps")
        with open(voucher_path, "w", encoding="ascii") as f:
            f.write(self.format_hps_voucher_hsyst(voucher))

    def update_hps_balance(self):
        total = 0
        for voucher in self.hps_vouchers.values():
            if not self.voucher_matches_current_server(voucher):
                continue
            if voucher.get("status") == "valid" and not voucher.get("invalidated"):
                total += int(voucher.get("value", 0))
        self.hps_balance_var.set(f"{total} HPS")
        self.update_hps_wallet_ui()

    def reserve_local_vouchers(self, voucher_ids, status="reserved"):
        if not voucher_ids:
            return
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                '''UPDATE browser_hps_vouchers SET status = ? WHERE voucher_id = ?''',
                [(status, voucher_id) for voucher_id in voucher_ids]
            )
            conn.commit()
        for voucher_id in voucher_ids:
            voucher = self.hps_vouchers.get(voucher_id)
            if voucher:
                voucher["status"] = status
        self.update_hps_balance()

    def invalidate_local_vouchers(self, voucher_ids, status="invalid"):
        if not voucher_ids:
            return
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                '''UPDATE browser_hps_vouchers SET status = ?, invalidated = 1 WHERE voucher_id = ?''',
                [(status, voucher_id) for voucher_id in voucher_ids]
            )
            conn.commit()
        for voucher_id in voucher_ids:
            voucher = self.hps_vouchers.get(voucher_id)
            if voucher:
                voucher["status"] = status
                voucher["invalidated"] = True
        self.update_hps_balance()

    def voucher_matches_current_server(self, voucher, issuer=None):
        issuer = issuer or (self.current_server or "")
        if voucher.get("issuer") == issuer:
            return True
        issuer_key = voucher.get("payload", {}).get("issuer_public_key", "")
        if issuer_key:
            return issuer_key == self.server_public_keys.get(self.current_server, "")
        return False

    def get_hps_balance_value(self, issuer=None):
        total = 0
        for voucher in self.hps_vouchers.values():
            if not self.voucher_matches_current_server(voucher, issuer=issuer):
                continue
            if voucher.get("status") == "valid" and not voucher.get("invalidated"):
                total += int(voucher.get("value", 0))
        return total

    def select_hps_vouchers_for_cost(self, cost, issuer=None, exclude_ids=None):
        voucher_ids = []
        total = 0
        exclude = set(exclude_ids or [])
        for voucher in self.hps_vouchers.values():
            if not self.voucher_matches_current_server(voucher, issuer=issuer):
                continue
            if voucher.get("status") != "valid" or voucher.get("invalidated"):
                continue
            if voucher.get("voucher_id") in exclude:
                continue
            voucher_ids.append(voucher["voucher_id"])
            total += int(voucher.get("value", 0))
            if total >= cost:
                break
        return voucher_ids, total

    def get_hps_pow_skip_cost(self, action_type):
        return int(self.hps_pow_skip_costs.get(action_type, 0))

    def prepare_hps_payment(self, action_type, exclude_ids=None):
        cost = self.get_hps_pow_skip_cost(action_type)
        if cost <= 0:
            return None
        if not self.confirm_fraud_action(f"Gasto HPS ({self.hps_pow_skip_labels.get(action_type, action_type)})"):
            return None
        issuer = self.current_server or ""
        voucher_ids, total = self.select_hps_vouchers_for_cost(cost, issuer, exclude_ids=exclude_ids)
        if total < cost:
            return None
        label = self.hps_pow_skip_labels.get(action_type, action_type)
        total_balance = self.get_hps_balance_value(issuer=issuer)
        if not messagebox.askyesno(
            "Usar saldo HPS",
            (
                f"Saldo total: {total_balance} HPS.\n"
                f"Usar {cost} HPS para pular o PoW de {label}?\n"
                "O custo pode ser menor por subsidio da custodia, com troco."
            )
        ):
            return None
        self.reserve_local_vouchers(voucher_ids)
        pow_audit = []
        trace_entries = []
        exchange_trace = []
        try:
            audit_future = asyncio.run_coroutine_threadsafe(
                self.fetch_voucher_audit(voucher_ids),
                self.loop
            )
            audit_results = audit_future.result(timeout=6.0)
            if audit_results:
                trace_future = asyncio.run_coroutine_threadsafe(
                    self.analyze_voucher_pow_trace(audit_results),
                    self.loop
                )
                pow_audit, trace_entries, _ = trace_future.result(timeout=6.0)
        except Exception:
            pow_audit = []
            trace_entries = []
        try:
            exchange_future = asyncio.run_coroutine_threadsafe(
                self.fetch_exchange_trace(voucher_ids),
                self.loop
            )
            exchange_trace = exchange_future.result(timeout=6.0)
        except Exception:
            exchange_trace = []
        details = [
            ("ACTION_TYPE", action_type),
            ("COST", str(cost)),
            ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
        ]
        if pow_audit:
            details.append(("VOUCHER_POW_AUDIT", json.dumps(pow_audit, ensure_ascii=True)))
        if trace_entries:
            details.append(("VOUCHER_TRACE", json.dumps(trace_entries, ensure_ascii=True)))
        if exchange_trace:
            details.append(("EXCHANGE_TRACE", json.dumps(exchange_trace, ensure_ascii=True)))
        contract_template = self.build_contract_template("spend_hps", details)
        signed_text, _ = self.apply_contract_signature(contract_template)
        contract_text = signed_text
        return {
            "voucher_ids": voucher_ids,
            "cost": cost,
            "action_type": action_type,
            "contract_content": base64.b64encode(contract_text.encode('utf-8')).decode('utf-8')
        }

    def run_pow_or_hps(self, action_type, pow_start, hps_start, exclude_ids=None):
        hps_payment = self.prepare_hps_payment(action_type, exclude_ids=exclude_ids)
        if hps_payment:
            hps_start(hps_payment)
            return
        pow_start()

    def log_hps_mining_message(self, message):
        if not self.hps_mining_log:
            return
        self.hps_mining_log.config(state=tk.NORMAL)
        self.hps_mining_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.hps_mining_log.see(tk.END)
        self.hps_mining_log.config(state=tk.DISABLED)

    def update_hps_mining_status(self, status, bits=None, elapsed_time=None, hashrate=None, attempts=None):
        self.hps_mining_status_var.set(status)
        if bits is not None:
            self.hps_mining_bits_var.set(str(bits))
        if elapsed_time is not None:
            self.hps_mining_elapsed_var.set(f"{elapsed_time:.2f}s")
        if hashrate is not None:
            self.hps_mining_hashrate_var.set(f"{hashrate:.0f} H/s")
        if attempts is not None:
            self.hps_mining_attempts_var.set(str(attempts))

    def start_hps_mining_ui(self, target_bits, target_seconds):
        self.update_hps_mining_status("Iniciando...", bits=target_bits, elapsed_time=0.0, hashrate=0.0, attempts=0)
        self.log_hps_mining_message(f"Desafio recebido: {target_bits} bits (alvo {target_seconds:.1f}s)")

    def record_hps_mint_success(self, solve_time, hashrate):
        self.hps_mining_count += 1
        self.hps_mining_total_time += solve_time
        self.hps_mining_count_var.set(str(self.hps_mining_count))
        self.hps_mining_total_time_var.set(f"{int(self.hps_mining_total_time)}s")
        self.update_hps_mining_status("Solução encontrada", elapsed_time=solve_time, hashrate=hashrate)
        self.log_hps_mining_message(f"Solução enviada em {solve_time:.2f}s ({hashrate:.0f} H/s)")

    def record_hps_mint_failure(self, reason="Falha na solução do PoW"):
        self.update_hps_mining_status(reason)
        self.log_hps_mining_message(reason)

    def update_miner_pending_signatures(self, count):
        self.miner_pending_signatures = max(0, int(count))
        self.miner_pending_var.set(str(self.miner_pending_signatures))
        if self.miner_pending_signatures == 0:
            self.miner_signature_blocked = False

    def update_miner_debt_status(self, status):
        if not isinstance(status, dict):
            return
        self.miner_debt_status = status
        pending = int(status.get("pending_signatures", self.miner_pending_signatures))
        self.update_miner_pending_signatures(pending)
        limit = int(status.get("debt_limit", 0))
        promise_active = int(status.get("promise_active", 0))
        pending_fines = int(status.get("pending_fines", 0))
        pending_delay_fines = int(status.get("pending_delay_fines", 0))
        fine_grace = int(status.get("fine_grace", 2))
        signature_blocked = (limit > 0 and pending >= limit)
        fine_blocked = pending_fines > fine_grace and not promise_active
        delay_blocked = pending_delay_fines > 0
        self.miner_mint_suspended = (signature_blocked or fine_blocked or delay_blocked)
        withheld_count = int(status.get("withheld_count", 0))
        withheld_total = int(status.get("withheld_total", 0))
        self.miner_withheld_var.set(str(withheld_count))
        self.miner_withheld_value_var.set(str(withheld_total))
        self.maybe_auto_pay_fine()

    def format_miner_debt_message(self, status):
        pending = int(status.get("pending_signatures", 0))
        pending_fines = int(status.get("pending_fines", 0))
        pending_delay_fines = int(status.get("pending_delay_fines", 0))
        signature_fines = int(status.get("signature_fines", 0))
        limit = int(status.get("debt_limit", 0))
        fine_amount = int(status.get("fine_amount", 0))
        fine_per_pending = int(status.get("fine_per_pending", 0))
        fine_per_text = "valor variavel"
        if pending_fines > 0 and fine_per_pending > 0 and fine_amount == (fine_per_pending * pending_fines):
            fine_per_text = f"{fine_per_pending} HPS por pendencia"
        mined_balance = float(status.get("mined_balance", 0))
        total_minted = float(status.get("total_minted", 0))
        reputation = int(status.get("reputation", 0))
        mining_pct = float(status.get("mining_pct", 0))
        punctuality_pct = float(status.get("punctuality_pct", 0))
        reputation_pct = float(status.get("reputation_pct", 0))
        participation_bonus = float(status.get("participation_bonus_pct", 0))
        combined_pct = float(status.get("combined_pct", 0))
        limit_raw = float(status.get("debt_limit_raw", 0))
        withheld_count = int(status.get("withheld_count", 0))
        withheld_total = int(status.get("withheld_total", 0))
        promise_active = int(status.get("promise_active", 0))
        promise_amount = float(status.get("promise_amount", 0))
        return (
            "Mineracao suspensa por pendencias de assinatura.\n\n"
            f"Pendencias de assinatura: {pending}\n"
            f"Pendencias de multa: {pending_fines}\n"
            f"Pendencias de assinatura com multa: {signature_fines}\n"
            f"Pendencias por atraso: {pending_delay_fines}\n"
            f"Limite atual: {limit}\n"
            f"Multa para liberar: {fine_amount} HPS ({fine_per_text})\n\n"
            f"Vouchers pendentes: {withheld_count} ({withheld_total} HPS)\n\n"
            f"Promessa ativa: {'sim' if promise_active else 'nao'}\n"
            f"Valor prometido restante: {promise_amount:.2f} HPS\n\n"
            "Regras de limite:\n"
            "Limite = 10 - (X% de 10), minimo 2.\n"
            "X% = historico de mineracao (0-50) + pontualidade (0-25) + reputacao (0-25) - participacao.\n"
            f"Historico: {mining_pct:.2f}% (saldo minerado {mined_balance:.2f} / base {total_minted:.2f}).\n"
            f"Pontualidade: {punctuality_pct:.2f}%.\n"
            f"Reputacao: {reputation_pct:.2f}% (rep {reputation}).\n"
            f"Participacao recente: -{participation_bonus:.2f}%.\n"
            f"X% total: {combined_pct:.2f}%.\n"
            f"Limite bruto: {limit_raw:.4f} (>= 9.5 vira 10, senao arredonda pra baixo)."
        )

    def show_miner_debt_popup(self, status, title="Mineracao suspensa"):
        if not status:
            return
        messagebox.showwarning(title, self.format_miner_debt_message(status))

    def can_cover_fine_amount(self, fine_amount):
        issuer = self.current_server or ""
        balance = self.get_hps_balance_value(issuer=issuer)
        withheld_total = int(self.miner_debt_status.get("withheld_total", 0))
        use_withheld = withheld_total > 0
        needed_from_issued = max(0, int(fine_amount) - (withheld_total if use_withheld else 0))
        return balance >= needed_from_issued

    def maybe_auto_pay_fine(self):
        auto_pay = self.miner_auto_pay_fine_var.get()
        auto_promise = self.miner_fine_promise_var.get()
        if not (auto_pay or auto_promise):
            return
        if self.miner_fine_request_in_flight:
            return
        pending_fines = int(self.miner_debt_status.get("pending_fines", 0))
        signature_fines = int(self.miner_debt_status.get("signature_fines", 0))
        pending_delay_fines = int(self.miner_debt_status.get("pending_delay_fines", 0))
        if (pending_fines + signature_fines) <= 0:
            return
        if self.pending_miner_transfers and signature_fines <= 0 and pending_delay_fines <= 0:
            return
        fine_amount = int(self.miner_debt_status.get("fine_amount", 0))
        if fine_amount <= 0:
            return
        if auto_pay and not auto_promise and not self.can_cover_fine_amount(fine_amount):
            return
        if not self.connected:
            return
        self.request_miner_fine(auto=True)

    def maybe_request_miner_fine_after_mint(self):
        if self.miner_fine_request_in_flight:
            return False
        if not self.connected:
            return False
        signature_fines = int(self.miner_debt_status.get("signature_fines", 0))
        pending_delay_fines = int(self.miner_debt_status.get("pending_delay_fines", 0))
        if self.pending_miner_transfers and signature_fines <= 0 and pending_delay_fines <= 0:
            return False
        if not (self.miner_auto_pay_fine_var.get() or self.miner_fine_promise_var.get()):
            return False
        self.request_miner_fine(auto=True)
        return True

    def maybe_prompt_miner_protections(self, auto=False):
        if auto or self.miner_protection_prompted:
            return
        self.miner_protection_prompted = True
        if not self.miner_signature_monitor_var.get():
            enable_monitor = messagebox.askyesno(
                "Monitoramento de assinaturas",
                "O monitoramento de assinaturas esta desativado.\n"
                "Deseja ativar para evitar penalidades do servidor?"
            )
            if enable_monitor:
                self.miner_signature_monitor_var.set(True)
                self.handle_signature_monitor_toggle()
        if self.miner_auto_pay_fine_var.get() or self.miner_fine_promise_var.get():
            return
        choice = messagebox.askyesnocancel(
            "Multas automaticas",
            "Deseja ativar o pagamento automatico de multas ou promessas?\n"
            "Sim = pagamento automatico\nNao = promessa automatica"
        )
        if choice is True:
            self.miner_auto_pay_fine_var.set(True)
            self.maybe_auto_pay_fine()
        elif choice is False:
            self.miner_fine_promise_var.set(True)
            self.maybe_auto_pay_fine()

    def handle_signature_monitor_toggle(self):
        if not self.miner_signature_monitor_var.get():
            return
        for transfer_id in list(self.pending_miner_transfers.keys()):
            self.show_signature_popup(transfer_id)
            if self.miner_signature_auto_var.get():
                self.root.after(100, lambda tid=transfer_id: self.sign_transfer_by_id(tid))

    async def fetch_exchange_inter_server_evidence(self, transfer):
        inter_server = transfer.get("inter_server", {}) or {}
        issuer = inter_server.get("issuer") or transfer.get("sender")
        reserved_id = inter_server.get("issuer_reserved_contract_id")
        out_id = inter_server.get("issuer_out_contract_id")
        owner_key_id = inter_server.get("issuer_owner_key_contract_id")
        exchange_contract_id = inter_server.get("exchange_contract_id")
        exchange_contract_hash = inter_server.get("exchange_contract_hash")
        exchange_contract_b64 = inter_server.get("exchange_contract_content") or ""
        issuer_voucher_ids = inter_server.get("issuer_voucher_ids", []) or []
        if not issuer:
            return None, "Endereco do emissor ausente."
        if not all([reserved_id, out_id, owner_key_id, exchange_contract_id, exchange_contract_hash, exchange_contract_b64]):
            return None, "Dados inter-servidor incompletos."
        server_info = await self.fetch_server_info(issuer)
        if not server_info or not server_info.get("public_key"):
            return None, "Nao foi possivel obter a chave publica do emissor."
        issuer_public_key = server_info.get("public_key")
        reserved_text = await self.fetch_contract_from_server(issuer, reserved_id)
        out_text = await self.fetch_contract_from_server(issuer, out_id)
        owner_key_text = await self.fetch_contract_from_server(issuer, owner_key_id)
        if not reserved_text or not out_text or not owner_key_text:
            return None, "Nao foi possivel obter contratos do emissor."
        if not self.verify_contract_signature_with_key(reserved_text, issuer_public_key):
            return None, "Assinatura do contrato reservado invalida."
        if not self.verify_contract_signature_with_key(out_text, issuer_public_key):
            return None, "Assinatura do contrato de queimadura invalida."
        if not self.verify_contract_signature_with_key(owner_key_text, issuer_public_key):
            return None, "Assinatura do contrato de chave do usuario invalida."
        owner_key_details = self.extract_contract_details_map(owner_key_text)
        owner_public_key = owner_key_details.get("OWNER_PUBLIC_KEY", "")
        if not owner_public_key:
            return None, "Contrato de chave sem chave publica."
        try:
            exchange_contract_text = base64.b64decode(exchange_contract_b64).decode("utf-8", errors="replace")
        except Exception:
            return None, "Contrato de cambio local invalido."
        exchange_hash = hashlib.sha256(exchange_contract_text.encode("utf-8")).hexdigest()
        if exchange_hash != exchange_contract_hash:
            return None, "Hash do contrato de cambio nao confere."
        if not self.verify_contract_signature_with_key(exchange_contract_text, owner_public_key):
            return None, "Assinatura do contrato de cambio invalida."
        issuer_voucher_audit = []
        if issuer_voucher_ids:
            issuer_voucher_audit = await self.fetch_voucher_audit_direct(issuer, issuer_voucher_ids)
            if not issuer_voucher_audit:
                return None, "Nao foi possivel auditar os vouchers do emissor."
        evidence = {
            "issuer": issuer,
            "issuer_public_key": issuer_public_key,
            "reserved_contract_id": reserved_id,
            "reserved_contract_text": reserved_text,
            "out_contract_id": out_id,
            "out_contract_text": out_text,
            "owner_key_contract_id": owner_key_id,
            "owner_key_contract_text": owner_key_text,
            "exchange_contract_id": exchange_contract_id,
            "exchange_contract_hash": exchange_contract_hash,
            "issuer_voucher_ids": issuer_voucher_ids,
            "issuer_voucher_audit": issuer_voucher_audit
        }
        return evidence, ""

    def sign_transfer_by_id(self, transfer_id):
        if not transfer_id:
            return
        transfer = self.pending_miner_transfers.get(transfer_id)
        if not transfer:
            self.log_hps_mining_message("Transferencia pendente nao encontrada.")
            return
        async def do_sign():
            start_time = time.time()
            voucher_ids = transfer.get("locked_voucher_ids", []) or []
            audit_results = []
            if voucher_ids:
                audit_results = await self.fetch_voucher_audit(voucher_ids, transfer_id=transfer_id)
            audit_summary, failures = self.evaluate_voucher_audit(audit_results)
            inter_server_evidence = None
            if transfer.get("transfer_type") == "exchange_in":
                inter_server_evidence, error = await self.fetch_exchange_inter_server_evidence(transfer)
                if not inter_server_evidence:
                    self.root.after(0, lambda: self.log_hps_mining_message(f"Falha no cambio inter-servidor: {error}"))
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Cambio inter-servidor",
                        f"Falha ao verificar dados do emissor.\n{error}"
                    ))
                    return
            pow_audit, trace_entries, trace_failures = await self.analyze_voucher_pow_trace(
                audit_results,
                inter_server_evidence=inter_server_evidence
            )
            exchange_trace = []
            if voucher_ids:
                exchange_trace = await self.fetch_exchange_trace(voucher_ids)
            if trace_failures:
                failures.update(trace_failures)
            if transfer_id in self.audit_override_validated:
                failures = {}
            elif voucher_ids:
                audited_ids = {item.get("voucher_id") for item in audit_results if item.get("voucher_id")}
                for voucher_id in voucher_ids:
                    if voucher_id not in audited_ids:
                        failures[voucher_id] = "audit_missing"
            if failures and all(reason in ("audit_missing", "trace_missing") for reason in failures.values()):
                self.root.after(0, lambda: self.log_hps_mining_message(
                    f"Auditoria indisponivel para {transfer_id}, prosseguindo com cautela."
                ))
                failures = {}
            if failures:
                if transfer_id in self.pending_invalidation_transfers:
                    self.root.after(0, lambda: self.log_hps_mining_message(f"Invalidação já em andamento para {transfer_id}."))
                    return
                invalid_ids = list(failures.keys())
                details = [
                    ("TRANSFER_ID", transfer_id),
                    ("REASON", "voucher_invalid"),
                    ("VOUCHERS", json.dumps(invalid_ids, ensure_ascii=True)),
                    ("EVIDENCE", json.dumps({
                        "failures": failures,
                        "audit": audit_summary,
                        "pow_audit": pow_audit,
                        "trace": trace_entries
                    }, ensure_ascii=True))
                ]
                contract_template = self.build_contract_template("voucher_invalidate", details)
                signed_text, _ = self.apply_contract_signature(contract_template)
                self.pending_invalidation_transfers.add(transfer_id)
                await self.sio.emit('invalidate_vouchers', {
                    "contract_content": base64.b64encode(signed_text.encode("utf-8")).decode("utf-8")
                })
                self.root.after(0, lambda: self.log_hps_mining_message("Invalidação de vouchers enviada."))
                return
            report_details = [
                ("TRANSFER_ID", transfer_id),
                ("TRANSFER_TYPE", transfer.get("transfer_type", "")),
                ("SENDER", transfer.get("sender", "")),
                ("RECEIVER", transfer.get("receiver", "")),
                ("AMOUNT", transfer.get("amount", 0)),
                ("FEE_AMOUNT", transfer.get("fee_amount", 0)),
                ("FEE_SOURCE", transfer.get("fee_source", "")),
                ("CONTRACT_ID", transfer.get("contract_id", "")),
                ("LOCKED_VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True)),
                ("VOUCHER_AUDIT", json.dumps(audit_summary, ensure_ascii=True)),
                ("VOUCHER_POW_AUDIT", json.dumps(pow_audit, ensure_ascii=True)),
                ("VOUCHER_TRACE", json.dumps(trace_entries, ensure_ascii=True))
            ]
            if exchange_trace:
                report_details.append(("EXCHANGE_TRACE", json.dumps(exchange_trace, ensure_ascii=True)))
            if inter_server_evidence:
                report_details.extend([
                    ("INTER_SERVER_ISSUER", inter_server_evidence.get("issuer", "")),
                    ("ISSUER_VOUCHER_IDS", json.dumps(inter_server_evidence.get("issuer_voucher_ids", []), ensure_ascii=True)),
                    ("ISSUER_VOUCHER_AUDIT", json.dumps(inter_server_evidence.get("issuer_voucher_audit", []), ensure_ascii=True)),
                    ("ISSUER_RESERVED_CONTRACT_ID", inter_server_evidence.get("reserved_contract_id", "")),
                    ("ISSUER_RESERVED_CONTRACT", base64.b64encode(inter_server_evidence.get("reserved_contract_text", "").encode("utf-8")).decode("utf-8")),
                    ("ISSUER_OUT_CONTRACT_ID", inter_server_evidence.get("out_contract_id", "")),
                    ("ISSUER_OUT_CONTRACT", base64.b64encode(inter_server_evidence.get("out_contract_text", "").encode("utf-8")).decode("utf-8")),
                    ("ISSUER_OWNER_KEY_CONTRACT_ID", inter_server_evidence.get("owner_key_contract_id", "")),
                    ("ISSUER_OWNER_KEY_CONTRACT", base64.b64encode(inter_server_evidence.get("owner_key_contract_text", "").encode("utf-8")).decode("utf-8")),
                    ("CLIENT_EXCHANGE_CONTRACT_ID", inter_server_evidence.get("exchange_contract_id", "")),
                    ("CLIENT_EXCHANGE_CONTRACT_HASH", inter_server_evidence.get("exchange_contract_hash", ""))
                ])
            report_template = self.build_contract_template("miner_signature_report", report_details)
            report_text, _ = self.apply_contract_signature(report_template)
            details = [
                ("TRANSFER_ID", transfer_id),
                ("TRANSFER_TYPE", transfer.get("transfer_type", "")),
                ("SENDER", transfer.get("sender", "")),
                ("RECEIVER", transfer.get("receiver", "")),
                ("AMOUNT", transfer.get("amount", 0))
            ]
            contract_template = self.build_contract_template("transfer_signature", details)
            signed_text, _ = self.apply_contract_signature(contract_template)
            elapsed = time.time() - start_time
            if elapsed < 4.0:
                await asyncio.sleep(4.0 - elapsed)
            await self.sio.emit('sign_transfer', {
                "transfer_id": transfer_id,
                "contract_content": base64.b64encode(signed_text.encode("utf-8")).decode("utf-8"),
                "report_content": base64.b64encode(report_text.encode("utf-8")).decode("utf-8")
            })
            self.root.after(0, lambda: self.log_hps_mining_message(f"Assinatura enviada para transferencia {transfer_id}."))

        asyncio.run_coroutine_threadsafe(do_sign(), self.loop)

    def show_monetary_transfer_popup(self, transfer_id, miner, status="awaiting_miner", reason="", details=None):
        if not transfer_id:
            return
        existing = self.monetary_transfer_popups.get(transfer_id)
        if existing and existing.get("window") and existing["window"].winfo_exists():
            return
        popup = tk.Toplevel(self.root)
        popup.title("Transacao em analise")
        popup.geometry("360x180")
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()
        miner_label = ttk.Label(popup, text=f"Minerador(a): {miner}", font=("Arial", 11, "bold"))
        miner_label.pack(padx=12, pady=(12, 6))
        status_text = self._format_monetary_status(status, reason)
        status_label = ttk.Label(popup, text=status_text, wraplength=320)
        status_label.pack(padx=12, pady=(0, 8))
        detail_label = ttk.Label(popup, text=self._format_monetary_details(details), wraplength=320)
        detail_label.pack(padx=12, pady=(0, 10))
        close_button = ttk.Button(popup, text="Fechar", command=popup.destroy)
        if status in ("signed", "invalidated", "failed"):
            close_button.pack(pady=(0, 10))
        popup.protocol("WM_DELETE_WINDOW", lambda: None)
        self.monetary_transfer_popups[transfer_id] = {
            "window": popup,
            "miner_label": miner_label,
            "status_label": status_label,
            "detail_label": detail_label,
            "close_button": close_button
        }

    def _format_monetary_status(self, status, reason):
        if status == "awaiting_miner":
            return "Aguardando mineradores disponiveis."
        if status == "assigned":
            return "Minerador encontrado. Sua transacao esta em analise."
        if status == "signed":
            return "Transacao validada pelo minerador."
        if status == "invalidated":
            return f"Transacao invalidada: {reason or 'motivo desconhecido'}."
        if status == "failed":
            return f"Transacao falhou: {reason or 'erro desconhecido'}."
        return "Sua transacao esta sendo analisada, aguarde..."

    def _format_monetary_details(self, details):
        if not details:
            return ""
        invalid_vouchers = details.get("invalid_vouchers")
        if isinstance(invalid_vouchers, dict) and invalid_vouchers:
            lines = [f"{vid}: {why}" for vid, why in invalid_vouchers.items()]
            return "Detalhes:\n" + "\n".join(lines[:6])
        message = details.get("message") if isinstance(details, dict) else ""
        return message or ""

    def update_monetary_transfer_popup(self, transfer_id, miner=None, status=None, reason="", details=None):
        entry = self.monetary_transfer_popups.get(transfer_id)
        if not entry:
            self.show_monetary_transfer_popup(transfer_id, miner or "desconhecido", status or "awaiting_miner", reason, details)
            return
        popup = entry.get("window")
        if not popup or not popup.winfo_exists():
            return
        miner_label = entry.get("miner_label")
        status_label = entry.get("status_label")
        detail_label = entry.get("detail_label")
        close_button = entry.get("close_button")
        if miner_label and miner:
            miner_label.config(text=f"Minerador(a): {miner}")
        if status_label and status:
            status_label.config(text=self._format_monetary_status(status, reason))
        if detail_label is not None:
            detail_label.config(text=self._format_monetary_details(details))
        if close_button:
            if status in ("signed", "invalidated", "failed"):
                if not close_button.winfo_ismapped():
                    close_button.pack(pady=(0, 10))
            else:
                if close_button.winfo_ismapped():
                    close_button.pack_forget()

    def close_monetary_transfer_popup(self, transfer_id, status=None):
        entry = self.monetary_transfer_popups.pop(transfer_id, None)
        if not entry:
            return
        popup = entry.get("window")
        if popup and popup.winfo_exists():
            popup.destroy()

    def show_signature_popup(self, transfer_id):
        transfer = self.pending_miner_transfers.get(transfer_id)
        if not transfer:
            return
        if transfer_id in self.signature_popups:
            popup = self.signature_popups.get(transfer_id)
            if popup and popup.winfo_exists():
                return
        popup = tk.Toplevel(self.root)
        popup.title("Assinatura de transferencia")
        popup.geometry("420x260")
        popup.transient(self.root)
        popup.grab_set()
        self.signature_popups[transfer_id] = popup

        info = [
            f"Transferencia: {transfer_id}",
            f"Tipo: {transfer.get('transfer_type', '')}",
            f"De: {transfer.get('sender', '')}",
            f"Para: {transfer.get('receiver', '')}",
            f"Valor: {transfer.get('amount', 0)} HPS",
            f"Taxa: {transfer.get('fee_amount', 0)} HPS",
            f"Fonte da taxa: {transfer.get('fee_source', '')}",
        ]
        deadline = transfer.get("miner_deadline", 0)
        if deadline:
            remaining = max(0, int(deadline - time.time()))
            info.append(f"Prazo: {remaining}s")

        ttk.Label(popup, text="Assinatura pendente", font=("Arial", 12, "bold")).pack(pady=8)
        for line in info:
            ttk.Label(popup, text=line).pack(anchor=tk.W, padx=12)
        countdown_label = ttk.Label(popup, text="")
        countdown_label.pack(anchor=tk.W, padx=12, pady=(4, 0))

        buttons = ttk.Frame(popup)
        buttons.pack(fill=tk.X, pady=12)
        ttk.Button(buttons, text="Assinar agora", command=lambda: self.sign_transfer_by_id(transfer_id)).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Fechar", command=popup.destroy).pack(side=tk.RIGHT, padx=8)

        def on_close():
            self.signature_popups.pop(transfer_id, None)
            popup.destroy()
        popup.protocol("WM_DELETE_WINDOW", on_close)
        if self.miner_signature_auto_var.get():
            def update_countdown():
                if transfer_id not in self.pending_miner_transfers:
                    return
                deadline = transfer.get("miner_deadline", 0)
                remaining = max(0, int(deadline - time.time()))
                countdown_label.config(text=f"Assinando automaticamente em {remaining}s.")
                if remaining <= 0:
                    return
                popup.after(500, update_countdown)
            update_countdown()

    def handle_miner_signature_request(self, data):
        transfer_id = data.get("transfer_id")
        if not transfer_id:
            return
        self.pending_miner_transfers[transfer_id] = data
        pending = data.get("pending_signatures", self.miner_pending_signatures)
        self.update_miner_pending_signatures(pending)
        self.miner_signature_blocked = True
        self.pow_solver.stop_solving()
        if self.hps_mint_callback:
            self.hps_mint_callback = None
            self.hps_mint_requested_at = None
        self.update_hps_mining_status("Assinatura pendente")
        deadline = data.get("miner_deadline", 0)
        if deadline:
            remaining = max(0, int(deadline - time.time()))
            self.log_hps_mining_message(f"Assinatura requerida em {remaining}s para transferencia {transfer_id}.")
        else:
            self.log_hps_mining_message(f"Assinatura requerida para transferencia {transfer_id}.")
        if self.miner_signature_monitor_var.get():
            self.show_signature_popup(transfer_id)
            if self.miner_signature_auto_var.get():
                self.root.after(100, lambda: self.sign_transfer_by_id(transfer_id))
        else:
            self.log_hps_mining_message("Ative o monitoramento de assinaturas para evitar bloqueio.")
            self.root.after(0, lambda: messagebox.showwarning(
                "Assinatura pendente",
                "Ative o monitoramento de assinaturas. Pendencias nao vistas bloqueiam a mineracao."
            ))

    def sign_next_pending_transfer(self):
        if not self.pending_miner_transfers:
            self.log_hps_mining_message("Nenhuma transferencia pendente para assinar.")
            return
        transfer_id = next(iter(self.pending_miner_transfers.keys()))
        self.sign_transfer_by_id(transfer_id)

    def request_miner_fine(self, auto=False):
        if self.miner_fine_request_in_flight:
            return
        self.miner_fine_request_in_flight = True
        self.miner_fine_request_source = "auto" if auto else "manual"
        asyncio.run_coroutine_threadsafe(self.sio.emit('request_miner_fine', {}), self.loop)

    def pay_miner_fine(self, fine_amount, pending_count, promise=None):
        issuer = self.current_server or ""
        promise = self.miner_fine_promise_var.get() if promise is None else bool(promise)
        withheld_total = int(self.miner_debt_status.get("withheld_total", 0))
        use_withheld = withheld_total > 0 and not promise
        needed_from_issued = max(0, fine_amount - (withheld_total if use_withheld else 0))
        voucher_ids = []
        total = 0
        if not promise:
            voucher_ids, total = self.select_hps_vouchers_for_cost(needed_from_issued, issuer)
            if total < needed_from_issued:
                self.log_hps_mining_message("Saldo insuficiente para pagar a multa.")
                self.miner_fine_request_in_flight = False
                self.miner_fine_request_source = ""
                return
            self.reserve_local_vouchers(voucher_ids)
        details = [
            ("AMOUNT", fine_amount),
            ("PENDING", pending_count)
        ]
        contract_template = self.build_contract_template("miner_fine", details)
        signed_text, _ = self.apply_contract_signature(contract_template)
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('pay_miner_fine', {
                "voucher_ids": voucher_ids,
                "contract_content": base64.b64encode(signed_text.encode("utf-8")).decode("utf-8"),
                "use_withheld": use_withheld,
                "promise": bool(promise)
            }),
            self.loop
        )
        self.log_hps_mining_message(f"Pagamento de multa enviado ({fine_amount} HPS).")

    def prompt_miner_fine_payment(self, fine_amount, pending_count, debt_status):
        balance = self.get_hps_balance_value(self.current_server or "")
        withheld_total = int(debt_status.get("withheld_total", 0))
        promise_active = int(debt_status.get("promise_active", 0))
        fine_per_pending = int(debt_status.get("fine_per_pending", 0))
        use_withheld = withheld_total > 0
        needed_from_issued = max(0, fine_amount - (withheld_total if use_withheld else 0))
        voucher_ids, total = self.select_hps_vouchers_for_cost(needed_from_issued, self.current_server or "")
        debit_estimate = total if needed_from_issued > 0 else 0
        fine_per_text = "valor variavel"
        if pending_count > 0 and fine_per_pending > 0 and fine_amount == (fine_per_pending * pending_count):
            fine_per_text = f"{fine_per_pending} HPS por pendencia"
        details = (
            f"Pendencias: {pending_count}\n"
            f"Multa total: {fine_amount} HPS ({fine_per_text})\n"
            f"Saldo atual: {balance} HPS\n"
            f"Vouchers pendentes: {withheld_total} HPS\n"
            f"Debito estimado no saldo: {debit_estimate} HPS\n"
            f"Promessa ativa: {'sim' if promise_active else 'nao'}"
        )
        popup = tk.Toplevel(self.root)
        popup.title("Pagamento de multa")
        popup.geometry("360x220")
        popup.transient(self.root)
        popup.grab_set()
        ttk.Label(popup, text="Como deseja prosseguir?", font=("Arial", 12, "bold")).pack(pady=8)
        ttk.Label(popup, text=details, justify=tk.LEFT).pack(anchor=tk.W, padx=12)
        buttons = ttk.Frame(popup)
        buttons.pack(fill=tk.X, pady=10)
        ttk.Button(buttons, text="Pagar agora", command=lambda: self._confirm_miner_fine_payment(popup, fine_amount, pending_count, False)).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Promessa", command=lambda: self._confirm_miner_fine_payment(popup, fine_amount, pending_count, True)).pack(side=tk.LEFT, padx=8)
        def close_popup():
            if popup and popup.winfo_exists():
                popup.destroy()
            self.miner_fine_request_in_flight = False
            self.miner_fine_request_source = ""
        ttk.Button(buttons, text="Cancelar", command=close_popup).pack(side=tk.RIGHT, padx=8)
        popup.protocol("WM_DELETE_WINDOW", close_popup)

    def _confirm_miner_fine_payment(self, popup, fine_amount, pending_count, promise):
        if popup and popup.winfo_exists():
            popup.destroy()
        self.pay_miner_fine(fine_amount, pending_count, promise=promise)

    def schedule_auto_mint(self, delay=None):
        if not self.hps_auto_mint_var.get():
            return
        delay = self.hps_auto_mint_interval if delay is None else delay
        delay = max(0.0, float(delay))
        if self.hps_auto_mint_job:
            self.root.after_cancel(self.hps_auto_mint_job)
        self.hps_auto_mint_job = self.root.after(int(delay * 1000), self.maybe_start_auto_mint)

    def maybe_start_auto_mint(self):
        self.hps_auto_mint_job = None
        if not self.hps_auto_mint_var.get():
            return
        if not self.connected:
            self.update_hps_mining_status("Aguardando conexão")
            self.schedule_auto_mint()
            return
        if self.miner_mint_suspended:
            self.update_hps_mining_status("Mineracao suspensa")
            self.schedule_auto_mint(5.0)
            return
        if self.miner_signature_blocked:
            self.update_hps_mining_status("Assinatura pendente")
            self.schedule_auto_mint(5.0)
            return
        if self.pow_solver.is_solving or any([
            self.upload_callback,
            self.dns_callback,
            self.report_callback,
            self.contract_reset_callback,
            self.contract_certify_callback,
            self.contract_transfer_callback,
            self.missing_contract_certify_callback,
            self.usage_contract_callback,
            self.hps_mint_callback,
            self.hps_transfer_callback
        ]):
            if self.hps_mint_callback and not self.pow_solver.is_solving:
                if self.hps_mint_requested_at and time.time() - self.hps_mint_requested_at > 45:
                    self.hps_mint_callback = None
                    self.hps_mint_requested_at = None
                else:
                    self.schedule_auto_mint(5.0)
                    return
            self.schedule_auto_mint(5.0)
            return
        self.start_hps_mint(auto=True)

    def toggle_auto_mint(self):
        if self.hps_auto_mint_var.get():
            self.maybe_prompt_miner_protections(auto=False)
            self.update_hps_mining_status("Ativo")
            self.schedule_auto_mint(0.1)
        else:
            self.update_hps_mining_status("Parado")
            if self.hps_auto_mint_job:
                self.root.after_cancel(self.hps_auto_mint_job)
                self.hps_auto_mint_job = None

    def update_hps_wallet_ui(self):
        if not hasattr(self, "hps_voucher_tree"):
            return
        self.hps_voucher_tree.delete(*self.hps_voucher_tree.get_children())
        for voucher in sorted(self.hps_vouchers.values(), key=lambda v: v.get("issued_at", 0), reverse=True):
            issued_at = time.strftime("%d/%m %H:%M", time.localtime(voucher.get("issued_at", 0)))
            status = "invalid" if voucher.get("invalidated") else voucher.get("status", "")
            self.hps_voucher_tree.insert(
                "",
                tk.END,
                iid=voucher["voucher_id"],
                values=(
                    voucher["voucher_id"][:10],
                    voucher.get("value", 0),
                    voucher.get("issuer", ""),
                    status,
                    voucher.get("reason", ""),
                    issued_at
                )
            )

    def refresh_hps_wallet(self):
        if not self.connected:
            return
        asyncio.run_coroutine_threadsafe(self.sio.emit('request_hps_wallet', {}), self.loop)

    async def request_economy_report(self):
        if not self.connected:
            return
        await self.sio.emit('request_economy_report', {})

    def save_economy_report_file(self, server_address, payload, signature):
        reports_dir = os.path.join(self.crypto_dir, "economy_reports")
        os.makedirs(reports_dir, exist_ok=True)
        timestamp = int(payload.get("timestamp", time.time()))
        safe_server = server_address.replace(":", "_").replace("/", "_")
        report_path = os.path.join(reports_dir, f"{safe_server}_{timestamp}.json")
        report = {"payload": payload, "signature": signature}
        try:
            with open(report_path, "w", encoding="ascii") as f:
                json.dump(report, f, indent=2, ensure_ascii=True)
        except Exception:
            pass

    def get_foreign_voucher_summary(self):
        summary = {}
        for voucher in self.hps_vouchers.values():
            if self.voucher_matches_current_server(voucher):
                continue
            if voucher.get("status") != "valid" or voucher.get("invalidated"):
                continue
            issuer = voucher.get("issuer", "")
            if not issuer:
                continue
            entry = summary.setdefault(issuer, {"count": 0, "total": 0})
            entry["count"] += 1
            entry["total"] += int(voucher.get("value", 0))
        return summary

    def update_exchange_ui(self):
        if not hasattr(self, "exchange_servers_tree"):
            return
        self.exchange_servers_tree.delete(*self.exchange_servers_tree.get_children())
        current_multiplier = None
        if self.current_server and self.current_server in self.server_economy_stats:
            current_multiplier = self.server_economy_stats[self.current_server].get("multiplier")
        for server_address, stats in sorted(self.server_economy_stats.items()):
            multiplier = float(stats.get("multiplier", 1.0))
            rate_orig = 1.0 / multiplier if multiplier else 0.0
            rate_to_current = ""
            if current_multiplier and multiplier:
                rate_to_current = f"{(current_multiplier / multiplier):.4f}"
            issued_at = time.strftime("%d/%m %H:%M", time.localtime(stats.get("last_report_ts", 0)))
            total_minted = float(stats.get("total_minted", 0.0))
            self.exchange_servers_tree.insert(
                "",
                tk.END,
                values=(
                    server_address,
                    f"{total_minted:.2f}",
                    f"{multiplier:.4f}",
                    f"{rate_orig:.4f}",
                    rate_to_current,
                    issued_at
                )
            )
        if hasattr(self, "exchange_voucher_tree"):
            self.exchange_voucher_tree.delete(*self.exchange_voucher_tree.get_children())
            summary = self.get_foreign_voucher_summary()
            for issuer, entry in summary.items():
                self.exchange_voucher_tree.insert(
                    "",
                    tk.END,
                    iid=issuer,
                    values=(issuer, entry["count"], entry["total"])
                )

    def invalidate_issuer_vouchers(self, issuer):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE browser_hps_vouchers SET invalidated = 1, status = ?
                              WHERE issuer = ?''', ("invalid", issuer))
            conn.commit()
        for voucher in self.hps_vouchers.values():
            if voucher.get("issuer") == issuer:
                voucher["invalidated"] = True
                voucher["status"] = "invalid"
        self.update_hps_balance()

    def start_hps_mint(self, auto=False):
        if not self.connected:
            if not auto:
                messagebox.showwarning("Aviso", "Conecte-se à rede para minerar $HPS.")
            return
        if not self.confirm_fraud_action("Mineração de HPS", auto=auto):
            return
        if self.miner_mint_suspended:
            if not auto:
                self.show_miner_debt_popup(self.miner_debt_status)
            return
        if self.pow_solver.is_solving or self.hps_mint_callback:
            if auto:
                self.schedule_auto_mint()
            else:
                messagebox.showinfo("Mineração", "Já existe uma mineração em andamento.")
            return
        self.maybe_prompt_miner_protections(auto=auto)
        self.update_hps_mining_status("Solicitando PoW")
        self.log_hps_mining_message("Solicitando desafio de PoW para mineração.")
        reason = self.hps_mint_reason_var.get().strip() or "mining"

        def do_mint(pow_nonce, hashrate_observed):
            details = [("REASON", reason)]
            if self.pending_hps_mint_voucher_id:
                details.append(("VOUCHER_ID", self.pending_hps_mint_voucher_id))
            contract_template = self.build_contract_template("hps_mint", details)
            signed_text, _ = self.apply_contract_signature(contract_template)
            contract_text = signed_text
            valid, error = self.validate_contract_text_allowed(contract_text, ["hps_mint"])
            if not valid:
                self.root.after(0, lambda: self.record_hps_mint_failure(f"Contrato invalido: {error}"))
                return
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('mint_hps_voucher', {
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed,
                    'reason': reason,
                    'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8')
                }),
                self.loop
            )
            self.pending_hps_mint_voucher_id = None

        self.hps_mint_callback = do_mint
        self.hps_mint_requested_at = time.time()
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("hps_mint"), self.loop)

    def open_selected_voucher(self):
        selection = self.hps_voucher_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um voucher para abrir.")
            return
        voucher_id = selection[0]
        voucher = self.hps_vouchers.get(voucher_id)
        if not voucher:
            messagebox.showwarning("Aviso", "Voucher não encontrado.")
            return
        self.show_voucher_popup(voucher)

    def show_voucher_popup(self, voucher):
        payload = voucher.get("payload", {})
        popup = tk.Toplevel(self.root)
        popup.title("Voucher $HPS")
        popup.geometry("360x220")
        popup.transient(self.root)
        popup.grab_set()

        canvas = tk.Canvas(popup, width=340, height=180, bg="#f2e6c9", highlightthickness=2, highlightbackground="#8b6b3f")
        canvas.pack(padx=10, pady=10)
        canvas.create_rectangle(8, 8, 332, 172, outline="#8b6b3f", width=2)
        canvas.create_text(20, 18, anchor="w", text="HPS", font=("Arial", 16, "bold"), fill="#5a432a")
        canvas.create_text(320, 18, anchor="e", text=f"{payload.get('value', 0)} HPS", font=("Arial", 14, "bold"), fill="#5a432a")
        canvas.create_text(20, 50, anchor="w", text=f"Dono: {payload.get('owner', '')}", font=("Arial", 10), fill="#5a432a")
        canvas.create_text(20, 75, anchor="w", text=f"Emissor: {payload.get('issuer', '')}", font=("Arial", 9), fill="#5a432a")
        canvas.create_text(20, 100, anchor="w", text=f"Motivo: {payload.get('reason', '')}", font=("Arial", 9), fill="#5a432a")
        issued_at = payload.get("issued_at", 0)
        issued_text = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(issued_at)) if issued_at else ""
        canvas.create_text(20, 125, anchor="w", text=f"Emitido em: {issued_text}", font=("Arial", 8), fill="#5a432a")
        conditions = payload.get("conditions", {})
        if conditions:
            canvas.create_text(20, 148, anchor="w", text=f"Condições: {json.dumps(conditions, ensure_ascii=True)}", font=("Arial", 7), fill="#5a432a")

    def save_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for server_address in self.known_servers:
                use_ssl = 1 if server_address.startswith('https://') else 0
                cursor.execute(
                    '''INSERT OR REPLACE INTO browser_known_servers 
                    (server_address, last_connected, is_active, use_ssl) 
                    VALUES (?, ?, ?, ?)''',
                    (server_address, time.time(), 1, use_ssl)
                )
            conn.commit()

    def calculate_disk_usage(self):
        if os.path.exists(self.crypto_dir):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(self.crypto_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    total_size += os.path.getsize(fp)
            self.used_disk_space = total_size
            
        self.disk_usage_var.set(f"Disco: {self.used_disk_space // (1024*1024)}MB/{self.disk_quota // (1024*1024)}MB")

    def generate_client_identifier(self):
        machine_id = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()
        return hashlib.sha256((machine_id + self.session_id).encode()).hexdigest()

    def setup_ui(self):
        self.setup_styles()
        self.setup_main_frames()
        self.setup_login_ui()
        self.setup_browser_ui()
        self.setup_dns_ui()
        self.setup_upload_ui()
        self.setup_hps_actions_ui()
        self.setup_hps_wallet_ui()
        self.setup_exchange_ui()
        self.setup_network_ui()
        self.setup_contracts_ui()
        self.setup_settings_ui()
        self.setup_servers_ui()
        self.setup_stats_ui()
        self.set_tab_visibility(False)
        self.show_login()

    def create_scrollable_tab(self, parent):
        container, content = create_scrollable_container(parent)
        return container, content

    def add_main_tab(self, frame, title):
        self.main_tabs[frame] = title
        self.main_tab_order.append(frame)
        if hasattr(self, "main_notebook"):
            self.main_notebook.add(frame, text=title)

    def set_tab_visibility(self, logged_in):
        self.logged_in = logged_in
        if not hasattr(self, "main_notebook"):
            return
        for frame in self.main_tab_order:
            title = self.main_tabs.get(frame, "")
            should_show = logged_in or title in self.allowed_tabs_logged_out
            try:
                self.main_notebook.tab(frame, state="normal" if should_show else "hidden")
            except Exception:
                if should_show:
                    try:
                        self.main_notebook.add(frame, text=title)
                    except Exception:
                        pass

    def setup_main_frames(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        ttk.Label(main_frame, text="Navegador P2P Hsyst", font=("Arial", 16, "bold")).grid(row=0, column=0, pady=10)

        self.main_notebook = ttk.Notebook(main_frame)
        self.main_notebook.grid(row=1, column=0, sticky=(tk.N, tk.E, tk.S, tk.W))
        self.main_area = self.main_notebook
        
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.status_var = tk.StringVar(value="Desconectado")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        self.user_var = tk.StringVar(value="Não logado")
        ttk.Label(status_frame, textvariable=self.user_var).pack(side=tk.RIGHT)
        
        self.reputation_var = tk.StringVar(value="100")
        ttk.Label(status_frame, textvariable=self.reputation_var).pack(side=tk.RIGHT, padx=20)
        
        self.ban_status_var = tk.StringVar(value="")
        self.ban_status_label = ttk.Label(status_frame, textvariable=self.ban_status_var, foreground="red")
        self.ban_status_label.pack(side=tk.RIGHT, padx=20)
        
        self.disk_usage_var = tk.StringVar(value=f"0MB/500MB")
        ttk.Label(status_frame, textvariable=self.disk_usage_var).pack(side=tk.RIGHT, padx=20)

    def setup_styles(self):
        style = ttk.Style()
        self.style = style
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", tabmargins=(4, 2, 4, 2))
        style.configure("TNotebook.Tab", padding=(12, 6))
        style.configure("Header.TLabel", font=("Arial", 14, "bold"))
        style.configure("Subtle.TLabel", foreground="#555555")
        style.configure("Accent.TButton", font=("Arial", 10, "bold"))
        style.configure("Trace.TLabelframe", padding=10)
        style.configure("Trace.TLabelframe.Label", font=("Arial", 10, "bold"))

    def setup_login_ui(self):
        self.login_frame, login_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.login_frame, "Login")
        
        ttk.Label(login_frame, text="Entrar na Rede P2P", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(login_frame, text="Servidor:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.server_var = tk.StringVar(value="localhost:8080")
        self.server_combo = ttk.Combobox(login_frame, textvariable=self.server_var, values=self.known_servers)
        self.server_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.server_combo['state'] = 'readonly'
        
        ttk.Label(login_frame, text="Usuário:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(login_frame, text="Senha:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*").grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.auto_login_var = tk.BooleanVar()
        ttk.Checkbutton(login_frame, text="Login automático", variable=self.auto_login_var).grid(row=4, column=0, columnspan=2, pady=5)
        
        self.save_keys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(login_frame, text="Salvar chaves criptográficas", variable=self.save_keys_var).grid(row=5, column=0, columnspan=2, pady=5)
        
        self.use_ssl_var = tk.BooleanVar(value=self.use_ssl)
        ttk.Checkbutton(login_frame, text="Usar SSL/TLS", variable=self.use_ssl_var).grid(row=6, column=0, columnspan=2, pady=5)
        
        self.auto_reconnect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(login_frame, text="Reconexão automática", variable=self.auto_reconnect_var).grid(row=7, column=0, columnspan=2, pady=5)
        
        button_frame = ttk.Frame(login_frame)
        button_frame.grid(row=8, column=0, columnspan=2, pady=20)
        
        self.enter_button = ttk.Button(button_frame, text="Entrar na Rede", command=self.enter_network)
        self.enter_button.pack(side=tk.LEFT, padx=5)
        
        self.exit_button = ttk.Button(button_frame, text="Sair da Rede", command=self.exit_network)
        self.exit_button.pack(side=tk.LEFT, padx=5)
        
        self.login_status = ttk.Label(login_frame, text="", foreground="red")
        self.login_status.grid(row=9, column=0, columnspan=2, pady=5)
        
        login_frame.columnconfigure(1, weight=1)

    def setup_browser_ui(self):
        self.browser_frame, browser_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.browser_frame, "Navegador")
        
        top_frame = ttk.Frame(browser_frame)
        top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(top_frame, text="Voltar", command=self.browser_back, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Avançar", command=self.browser_forward, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Recarregar", command=self.browser_reload, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Início", command=self.browser_home, width=8).pack(side=tk.LEFT, padx=2)
        
        self.browser_url_var = tk.StringVar(value="hps://rede")
        self.browser_url_entry = ttk.Entry(top_frame, textvariable=self.browser_url_var, font=("Arial", 10))
        self.browser_url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browser_url_entry.bind('<Return>', lambda e: self.browser_navigate())
        
        ttk.Button(top_frame, text="Segurança", command=self.show_security_dialog, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Buscar", command=self.show_search_dialog, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Ir", command=self.browser_navigate).pack(side=tk.LEFT, padx=2)
        
        self.browser_content = scrolledtext.ScrolledText(browser_frame, wrap=tk.WORD, font=("Arial", 11))
        self.browser_content.pack(fill=tk.BOTH, expand=True, pady=10)
        self.browser_content.config(state=tk.DISABLED)
        
        self.browser_content.tag_configure("title", font=("Arial", 14, "bold"))
        self.browser_content.tag_configure("verified", foreground="green")
        self.browser_content.tag_configure("unverified", foreground="orange")
        self.browser_content.tag_configure("link", foreground="blue", underline=True)
        self.browser_content.bind("<Button-1>", self.handle_content_click)

    def setup_dns_ui(self):
        self.dns_frame, dns_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.dns_frame, "DNS")
        
        ttk.Label(dns_frame, text="Sistema de Nomes Descentralizado", font=("Arial", 14, "bold")).pack(pady=10)
        
        dns_top_frame = ttk.Frame(dns_frame)
        dns_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(dns_top_frame, text="Domínio:").pack(side=tk.LEFT, padx=5)
        self.dns_domain_var = tk.StringVar()
        ttk.Entry(dns_top_frame, textvariable=self.dns_domain_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(dns_top_frame, text="Registrar", command=self.register_dns).pack(side=tk.LEFT, padx=5)
        ttk.Button(dns_top_frame, text="Resolver", command=self.resolve_dns).pack(side=tk.LEFT, padx=5)
        ttk.Button(dns_top_frame, text="Seguranca", command=self.show_security_dialog).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(dns_frame, text="Hash do conteúdo:").pack(anchor=tk.W, pady=5)
        
        dns_content_frame = ttk.Frame(dns_frame)
        dns_content_frame.pack(fill=tk.X, pady=5)
        
        self.dns_content_hash_var = tk.StringVar()
        ttk.Entry(dns_content_frame, textvariable=self.dns_content_hash_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(dns_content_frame, text="Selecionar Arquivo", command=self.select_dns_content_file).pack(side=tk.LEFT, padx=5)
        
        self.dns_status = ttk.Label(dns_frame, text="", foreground="red")
        self.dns_status.pack(pady=5)
        
        self.dns_tree = ttk.Treeview(dns_frame, columns=("domain", "content_hash", "verified"), show="headings")
        self.dns_tree.heading("domain", text="Domínio")
        self.dns_tree.heading("content_hash", text="Hash do Conteúdo")
        self.dns_tree.heading("verified", text="Verificado")
        self.dns_tree.column("domain", width=200)
        self.dns_tree.column("content_hash", width=300)
        self.dns_tree.column("verified", width=100)
        self.dns_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        self.dns_tree.bind("<Double-1>", self.open_dns_content)

    def setup_upload_ui(self):
        self.upload_frame, upload_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.upload_frame, "Upload")
        
        ttk.Label(upload_frame, text="Upload de Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        upload_form_frame = ttk.Frame(upload_frame)
        upload_form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(upload_form_frame, text="Arquivo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.upload_file_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_file_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Button(upload_form_frame, text="Selecionar", command=self.select_upload_file).grid(row=0, column=2, pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Título:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.upload_title_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_title_var).grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Descrição:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.upload_description_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_description_var).grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Tipo MIME:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.upload_mime_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_mime_var).grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Button(upload_form_frame, text="Upload", command=self.upload_file).grid(row=4, column=0, columnspan=3, pady=10)
        
        self.upload_status = ttk.Label(upload_frame, text="", foreground="red")
        self.upload_status.pack(pady=5)
        
        upload_form_frame.columnconfigure(1, weight=1)

    def setup_hps_actions_ui(self):
        self.hps_actions_frame, hps_actions_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.hps_actions_frame, "Acoes HPS")

        ttk.Label(hps_actions_frame, text="Ações HPS", font=("Arial", 14, "bold")).pack(pady=10)

        select_frame = ttk.Frame(hps_actions_frame)
        select_frame.pack(fill=tk.X, pady=10)

        ttk.Label(select_frame, text="Tipo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.hps_action_var = tk.StringVar(value="Transferir arquivo")
        hps_actions = [
            "Transferir arquivo",
            "Transferir HPS",
            "Transferir dominio",
            "Transferir API App",
            "Criar/Atualizar API App"
        ]
        action_combo = ttk.Combobox(select_frame, textvariable=self.hps_action_var, values=hps_actions, state="readonly")
        action_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        action_combo.bind("<<ComboboxSelected>>", lambda e: self.update_hps_action_fields())
        select_frame.columnconfigure(1, weight=1)

        self.hps_target_user_var = tk.StringVar()
        self.hps_app_name_var = tk.StringVar()
        self.hps_domain_var = tk.StringVar()
        self.hps_new_owner_var = tk.StringVar()
        self.hps_content_hash_var = tk.StringVar()
        self.hps_transfer_amount_var = tk.StringVar()

        self.hps_action_frames = {}

        file_frame = ttk.Frame(hps_actions_frame)
        ttk.Label(file_frame, text="Usuario destino:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.hps_target_user_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(file_frame, text="Hash do conteudo:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.hps_content_hash_var).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        file_frame.columnconfigure(1, weight=1)
        self.hps_action_frames["Transferir arquivo"] = file_frame

        hps_transfer_frame = ttk.Frame(hps_actions_frame)
        ttk.Label(hps_transfer_frame, text="Usuário destino:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(hps_transfer_frame, textvariable=self.hps_target_user_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(hps_transfer_frame, text="Valor (HPS):").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(hps_transfer_frame, textvariable=self.hps_transfer_amount_var).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        hps_transfer_frame.columnconfigure(1, weight=1)
        self.hps_action_frames["Transferir HPS"] = hps_transfer_frame

        domain_frame = ttk.Frame(hps_actions_frame)
        ttk.Label(domain_frame, text="Dominio:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(domain_frame, textvariable=self.hps_domain_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(domain_frame, text="Novo dono:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(domain_frame, textvariable=self.hps_new_owner_var).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        domain_frame.columnconfigure(1, weight=1)
        self.hps_action_frames["Transferir dominio"] = domain_frame

        api_transfer_frame = ttk.Frame(hps_actions_frame)
        ttk.Label(api_transfer_frame, text="Usuario destino:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(api_transfer_frame, textvariable=self.hps_target_user_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(api_transfer_frame, text="Nome do App:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(api_transfer_frame, textvariable=self.hps_app_name_var).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        api_transfer_frame.columnconfigure(1, weight=1)
        self.hps_action_frames["Transferir API App"] = api_transfer_frame

        api_frame = ttk.Frame(hps_actions_frame)
        ttk.Label(api_frame, text="Nome do App:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(api_frame, textvariable=self.hps_app_name_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        api_frame.columnconfigure(1, weight=1)
        self.hps_action_frames["Criar/Atualizar API App"] = api_frame

        action_button = ttk.Button(hps_actions_frame, text="Aplicar Ação", command=self.apply_hps_action_template)
        action_button.pack(pady=10)

        self.update_hps_action_fields()

    def setup_hps_wallet_ui(self):
        self.hps_wallet_frame, wallet_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.hps_wallet_frame, "Carteira HPS")
        
        ttk.Label(wallet_frame, text="Carteira $HPS", font=("Arial", 14, "bold")).pack(pady=10)

        balance_frame = ttk.Frame(wallet_frame)
        balance_frame.pack(fill=tk.X, pady=5)
        ttk.Label(balance_frame, text="Saldo atual:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        ttk.Label(balance_frame, textvariable=self.hps_balance_var).pack(side=tk.LEFT, padx=5)
        ttk.Button(balance_frame, text="Atualizar", command=self.refresh_hps_wallet).pack(side=tk.RIGHT, padx=5)

        mint_frame = ttk.Frame(wallet_frame)
        mint_frame.pack(fill=tk.X, pady=5)
        ttk.Label(mint_frame, text="Motivo da mineração:").pack(side=tk.LEFT, padx=5)
        self.hps_mint_reason_var = tk.StringVar(value="mining")
        ttk.Entry(mint_frame, textvariable=self.hps_mint_reason_var).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(mint_frame, text="Minerar $HPS (PoW)", command=self.start_hps_mint).pack(side=tk.RIGHT, padx=5)

        mining_frame = ttk.LabelFrame(wallet_frame, text="Mineração contínua", padding="10")
        mining_frame.pack(fill=tk.BOTH, pady=10)

        controls_frame = ttk.Frame(mining_frame)
        controls_frame.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(
            controls_frame,
            text="Ativar mineração contínua (sem pausa)",
            variable=self.hps_auto_mint_var,
            command=self.toggle_auto_mint
        ).pack(side=tk.LEFT, padx=5)
        ttk.Label(controls_frame, textvariable=self.hps_mining_status_var).pack(side=tk.RIGHT, padx=5)

        mining_grid = ttk.Frame(mining_frame)
        mining_grid.pack(fill=tk.X, pady=5)
        ttk.Label(mining_grid, text="Bits alvo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_bits_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Tempo decorrido:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_elapsed_var).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Hashrate:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_hashrate_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Tentativas:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_attempts_var).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Minerações concluídas:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_count_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Tempo total:").grid(row=2, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.hps_mining_total_time_var).grid(row=2, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Pendências de assinatura:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.miner_pending_var).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Vouchers pendentes:").grid(row=3, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.miner_withheld_var).grid(row=3, column=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, text="Valor pendente:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(mining_grid, textvariable=self.miner_withheld_value_var).grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)
        for col in range(4):
            mining_grid.columnconfigure(col, weight=1)

        mining_actions = ttk.Frame(mining_frame)
        mining_actions.pack(fill=tk.X, pady=5)
        ttk.Button(mining_actions, text="Assinar próxima pendência", command=self.sign_next_pending_transfer).pack(side=tk.LEFT, padx=5)
        ttk.Button(mining_actions, text="Pagar multa", command=self.request_miner_fine).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(
            mining_actions,
            text="Pagar multa automaticamente",
            variable=self.miner_auto_pay_fine_var,
            command=self.maybe_auto_pay_fine
        ).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(
            mining_actions,
            text="Promessa de pagamento",
            variable=self.miner_fine_promise_var
        ).pack(side=tk.LEFT, padx=5)

        self.hps_mining_log = scrolledtext.ScrolledText(mining_frame, height=6, width=50)
        self.hps_mining_log.pack(fill=tk.BOTH, expand=True, pady=5)
        self.hps_mining_log.config(state=tk.DISABLED)

        signature_frame = ttk.LabelFrame(wallet_frame, text="Assinaturas de transferencia", padding="10")
        signature_frame.pack(fill=tk.X, pady=10)
        ttk.Label(
            signature_frame,
            text="Ative o monitoramento para evitar bloqueio por assinaturas pendentes.",
            foreground="#444"
        ).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Checkbutton(
            signature_frame,
            text="Monitorar assinaturas",
            variable=self.miner_signature_monitor_var,
            command=self.handle_signature_monitor_toggle
        ).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Checkbutton(
            signature_frame,
            text="Consentir assinatura automatica",
            variable=self.miner_signature_auto_var
        ).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(signature_frame, text="Pendencias atuais:").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(signature_frame, textvariable=self.miner_pending_var).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Button(signature_frame, text="Assinar proxima pendencia", command=self.sign_next_pending_transfer).pack(anchor=tk.W, padx=5, pady=4)

        self.hps_voucher_tree = ttk.Treeview(
            wallet_frame,
            columns=("voucher_id", "value", "issuer", "status", "reason", "issued_at"),
            show="headings"
        )
        self.hps_voucher_tree.heading("voucher_id", text="Voucher")
        self.hps_voucher_tree.heading("value", text="Valor")
        self.hps_voucher_tree.heading("issuer", text="Emissor")
        self.hps_voucher_tree.heading("status", text="Status")
        self.hps_voucher_tree.heading("reason", text="Motivo")
        self.hps_voucher_tree.heading("issued_at", text="Emitido em")
        self.hps_voucher_tree.column("voucher_id", width=180)
        self.hps_voucher_tree.column("value", width=60)
        self.hps_voucher_tree.column("issuer", width=150)
        self.hps_voucher_tree.column("status", width=80)
        self.hps_voucher_tree.column("reason", width=120)
        self.hps_voucher_tree.column("issued_at", width=140)
        self.hps_voucher_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        voucher_buttons = ttk.Frame(wallet_frame)
        voucher_buttons.pack(fill=tk.X, pady=5)
        ttk.Button(voucher_buttons, text="Abrir Voucher", command=self.open_selected_voucher).pack(side=tk.LEFT, padx=5)

    def setup_exchange_ui(self):
        self.exchange_frame, exchange_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.exchange_frame, "Cambio")
        ttk.Label(exchange_frame, text="Cambio HPS", font=("Arial", 14, "bold")).pack(pady=10)

        servers_frame = ttk.LabelFrame(exchange_frame, text="Economia por servidor", padding="10")
        servers_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.exchange_servers_tree = ttk.Treeview(
            servers_frame,
            columns=("server", "total", "multiplier", "rate_orig", "rate_current", "updated"),
            show="headings"
        )
        self.exchange_servers_tree.heading("server", text="Servidor")
        self.exchange_servers_tree.heading("total", text="Total")
        self.exchange_servers_tree.heading("multiplier", text="Inflacao")
        self.exchange_servers_tree.heading("rate_orig", text="Rate HPS-orig")
        self.exchange_servers_tree.heading("rate_current", text="Rate p/ atual")
        self.exchange_servers_tree.heading("updated", text="Atualizado")
        self.exchange_servers_tree.column("server", width=220)
        self.exchange_servers_tree.column("total", width=90)
        self.exchange_servers_tree.column("multiplier", width=90)
        self.exchange_servers_tree.column("rate_orig", width=110)
        self.exchange_servers_tree.column("rate_current", width=110)
        self.exchange_servers_tree.column("updated", width=130)
        self.exchange_servers_tree.pack(fill=tk.BOTH, expand=True)

        voucher_frame = ttk.LabelFrame(exchange_frame, text="Vouchers estrangeiros", padding="10")
        voucher_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.exchange_voucher_tree = ttk.Treeview(
            voucher_frame,
            columns=("issuer", "count", "total"),
            show="headings"
        )
        self.exchange_voucher_tree.heading("issuer", text="Emissor")
        self.exchange_voucher_tree.heading("count", text="Qtd")
        self.exchange_voucher_tree.heading("total", text="Total")
        self.exchange_voucher_tree.column("issuer", width=220)
        self.exchange_voucher_tree.column("count", width=80)
        self.exchange_voucher_tree.column("total", width=80)
        self.exchange_voucher_tree.pack(fill=tk.BOTH, expand=True)

        actions_frame = ttk.Frame(exchange_frame)
        actions_frame.pack(fill=tk.X, pady=5)
        ttk.Button(actions_frame, text="Atualizar", command=self.update_exchange_ui).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Converter Selecionados", command=self.start_exchange_for_selected).pack(side=tk.LEFT, padx=5)

    def start_exchange_for_selected(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se a um servidor para converter.")
            return
        if not self.confirm_fraud_action("Câmbio HPS"):
            return
        selection = self.exchange_voucher_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um emissor para converter.")
            return
        issuer = selection[0]
        vouchers = []
        voucher_ids = []
        total = 0
        issuer_public_key = ""
        for voucher in self.hps_vouchers.values():
            if voucher.get("issuer") != issuer:
                continue
            if voucher.get("status") != "valid" or voucher.get("invalidated"):
                continue
            vouchers.append(voucher)
            payload = voucher.get("payload", {})
            if not issuer_public_key:
                issuer_public_key = payload.get("issuer_public_key", "")
            voucher_ids.append(payload.get("voucher_id", ""))
            total += int(payload.get("value", 0))
        if not vouchers:
            messagebox.showwarning("Aviso", "Nenhum voucher valido para converter.")
            return
        target_amount = simpledialog.askinteger(
            "Cambio",
            f"Total disponivel: {total} HPS\nQuanto deseja converter?",
            minvalue=1,
            maxvalue=total
        )
        if target_amount is None:
            return
        if target_amount <= 0 or target_amount > total:
            messagebox.showwarning("Aviso", "Valor de conversao invalido.")
            return
        vouchers_sorted = sorted(
            vouchers,
            key=lambda v: int((v.get("payload") or {}).get("value", 0)),
            reverse=True
        )
        selected_vouchers = []
        voucher_ids = []
        total = 0
        for voucher in vouchers_sorted:
            if total >= target_amount:
                break
            payload = voucher.get("payload", {})
            value = int(payload.get("value", 0))
            selected_vouchers.append(voucher)
            voucher_ids.append(payload.get("voucher_id", ""))
            total += value
        if total < target_amount:
            messagebox.showwarning("Aviso", "Saldo insuficiente para converter o valor desejado.")
            return
        if total != target_amount:
            proceed = messagebox.askyesno(
                "Cambio",
                f"Nao foi possivel atingir o valor exato.\nConverter {total} HPS?"
            )
            if not proceed:
                return
        vouchers = selected_vouchers
        issuer_address = issuer
        if issuer_public_key and issuer.startswith("0.0.0.0"):
            for stats in self.server_economy_stats.values():
                report_payload = stats.get("report_payload") or ""
                if not report_payload:
                    continue
                try:
                    report = json.loads(report_payload)
                except Exception:
                    continue
                if report.get("issuer_public_key") == issuer_public_key:
                    issuer_address = stats.get("server_address", issuer)
                    break

        timestamp = time.time()
        target_server = self.current_server_address or (self.current_server or "")
        proof_issuer = issuer_address or issuer
        proof_payload = {
            "issuer": proof_issuer,
            "target_server": target_server,
            "voucher_ids": sorted(voucher_ids),
            "timestamp": timestamp
        }
        signature = self.private_key.sign(
            self.canonicalize_payload(proof_payload).encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        details = [
            ("ISSUER", proof_issuer),
            ("TARGET_SERVER", target_server),
            ("VOUCHERS", json.dumps(sorted(voucher_ids), ensure_ascii=True)),
            ("TIMESTAMP", int(timestamp))
        ]
        contract_template = self.build_contract_template("exchange_hps", details)
        signed_text, _ = self.apply_contract_signature(contract_template)
        fallback_report = None
        issuer_stats = self.server_economy_stats.get(issuer_address, {}) or self.server_economy_stats.get(issuer, {})
        if issuer_stats.get("report_payload") and issuer_stats.get("report_signature"):
            try:
                fallback_report = {
                    "payload": json.loads(issuer_stats["report_payload"]),
                    "signature": issuer_stats["report_signature"]
                }
            except Exception:
                fallback_report = None
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('request_exchange_quote', {
                "vouchers": vouchers,
                "client_signature": base64.b64encode(signature).decode("utf-8"),
                "client_public_key": base64.b64encode(self.public_key_pem).decode("utf-8"),
                "timestamp": timestamp,
                "target_server": target_server,
                "issuer_address": issuer_address,
                "fallback_report": fallback_report,
                "contract_content": base64.b64encode(signed_text.encode("utf-8")).decode("utf-8")
            }),
            self.loop
        )

    def update_hps_action_fields(self):
        for frame in self.hps_action_frames.values():
            frame.pack_forget()
        selected = self.hps_action_var.get()
        frame = self.hps_action_frames.get(selected)
        if frame:
            frame.pack(fill=tk.X, pady=5)

    def setup_network_ui(self):
        self.network_frame, network_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.network_frame, "Rede")
        
        ttk.Label(network_frame, text="Rede P2P", font=("Arial", 14, "bold")).pack(pady=10)
        
        network_top_frame = ttk.Frame(network_frame)
        network_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(network_top_frame, text="Atualizar", command=self.refresh_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(network_top_frame, text="Sincronizar", command=self.sync_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(network_top_frame, text="Meu Nó", command=self.show_my_node).pack(side=tk.LEFT, padx=5)
        
        self.network_tree = ttk.Treeview(network_frame, columns=("node_id", "address", "type", "reputation", "status"), show="headings")
        self.network_tree.heading("node_id", text="ID do Nó")
        self.network_tree.heading("address", text="Endereço")
        self.network_tree.heading("type", text="Tipo")
        self.network_tree.heading("reputation", text="Reputação")
        self.network_tree.heading("status", text="Status")
        self.network_tree.column("node_id", width=150)
        self.network_tree.column("address", width=150)
        self.network_tree.column("type", width=100)
        self.network_tree.column("reputation", width=80)
        self.network_tree.column("status", width=80)
        self.network_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        network_stats_frame = ttk.Frame(network_frame)
        network_stats_frame.pack(fill=tk.X, pady=10)
        
        self.network_stats_var = tk.StringVar(value="Nós: 0 | Conteúdo: 0 | DNS: 0")
        ttk.Label(network_stats_frame, textvariable=self.network_stats_var).pack()

    def setup_contracts_ui(self):
        self.contracts_frame, contracts_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.contracts_frame, "Certificados")

        ttk.Label(contracts_frame, text="Certificados e Contratos", style="Header.TLabel").pack(pady=10)

        self.contracts_notebook = ttk.Notebook(contracts_frame)
        self.contracts_notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        voucher_tab = ttk.Frame(self.contracts_notebook)
        contracts_tab = ttk.Frame(self.contracts_notebook)
        spend_tab = ttk.Frame(self.contracts_notebook)
        self.contracts_notebook.add(voucher_tab, text="Vouchers")
        self.contracts_notebook.add(contracts_tab, text="Contratos")
        self.contracts_notebook.add(spend_tab, text="Gastos")

        voucher_search_frame = ttk.Frame(voucher_tab)
        voucher_search_frame.pack(fill=tk.X, pady=8)
        ttk.Label(voucher_search_frame, text="Voucher ID(s):").pack(side=tk.LEFT, padx=5)
        self.voucher_search_var = tk.StringVar()
        ttk.Entry(voucher_search_frame, textvariable=self.voucher_search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(voucher_search_frame, text="Analisar", command=self.search_voucher_genealogy).pack(side=tk.LEFT, padx=5)
        ttk.Button(voucher_search_frame, text="Limpar", command=self.clear_voucher_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(voucher_search_frame, text="Ver contrato", command=self.open_voucher_issue_contract).pack(side=tk.LEFT, padx=5)

        voucher_details_frame = ttk.LabelFrame(voucher_tab, text="Detalhes", padding="10")
        voucher_details_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.voucher_loading_bar = ttk.Progressbar(voucher_details_frame, mode="indeterminate")
        self.voucher_loading_bar.pack(fill=tk.X, padx=4, pady=(0, 6))
        self.voucher_loading_bar.pack_forget()
        self.voucher_details_text = scrolledtext.ScrolledText(voucher_details_frame, height=8)
        self.voucher_details_text.pack(fill=tk.BOTH, expand=True)
        self.voucher_details_text.config(state=tk.DISABLED)

        voucher_trace_frame = ttk.LabelFrame(voucher_tab, text="Árvore Genealógica", padding="10", style="Trace.TLabelframe")
        voucher_trace_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.voucher_trace_text = scrolledtext.ScrolledText(voucher_trace_frame, height=18)
        self.voucher_trace_text.pack(fill=tk.BOTH, expand=True)
        self.voucher_trace_text.config(state=tk.DISABLED)
        self.voucher_last_audit = []
        self.voucher_last_trace = []
        self.voucher_last_exchange_trace = []

        search_frame = ttk.Frame(contracts_tab)
        search_frame.pack(fill=tk.X, pady=10)

        ttk.Label(search_frame, text="Filtro:").pack(side=tk.LEFT, padx=5)
        self.contract_filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(search_frame, textvariable=self.contract_filter_var,
                                    values=["all", "hash", "domain", "user", "type", "api_app"], width=12)
        filter_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(search_frame, text="Valor:").pack(side=tk.LEFT, padx=5)
        self.contract_search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.contract_search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Button(search_frame, text="Buscar", command=self.search_contracts_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Limpar", command=self.clear_contracts_search).pack(side=tk.LEFT, padx=5)

        help_frame = ttk.Frame(contracts_tab)
        help_frame.pack(fill=tk.X, pady=5)
        ttk.Label(
            help_frame,
            text="Dica: filtre por hash, dominio, usuario ou tipo. Clique duas vezes para abrir o analisador.",
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(help_frame, text="Atualizar", command=self.search_contracts_action).pack(side=tk.RIGHT, padx=5)
        ttk.Button(help_frame, text="Abrir Analisador", command=self.open_selected_contract_analyzer).pack(side=tk.RIGHT, padx=5)

        self.invalidated_contract_frame = ttk.Frame(contracts_tab)
        self.invalidated_contract_label = ttk.Label(
            self.invalidated_contract_frame,
            text="Contrato invalidado detectado. Certifique o hash abaixo para regularizar.",
            foreground="red"
        )
        self.invalidated_contract_label.pack(side=tk.LEFT, padx=5)
        self.invalidated_contract_hash_var = tk.StringVar()
        ttk.Entry(self.invalidated_contract_frame, textvariable=self.invalidated_contract_hash_var, width=50).pack(side=tk.LEFT, padx=5)
        self.invalidated_contract_type_var = tk.StringVar(value="content")
        ttk.Combobox(
            self.invalidated_contract_frame,
            textvariable=self.invalidated_contract_type_var,
            values=["content", "domain"],
            state="readonly",
            width=10
        ).pack(side=tk.LEFT, padx=5)
        self.invalidated_contract_button = tk.Button(
            self.invalidated_contract_frame,
            text="Certificar",
            fg="red",
            font=("Arial", 10, "bold"),
            command=self.start_missing_contract_certify
        )
        self.invalidated_contract_button.pack(side=tk.LEFT, padx=5)

        self.contracts_tree = ttk.Treeview(
            contracts_tab,
            columns=("contract_id", "action", "content_hash", "domain", "username", "verified", "timestamp"),
            show="headings"
        )
        self.contracts_tree.heading("contract_id", text="ID")
        self.contracts_tree.heading("action", text="Ação")
        self.contracts_tree.heading("content_hash", text="Hash")
        self.contracts_tree.heading("domain", text="Domínio")
        self.contracts_tree.heading("username", text="Usuário")
        self.contracts_tree.heading("verified", text="Verificado")
        self.contracts_tree.heading("timestamp", text="Data")
        self.contracts_tree.column("contract_id", width=160)
        self.contracts_tree.column("action", width=120)
        self.contracts_tree.column("content_hash", width=180)
        self.contracts_tree.column("domain", width=120)
        self.contracts_tree.column("username", width=120)
        self.contracts_tree.column("verified", width=80)
        self.contracts_tree.column("timestamp", width=140)
        self.contracts_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        self.contracts_tree.tag_configure("invalid", foreground="red")
        self.contracts_tree.bind("<<TreeviewSelect>>", self.on_contract_select)
        self.contracts_tree.bind("<Double-1>", lambda e: self.open_selected_contract_analyzer())

        details_frame = ttk.LabelFrame(contracts_tab, text="Detalhes do Contrato", padding="10")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.contract_details_text = scrolledtext.ScrolledText(details_frame, height=12)
        self.contract_details_text.pack(fill=tk.BOTH, expand=True)
        self.contract_details_text.config(state=tk.DISABLED)

        spend_search_frame = ttk.Frame(spend_tab)
        spend_search_frame.pack(fill=tk.X, pady=8)
        ttk.Label(spend_search_frame, text="Voucher ou Contrato:").pack(side=tk.LEFT, padx=5)
        self.spend_search_var = tk.StringVar()
        ttk.Entry(spend_search_frame, textvariable=self.spend_search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(spend_search_frame, text="Analisar", command=self.search_spend_genealogy).pack(side=tk.LEFT, padx=5)
        ttk.Button(spend_search_frame, text="Limpar", command=self.clear_spend_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(spend_search_frame, text="Ver contrato", command=self.open_spend_contract).pack(side=tk.LEFT, padx=5)

        spend_details_frame = ttk.LabelFrame(spend_tab, text="Detalhes", padding="10")
        spend_details_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.spend_loading_bar = ttk.Progressbar(spend_details_frame, mode="indeterminate")
        self.spend_loading_bar.pack(fill=tk.X, padx=4, pady=(0, 6))
        self.spend_loading_bar.pack_forget()
        self.spend_details_text = scrolledtext.ScrolledText(spend_details_frame, height=8)
        self.spend_details_text.pack(fill=tk.BOTH, expand=True)
        self.spend_details_text.config(state=tk.DISABLED)

        spend_trace_frame = ttk.LabelFrame(spend_tab, text="Árvore Genealógica", padding="10", style="Trace.TLabelframe")
        spend_trace_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.spend_trace_text = scrolledtext.ScrolledText(spend_trace_frame, height=18)
        self.spend_trace_text.pack(fill=tk.BOTH, expand=True)
        self.spend_trace_text.config(state=tk.DISABLED)
        self.spend_current_contract = None

    def setup_settings_ui(self):
        self.settings_frame, settings_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.settings_frame, "Config")
        
        ttk.Label(settings_frame, text="Configurações", font=("Arial", 14, "bold")).pack(pady=10)
        
        settings_form_frame = ttk.Frame(settings_frame)
        settings_form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(settings_form_frame, text="ID do Cliente:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.client_identifier).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="ID da Sessão:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.session_id).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="ID do Nó:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.node_id).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="Chave Pública:").grid(row=4, column=0, sticky=tk.W, pady=5)
        pub_key_text = scrolledtext.ScrolledText(settings_form_frame, height=4, width=50)
        pub_key_text.grid(row=4, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))
        if self.public_key_pem:
            pub_key_text.insert(tk.END, self.public_key_pem.decode('utf-8'))
        pub_key_text.config(state=tk.DISABLED)
        
        ttk.Button(settings_form_frame, text="Gerar Chaves", command=self.generate_new_keys).grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(settings_form_frame, text="Exportar Chaves", command=self.export_keys).grid(row=6, column=0, columnspan=2, pady=5)
        ttk.Button(settings_form_frame, text="Importar Chaves", command=self.import_keys).grid(row=7, column=0, columnspan=2, pady=5)

        pow_frame = ttk.LabelFrame(settings_form_frame, text="Mineração PoW", padding="10")
        pow_frame.grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        max_threads = max(1, os.cpu_count() or 1)
        ttk.Label(pow_frame, text="Threads de mineração:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(pow_frame, from_=1, to=max_threads, textvariable=self.pow_threads_var, width=6).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(pow_frame, text=f"Máx: {max_threads}").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Button(pow_frame, text="Salvar", command=self.save_pow_settings).grid(row=1, column=0, columnspan=3, pady=5)
        
        settings_form_frame.columnconfigure(1, weight=1)

    def save_pow_settings(self):
        max_threads = max(1, os.cpu_count() or 1)
        try:
            threads = int(self.pow_threads_var.get())
        except (TypeError, ValueError):
            threads = 1
        threads = max(1, min(max_threads, threads))
        self.pow_threads_var.set(str(threads))
        self.pow_threads = threads
        self.save_setting("pow_threads", threads)
        messagebox.showinfo("Configurações", "Configurações de mineração salvas.")

    def setup_servers_ui(self):
        self.servers_frame, servers_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.servers_frame, "Servidores")
        
        ttk.Label(servers_frame, text="Servidores Conhecidos", font=("Arial", 14, "bold")).pack(pady=10)
        
        servers_top_frame = ttk.Frame(servers_frame)
        servers_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(servers_top_frame, text="Novo Servidor:").pack(side=tk.LEFT, padx=5)
        self.new_server_var = tk.StringVar()
        ttk.Entry(servers_top_frame, textvariable=self.new_server_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(servers_top_frame, text="Adicionar", command=self.add_server).pack(side=tk.LEFT, padx=5)
        
        self.servers_tree = ttk.Treeview(servers_frame, columns=("address", "status", "reputation"), show="headings")
        self.servers_tree.heading("address", text="Endereço")
        self.servers_tree.heading("status", text="Status")
        self.servers_tree.heading("reputation", text="Reputação")
        self.servers_tree.column("address", width=200)
        self.servers_tree.column("status", width=100)
        self.servers_tree.column("reputation", width=100)
        self.servers_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        servers_button_frame = ttk.Frame(servers_frame)
        servers_button_frame.pack(pady=10)
        
        ttk.Button(servers_button_frame, text="Remover", command=self.remove_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(servers_button_frame, text="Conectar", command=self.connect_selected_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(servers_button_frame, text="Atualizar", command=self.refresh_servers).pack(side=tk.LEFT, padx=5)

    def setup_stats_ui(self):
        self.stats_frame, stats_frame = self.create_scrollable_tab(self.main_area)
        self.add_main_tab(self.stats_frame, "Stats")
        
        ttk.Label(stats_frame, text="Estatísticas", font=("Arial", 14, "bold")).pack(pady=10)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.stats_vars = {}
        stats_data = [
            ("Tempo de Sessão:", "0h 0m 0s"),
            ("Dados Enviados:", "0 MB"),
            ("Dados Recebidos:", "0 MB"),
            ("Conteúdo Baixado:", "0 arquivos"),
            ("Conteúdo Publicado:", "0 arquivos"),
            ("DNS Registrados:", "0 domínios"),
            ("PoW Resolvidos:", "0"),
            ("Tempo Total PoW:", "0s"),
            ("Conteúdos Reportados:", "0"),
        ]
        
        for i, (label, value) in enumerate(stats_data):
            ttk.Label(stats_grid, text=label, font=("Arial", 10, "bold")).grid(row=i, column=0, sticky=tk.W, pady=5, padx=10)
            var = tk.StringVar(value=value)
            ttk.Label(stats_grid, textvariable=var, font=("Arial", 10)).grid(row=i, column=1, sticky=tk.W, pady=5, padx=10)
            self.stats_vars[label] = var
            
        ttk.Button(stats_frame, text="Atualizar", command=self.update_stats).pack(pady=10)

    def show_login(self):
        if not self.logged_in:
            self.set_tab_visibility(False)
        self.show_frame(self.login_frame)
        self.update_nav_buttons("login")

    def show_server_analysis_popup(self):
        if self.server_analysis_popup and self.server_analysis_popup.winfo_exists():
            return
        popup = tk.Toplevel(self.root)
        popup.title("Analisando servidor")
        popup.geometry("320x140")
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()
        ttk.Label(popup, text="Analisando servidor...", font=("Arial", 12, "bold")).pack(pady=(18, 6))
        ttk.Label(popup, text="Verificando integridade e vouchers.").pack(pady=(0, 12))
        popup.protocol("WM_DELETE_WINDOW", lambda: None)
        self.server_analysis_popup = popup

    def close_server_analysis_popup(self):
        popup = self.server_analysis_popup
        self.server_analysis_popup = None
        if popup and popup.winfo_exists():
            popup.destroy()

    def start_server_analysis(self):
        self.server_analysis_steps = {"wallet": False, "server": False}
        self.server_analysis_in_progress = True
        self.wallet_fraud_checked = False
        self.root.after(0, self.show_server_analysis_popup)

    def mark_server_analysis_done(self, step):
        if not self.server_analysis_in_progress:
            return
        if step in self.server_analysis_steps:
            self.server_analysis_steps[step] = True
        if all(self.server_analysis_steps.values()):
            self.server_analysis_in_progress = False
            self.root.after(0, self.close_server_analysis_popup)
            self.root.after(0, self.show_browser)

    def on_close(self):
        if self.connected:
            self.exit_network()
        self.root.after(200, self.root.destroy)

    def show_browser(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar o navegador.")
            return
        self.show_frame(self.browser_frame)
        self.update_nav_buttons("browser")

    def show_dns(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar o DNS.")
            return
        self.show_frame(self.dns_frame)
        self.update_nav_buttons("dns")
        self.refresh_dns_records()

    def show_upload(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para fazer upload.")
            return
        self.show_frame(self.upload_frame)
        self.update_nav_buttons("upload")

    def show_hps_actions(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar as ações HPS.")
            return
        self.show_frame(self.hps_actions_frame)
        self.update_nav_buttons("hps_actions")

    def show_hps_wallet(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar a carteira HPS.")
            return
        self.show_frame(self.hps_wallet_frame)
        self.update_nav_buttons("hps_wallet")
        self.update_hps_balance()
        self.refresh_hps_wallet()

    def show_exchange(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar o cambio.")
            return
        self.show_frame(self.exchange_frame)
        self.update_nav_buttons("exchange")
        self.update_exchange_ui()

    def show_network(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para ver a rede.")
            return
        self.show_frame(self.network_frame)
        self.update_nav_buttons("network")
        self.refresh_network()

    def show_certificates(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para ver contratos.")
            return
        self.show_frame(self.contracts_frame)
        self.update_nav_buttons("certificates")
        self.contract_filter_var.set("all")
        self.contract_search_var.set("")
        self.search_contracts_action()
        self.update_certify_missing_contract_ui()
        if self.pending_transfers:
            self.show_contract_alert("Você está com pendências contratuais. Clique em Certificados")
            messagebox.showwarning("Pendencias Contratuais", "Ha uma transferencia pendente para voce. Abra o contrato em vermelho para resolver.")

    def show_settings(self):
        self.show_frame(self.settings_frame)
        self.update_nav_buttons("settings")

    def show_servers(self):
        self.show_frame(self.servers_frame)
        self.update_nav_buttons("servers")
        self.refresh_servers()

    def show_stats(self):
        self.show_frame(self.stats_frame)
        self.update_nav_buttons("stats")
        self.update_stats()

    def show_frame(self, frame):
        if hasattr(self, "main_notebook"):
            try:
                self.main_notebook.select(frame)
            except Exception:
                pass

    def update_nav_buttons(self, active_button):
        self.active_section = active_button
        if not hasattr(self, "nav_buttons"):
            return
        for name, button in self.nav_buttons.items():
            if name == active_button:
                button.config(style="Accent.TButton")
            else:
                button.config(style="TButton")

    def clear_contracts_search(self):
        self.contract_search_var.set("")
        for item in self.contracts_tree.get_children():
            self.contracts_tree.delete(item)
        self.contract_details_text.config(state=tk.NORMAL)
        self.contract_details_text.delete(1.0, tk.END)
        self.contract_details_text.config(state=tk.DISABLED)

    def clear_voucher_search(self):
        self.voucher_search_var.set("")
        self.voucher_last_audit = []
        self.voucher_last_trace = []
        self.voucher_last_exchange_trace = []
        self.stop_voucher_loading()
        self.voucher_details_text.config(state=tk.NORMAL)
        self.voucher_details_text.delete(1.0, tk.END)
        self.voucher_details_text.insert(tk.END, "Busca limpa.")
        self.voucher_details_text.config(state=tk.DISABLED)
        self.voucher_trace_text.config(state=tk.NORMAL)
        self.voucher_trace_text.delete(1.0, tk.END)
        self.voucher_trace_text.insert(tk.END, "Árvore limpa.")
        self.voucher_trace_text.config(state=tk.DISABLED)

    def clear_spend_search(self):
        self.spend_search_var.set("")
        self.spend_current_contract = None
        self.stop_spend_loading()
        self.spend_details_text.config(state=tk.NORMAL)
        self.spend_details_text.delete(1.0, tk.END)
        self.spend_details_text.insert(tk.END, "Busca limpa.")
        self.spend_details_text.config(state=tk.DISABLED)
        self.spend_trace_text.config(state=tk.NORMAL)
        self.spend_trace_text.delete(1.0, tk.END)
        self.spend_trace_text.insert(tk.END, "Árvore limpa.")
        self.spend_trace_text.config(state=tk.DISABLED)

    def parse_trace_entries_from_contract_text(self, contract_text):
        trace_entries = []
        exchange_entries = []
        if not contract_text:
            return trace_entries, exchange_entries
        trace_raw = self.extract_contract_detail_from_text(contract_text, "VOUCHER_TRACE")
        if trace_raw:
            try:
                trace_entries = json.loads(trace_raw)
            except Exception:
                trace_entries = []
        exchange_raw = self.extract_contract_detail_from_text(contract_text, "EXCHANGE_TRACE")
        if exchange_raw:
            try:
                exchange_entries = json.loads(exchange_raw)
            except Exception:
                exchange_entries = []
        return trace_entries, exchange_entries

    def build_trace_tree_text(self, trace_entries, audit_results=None, exchange_trace=None):
        audit_by_id = {info.get("voucher_id"): info for info in (audit_results or []) if info.get("voucher_id")}
        lines = []
        for entry in trace_entries or []:
            voucher_id = entry.get("voucher_id", "")
            info = audit_by_id.get(voucher_id, {})
            payload = info.get("payload", {}) or {}
            value = payload.get("value", "")
            owner = payload.get("owner", "")
            issuer = payload.get("issuer", "")
            lines.append(f"Voucher {voucher_id}")
            if value or owner or issuer:
                lines.append(f"  Valor: {value} | Dono: {owner} | Emissor: {issuer}")
            chain = entry.get("trace_contract_chain") or []
            if not chain:
                lines.append("  (sem cadeia registrada)")
            for link in chain:
                action = link.get("action_type", "")
                contract_hash = link.get("contract_hash", "")
                source_id = link.get("source_voucher_id", "")
                lines.append(f"  {link.get('voucher_id', '')} --[{action} {contract_hash[:16]}]--> {source_id}")
            lines.append("")
        if exchange_trace:
            lines.append("=== TRACE DE CAMBIO ===")
            for ex in exchange_trace:
                lines.append(f"Voucher {ex.get('voucher_id', '')} | Transfer {ex.get('transfer_id', '')}")
                inter = ex.get("inter_server_payload", {}) or {}
                exchange_contract_id = inter.get("exchange_contract_id", "")
                exchange_contract_hash = inter.get("exchange_contract_hash", "")
                if exchange_contract_id or exchange_contract_hash:
                    lines.append(f"  Contrato de cambio: {exchange_contract_id} ({exchange_contract_hash[:16]})")
                report_id = ex.get("report_contract_id", "")
                report_hash = ex.get("report_contract_hash", "")
                if report_id or report_hash:
                    lines.append(f"  Relatorio do minerador: {report_id} ({report_hash[:16]})")
                report_trace = ex.get("report_trace", []) or []
                for entry in report_trace:
                    voucher_id = entry.get("voucher_id", "")
                    lines.append(f"  Voucher {voucher_id}")
                    chain = entry.get("trace_contract_chain") or []
                    for link in chain:
                        action = link.get("action_type", "")
                        contract_hash = link.get("contract_hash", "")
                        source_id = link.get("source_voucher_id", "")
                        lines.append(f"    {link.get('voucher_id', '')} --[{action} {contract_hash[:16]}]--> {source_id}")
                lines.append("")
        return "\n".join(lines).strip() or "Nenhum trace disponível."

    def build_voucher_details_text(self, audit_results, pow_audit=None):
        pow_by_id = {item.get("voucher_id"): item for item in (pow_audit or []) if item.get("voucher_id")}
        lines = []
        for info in audit_results or []:
            voucher_id = info.get("voucher_id", "")
            payload = info.get("payload", {}) or {}
            signatures = info.get("signatures", {}) or {}
            status = info.get("status", "")
            invalidated = info.get("invalidated", False)
            lines.append(f"Voucher: {voucher_id}")
            lines.append(f"  Valor: {payload.get('value', '')}")
            lines.append(f"  Dono: {payload.get('owner', '')}")
            lines.append(f"  Emissor: {payload.get('issuer', '')}")
            lines.append(f"  Motivo: {payload.get('reason', '')}")
            lines.append(f"  Status: {status} | Invalidado: {invalidated}")
            lines.append(f"  Assinatura dono: {signatures.get('owner', '')[:24]}")
            lines.append(f"  Assinatura emissor: {signatures.get('issuer', '')[:24]}")
            pow_entry = pow_by_id.get(voucher_id, {})
            if pow_entry:
                lines.append(f"  PoW ok: {pow_entry.get('pow_ok', False)} | Motivo: {pow_entry.get('pow_reason', '')}")
            lines.append("")
        return "\n".join(lines).strip() or "Nenhum detalhe encontrado."

    def start_voucher_loading(self):
        if self.voucher_loading_bar:
            self.voucher_loading_bar.pack(fill=tk.X, padx=4, pady=(0, 6))
            self.voucher_loading_bar.start(8)

    def stop_voucher_loading(self):
        if self.voucher_loading_bar:
            self.voucher_loading_bar.stop()
            self.voucher_loading_bar.pack_forget()

    def start_spend_loading(self):
        if self.spend_loading_bar:
            self.spend_loading_bar.pack(fill=tk.X, padx=4, pady=(0, 6))
            self.spend_loading_bar.start(8)

    def stop_spend_loading(self):
        if self.spend_loading_bar:
            self.spend_loading_bar.stop()
            self.spend_loading_bar.pack_forget()

    def _apply_voucher_genealogy_results(self, audit_results, pow_audit, trace_entries, exchange_trace):
        self.stop_voucher_loading()
        self.voucher_last_audit = audit_results
        self.voucher_last_trace = trace_entries
        self.voucher_last_exchange_trace = exchange_trace
        details_text = self.build_voucher_details_text(audit_results, pow_audit=pow_audit)
        trace_text = self.build_trace_tree_text(trace_entries, audit_results=audit_results, exchange_trace=exchange_trace)
        self.voucher_details_text.config(state=tk.NORMAL)
        self.voucher_details_text.delete(1.0, tk.END)
        self.voucher_details_text.insert(tk.END, details_text)
        self.voucher_details_text.config(state=tk.DISABLED)
        self.voucher_trace_text.config(state=tk.NORMAL)
        self.voucher_trace_text.delete(1.0, tk.END)
        self.voucher_trace_text.insert(tk.END, trace_text)
        self.voucher_trace_text.config(state=tk.DISABLED)

    def search_voucher_genealogy(self):
        query = self.voucher_search_var.get().strip()
        if not query:
            messagebox.showwarning("Aviso", "Informe um voucher para analisar.")
            return
        self.start_voucher_loading()
        voucher_ids = [item.strip() for item in re.split(r"[,\s]+", query) if item.strip()]
        self.voucher_details_text.config(state=tk.NORMAL)
        self.voucher_details_text.delete(1.0, tk.END)
        self.voucher_details_text.insert(tk.END, "Carregando detalhes...")
        self.voucher_details_text.config(state=tk.DISABLED)
        self.voucher_trace_text.config(state=tk.NORMAL)
        self.voucher_trace_text.delete(1.0, tk.END)
        self.voucher_trace_text.insert(tk.END, "Analisando árvore genealógica...")
        self.voucher_trace_text.config(state=tk.DISABLED)

        def worker():
            audit_results = []
            pow_audit = []
            trace_entries = []
            exchange_trace = []
            try:
                audit_future = asyncio.run_coroutine_threadsafe(
                    self.fetch_voucher_audit(voucher_ids),
                    self.loop
                )
                audit_results = audit_future.result(timeout=10.0)
                if audit_results:
                    trace_future = asyncio.run_coroutine_threadsafe(
                        self.analyze_voucher_pow_trace(audit_results),
                        self.loop
                    )
                    pow_audit, trace_entries, _ = trace_future.result(timeout=10.0)
                exchange_future = asyncio.run_coroutine_threadsafe(
                    self.fetch_exchange_trace(voucher_ids),
                    self.loop
                )
                exchange_trace = exchange_future.result(timeout=10.0)
            except Exception:
                audit_results = []
                pow_audit = []
                trace_entries = []
                exchange_trace = []
            self.root.after(0, lambda: self._apply_voucher_genealogy_results(
                audit_results, pow_audit, trace_entries, exchange_trace
            ))

        threading.Thread(target=worker, daemon=True).start()

    def open_voucher_issue_contract(self):
        if not self.voucher_last_audit:
            messagebox.showwarning("Aviso", "Nenhum voucher analisado.")
            return
        issue_contract_b64 = self.voucher_last_audit[0].get("issue_contract", "") or ""
        if not issue_contract_b64:
            messagebox.showwarning("Aviso", "Contrato de emissão ausente.")
            return
        try:
            contract_text = base64.b64decode(issue_contract_b64).decode("utf-8", errors="replace")
        except Exception:
            messagebox.showwarning("Aviso", "Contrato inválido.")
            return
        contract_info = {
            "contract_id": "",
            "action_type": "voucher_issue",
            "content_hash": "",
            "domain": "",
            "username": "",
            "signature": "",
            "timestamp": None,
            "verified": True,
            "integrity_ok": True,
            "contract_content": contract_text
        }
        self.show_contract_analyzer(contract_info, title="Contrato de Emissão", force_raw=True)

    def search_spend_genealogy(self):
        query = self.spend_search_var.get().strip()
        if not query:
            messagebox.showwarning("Aviso", "Informe um voucher ou contrato para analisar.")
            return
        self.start_spend_loading()
        contract_info = None
        if len(query) >= 32 and "-" in query:
            contract_info = self.get_contract_from_cache(query)
            if not contract_info:
                asyncio.run_coroutine_threadsafe(self.sio.emit('get_contract', {'contract_id': query}), self.loop)
        if not contract_info:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content
                                  FROM browser_contracts_cache
                                  WHERE action_type = ? AND contract_content LIKE ?
                                  ORDER BY timestamp DESC LIMIT 1''',
                               ("spend_hps", f"%{query}%"))
                row = cursor.fetchone()
            if row:
                contract_info = {
                    "contract_id": row[0],
                    "action_type": row[1],
                    "content_hash": row[2],
                    "domain": row[3],
                    "username": row[4],
                    "signature": row[5],
                    "timestamp": row[6],
                    "verified": bool(row[7]),
                    "contract_content": row[8]
                }
        if not contract_info or not contract_info.get("contract_content"):
            self.stop_spend_loading()
            messagebox.showwarning("Aviso", "Contrato de gasto não encontrado no cache.")
            return
        self.spend_current_contract = contract_info
        contract_text = contract_info.get("contract_content", "") or ""
        trace_entries, exchange_entries = self.parse_trace_entries_from_contract_text(contract_text)
        trace_text = self.build_trace_tree_text(trace_entries, exchange_trace=exchange_entries)
        self.spend_trace_text.config(state=tk.NORMAL)
        self.spend_trace_text.delete(1.0, tk.END)
        self.spend_trace_text.insert(tk.END, trace_text)
        self.spend_trace_text.config(state=tk.DISABLED)
        self.spend_details_text.config(state=tk.NORMAL)
        self.spend_details_text.delete(1.0, tk.END)
        self.spend_details_text.insert(tk.END, f"Contrato: {contract_info.get('contract_id', '')}\nAção: {contract_info.get('action_type', '')}")
        self.spend_details_text.config(state=tk.DISABLED)
        self.stop_spend_loading()

    def open_spend_contract(self):
        if not self.spend_current_contract:
            messagebox.showwarning("Aviso", "Nenhum contrato de gasto selecionado.")
            return
        self.show_contract_analyzer(self.spend_current_contract, title="Contrato de Gasto")

    def search_contracts_action(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
        search_value = self.contract_search_var.get().strip()
        search_type = self.contract_filter_var.get()
        
        self.contracts_filter_mode = search_type
        self.contracts_filter_value = search_value
        self.contracts_pending_details = set()
        self.contracts_results_cache = {}
        
        for item in self.contracts_tree.get_children():
            self.contracts_tree.delete(item)
        
        self.contract_details_text.config(state=tk.NORMAL)
        self.contract_details_text.delete(1.0, tk.END)
        self.contract_details_text.insert(tk.END, "Buscando contratos...")
        self.contract_details_text.config(state=tk.DISABLED)
        
        if search_type == "api_app":
            if not search_value:
                messagebox.showwarning("Aviso", "Informe o nome do API APP para buscar.")
                return
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('search_contracts', {'search_type': 'all', 'search_value': ''}),
                self.loop
            )
            return
        
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('search_contracts', {'search_type': search_type, 'search_value': search_value}),
            self.loop
        )

    def populate_contracts_tree(self, contracts):
        for item in self.contracts_tree.get_children():
            self.contracts_tree.delete(item)
        for contract in contracts:
            timestamp = contract.get('timestamp')
            if timestamp:
                try:
                    timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    timestamp_str = str(timestamp)
            else:
                timestamp_str = ""
            integrity_ok = contract.get('integrity_ok')
            if integrity_ok is None:
                integrity_ok = contract.get('verified', False)
            is_pending = contract.get('contract_id') in self.pending_transfers_by_contract
            tags = ("invalid",) if not integrity_ok or is_pending else ()
            self.contracts_tree.insert("", tk.END, values=(
                contract.get('contract_id', ''),
                contract.get('action_type', ''),
                (contract.get('content_hash') or '')[:16] + "..." if contract.get('content_hash') else "",
                contract.get('domain', '') or "",
                contract.get('username', '') or "",
                "Sim" if contract.get('verified') else "Não",
                timestamp_str
            ), tags=tags)

    def on_contract_select(self, event):
        selection = self.contracts_tree.selection()
        if not selection:
            return
        item = selection[0]
        contract_id = self.contracts_tree.item(item, 'values')[0]
        if not contract_id:
            return
        contract_info = self.get_contract_from_cache(contract_id)
        has_cached_content = bool(contract_info and contract_info.get('contract_content'))
        if has_cached_content:
            self.display_contract_details(contract_info)
        asyncio.run_coroutine_threadsafe(self.sio.emit('get_contract', {'contract_id': contract_id}), self.loop)
        if not has_cached_content:
            self.contract_details_text.config(state=tk.NORMAL)
            self.contract_details_text.delete(1.0, tk.END)
            self.contract_details_text.insert(tk.END, "Carregando detalhes do contrato...")
            self.contract_details_text.config(state=tk.DISABLED)

    def open_selected_contract_analyzer(self):
        selection = self.contracts_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um contrato para analisar.")
            return
        contract_id = self.contracts_tree.item(selection[0], 'values')[0]
        if not contract_id:
            return
        contract_info = self.get_contract_from_cache(contract_id)
        if contract_info and contract_info.get('contract_content'):
            self.show_contract_analyzer(contract_info)
            return
        self.pending_contract_analyzer_id = contract_id
        asyncio.run_coroutine_threadsafe(self.sio.emit('get_contract', {'contract_id': contract_id}), self.loop)
        messagebox.showinfo("Carregando", "Buscando detalhes do contrato para analise.")

    def display_contract_details(self, contract_info):
        contract_content = contract_info.get('contract_content') or ""
        contract_hash = hashlib.sha256(contract_content.encode('utf-8')).hexdigest() if contract_content else ""
        verified_text = "Sim" if contract_info.get('verified') else "Não"
        integrity_ok = contract_info.get('integrity_ok')
        if integrity_ok is None:
            integrity_ok = contract_info.get('verified', False)
        integrity_text = "OK" if integrity_ok else "ADULTERADO"
        timestamp = contract_info.get('timestamp')
        timestamp_str = ""
        if timestamp:
            try:
                timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                timestamp_str = str(timestamp)
        
        details = [
            f"ID: {contract_info.get('contract_id', '')}",
            f"Ação: {contract_info.get('action_type', '')}",
            f"Hash do conteúdo: {contract_info.get('content_hash', '')}",
            f"Domínio: {contract_info.get('domain', '')}",
            f"Usuário: {contract_info.get('username', '')}",
            f"Verificado: {verified_text}",
            f"Integridade: {integrity_text}",
            f"Data: {timestamp_str}",
            f"Hash do contrato: {contract_hash}",
            f"Assinatura: {contract_info.get('signature', '')}",
            "",
            "Contrato:",
            contract_content
        ]
        
        self.contract_details_text.config(state=tk.NORMAL)
        self.contract_details_text.delete(1.0, tk.END)
        self.contract_details_text.insert(tk.END, "\n".join(details))
        self.contract_details_text.config(state=tk.DISABLED)

    def extract_contract_details_lines(self, contract_text):
        if not contract_text:
            return []
        details_lines = []
        in_details = False
        for line in contract_text.splitlines():
            line = line.strip()
            if line == "### DETAILS:":
                in_details = True
                continue
            if line == "### :END DETAILS":
                break
            if in_details and line.startswith("# "):
                details_lines.append(line[2:])
        return details_lines

    def build_contract_summary(self, contract_info, contract_text):
        contract_hash = hashlib.sha256(contract_text.encode('utf-8')).hexdigest() if contract_text else ""
        verified_text = "Sim" if contract_info.get('verified') else "Não"
        integrity_ok = contract_info.get('integrity_ok')
        if integrity_ok is None:
            integrity_ok = contract_info.get('verified', False)
        integrity_text = "OK" if integrity_ok else "ADULTERADO"
        timestamp = contract_info.get('timestamp')
        timestamp_str = ""
        if timestamp:
            try:
                timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                timestamp_str = str(timestamp)
        summary = [
            f"ID: {contract_info.get('contract_id', '')}",
            f"Ação: {contract_info.get('action_type', '')}",
            f"Hash do conteúdo: {contract_info.get('content_hash', '')}",
            f"Domínio: {contract_info.get('domain', '')}",
            f"Usuário: {contract_info.get('username', '')}",
            f"Verificado: {verified_text}",
            f"Integridade: {integrity_text}",
            f"Data: {timestamp_str}",
            f"Hash do contrato: {contract_hash}",
            f"Assinatura: {contract_info.get('signature', '')}",
            ""
        ]
        details_lines = self.extract_contract_details_lines(contract_text)
        if details_lines:
            summary.append("Detalhes:")
            summary.extend(details_lines)
        return summary

    def show_genealogy_dialog(self, title, trace_entries, exchange_trace=None, contract_info=None):
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.geometry("900x700")
        popup.transient(self.root)
        popup.update_idletasks()
        try:
            popup.wait_visibility()
            popup.grab_set()
        except tk.TclError:
            popup.after(50, popup.grab_set)
        container, main_frame = create_scrollable_container(popup, padding="15")
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=title, font=("Arial", 14, "bold")).pack(pady=10)

        if contract_info:
            summary = self.build_contract_summary(contract_info, contract_info.get("contract_content") or "")
            info_frame = ttk.LabelFrame(main_frame, text="Resumo do Contrato", padding="10")
            info_frame.pack(fill=tk.BOTH, expand=True, pady=6)
            info_text = scrolledtext.ScrolledText(info_frame, height=8)
            info_text.pack(fill=tk.BOTH, expand=True)
            info_text.insert(tk.END, "\n".join(summary))
            info_text.config(state=tk.DISABLED)

        tree_frame = ttk.LabelFrame(main_frame, text="Árvore Genealógica", padding="10")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        tree_text = scrolledtext.ScrolledText(tree_frame, height=20)
        tree_text.pack(fill=tk.BOTH, expand=True)
        tree_text.insert(tk.END, self.build_trace_tree_text(trace_entries, exchange_trace=exchange_trace))
        tree_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        if contract_info:
            ttk.Button(
                button_frame,
                text="Ver contrato",
                command=lambda: self.show_contract_analyzer(contract_info, title="Contrato", force_raw=True)
            ).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=popup.destroy).pack(side=tk.LEFT, padx=5)

    def show_contract_analyzer(self, contract_info, title="Analisador de Contratos", allow_proceed=False, force_raw=False):
        contract_text = contract_info.get('contract_content') or ""
        if not force_raw:
            trace_entries, exchange_entries = self.parse_trace_entries_from_contract_text(contract_text)
            if contract_info.get("action_type") in ("miner_signature_report", "spend_hps") and trace_entries:
                self.show_genealogy_dialog(
                    "Árvore Genealógica",
                    trace_entries,
                    exchange_trace=exchange_entries,
                    contract_info=contract_info
                )
                return
        summary_lines = self.build_contract_summary(contract_info, contract_text)
        integrity_ok = contract_info.get('integrity_ok')
        if integrity_ok is None:
            integrity_ok = contract_info.get('verified', False)
        contract_id = contract_info.get('contract_id')
        owner = contract_info.get('username')
        is_owner = bool(self.current_user and owner and self.current_user == owner)
        reissue_callback = None
        certify_callback = None
        invalidate_callback = None
        transfer_accept_callback = None
        transfer_reject_callback = None
        transfer_renounce_callback = None
        inter_server_verify_callback = None
        pending_transfer = self.pending_transfers_by_contract.get(contract_id)
        if pending_transfer and pending_transfer.get('target_user') == self.current_user:
            transfer_note = ""
            if pending_transfer.get("transfer_type") == "hps_transfer":
                amount = pending_transfer.get("hps_amount")
                if amount is not None:
                    transfer_note = f" Valor: {amount} HPS."
            messagebox.showwarning(
                "Transferencia Pendente",
                f"{pending_transfer.get('original_owner')} quer transferir para voce. "
                f"Use os botoes para aceitar, rejeitar ou renunciar.{transfer_note}"
            )
            transfer_accept_callback = lambda: self.start_transfer_accept(pending_transfer)
            transfer_reject_callback = lambda: self.start_transfer_reject(pending_transfer)
            transfer_renounce_callback = lambda: self.start_transfer_renounce(pending_transfer)
        if not integrity_ok:
            if is_owner:
                reissue_callback = lambda: self.start_contract_reissue(contract_info)
            else:
                certify_callback = lambda: self.start_contract_certify(contract_info)
        if is_owner:
            invalidate_callback = lambda: self.start_contract_invalidate(contract_info)
        if contract_info.get("action_type") in ("hps_exchange_reserved", "hps_exchange_out", "hps_exchange_owner_key"):
            issuer = self.extract_contract_detail_from_text(contract_text, "ISSUER")
            if issuer:
                inter_server_verify_callback = lambda issuer_addr=issuer: self.verify_inter_server_signature(contract_info, issuer_addr)
        dialog = ContractAnalyzerDialog(
            self.root,
            summary_lines,
            contract_text,
            title=title,
            allow_proceed=allow_proceed,
            integrity_ok=integrity_ok,
            verify_callback=lambda: self.refresh_contract_analyzer(contract_id),
            inter_server_verify_callback=inter_server_verify_callback,
            reissue_callback=reissue_callback,
            certify_callback=certify_callback,
            invalidate_callback=invalidate_callback,
            transfer_accept_callback=transfer_accept_callback,
            transfer_reject_callback=transfer_reject_callback,
            transfer_renounce_callback=transfer_renounce_callback
        )
        self.root.wait_window(dialog.window)
        return dialog.proceed

    def refresh_contract_analyzer(self, contract_id):
        if not contract_id:
            return
        self.pending_contract_analyzer_id = contract_id
        asyncio.run_coroutine_threadsafe(self.sio.emit('get_contract', {'contract_id': contract_id}), self.loop)

    def verify_inter_server_signature(self, contract_info, issuer_address):
        contract_text = contract_info.get("contract_content") or ""
        async def do_verify():
            info = await self.fetch_server_info(issuer_address)
            if not info or not info.get("public_key"):
                self.root.after(0, lambda: messagebox.showerror(
                    "Verificacao inter-servidor",
                    "Nao foi possivel obter a chave publica do servidor emissor."
                ))
                return
            ok = self.verify_contract_signature_with_key(contract_text, info.get("public_key"))
            if ok:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Verificacao inter-servidor",
                    "Assinatura do servidor emissor confirmada."
                ))
            else:
                self.root.after(0, lambda: messagebox.showwarning(
                    "Verificacao inter-servidor",
                    "Assinatura do servidor emissor nao confere."
                ))
        asyncio.run_coroutine_threadsafe(do_verify(), self.loop)

    def start_contract_invalidate(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        def start_pow():
            def do_invalidate(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('invalidate_contract', {
                        'contract_id': contract_id,
                        'pow_nonce': pow_nonce,
                        'hashrate_observed': hashrate_observed
                    }),
                    self.loop
                )
            self.contract_reset_callback = do_invalidate
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_reset"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('invalidate_contract', {
                    'contract_id': contract_id,
                    'pow_nonce': "",
                    'hashrate_observed': 0.0,
                    'hps_payment': hps_payment
                }),
                self.loop
            )

        self.run_pow_or_hps("contract_reset", start_pow, start_hps)

    def start_contract_reissue(self, contract_info):
        self.pending_contract_reissue = contract_info
        self.start_contract_invalidate(contract_info)

    def start_contract_certify(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        target_type = "domain" if contract_info.get('domain') else "content"
        target_id = contract_info.get('domain') or contract_info.get('content_hash')
        if not target_id:
            messagebox.showerror("Erro", "Contrato sem alvo valido para certificacao.")
            return
        self.open_contract_certification_dialog(
            target_type=target_type,
            target_id=target_id,
            reason="invalid_contract",
            title_suffix="(Certificacao de Contrato)",
            contract_id=contract_id,
            original_owner=contract_info.get('username'),
            original_action=contract_info.get('action_type')
        )

    def handle_canonical_contract(self, contract_text):
        if not self.pending_certify_contract_id:
            return
        contract_id = self.pending_certify_contract_id
        self.pending_certify_contract_id = None
        messagebox.showwarning(
            "Aviso",
            "Fluxo de certificacao antigo nao esta disponivel. Abra o contrato novamente para certificar."
        )

    def handle_contract_reissue_success(self, data):
        contract_info = getattr(self, 'pending_contract_reissue', None)
        self.pending_contract_reissue = None
        if not contract_info:
            messagebox.showinfo("Contrato", "Contrato invalidado com sucesso.")
            return
        action_type = contract_info.get('action_type')
        content_hash = contract_info.get('content_hash')
        domain = contract_info.get('domain')
        if action_type == "register_dns" and domain:
            content_hash = self.dns_content_hash_var.get().strip() or content_hash
            if not content_hash:
                messagebox.showwarning("DNS", "Informe o hash do conteudo para reemitir o contrato de DNS.")
                return
            self.dns_domain_var.set(domain)
            self.dns_content_hash_var.set(content_hash)
            self.register_dns()
            return
        if content_hash:
            cached = self.load_cached_content(content_hash)
            if not cached:
                messagebox.showwarning("Upload", "Arquivo nao encontrado no cache local para reenvio.")
                return
            self.upload_content_bytes(
                cached['title'],
                cached.get('description', ''),
                cached.get('mime_type', 'application/octet-stream'),
                cached['content']
            )

    def start_transfer_accept(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        if pending_transfer.get("transfer_type") == "hps_transfer":
            self.start_hps_transfer_accept(transfer_id)
            return
        self.pending_transfer_accept_id = transfer_id
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('get_transfer_payload', {'transfer_id': transfer_id}),
            self.loop
        )

    def start_hps_transfer_accept(self, transfer_id):
        def start_pow():
            def do_accept(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('accept_hps_transfer', {
                        'transfer_id': transfer_id,
                        'pow_nonce': pow_nonce,
                        'hashrate_observed': hashrate_observed
                    }),
                    self.loop
                )
            self.contract_transfer_callback = do_accept
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_transfer"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('accept_hps_transfer', {
                    'transfer_id': transfer_id,
                    'pow_nonce': "",
                    'hashrate_observed': 0.0,
                    'hps_payment': hps_payment
                }),
                self.loop
            )

        self.run_pow_or_hps("contract_transfer", start_pow, start_hps)

    def start_transfer_reject(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        def start_pow():
            def do_reject(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('reject_transfer', {
                        'transfer_id': transfer_id,
                        'pow_nonce': pow_nonce,
                        'hashrate_observed': hashrate_observed
                    }),
                    self.loop
                )
            self.contract_transfer_callback = do_reject
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_transfer"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('reject_transfer', {
                    'transfer_id': transfer_id,
                    'pow_nonce': "",
                    'hashrate_observed': 0.0,
                    'hps_payment': hps_payment
                }),
                self.loop
            )

        self.run_pow_or_hps("contract_transfer", start_pow, start_hps)

    def start_transfer_renounce(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        def start_pow():
            def do_renounce(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('renounce_transfer', {
                        'transfer_id': transfer_id,
                        'pow_nonce': pow_nonce,
                        'hashrate_observed': hashrate_observed
                    }),
                    self.loop
                )
            self.contract_transfer_callback = do_renounce
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_transfer"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('renounce_transfer', {
                    'transfer_id': transfer_id,
                    'pow_nonce': "",
                    'hashrate_observed': 0.0,
                    'hps_payment': hps_payment
                }),
                self.loop
            )

        self.run_pow_or_hps("contract_transfer", start_pow, start_hps)

    def get_contract_from_cache(self, contract_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content
                              FROM browser_contracts_cache WHERE contract_id = ?''', (contract_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'contract_id': row[0],
                'action_type': row[1],
                'content_hash': row[2],
                'domain': row[3],
                'username': row[4],
                'signature': row[5],
                'timestamp': row[6],
                'verified': bool(row[7]),
                'integrity_ok': bool(row[7]),
                'contract_content': row[8]
            }

    def setup_cryptography(self):
        private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
        public_key_path = os.path.join(self.crypto_dir, "public_key.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(public_key_path, "rb") as f:
                    self.public_key_pem = f.read()
                logger.info("Chaves criptográficas carregadas do armazenamento local.")
            except Exception as e:
                logger.error(f"Erro ao carregar chaves existentes: {e}. Gerando novas chaves.")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        try:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            self.public_key_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            logger.info("Novas chaves criptográficas geradas.")
        except Exception as e:
            logger.error(f"Erro ao gerar chaves: {e}")
            messagebox.showerror("Erro", f"Falha ao gerar chaves criptográficas: {e}")

    def save_keys(self):
        if not self.save_keys_var.get():
            return
            
        try:
            private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
            public_key_path = os.path.join(self.crypto_dir, "public_key.pem")
            
            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            with open(public_key_path, "wb") as f:
                f.write(self.public_key_pem)
                
            logger.info("Chaves criptográficas salvas localmente.")
        except Exception as e:
            logger.error(f"Erro ao salvar chaves: {e}")

    def generate_new_keys(self):
        if messagebox.askyesno("Confirmar", "Gerar novas chaves criptográficas? Isso pode afetar seu acesso a conteúdo existente."):
            self.generate_keys()
            self.save_keys()
            messagebox.showinfo("Sucesso", "Novas chaves geradas e salvas.")

    def export_keys(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("Arquivos PEM", "*.pem")])
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                messagebox.showinfo("Sucesso", f"Chave privada exportada para: {file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar chave: {e}")

    def import_keys(self):
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos PEM", "*.pem")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.public_key_pem = self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.save_keys()
                messagebox.showinfo("Sucesso", "Chaves importadas com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao importar chaves: {e}")

    def start_network_thread(self):
        def run_network():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            ssl_context = None
            if self.use_ssl_var.get():
                ssl_context = ssl.create_default_context()
                if not self.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
            self.sio = socketio.AsyncClient(
                ssl_verify=ssl_context if ssl_context else False,
                reconnection=True,
                reconnection_attempts=5,
                reconnection_delay=1,
                reconnection_delay_max=5,
                request_timeout=120
            )
            self.setup_socket_handlers()
            
            self.loop.run_forever()
            
        self.network_thread = threading.Thread(target=run_network, daemon=True)
        self.network_thread.start()

    def setup_socket_handlers(self):
        @self.sio.event
        async def connect():
            logger.info(f"Conectado ao servidor {self.current_server}")
            self.root.after(0, lambda: self.update_status(f"Conectado a {self.current_server}"))
            self.connected = True
            self.connection_attempts = 0
            await self.sio.emit('request_server_auth_challenge', {})

        @self.sio.event
        async def disconnect():
            logger.info(f"Desconectado do servidor {self.current_server}")
            self.root.after(0, lambda: self.update_status("Desconectado"))
            self.connected = False
            self.logged_in = False
            self.root.after(0, lambda: self.set_tab_visibility(False))
            if self.current_user and self.auto_reconnect_var.get():
                self.root.after(5000, self.try_reconnect)

        @self.sio.event
        async def connect_error(data):
            logger.error(f"Erro de conexão: {data}")
            self.root.after(0, lambda: self.update_login_status(f"Erro de conexão: {data}"))

        @self.sio.event
        async def status(data):
            message = data.get('message', '')
            logger.info(f"Status do servidor: {message}")

        @self.sio.event
        async def server_auth_challenge(data):
            challenge = data.get('challenge')
            server_public_key_b64 = data.get('server_public_key')
            server_signature_b64 = data.get('signature')
            
            if not all([challenge, server_public_key_b64, server_signature_b64]):
                logger.error("Desafio de autenticação do servidor incompleto")
                self.root.after(0, lambda: self.update_login_status("Falha na autenticação do servidor: dados incompletos"))
                return
                
            try:
                server_public_key = serialization.load_pem_public_key(base64.b64decode(server_public_key_b64), backend=default_backend())
                server_public_key.verify(
                    base64.b64decode(server_signature_b64),
                    challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.server_public_keys[self.current_server] = server_public_key_b64
                
                client_challenge = secrets.token_urlsafe(32)
                self.client_auth_challenge = client_challenge
                
                client_signature = self.private_key.sign(
                    client_challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                await self.sio.emit('verify_server_auth_response', {
                    'client_challenge': client_challenge,
                    'client_signature': base64.b64encode(client_signature).decode('utf-8'),
                    'client_public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                })
                
                logger.info("Resposta de autenticação do servidor enviada")
                
            except InvalidSignature:
                logger.error("Assinatura do servidor inválida")
                self.root.after(0, lambda: self.update_login_status("Falha na autenticação do servidor: assinatura inválida"))
            except Exception as e:
                logger.error(f"Erro na autenticação do servidor: {e}")
                self.root.after(0, lambda: self.update_login_status(f"Erro na autenticação do servidor: {str(e)}"))

        @self.sio.event
        async def server_auth_result(data):
            success = data.get('success', False)
            if success:
                logger.info("Autenticação do servidor bem-sucedida")
                self.root.after(0, lambda: self.update_login_status("Servidor autenticado com sucesso"))
                if self.username_var.get() and self.password_var.get():
                    await self.sio.emit('request_usage_contract', {
                        'username': self.username_var.get().strip()
                    })
            else:
                error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha na autenticação do servidor: {error}")
                self.root.after(0, lambda: self.update_login_status(f"Falha na autenticação do servidor: {error}"))

        @self.sio.event
        async def pow_challenge(data):
            if 'error' in data:
                error = data['error']
                logger.error(f"Erro no desafio PoW: {error}")
                self.root.after(0, lambda: self.update_login_status(f"Erro PoW: {error}"))
                action_type = self.last_pow_action_type
                if action_type:
                    self.clear_pending_pow_action(action_type)
                    if action_type == "hps_mint":
                        self.root.after(0, lambda: self.record_hps_mint_failure(f"Erro no desafio: {error}"))
                        self.root.after(0, self.schedule_auto_mint)
                if data.get("debt_status"):
                    self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))
                    self.root.after(0, lambda: self.show_miner_debt_popup(data.get("debt_status")))
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_ban(duration, "Rate limit excedido"))
                return
                
            challenge = data.get('challenge')
            target_bits = data.get('target_bits')
            message = data.get('message', '')
            target_seconds = data.get('target_seconds', 30.0)
            action_type = data.get('action_type', 'login')
            voucher_id = data.get('voucher_id')
            
            logger.info(f"Desafio PoW recebido: {message} - {target_bits} bits")
            self.root.after(0, lambda: self.update_login_status(f"Resolvendo PoW: {target_bits} bits"))

            if action_type == "hps_mint":
                debt_status = data.get("debt_status")
                if debt_status:
                    self.root.after(0, lambda: self.update_miner_debt_status(debt_status))
                if data.get("minting_withheld") and debt_status:
                    self.root.after(0, lambda: self.show_miner_debt_popup(debt_status))
                if data.get("debt_warning") and debt_status:
                    def warn_and_continue():
                        proceed = messagebox.askyesno(
                            "Aviso de mineracao",
                            "Voce esta a 1 mineracao de distancia de ser bloqueado.\nDeseja continuar minerando?"
                        )
                        if not proceed:
                            self.clear_pending_pow_action("hps_mint")
                            self.record_hps_mint_failure("Mineracao cancelada pelo usuario.")
                            return
                        self.pending_hps_mint_voucher_id = voucher_id
                        self.start_hps_mining_ui(target_bits, target_seconds)
                        self.pow_solver.solve_challenge(
                            challenge,
                            target_bits,
                            target_seconds,
                            action_type,
                            use_popup=(action_type != "hps_mint")
                        )
                    self.root.after(0, warn_and_continue)
                    return
                self.pending_hps_mint_voucher_id = voucher_id
                self.root.after(0, lambda: self.start_hps_mining_ui(target_bits, target_seconds))

            self.pow_solver.solve_challenge(challenge, target_bits, target_seconds, action_type, use_popup=(action_type != "hps_mint"))

        @self.sio.event
        async def usage_contract_required(data):
            self.root.after(0, lambda: self.start_usage_contract_flow(data))

        @self.sio.event
        async def usage_contract_status(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_login_status(f"Falha no contrato de uso: {error}"))
                return
            if not data.get('required', False):
                await self.request_pow_challenge("login")

        @self.sio.event
        async def usage_contract_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: self.update_login_status(message))
                return
            success = data.get('success', False)
            if success:
                self.root.after(0, lambda: self.update_login_status("Contrato de uso aceito. Iniciando PoW de login..."))
                await self.request_pow_challenge("login")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_login_status(f"Falha no contrato de uso: {error}"))

        @self.sio.event
        async def authentication_result(data):
            success = data.get('success', False)
            if success:
                username = data.get('username')
                reputation = data.get('reputation', 100)
                server_address = data.get("server_address", "")
                self.current_user = username
                self.logged_in = True
                self.reputation = reputation
                self.stats_data['session_start'] = time.time()
                if server_address:
                    self.current_server_address = server_address
                
                self.root.after(0, lambda: self.set_tab_visibility(True))
                self.root.after(0, lambda: self.update_user_status(username, reputation))
                self.root.after(0, lambda: self.update_login_status("Login bem-sucedido!"))
                self.root.after(0, self.start_server_analysis)
                
                await self.join_network()
                await self.sync_client_files()
                await self.sync_client_dns_files()
                await self.sync_client_contracts()
                await self.request_pending_transfers()
                await self.sio.emit('request_hps_wallet', {})
                await self.request_economy_report()
                await self.submit_fraud_reports()
                await self.audit_server_integrity()
                
                logger.info(f"Login bem-sucedido: {username}")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_login_status(f"Falha no login: {error}"))
                logger.error(f"Falha no login: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_ban(duration, "Múltiplas tentativas de login falhas"))

        @self.sio.event
        async def hps_wallet_sync(data):
            if 'error' in data:
                logger.error(f"Erro ao sincronizar carteira HPS: {data.get('error')}")
                return
            vouchers = data.get('vouchers', []) or []
            debt_status = data.get("debt_status")
            if debt_status:
                self.root.after(0, lambda: self.update_miner_debt_status(debt_status))
            for voucher in vouchers:
                self.store_voucher_record(voucher)
            self.root.after(0, self.update_hps_balance)
            self.root.after(0, self.update_exchange_ui)
            self.root.after(0, self.maybe_start_auto_mint)
            if self.server_analysis_in_progress and not self.wallet_fraud_check_inflight and vouchers:
                self.wallet_fraud_check_inflight = True
                try:
                    await self.audit_wallet_vouchers_for_fraud(vouchers)
                finally:
                    self.wallet_fraud_check_inflight = False
            elif self.server_analysis_in_progress:
                self.mark_server_analysis_done("wallet")

        @self.sio.event
        async def hps_economy_status(data):
            pow_costs = data.get('pow_costs') or {}
            for key, value in pow_costs.items():
                try:
                    self.hps_pow_skip_costs[key] = int(value)
                except Exception:
                    continue
            if self.current_server:
                payload = {
                    "issuer": self.current_server,
                    "multiplier": data.get("multiplier", 1.0),
                    "total_minted": data.get("total_minted", 0.0),
                    "custody_balance": data.get("custody_balance", 0.0),
                    "owner_balance": data.get("owner_balance", 0.0),
                    "rebate_balance": data.get("rebate_balance", 0.0),
                    "exchange_fee_rate": data.get("exchange_fee_rate", 0.02),
                    "exchange_fee_min": data.get("exchange_fee_min", 1),
                    "timestamp": time.time()
                }
                self.store_server_economy(self.current_server, payload, "")
                self.root.after(0, self.update_exchange_ui)

        @self.sio.event
        async def economy_report(data):
            if not isinstance(data, dict) or data.get("error"):
                return
            payload = data.get("payload", {})
            signature = data.get("signature", "")
            server_address = payload.get("issuer")
            if not server_address:
                return
            pow_costs = payload.get("pow_costs") or {}
            for key, value in pow_costs.items():
                try:
                    self.hps_pow_skip_costs[key] = int(value)
                except Exception:
                    continue
            self.store_server_economy(server_address, payload, signature)
            self.save_economy_report_file(server_address, payload, signature)
            self.root.after(0, self.update_exchange_ui)

        @self.sio.event
        async def economy_alert(data):
            reason = data.get("reason", "")
            issuer = data.get("issuer", "")
            if reason:
                self.root.after(0, lambda: messagebox.showwarning("Alerta de economia", f"Servidor {issuer} com alerta: {reason}"))

        @self.sio.event
        async def exchange_quote(data):
            if data.get("pending"):
                message = data.get("message", "Transacao em analise pelo minerador.")
                self.root.after(0, lambda: messagebox.showinfo("Cambio", message))
                return
            if not data.get("success"):
                error = data.get("error", "Erro no cambio")
                self.root.after(0, lambda: messagebox.showerror("Cambio", error))
                return
            quote_id = data.get("quote_id")
            rate = float(data.get("rate", 1.0))
            converted = int(data.get("converted_value", 0))
            fee = int(data.get("fee_amount", 0))
            receive = int(data.get("receive_amount", 0))
            def prompt_confirm():
                if messagebox.askyesno("Cambio", f"Taxa: {rate:.4f}\nConvertido: {converted} HPS\nTaxa: {fee} HPS\nReceber: {receive} HPS\nConfirmar conversao?"):
                    asyncio.run_coroutine_threadsafe(self.sio.emit('confirm_exchange', {'quote_id': quote_id}), self.loop)
            self.root.after(0, prompt_confirm)

        @self.sio.event
        async def exchange_complete(data):
            if not data.get("success"):
                error = data.get("error", "Erro no cambio")
                self.root.after(0, lambda: messagebox.showerror("Cambio", error))
                return
            spent_ids = data.get("spent_voucher_ids", []) or []
            if spent_ids:
                self.invalidate_local_vouchers(spent_ids, status="converted")
            self.root.after(0, self.refresh_hps_wallet)

        @self.sio.event
        async def hps_voucher_offer(data):
            voucher_id = data.get('voucher_id')
            payload = data.get('payload')
            if not voucher_id or not payload:
                return
            try:
                signature = self.private_key.sign(
                    self.canonicalize_payload(payload).encode("utf-8"),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                await self.sio.emit('confirm_hps_voucher', {
                    'voucher_id': voucher_id,
                    'owner_signature': base64.b64encode(signature).decode('utf-8')
                })
            except Exception as e:
                logger.error(f"Erro ao assinar voucher HPS: {e}")

        @self.sio.event
        async def hps_voucher_withheld(data):
            value = int(data.get("value", 0))
            debt_status = data.get("debt_status")
            if debt_status:
                self.root.after(0, lambda: self.update_miner_debt_status(debt_status))
                self.root.after(0, lambda: self.show_miner_debt_popup(debt_status))
            self.root.after(0, lambda: self.update_hps_mining_status("Voucher pendente"))
            self.root.after(0, lambda: self.log_hps_mining_message(f"Voucher pendente ({value} HPS)."))
            if data.get("mode") == "promise" and debt_status:
                remaining = float(debt_status.get("promise_amount", 0.0))
                def show_progress():
                    messagebox.showinfo(
                        "Promessa de pagamento",
                        f"Enviado para custodia: {value} HPS\nFalta: {remaining:.2f} HPS"
                    )
                self.root.after(0, show_progress)
            def after_withheld():
                if not self.maybe_request_miner_fine_after_mint():
                    self.schedule_auto_mint(0.1)
            self.root.after(0, after_withheld)

        @self.sio.event
        async def hps_voucher_issued(data):
            voucher = data.get('voucher')
            if not voucher:
                return
            self.store_voucher_record(voucher)
            self.root.after(0, lambda: self.update_hps_mining_status("Voucher emitido"))
            self.root.after(0, lambda: self.log_hps_mining_message("Voucher $HPS emitido com sucesso."))
            def after_issue():
                if not self.maybe_request_miner_fine_after_mint():
                    self.schedule_auto_mint(0.1)
            self.root.after(0, after_issue)

        @self.sio.event
        async def hps_voucher_error(data):
            error = data.get('error', 'Erro desconhecido')
            self.root.after(0, lambda: self.update_hps_mining_status("Erro no voucher"))
            self.root.after(0, lambda: self.log_hps_mining_message(f"Erro no voucher: {error}"))
            if data.get("debt_status"):
                self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))
                self.root.after(0, lambda: self.show_miner_debt_popup(data.get("debt_status")))
            self.root.after(0, lambda: self.schedule_auto_mint(0.1))

        @self.sio.event
        async def miner_signature_request(data):
            self.root.after(0, lambda: self.handle_miner_signature_request(data))

        @self.sio.event
        async def miner_signature_ack(data):
            if not data.get("success"):
                error = data.get("error", "Erro ao assinar transferencia")
                self.root.after(0, lambda: self.log_hps_mining_message(f"Assinatura falhou: {error}"))
                if "reassigned" in str(error).lower():
                    transfer_id = data.get("transfer_id")
                    if transfer_id and transfer_id in self.pending_miner_transfers:
                        self.pending_miner_transfers.pop(transfer_id, None)
                        self.root.after(0, lambda: self.update_miner_pending_signatures(self.miner_pending_signatures - 1))
                return
            transfer_id = data.get("transfer_id")
            if transfer_id and transfer_id in self.pending_miner_transfers:
                self.pending_miner_transfers.pop(transfer_id, None)
            if transfer_id in self.signature_popups:
                popup = self.signature_popups.pop(transfer_id, None)
                if popup and popup.winfo_exists():
                    self.root.after(0, popup.destroy)
            self.root.after(0, lambda: self.log_hps_mining_message(f"Transferencia {transfer_id} assinada."))
            self.root.after(0, lambda: self.update_miner_pending_signatures(self.miner_pending_signatures - 1))
            if data.get("debt_status"):
                self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))
            if not self.pending_miner_transfers:
                self.root.after(0, lambda: self.update_hps_mining_status("Ativo"))
                self.miner_signature_blocked = False
                if self.hps_auto_mint_var.get():
                    self.root.after(0, lambda: self.schedule_auto_mint(0.1))

        @self.sio.event
        async def miner_signature_update(data):
            pending = data.get("pending_signatures", 0)
            self.root.after(0, lambda: self.update_miner_pending_signatures(pending))
            if data.get("debt_status"):
                self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))

        @self.sio.event
        async def voucher_audit(data):
            if not data.get("success", False):
                return
            request_id = data.get("request_id")
            if not request_id:
                return
            future = self.voucher_audit_futures.get(request_id)
            if future and not future.done():
                future.set_result(data.get("vouchers", []))

        @self.sio.event
        async def exchange_trace(data):
            if not data.get("success", False):
                return
            request_id = data.get("request_id")
            if not request_id:
                return
            future = self.exchange_trace_futures.get(request_id)
            if future and not future.done():
                future.set_result(data.get("traces", []))

        @self.sio.event
        async def voucher_invalidate_ack(data):
            if not data.get("success"):
                error = data.get("error", "Erro ao invalidar vouchers")
                self.root.after(0, lambda: self.log_hps_mining_message(f"Invalidação falhou: {error}"))
                transfer_id = data.get("transfer_id")
                if transfer_id:
                    self.pending_invalidation_transfers.discard(transfer_id)
                    if error == "Vouchers are valid":
                        self.audit_override_validated.add(transfer_id)
                        self.root.after(0, lambda: self.log_hps_mining_message(f"Vouchers válidos, retomando assinatura {transfer_id}."))
                        self.root.after(0, lambda: self.sign_transfer_by_id(transfer_id))
                return
            transfer_id = data.get("transfer_id")
            if transfer_id:
                self.pending_invalidation_transfers.discard(transfer_id)
                self.audit_override_validated.discard(transfer_id)
                if transfer_id in self.pending_miner_transfers:
                    self.pending_miner_transfers.pop(transfer_id, None)
                    self.root.after(0, lambda: self.update_miner_pending_signatures(self.miner_pending_signatures - 1))
                if transfer_id in self.signature_popups:
                    popup = self.signature_popups.pop(transfer_id, None)
                    if popup and popup.winfo_exists():
                        self.root.after(0, popup.destroy)
            self.root.after(0, lambda: self.log_hps_mining_message("Vouchers invalidados pelo minerador."))

        @self.sio.event
        async def monetary_transfer_pending(data):
            transfer_id = data.get("transfer_id")
            miner = data.get("assigned_miner") or "desconhecido"
            status = data.get("status") or "awaiting_miner"
            if not transfer_id:
                return
            self.root.after(0, lambda: self.show_monetary_transfer_popup(transfer_id, miner, status))

        @self.sio.event
        async def monetary_transfer_update(data):
            transfer_id = data.get("transfer_id")
            status = data.get("status")
            miner = data.get("assigned_miner")
            reason = data.get("reason", "")
            details = data.get("details")
            if not transfer_id:
                return
            self.root.after(0, lambda: self.update_monetary_transfer_popup(transfer_id, miner, status, reason, details))

        @self.sio.event
        async def miner_fine_quote(data):
            if not data.get("success"):
                error = data.get("error", "Erro ao obter multa")
                self.root.after(0, lambda: self.log_hps_mining_message(f"Multa: {error}"))
                if self.miner_fine_request_source == "auto" and self.hps_auto_mint_var.get():
                    self.root.after(0, lambda: self.schedule_auto_mint(0.1))
                self.miner_fine_request_in_flight = False
                self.miner_fine_request_source = ""
                return
            fine_amount = int(data.get("fine_amount", 0))
            pending = int(data.get("pending_total", data.get("pending_fines", data.get("pending_signatures", 0))))
            if data.get("debt_status"):
                self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))
            if fine_amount <= 0:
                self.root.after(0, lambda: self.log_hps_mining_message("Nenhuma multa pendente."))
                if self.miner_fine_request_source == "auto" and self.hps_auto_mint_var.get():
                    self.root.after(0, lambda: self.schedule_auto_mint(0.1))
                self.miner_fine_request_in_flight = False
                self.miner_fine_request_source = ""
                return
            if self.miner_fine_request_source == "manual":
                debt_status = data.get("debt_status") or self.miner_debt_status
                self.root.after(0, lambda: self.prompt_miner_fine_payment(fine_amount, pending, debt_status))
            elif self.miner_auto_pay_fine_var.get() or self.miner_fine_promise_var.get():
                if self.pending_miner_transfers:
                    if self.hps_auto_mint_var.get():
                        self.root.after(0, lambda: self.schedule_auto_mint(0.1))
                    self.miner_fine_request_in_flight = False
                    self.miner_fine_request_source = ""
                    return
                if self.miner_auto_pay_fine_var.get() and self.can_cover_fine_amount(fine_amount):
                    self.root.after(0, lambda: self.pay_miner_fine(fine_amount, pending, promise=False))
                elif self.miner_fine_promise_var.get():
                    self.root.after(0, lambda: self.pay_miner_fine(fine_amount, pending, promise=True))
                else:
                    if self.hps_auto_mint_var.get():
                        self.root.after(0, lambda: self.schedule_auto_mint(0.1))
                    self.miner_fine_request_in_flight = False
                    self.miner_fine_request_source = ""
            else:
                self.miner_fine_request_in_flight = False
                self.miner_fine_request_source = ""

        @self.sio.event
        async def miner_fine_ack(data):
            if not data.get("success"):
                error = data.get("error", "Erro ao pagar multa")
                self.root.after(0, lambda: self.log_hps_mining_message(f"Multa falhou: {error}"))
                if self.miner_fine_request_source == "auto" and self.hps_auto_mint_var.get():
                    self.root.after(0, lambda: self.schedule_auto_mint(0.1))
                self.miner_fine_request_in_flight = False
                self.miner_fine_request_source = ""
                return
            amount = data.get("amount", 0)
            self.root.after(0, lambda: self.log_hps_mining_message(f"Multa paga: {amount} HPS."))
            if data.get("debt_status"):
                self.root.after(0, lambda: self.update_miner_debt_status(data.get("debt_status")))
            self.miner_fine_request_in_flight = False
            self.miner_fine_request_source = ""
            self.miner_signature_blocked = False
            if self.hps_auto_mint_var.get():
                self.root.after(0, lambda: self.schedule_auto_mint(0.1))

        @self.sio.event
        async def miner_ban(data):
            reason = data.get("reason", "Banimento do minerador")
            self.root.after(0, lambda: self.update_hps_mining_status("Mineracao bloqueada"))
            self.root.after(0, lambda: self.log_hps_mining_message(f"Mineracao bloqueada: {reason}"))
            self.pow_solver.stop_solving()
            self.miner_signature_blocked = True

        @self.sio.event
        async def hps_transfer_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Transferência HPS", message))
                return
            success = data.get('success', False)
            if success:
                message = data.get('message', 'Transferência HPS iniciada.')
                self.root.after(0, lambda: messagebox.showinfo("Transferência HPS", message))
                self.root.after(0, self.refresh_hps_wallet)
                return
            error = data.get('error', 'Erro desconhecido')
            self.root.after(0, lambda: messagebox.showerror("Transferência HPS", error))
            self.root.after(0, self.refresh_hps_wallet)

        @self.sio.event
        async def hps_issuer_invalidated(data):
            issuer = data.get('issuer')
            reason = data.get('reason', '')
            if not issuer:
                return
            self.invalidate_issuer_vouchers(issuer)
            self.root.after(0, lambda: messagebox.showwarning("Issuer inválido", f"Emissor {issuer} invalidado. Motivo: {reason}"))

        @self.sio.event
        async def network_joined(data):
            success = data.get('success', False)
            if success:
                logger.info("Entrou na rede com sucesso")
                await self.sio.emit('get_network_state', {})
            else:
                error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha ao entrar na rede: {error}")

        @self.sio.event
        async def search_results(data):
            if 'error' in data:
                error = data['error']
                self.root.after(0, lambda: self.display_content_error(f"Erro na busca: {error}"))
                return
                
            results = data.get('results', [])
            self.root.after(0, lambda: self.display_search_results(results))

        @self.sio.event
        async def content_response(data):
            if 'error' in data:
                if data.get('error') == 'contract_violation':
                    self.root.after(0, lambda: self.handle_contract_blocked_content_access(data))
                    return
                error = data['error']
                self.root.after(0, lambda: self.display_content_error(f"Erro no conteúdo: {error}"))
                return
            
            if data.get('is_api_app_update'):
                try:
                    update_payload = json.loads(base64.b64decode(data.get('content', '')).decode('utf-8'))
                except Exception:
                    update_payload = {}
                new_hash = update_payload.get('new_hash', '')
                app_name = update_payload.get('app_name', '')
                old_hash = data.get('content_hash', '')
                self.root.after(0, lambda: self.handle_api_app_update_flow(app_name, old_hash, new_hash))
                return
                
            content_b64 = data.get('content')
            title = data.get('title', 'Sem título')
            description = data.get('description', '')
            mime_type = data.get('mime_type', 'text/plain')
            username = data.get('username', 'Desconhecido')
            signature = data.get('signature', '')
            public_key = data.get('public_key', '')
            verified = data.get('verified', False)
            content_hash = data.get('content_hash', '')
            
            try:
                content = base64.b64decode(content_b64)
                self.stats_data['data_received'] += len(content)
                self.stats_data['content_downloaded'] += 1
                
                integrity_ok = True
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != content_hash:
                    integrity_ok = False
                    logger.warning(f"Integridade do arquivo comprometida para {content_hash}. Esperado: {content_hash}, Real: {actual_hash}")
                    messagebox.showwarning("Aviso de Segurança", "Este arquivo foi adulterado no servidor. A integridade não pode ser garantida.")
                
                self.save_content_to_storage(content_hash, content, {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified
                })
                
                content_info = {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified,
                    'content': content,
                    'content_hash': content_hash,
                    'reputation': data.get('reputation', 100),
                    'integrity_ok': integrity_ok,
                    'original_owner': data.get('original_owner', username),
                    'certifier': data.get('certifier', '')
                }

                contracts = data.get('contracts', [])
                if contracts:
                    self.store_contracts(contracts)

                content_info['contracts'] = contracts
                content_info['contract_violation'] = data.get('contract_violation', False) or not contracts
                content_info['contract_violation_reason'] = data.get('contract_violation_reason', '')
                self.root.after(0, lambda: self.handle_content_contracts(content_info))
                
            except Exception as e:
                logger.error(f"Erro ao decodificar conteúdo: {e}")
                self.root.after(0, lambda: self.display_content_error(f"Erro ao processar conteúdo: {e}"))

        @self.sio.event
        async def publish_result(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: self.update_upload_status(message))
                return
            success = data.get('success', False)
            if success:
                content_hash = data.get('content_hash')
                verified = data.get('verified', False)
                self.stats_data['content_uploaded'] += 1
                self.root.after(0, lambda: self.update_upload_status(f"Upload bem-sucedido! Hash: {content_hash}"))
                self.root.clipboard_clear()
                self.root.clipboard_append(content_hash)
                
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
                    
                messagebox.showinfo("Upload Concluído", f"Upload concluído com sucesso! Hash: {content_hash} Hash copiado para área de transferência!")
                asyncio.run_coroutine_threadsafe(self.request_pending_transfers(), self.loop)
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_upload_status(f"Falha no upload: {error}"))
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
                messagebox.showerror("Erro no Upload", f"Falha no upload: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_upload_block(duration))

        @self.sio.event
        async def dns_result(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: self.update_dns_status(message))
                return
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                verified = data.get('verified', False)
                self.stats_data['dns_registered'] += 1
                self.root.after(0, lambda: self.update_dns_status(f"DNS registrado: {domain}"))
                self.root.after(0, self.refresh_dns_records)
                messagebox.showinfo("DNS Registrado", f"Domínio {domain} registrado com sucesso!")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_dns_status(f"Falha no registro DNS: {error}"))
                messagebox.showerror("Erro no DNS", f"Falha no registro DNS: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_dns_block(duration))

        @self.sio.event
        async def dns_resolution(data):
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                content_hash = data.get('content_hash')
                username = data.get('username')
                verified = data.get('verified', False)
                signature = data.get('signature', '')
                
                self.root.after(0, lambda: self.update_dns_status(f"DNS resolvido: {domain}"))
                self.browser_url_var.set(f"hps://{content_hash}")
                self.root.after(0, lambda: self.request_content_by_hash(content_hash))
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO browser_dns_records 
                        (domain, content_hash, username, verified, timestamp, ddns_hash) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (domain, content_hash, username, verified, time.time(), ""))
                    conn.commit()
                    
                self.root.after(0, self.refresh_dns_records)
                
                ddns_content = self.create_ddns_file(domain, content_hash)
                self.save_ddns_to_storage(domain, ddns_content, {
                    'content_hash': content_hash,
                    'username': username,
                    'verified': verified,
                    'signature': signature,
                    'public_key': ''
                })
                
                contracts = data.get('contracts', [])
                if contracts:
                    self.store_contracts(contracts)
                if data.get('contract_violation') or not contracts:
                    self.report_contract_violation("domain", domain=domain, reason=data.get('contract_violation_reason', 'missing_contract'))
                    reason = data.get('contract_violation_reason', 'missing_contract')
                    if reason == 'invalid_contract' or reason == 'invalid_signature':
                        messagebox.showwarning("Contrato Adulterado", "O contrato deste dominio foi adulterado ou e invalido. O servidor foi notificado.")
                    else:
                        messagebox.showwarning("Contrato Ausente", "Este dominio nao possui contrato valido. O servidor foi notificado.")
                self.current_dns_info = {
                    'domain': domain,
                    'content_hash': content_hash,
                    'username': username,
                    'verified': verified,
                    'contracts': contracts,
                    'contract_violation': data.get('contract_violation', False) or not contracts,
                    'original_owner': data.get('original_owner', username),
                    'certifier': data.get('certifier', '')
                }
            else:
                if data.get('error') == 'contract_violation':
                    self.root.after(0, lambda: self.handle_contract_blocked_dns_access(data))
                    return
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_dns_status(f"Falha na resolução DNS: {error}"))
                messagebox.showerror("Erro no DNS", f"Falha na resolução DNS: {error}")

        @self.sio.event
        async def network_state(data):
            if 'error' in data:
                return
                
            online_nodes = data.get('online_nodes', 0)
            total_content = data.get('total_content', 0)
            total_dns = data.get('total_dns', 0)
            node_types = data.get('node_types', {})
            
            self.root.after(0, lambda: self.update_network_stats(online_nodes, total_content, total_dns, node_types))

        @self.sio.event
        async def server_list(data):
            if 'error' in data:
                return
                
            servers = data.get('servers', [])
            self.root.after(0, lambda: self.update_servers_list(servers))

        @self.sio.event
        async def reputation_update(data):
            reputation = data.get('reputation', 100)
            self.reputation = reputation
            self.root.after(0, lambda: self.update_reputation(reputation))

        @self.sio.event
        async def ban_notification(data):
            duration = data.get('duration', 300)
            reason = data.get('reason', 'Desconhecido')
            self.root.after(0, lambda: self.handle_ban(duration, reason))

        @self.sio.event
        async def contract_violation_notice(data):
            violation_type = data.get('violation_type')
            content_hash = data.get('content_hash')
            domain = data.get('domain')
            reason = data.get('reason', 'invalid_contract')
            target = domain or content_hash or "desconhecido"
            message = f"Contrato adulterado: {target}"
            if reason == "missing_contract":
                message = f"Contrato ausente: {target}"
            logger.info(f"Aviso de violacao recebido: {data}")
            if domain:
                self.active_contract_violations[("domain", domain)] = reason
            elif content_hash:
                self.active_contract_violations[("content", content_hash)] = reason
            else:
                self.active_contract_violations[("unknown", target)] = reason
            self.root.after(0, self.update_certify_missing_contract_ui)
            self.root.after(0, lambda: self.show_contract_alert("Você está com pendências contratuais. Clique em Certificados"))
            self.root.after(0, lambda: messagebox.showwarning("Contrato Adulterado", message))

        @self.sio.event
        async def contract_violation_cleared(data):
            content_hash = data.get('content_hash')
            domain = data.get('domain')
            if domain:
                self.active_contract_violations.pop(("domain", domain), None)
            elif content_hash:
                self.active_contract_violations.pop(("content", content_hash), None)
            self.root.after(0, self.update_certify_missing_contract_ui)
            if not self.active_contract_violations and not self.pending_transfers:
                self.root.after(0, self.clear_contract_alert)

        @self.sio.event
        async def pending_transfers(data):
            if 'error' in data:
                return
            transfers = data.get('transfers', []) or []
            self.pending_transfers = transfers
            self.pending_transfers_by_contract = {t.get('contract_id'): t for t in transfers if t.get('contract_id')}
            if transfers:
                self.root.after(0, lambda: self.show_contract_alert("Você está com pendências contratuais. Clique em Certificados"))
                if time.time() - self.last_pending_transfer_notice > 10:
                    self.last_pending_transfer_notice = time.time()
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Pendência Contratual",
                        f"Você tem {len(transfers)} pendência(s) contratual(is). Abra Certificados para resolver."
                    ))
            else:
                if not self.active_contract_violations:
                    self.root.after(0, self.clear_contract_alert)

        @self.sio.event
        async def pending_transfer_notice(data):
            count = data.get('count', 1)
            if count > 0:
                self.root.after(0, lambda: self.show_contract_alert("Você está com pendências contratuais. Clique em Certificados"))
                if time.time() - self.last_pending_transfer_notice > 10:
                    self.last_pending_transfer_notice = time.time()
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Pendência Contratual",
                        f"Você tem {count} pendência(s) contratual(is). Abra Certificados para resolver."
                    ))

        @self.sio.event
        async def transfer_payload(data):
            if 'error' in data:
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao obter transferencia: {data.get('error')}"))
                return
            content_b64 = data.get('content_b64')
            if not content_b64:
                self.root.after(0, lambda: messagebox.showerror("Erro", "Arquivo de transferencia nao encontrado."))
                return
            try:
                content = base64.b64decode(content_b64)
            except Exception:
                self.root.after(0, lambda: messagebox.showerror("Erro", "Arquivo de transferencia invalido."))
                return
            title = data.get('title', '')
            description = data.get('description', '')
            mime_type = data.get('mime_type', 'application/octet-stream')
            self.root.after(0, lambda: self.upload_content_bytes(title, description, mime_type, content))

        @self.sio.event
        async def accept_hps_transfer_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Transferencia", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao aceitar transferencia: {error}"))
                return
            amount = data.get('amount')
            if amount is not None:
                self.root.after(0, lambda: messagebox.showinfo("Transferencia", f"Transferencia HPS aceita: {amount} HPS."))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Transferencia", "Transferencia HPS aceita."))
            self.root.after(0, lambda: asyncio.run_coroutine_threadsafe(self.request_pending_transfers(), self.loop))

        @self.sio.event
        async def reject_transfer_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Transferencia", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao rejeitar transferencia: {error}"))
                return
            self.root.after(0, lambda: messagebox.showinfo("Transferencia", "Transferencia rejeitada."))
            self.root.after(0, lambda: asyncio.run_coroutine_threadsafe(self.request_pending_transfers(), self.loop))

        @self.sio.event
        async def renounce_transfer_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Transferencia", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao renunciar transferencia: {error}"))
                return
            self.root.after(0, lambda: messagebox.showinfo("Transferencia", "Transferencia renunciada."))
            self.root.after(0, lambda: asyncio.run_coroutine_threadsafe(self.request_pending_transfers(), self.loop))

        @self.sio.event
        async def contract_canonical(data):
            if 'error' in data:
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao obter contrato valido: {data.get('error')}"))
                return
            contract_text = data.get('contract_text', '')
            if not contract_text:
                self.root.after(0, lambda: messagebox.showerror("Erro", "Contrato valido nao encontrado."))
                return
            if self.pending_missing_contract_target:
                self.root.after(0, lambda: self.handle_missing_contract_canonical(contract_text))
            else:
                self.root.after(0, lambda: self.handle_canonical_contract(contract_text))

        @self.sio.event
        async def backup_server(data):
            if 'error' in data:
                logger.warning(f"Nenhum servidor de backup disponível: {data['error']}")
            else:
                backup_server = data.get('server')
                self.backup_server = backup_server
                logger.info(f"Servidor de backup definido: {backup_server}")
                self.root.after(0, lambda: self.update_status(f"Backup: {backup_server}"))

        @self.sio.event
        async def content_search_status(data):
            status = data.get('status', '')
            content_hash = data.get('content_hash', '')
            if status == 'searching_network':
                self.root.after(0, lambda: self.update_status(f"Buscando conteúdo {content_hash} na rede..."))

        @self.sio.event
        async def dns_search_status(data):
            status = data.get('status', '')
            domain = data.get('domain', '')
            if status == 'searching_network':
                self.root.after(0, lambda: self.update_status(f"Buscando DNS {domain} na rede..."))

        @self.sio.event
        async def client_files_sync(data):
            try:
                files = data.get('files', [])
                await self.process_client_files_sync(files)
            except Exception as e:
                logger.error(f"Erro ao sincronizar arquivos do cliente: {e}")

        @self.sio.event
        async def client_files_response(data):
            try:
                missing_files = data.get('missing_files', [])
                await self.share_missing_files(missing_files)
            except Exception as e:
                logger.error(f"Erro ao processar resposta de arquivos do cliente: {e}")

        @self.sio.event
        async def client_dns_files_response(data):
            try:
                missing_dns = data.get('missing_dns', [])
                await self.share_missing_dns_files(missing_dns)
            except Exception as e:
                logger.error(f"Erro ao processar resposta de DNS do cliente: {e}")

        @self.sio.event
        async def client_contracts_response(data):
            try:
                missing_contracts = data.get('missing_contracts', [])
                await self.share_missing_contracts(missing_contracts)
            except Exception as e:
                logger.error(f"Erro ao processar resposta de contratos do cliente: {e}")

        @self.sio.event
        async def request_content_from_client(data):
            try:
                content_hash = data.get('content_hash')
                if not content_hash:
                    return
                    
                file_path = os.path.join(self.crypto_dir, "content", f"{content_hash}.dat")
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    actual_hash = hashlib.sha256(content).hexdigest()
                    if actual_hash != content_hash:
                        logger.warning(f"Content {content_hash} integrity check failed")
                        return
                        
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT title, description, mime_type, username, signature, public_key, verified FROM browser_content_cache WHERE content_hash = ?', (content_hash,))
                        row = cursor.fetchone()
                        if not row:
                            logger.warning(f"Metadata not found for content {content_hash}")
                            return
                            
                        title, description, mime_type, username, signature, public_key, verified = row
                        
                    await self.sio.emit('content_from_client', {
                        'content_hash': content_hash,
                        'content': base64.b64encode(content).decode('utf-8'),
                        'title': title,
                        'description': description,
                        'mime_type': mime_type,
                        'username': username,
                        'signature': signature,
                        'public_key': public_key,
                        'verified': verified
                    })
                    
                    logger.info(f"Content {content_hash} shared to network")
                    
            except Exception as e:
                logger.error(f"Error sharing content to network: {e}")

        @self.sio.event
        async def request_ddns_from_client(data):
            try:
                domain = data.get('domain')
                if not domain:
                    return
                await self.send_ddns_to_server(domain)
            except Exception as e:
                logger.error(f"Error sharing DDNS to network: {e}")

        @self.sio.event
        async def request_contract_from_client(data):
            try:
                contract_id = data.get('contract_id')
                if not contract_id:
                    return
                await self.send_contract_to_server(contract_id)
            except Exception as e:
                logger.error(f"Error sharing contract to network: {e}")

        @self.sio.event
        async def ddns_from_client(data):
            try:
                domain = data.get('domain')
                ddns_content_b64 = data.get('ddns_content')
                content_hash = data.get('content_hash')
                username = data.get('username')
                signature = data.get('signature', '')
                public_key = data.get('public_key', '')
                verified = data.get('verified', False)
                if not all([domain, ddns_content_b64, content_hash, username]):
                    return
                ddns_content = base64.b64decode(ddns_content_b64)
                ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                self.save_ddns_to_storage(domain, ddns_content, {
                    'content_hash': content_hash,
                    'username': username,
                    'verified': verified,
                    'signature': signature,
                    'public_key': public_key
                })
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO browser_dns_records 
                        (domain, content_hash, username, verified, timestamp, ddns_hash) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (domain, content_hash, username, int(bool(verified)), time.time(), ddns_hash))
                    conn.commit()
            except Exception as e:
                logger.error(f"Error processing DDNS from network: {e}")

        @self.sio.event
        async def contract_from_client(data):
            try:
                contract_id = data.get('contract_id')
                contract_content_b64 = data.get('contract_content')
                if not contract_id or not contract_content_b64:
                    return
                contract_info = {
                    'contract_id': contract_id,
                    'action_type': data.get('action_type', ''),
                    'content_hash': data.get('content_hash'),
                    'domain': data.get('domain'),
                    'username': data.get('username', ''),
                    'signature': data.get('signature', ''),
                    'verified': data.get('verified', False),
                    'timestamp': time.time(),
                    'contract_content': base64.b64decode(contract_content_b64).decode('utf-8', errors='replace')
                }
                self.save_contract_to_storage(contract_info)
            except Exception as e:
                logger.error(f"Error processing contract from network: {e}")

        @self.sio.event
        async def contracts_results(data):
            try:
                if 'error' in data:
                    return
                contracts = data.get('contracts', [])
                if self.contracts_filter_mode == "api_app":
                    for contract in contracts:
                        contract_id = contract.get('contract_id')
                        if contract_id:
                            self.contracts_pending_details.add(contract_id)
                            await self.sio.emit('get_contract', {'contract_id': contract_id})
                    return
                if contracts:
                    self.store_contracts(contracts)
                self.populate_contracts_tree(contracts)
            except Exception as e:
                logger.error(f"Error processing contracts results: {e}")

        @self.sio.event
        async def contract_details(data):
            try:
                if 'error' in data:
                    return
                contract_info = data.get('contract')
                if contract_info:
                    self.save_contract_to_storage(contract_info)
                    contract_id = contract_info.get('contract_id')
                    if self.pending_contract_analyzer_id == contract_id:
                        self.pending_contract_analyzer_id = None
                        self.root.after(0, lambda: self.show_contract_analyzer(contract_info))
                    if self.contracts_filter_mode == "api_app" and contract_id in self.contracts_pending_details:
                        contract_text = contract_info.get('contract_content', '') or ''
                        app_name = self.contracts_filter_value.strip()
                        if app_name and f"# APP: {app_name}".lower() in contract_text.lower():
                            self.contracts_results_cache[contract_id] = contract_info
                            self.populate_contracts_tree(list(self.contracts_results_cache.values()))
                        self.contracts_pending_details.discard(contract_id)
                        return
                    selection = self.contracts_tree.selection()
                    if selection:
                        current_id = self.contracts_tree.item(selection[0], 'values')[0]
                        if current_id == contract_id:
                            self.display_contract_details(contract_info)
            except Exception as e:
                logger.error(f"Error processing contract details: {e}")

        @self.sio.event
        async def api_app_versions(data):
            self.root.after(0, lambda: self.handle_api_app_versions_response(data))

        @self.sio.event
        async def report_result(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Reporte", message))
                return
            success = data.get('success', False)
            if success:
                self.stats_data['content_reported'] += 1
                self.root.after(0, lambda: messagebox.showinfo("Sucesso", "Conteúdo reportado com sucesso!"))
                logger.info("Conteúdo reportado com sucesso")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no reporte: {error}"))
                logger.error(f"Falha no reporte: {error}")

        @self.sio.event
        async def invalidate_contract_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Contrato", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao invalidar contrato: {error}"))
                return
            self.root.after(0, self.clear_contract_alert)
            self.root.after(0, lambda: self.handle_contract_reissue_success(data))

        @self.sio.event
        async def certify_contract_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Certificacao", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao certificar contrato: {error}"))
                return
            self.root.after(0, self.clear_contract_alert)
            self.root.after(0, lambda: messagebox.showinfo("Certificacao", "Contrato certificado com sucesso."))
            if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_report_block(duration))

            if self.report_window and self.report_window.window.winfo_exists():
                self.report_window.destroy()
                self.report_window = None

        @self.sio.event
        async def certify_missing_contract_ack(data):
            if data.get('pending'):
                message = data.get('message', 'Transacao em analise pelo minerador.')
                self.root.after(0, lambda: messagebox.showinfo("Certificacao", message))
                return
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao certificar contrato: {error}"))
                return
            self.root.after(0, self.clear_contract_alert)
            self.root.after(0, lambda: messagebox.showinfo("Certificacao", "Contrato certificado com sucesso."))

    async def process_client_files_sync(self, files):
        content_hashes = [file['content_hash'] for file in files]
        await self.sio.emit('request_client_files', {
            'content_hashes': content_hashes
        })

    async def share_missing_files(self, missing_files):
        for content_hash in missing_files:
            file_path = os.path.join(self.crypto_dir, "content", f"{content_hash}.dat")
            if os.path.exists(file_path):
                await self.sio.emit('request_content_from_client', {'content_hash': content_hash})
                await asyncio.sleep(0.1)

    async def process_client_dns_files_sync(self, dns_files):
        domains = [dns_file['domain'] for dns_file in dns_files]
        if not domains:
            return
        await self.sio.emit('request_client_dns_files', {
            'domains': domains
        })

    async def share_missing_dns_files(self, missing_dns):
        for domain in missing_dns:
            await self.send_ddns_to_server(domain)
            await asyncio.sleep(0.1)

    async def process_client_contracts_sync(self, contracts):
        contract_ids = [contract['contract_id'] for contract in contracts]
        if not contract_ids:
            return
        await self.sio.emit('request_client_contracts', {
            'contract_ids': contract_ids,
            'contracts': contracts
        })

    async def share_missing_contracts(self, missing_contracts):
        for contract_id in missing_contracts:
            await self.send_contract_to_server(contract_id)
            await asyncio.sleep(0.1)

    def get_ddns_record(self, domain):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT ddns_hash, content_hash, username, verified, signature, public_key
                              FROM browser_ddns_cache WHERE domain = ?''', (domain,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'ddns_hash': row[0],
                'content_hash': row[1],
                'username': row[2],
                'verified': bool(row[3]),
                'signature': row[4] or '',
                'public_key': row[5] or ''
            }

    async def send_ddns_to_server(self, domain):
        record = self.get_ddns_record(domain)
        if not record:
            return
        ddns_file_path = os.path.join(self.crypto_dir, "ddns", f"{record['ddns_hash']}.ddns")
        if not os.path.exists(ddns_file_path):
            return
        with open(ddns_file_path, 'rb') as f:
            ddns_content = f.read()
        await self.sio.emit('ddns_from_client', {
            'domain': domain,
            'ddns_content': base64.b64encode(ddns_content).decode('utf-8'),
            'content_hash': record['content_hash'],
            'username': record['username'],
            'signature': record['signature'],
            'public_key': record['public_key'],
            'verified': record['verified']
        })

    def get_contract_record(self, contract_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT action_type, content_hash, domain, username, signature, verified, contract_content
                              FROM browser_contracts_cache WHERE contract_id = ?''', (contract_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'action_type': row[0],
                'content_hash': row[1],
                'domain': row[2],
                'username': row[3],
                'signature': row[4] or '',
                'verified': bool(row[5]),
                'contract_content': row[6]
            }

    async def send_contract_to_server(self, contract_id):
        record = self.get_contract_record(contract_id)
        if not record:
            return
        contracts_dir = os.path.join(self.crypto_dir, "contracts")
        contract_path = os.path.join(contracts_dir, f"{contract_id}.contract")
        contract_text = record.get('contract_content')
        if os.path.exists(contract_path):
            with open(contract_path, 'rb') as f:
                contract_text = f.read().decode('utf-8', errors='replace')
        if not contract_text:
            return
        await self.sio.emit('contract_from_client', {
            'contract_id': contract_id,
            'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
            'action_type': record.get('action_type', ''),
            'content_hash': record.get('content_hash'),
            'domain': record.get('domain'),
            'username': record.get('username', ''),
            'signature': record.get('signature', ''),
            'verified': record.get('verified', False)
        })

    async def request_pow_challenge(self, action_type):
        if not self.connected:
            return
        self.last_pow_action_type = action_type
        await self.sio.emit('request_pow_challenge', {
            'client_identifier': self.client_identifier,
            'action_type': action_type
        })

    def clear_pending_pow_action(self, action_type):
        if action_type == "upload":
            self.upload_callback = None
        elif action_type == "dns":
            self.dns_callback = None
        elif action_type == "report":
            self.report_callback = None
        elif action_type == "contract_reset":
            self.contract_reset_callback = None
        elif action_type == "contract_certify":
            if self.contract_certify_callback:
                self.contract_certify_callback = None
            else:
                self.missing_contract_certify_callback = None
        elif action_type == "contract_transfer":
            self.contract_transfer_callback = None
        elif action_type == "usage_contract":
            self.usage_contract_callback = None
        elif action_type == "hps_mint":
            self.hps_mint_callback = None
            self.hps_mint_requested_at = None
            self.pending_hps_mint_voucher_id = None
        elif action_type == "hps_transfer":
            self.hps_transfer_callback = None

    async def request_pending_transfers(self):
        if not self.connected:
            return
        await self.sio.emit('get_pending_transfers', {})

    async def send_authentication(self, pow_nonce, hashrate_observed):
        if not self.connected:
            return
            
        password_hash = hashlib.sha256(self.password_var.get().encode()).hexdigest()
        
        if not self.client_auth_challenge:
            logger.error("Client authentication challenge not set")
            self.root.after(0, lambda: self.update_login_status("Erro: Desafio de autenticação do cliente ausente"))
            return
            
        client_challenge_signature = self.private_key.sign(
            self.client_auth_challenge.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        await self.sio.emit('authenticate', {
            'username': self.username_var.get(),
            'password_hash': password_hash,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'node_type': 'client',
            'client_identifier': self.client_identifier,
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed,
            'client_challenge_signature': base64.b64encode(client_challenge_signature).decode('utf-8'),
            'client_challenge': self.client_auth_challenge
        })

    async def join_network(self):
        if not self.connected or not self.current_user:
            return
            
        await self.sio.emit('join_network', {
            'node_id': self.node_id,
            'address': f"client_{self.client_identifier}",
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'username': self.current_user,
            'node_type': 'client',
            'client_identifier': self.client_identifier
        })

    async def sync_client_files(self):
        if not self.connected or not self.current_user:
            return
            
        files = []
        content_dir = os.path.join(self.crypto_dir, "content")
        if os.path.exists(content_dir):
            for filename in os.listdir(content_dir):
                if filename.endswith('.dat'):
                    file_path = os.path.join(content_dir, filename)
                    content_hash = filename[:-4]
                    file_size = os.path.getsize(file_path)
                    files.append({
                        'content_hash': content_hash,
                        'file_name': filename,
                        'file_size': file_size
                    })
                    
        await self.sio.emit('sync_client_files', {
            'files': files
        })

    async def sync_client_dns_files(self):
        if not self.connected or not self.current_user:
            return
        dns_files = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, ddns_hash FROM browser_ddns_cache')
            for row in cursor.fetchall():
                dns_files.append({'domain': row[0], 'ddns_hash': row[1]})
        await self.sio.emit('sync_client_dns_files', {
            'dns_files': dns_files
        })
        await self.process_client_dns_files_sync(dns_files)

    async def sync_client_contracts(self):
        if not self.connected or not self.current_user:
            return
        contracts = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT contract_id, content_hash, domain FROM browser_contracts_cache')
            for row in cursor.fetchall():
                contracts.append({
                    'contract_id': row[0],
                    'content_hash': row[1],
                    'domain': row[2]
                })
        await self.sio.emit('sync_client_contracts', {
            'contracts': contracts
        })
        await self.process_client_contracts_sync(contracts)

    def show_custody_blocked_popup(self):
        message = 'O nome de usuário "custody" é de uso especial para a administração do servidor.'
        window = tk.Toplevel(self.root)
        window.title("Nome de usuario reservado")
        window.geometry("520x180")
        window.transient(self.root)
        window.grab_set()
        container, main_frame = create_scrollable_container(window, padding="15")
        container.pack(fill=tk.BOTH, expand=True)
        background = window.cget("bg")
        label = tk.Label(
            main_frame,
            text=message,
            font=("Arial", 12, "bold"),
            fg="red",
            bg=background,
            wraplength=480,
            justify=tk.CENTER
        )
        label.pack(pady=20, padx=10, fill=tk.BOTH, expand=True)
        ttk.Button(main_frame, text="Fechar", command=window.destroy).pack(pady=10)

        def blink(state=True):
            if not window.winfo_exists():
                return
            label.config(fg="red" if state else background)
            window.after(500, lambda: blink(not state))

        blink()

    def enter_network(self):
        if self.connected:
            messagebox.showinfo("Info", "Você já está conectado à rede.")
            return
            
        server_address = self.server_var.get()
        if not server_address:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor.")
            return
            
        if not self.username_var.get() or not self.password_var.get():
            messagebox.showwarning("Aviso", "Por favor, preencha nome de usuário e senha.")
            return

        if self.username_var.get().strip().lower() == "custody":
            self.show_custody_blocked_popup()
            return
            
        self.current_server = server_address
        self.root.after(0, lambda: self.update_login_status("Conectando..."))
        
        asyncio.run_coroutine_threadsafe(self._connect_to_server(server_address), self.loop)

    def exit_network(self):
        if not self.connected:
            messagebox.showinfo("Info", "Você já está desconectado da rede.")
            return
            
        self.auto_reconnect = False
        self.server_analysis_in_progress = False
        self.server_analysis_steps = {"wallet": False, "server": False}
        self.close_server_analysis_popup()
        self.wallet_fraud_checked = False
        self.current_fraud_report = None
        self.current_fraud_server = ""
        asyncio.run_coroutine_threadsafe(self.request_economy_report(), self.loop)
        self.current_user = None
        self.logged_in = False
        self.reputation = 100
        self.root.after(0, lambda: self.update_user_status("Não logado", 100))
        self.root.after(0, lambda: self.set_tab_visibility(False))
        self.root.after(0, self.show_login)
        
        asyncio.run_coroutine_threadsafe(self.sio.disconnect(), self.loop)

    def try_reconnect(self):
        if not self.auto_reconnect_var.get() or self.connected:
            return
            
        if self.backup_server and self.backup_server != self.current_server:
            self.server_var.set(self.backup_server)
            self.current_server = self.backup_server
            logger.info(f"Tentando reconectar ao servidor de backup: {self.backup_server}")
        else:
            logger.info(f"Tentando reconectar ao servidor: {self.current_server}")
            
        self.root.after(0, lambda: self.update_login_status("Tentando reconectar..."))
        asyncio.run_coroutine_threadsafe(self._connect_to_server(self.current_server), self.loop)

    async def _connect_to_server(self, server_address):
        try:
            if self.sio and self.connected:
                await self.sio.disconnect()
                
            protocol = "https" if self.use_ssl_var.get() else "http"
            server_url = f"{protocol}://{server_address}"
            
            await self.sio.connect(server_url, wait_timeout=10)
            logger.info(f"Conectando a {server_url}")
            
        except Exception as e:
            logger.error(f"Erro de conexão: {e}")
            self.root.after(0, lambda: self.update_login_status(f"Erro de conexão: {e}"))
            self.connection_attempts += 1
            if self.connection_attempts < self.max_connection_attempts and self.auto_reconnect_var.get():
                self.root.after(5000, self.try_reconnect)
            else:
                self.root.after(0, lambda: self.update_login_status("Falha na conexão após múltiplas tentativas"))

    def update_status(self, status):
        self.status_var.set(status)

    def update_user_status(self, username, reputation):
        self.user_var.set(f"{username}")
        self.reputation_var.set(f"{reputation}")

    def update_login_status(self, message):
        self.login_status.config(text=message)
        if "bem-sucedido" in message or "conectado" in message:
            self.login_status.config(foreground="green")
        elif "Falha" in message or "Erro" in message:
            self.login_status.config(foreground="red")
        else:
            self.login_status.config(foreground="black")

    def update_upload_status(self, message):
        self.upload_status.config(text=message)
        if "bem-sucedido" in message:
            self.upload_status.config(foreground="green")
        elif "Falha" in message:
            self.upload_status.config(foreground="red")
        else:
            self.upload_status.config(foreground="black")

    def update_dns_status(self, message):
        self.dns_status.config(text=message)
        if "registrado" in message or "resolvido" in message:
            self.dns_status.config(foreground="green")
        elif "Falha" in message:
            self.dns_status.config(foreground="red")
        else:
            self.dns_status.config(foreground="black")

    def update_reputation(self, reputation):
        self.reputation = reputation
        self.reputation_var.set(f"{reputation}")

    def handle_ban(self, duration, reason):
        self.banned_until = time.time() + duration
        self.ban_duration = duration
        self.ban_reason = reason
        self.ban_status_message = f"Banido por {int(duration)}s: {reason}"
        self._apply_status_message(self.ban_status_message)
        
        def update_ban_timer():
            if self.banned_until and time.time() < self.banned_until:
                remaining = int(self.banned_until - time.time())
                self.ban_status_message = f"Banido por {remaining}s: {reason}"
                self._apply_status_message(self.ban_status_message)
                self.root.after(1000, update_ban_timer)
            else:
                self.banned_until = None
                self.ban_status_message = ""
                if self.contract_alert_active:
                    self._apply_status_message(self.contract_alert_message)
                else:
                    self.ban_status_var.set("")
                
        update_ban_timer()

    def show_contract_alert(self, message):
        self.contract_alert_active = True
        self.contract_alert_message = message
        self.contract_alert_blink = False
        self._blink_contract_alert()

    def clear_contract_alert(self):
        self.contract_alert_active = False
        if not self.banned_until:
            self.ban_status_var.set("")
            self.ban_status_label.config(foreground="red")
        elif self.ban_status_message:
            self._apply_status_message(self.ban_status_message)

    def _blink_contract_alert(self):
        if not self.contract_alert_active:
            return
        self.contract_alert_blink = not self.contract_alert_blink
        self.ban_status_label.config(foreground="red")
        self._apply_status_message(self.contract_alert_message)
        self.root.after(1000, self._blink_contract_alert)

    def _apply_status_message(self, message):
        if self.contract_alert_active:
            if self.contract_alert_blink:
                if self.banned_until and time.time() < self.banned_until and self.ban_status_message:
                    combined = f"{self.ban_status_message} | {self.contract_alert_message}"
                    self.ban_status_var.set(combined)
                else:
                    self.ban_status_var.set(self.contract_alert_message)
            else:
                if self.banned_until and time.time() < self.banned_until and self.ban_status_message:
                    self.ban_status_var.set(self.ban_status_message)
                else:
                    self.ban_status_var.set("")
            return
        self.ban_status_var.set(message)

    def update_certify_missing_contract_ui(self):
        invalidated_targets = [
            key for key, reason in self.active_contract_violations.items()
            if reason == "missing_contract"
        ]
        if not invalidated_targets:
            if self.invalidated_contract_frame.winfo_ismapped():
                self.invalidated_contract_frame.pack_forget()
            return
        if not self.invalidated_contract_frame.winfo_ismapped():
            self.invalidated_contract_frame.pack(fill=tk.X, pady=5)
        if len(invalidated_targets) == 1:
            target_type, target_id = invalidated_targets[0]
            self.invalidated_contract_type_var.set(target_type)
            self.invalidated_contract_hash_var.set(target_id)

    def start_missing_contract_certify(self):
        target_id = self.invalidated_contract_hash_var.get().strip()
        if not target_id:
            messagebox.showwarning("Aviso", "Informe o hash do arquivo para certificar.")
            return
        target_type = self.invalidated_contract_type_var.get()
        if target_type == "content" and len(target_id) < 32:
            messagebox.showwarning("Aviso", "Hash inválido.")
            return
        if target_type == "domain":
            target_id = target_id.lower()
        self.open_contract_certification_dialog(
            target_type=target_type,
            target_id=target_id,
            reason="missing_contract",
            title_suffix="(Certificacao de Contrato Ausente)"
        )

    def handle_missing_contract_canonical(self, contract_text):
        target = self.pending_missing_contract_target
        if not target:
            return
        target_type, target_id = target
        self.pending_missing_contract_target = None
        self.open_contract_certification_dialog(
            target_type=target_type,
            target_id=target_id,
            reason="missing_contract",
            title_suffix="(Certificacao de Contrato Ausente)"
        )

    def handle_upload_block(self, duration):
        self.upload_blocked_until = time.time() + duration
        messagebox.showwarning("Upload Bloqueado", f"Upload bloqueado por {int(duration)} segundos devido a limite de taxa.")

    def handle_dns_block(self, duration):
        self.dns_blocked_until = time.time() + duration
        messagebox.showwarning("DNS Bloqueado", f"Operações DNS bloqueadas por {int(duration)} segundos devido a limite de taxa.")

    def handle_report_block(self, duration):
        self.report_blocked_until = time.time() + duration
        messagebox.showwarning("Reporte Bloqueado", f"Reportes bloqueados por {int(duration)} segundos devido a limite de taxa.")

    def browser_navigate(self):
        url = self.browser_url_var.get().strip()
        if url.startswith("hps://"):
            if url == "hps://rede":
                self.show_network_content()
            elif url.startswith("hps://dns:"):
                domain = url[len("hps://dns:"):]
                self.resolve_dns_url(domain)
            elif url.startswith("hps://"):
                content_hash = url[len("hps://"):]
                if len(content_hash) == 64:
                    self.request_content_by_hash(content_hash)
                else:
                    self.resolve_dns_url(content_hash)
        else:
            messagebox.showwarning("Aviso", "URL deve começar com hps://")

    def browser_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            url = self.history[self.history_index]
            self.browser_url_var.set(url)
            self.browser_navigate()

    def browser_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            url = self.history[self.history_index]
            self.browser_url_var.set(url)
            self.browser_navigate()

    def browser_reload(self):
        current_url = self.browser_url_var.get()
        if current_url:
            self.browser_navigate()

    def browser_home(self):
        self.browser_url_var.set("hps://rede")
        self.browser_navigate()

    def add_to_history(self, url):
        if self.history and self.history[-1] == url:
            return
        self.history.append(url)
        self.history_index = len(self.history) - 1

    def show_search_dialog(self):
        if self.search_dialog and self.search_dialog.window.winfo_exists():
            self.search_dialog.window.lift()
            return
            
        self.search_dialog = SearchDialog(self.root, self)

    async def _search_content(self, query, content_type="all", sort_by="reputation"):
        if not self.connected:
            return
            
        await self.sio.emit('search_content', {
            'query': query,
            'limit': 50,
            'content_type': content_type if content_type != "all" else "",
            'sort_by': sort_by
        })

    def display_search_results(self, results):
        if not self.search_dialog or not self.search_dialog.window.winfo_exists():
            return
            
        search_dialog_instance = self.search_dialog
        search_dialog_instance.results_text.config(state=tk.NORMAL)
        search_dialog_instance.results_text.delete(1.0, tk.END)
        
        if not results:
            search_dialog_instance.results_text.insert(tk.END, "Nenhum resultado encontrado.")
            search_dialog_instance.results_text.config(state=tk.DISABLED)
            return
            
        for result in results:
            verified = result.get('verified', False)
            status_tag = "verified" if verified else "unverified"
            status_text = "✓" if verified else "⚠"
            
            search_dialog_instance.results_text.insert(tk.END, f"{status_text} ", status_tag)
            search_dialog_instance.results_text.insert(tk.END, f"{result['title']}", "title")
            search_dialog_instance.results_text.insert(tk.END, f"   Hash: {result['content_hash']}")
            search_dialog_instance.results_text.insert(tk.END, f"   Autor: {result['username']} (Reputação: {result.get('reputation', 100)})")
            search_dialog_instance.results_text.insert(tk.END, f"   Tipo: {result['mime_type']}")
            search_dialog_instance.results_text.insert(tk.END, f"   Acessar: hps://{result['content_hash']}", "link")
            search_dialog_instance.results_text.insert(tk.END, "")
            
        search_dialog_instance.results_text.config(state=tk.DISABLED)

    def display_content(self, content_info):
        content = content_info['content']
        title = content_info['title']
        description = content_info['description']
        mime_type = content_info['mime_type']
        username = content_info['username']
        verified = content_info['verified']
        integrity_ok = content_info.get('integrity_ok', True)
        
        self.current_content_info = content_info
        
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        
        if content_info.get('local_only'):
            self.browser_content.insert(
                tk.END,
                "⚠ ALERTA: Conteúdo local exibido porque o servidor bloqueou o acesso por quebra de contrato.\n",
                "unverified"
            )
        if content_info.get('contract_violation'):
            self.browser_content.insert(tk.END, "⚠ ALERTA: Este arquivo esta sem contrato valido e pode estar violado.", "unverified")
        if not integrity_ok:
            self.browser_content.insert(tk.END, "⚠ ATENÇÃO: Este conteúdo foi adulterado no servidor. A integridade não pode ser garantida.", "unverified")
        elif not verified:
            self.browser_content.insert(tk.END, "⚠ ATENÇÃO: Este conteúdo não foi verificado. A autenticidade não pode ser garantida.", "unverified")

        if mime_type == 'application/hps-voucher':
            try:
                text = content.decode('utf-8')
                try:
                    voucher = json.loads(text)
                except Exception:
                    voucher = self.parse_hps_voucher_hsyst(text)
                if voucher:
                    self.show_voucher_popup(voucher)
                else:
                    raise ValueError("Voucher inválido")
                self.browser_content.insert(tk.END, "Voucher $HPS recebido. Consulte o popup para detalhes.")
                self.browser_content.config(state=tk.DISABLED)
                return
            except Exception:
                pass
            
        header_end_marker = b'### :END START'
        if content.startswith(b'# HSYST P2P SERVICE') and header_end_marker in content:
            header_part, content = content.split(header_end_marker, 1)
            
        if mime_type.startswith('text/'):
            try:
                text_content = content.decode('utf-8')
                self.browser_content.insert(tk.END, text_content)
            except UnicodeDecodeError:
                self.browser_content.insert(tk.END, "[Conteúdo binário não pode ser exibido como texto]")
        elif mime_type.startswith('image/'):
            try:
                image = Image.open(io.BytesIO(content))
                image.thumbnail((400, 400), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)
                
                image_label = ttk.Label(self.browser_content, image=photo)
                image_label.image = photo
                self.browser_content.window_create(tk.END, window=image_label)
                self.browser_content.insert(tk.END, "")
            except Exception as e:
                self.browser_content.insert(tk.END, f"[Erro ao exibir imagem: {e}]")
        elif mime_type in ['application/pdf', 'application/octet-stream']:
            self.browser_content.insert(tk.END, f"[Arquivo binário - {len(content)} bytes]")
            
        self.browser_content.config(state=tk.DISABLED)

    def report_contract_violation(self, violation_type, content_hash=None, domain=None, reason="missing_contract"):
        key = (violation_type, content_hash or domain)
        if key in self.reported_contract_issues:
            return
        self.reported_contract_issues.add(key)
        if not self.connected:
            return
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('contract_violation', {
                'violation_type': violation_type,
                'content_hash': content_hash,
                'domain': domain,
                'reason': reason
            }),
            self.loop
        )

    def handle_content_contracts(self, content_info):
        contracts = content_info.get('contracts', []) or []
        title = content_info.get('title', '')
        content_hash = content_info.get('content_hash', '')
        contract_violation = content_info.get('contract_violation', False)

        if contract_violation:
            self.report_contract_violation(
                "content",
                content_hash=content_hash,
                reason=content_info.get('contract_violation_reason', 'missing_contract')
            )
            reason = content_info.get('contract_violation_reason', 'missing_contract')
            if reason == 'invalid_contract' or reason == 'invalid_signature':
                messagebox.showwarning("Contrato Adulterado", "O contrato deste arquivo foi adulterado ou e invalido. O servidor foi notificado.")
            else:
                messagebox.showwarning("Contrato Ausente", "Este arquivo nao possui contrato valido. O servidor foi notificado.")

        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            transfer_contract = None
            for contract in contracts:
                if contract.get('action_type') == 'transfer_domain':
                    transfer_contract = contract
                    break
            if not transfer_contract:
                self.report_contract_violation("content", content_hash=content_hash, reason="missing_transfer_contract")
                messagebox.showwarning("Transferencia de Dominio", "Contrato de transferencia nao encontrado. O servidor foi notificado.")
                self.display_content(content_info)
                return
            proceed = self.show_contract_analyzer(
                transfer_contract,
                title="Transferencia de Dominio - Contrato",
                allow_proceed=True
            )
            if proceed:
                self.display_content(content_info)
            return

        app_name = self.extract_app_name(title)
        if app_name or title.startswith('(HPS!api)'):
            self.request_api_app_versions(app_name, title, content_info.get('content_hash'), content_info=content_info)
            return

        self.display_content(content_info)

    def handle_api_app_update_flow(self, app_name, old_hash, new_hash):
        self.request_api_app_versions(
            app_name,
            "",
            old_hash,
            content_info=None,
            fallback_hash=new_hash,
            allow_legacy=True
        )

    def request_api_app_versions(self, app_name, title, current_hash, content_info=None, fallback_hash=None, allow_legacy=False):
        if not self.connected:
            return
        request_id = str(uuid.uuid4())
        self.pending_api_app_requests[request_id] = {
            'app_name': app_name,
            'title': title,
            'current_hash': current_hash,
            'content_info': content_info,
            'fallback_hash': fallback_hash,
            'allow_legacy': allow_legacy
        }
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('get_api_app_versions', {
                'request_id': request_id,
                'title': title,
                'app_name': app_name
            }),
            self.loop
        )

    def handle_api_app_versions_response(self, data):
        request_id = data.get('request_id')
        request = self.pending_api_app_requests.pop(request_id, None)
        if not request:
            return
        if data.get('success') is False or data.get('error'):
            messagebox.showwarning("API App", f"Falha ao buscar versoes: {data.get('error', 'erro desconhecido')}")
            if request.get('content_info'):
                self.display_content(request['content_info'])
            elif request.get('fallback_hash'):
                self.browser_url_var.set(f"hps://{request['fallback_hash']}")
                self.request_content_by_hash(request['fallback_hash'])
            return
        versions = data.get('versions', []) or []
        latest_hash = data.get('latest_hash')
        app_name = request.get('app_name') or request.get('title') or data.get('app_name') or "API App"
        current_hash = request.get('current_hash')
        content_info = request.get('content_info')
        fallback_hash = request.get('fallback_hash')
        allow_legacy = request.get('allow_legacy', False)

        if not versions:
            messagebox.showwarning("API App", "Nao foi possivel localizar contratos de versao para este app.")
            if fallback_hash:
                self.browser_url_var.set(f"hps://{fallback_hash}")
                self.request_content_by_hash(fallback_hash)
            elif content_info:
                self.display_content(content_info)
            return

        if latest_hash and current_hash == latest_hash and content_info:
            notice = ApiAppNoticeDialog(self.root, app_name, is_latest=True)
            self.root.wait_window(notice.window)
            if notice.analyze_versions:
                self.open_api_app_versions_dialog(app_name, versions, current_hash, content_info, latest_hash, allow_legacy)
                return
            if notice.proceed:
                self.display_content(content_info)
                return
            self.display_content(content_info)
            return

        self.open_api_app_versions_dialog(app_name, versions, current_hash, content_info, latest_hash, allow_legacy, fallback_hash)

    def open_api_app_versions_dialog(self, app_name, versions, current_hash, content_info, latest_hash, allow_legacy, fallback_hash=None):
        dialog = ApiAppVersionsDialog(self.root, app_name, versions, current_hash)
        self.root.wait_window(dialog.window)
        if dialog.selected_hash:
            selected_hash = dialog.selected_hash
            self.browser_url_var.set(f"hps://{selected_hash}")
            if latest_hash and selected_hash != latest_hash:
                self.add_to_history(f"hps://{selected_hash}")
                asyncio.run_coroutine_threadsafe(
                    self._request_content_by_hash(selected_hash, allow_legacy=True),
                    self.loop
                )
            else:
                self.request_content_by_hash(selected_hash)
            return
        if dialog.proceed_current and current_hash:
            self.browser_url_var.set(f"hps://{current_hash}")
            if allow_legacy:
                self.add_to_history(f"hps://{current_hash}")
                asyncio.run_coroutine_threadsafe(
                    self._request_content_by_hash(current_hash, allow_legacy=True),
                    self.loop
                )
            else:
                self.request_content_by_hash(current_hash)
            return
        if content_info:
            self.display_content(content_info)
            return
        if fallback_hash:
            self.browser_url_var.set(f"hps://{fallback_hash}")
            self.request_content_by_hash(fallback_hash)

    def display_content_error(self, error):
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        self.browser_content.insert(tk.END, f"Erro: {error}")
        self.browser_content.config(state=tk.DISABLED)

    def show_contract_blocked_dialog(self, message):
        dialog = ContractBlockedDialog(self.root, message)
        self.root.wait_window(dialog.window)
        return dialog.proceed

    def get_cached_dns_hash(self, domain):
        if not domain:
            return None
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT content_hash FROM browser_dns_records WHERE domain = ?', (domain,))
            row = cursor.fetchone()
            return row[0] if row else None

    def handle_contract_blocked_content_access(self, data):
        content_hash = data.get('content_hash', '')
        reason = data.get('contract_violation_reason', 'contract_violation')
        message = "Contrato adulterado ou ausente. O conteudo foi bloqueado no servidor."
        if reason == "missing_contract":
            message = "Contrato ausente. O conteudo foi bloqueado no servidor."
        proceed = self.show_contract_blocked_dialog(message)
        if not proceed:
            return
        cached = self.load_cached_content(content_hash) if content_hash else None
        if not cached:
            self.display_content_error("Not Found")
            return
        cached['contract_violation'] = True
        cached['contract_violation_reason'] = reason
        cached['contract_blocked'] = True
        cached['local_only'] = True
        cached['contracts'] = data.get('contracts', [])
        cached['certifier'] = data.get('certifier', '')
        cached['original_owner'] = data.get('original_owner', cached.get('username', ''))
        self.display_content(cached)

    def handle_contract_blocked_dns_access(self, data):
        domain = data.get('domain', '')
        reason = data.get('contract_violation_reason', 'contract_violation')
        message = "Contrato adulterado ou ausente. O dominio foi bloqueado no servidor."
        if reason == "missing_contract":
            message = "Contrato ausente. O dominio foi bloqueado no servidor."
        proceed = self.show_contract_blocked_dialog(message)
        self.current_dns_info = {
            'domain': domain,
            'content_hash': data.get('content_hash', ''),
            'contract_blocked': True,
            'contract_violation_reason': reason
        }
        if not proceed:
            return
        content_hash = data.get('content_hash') or self.get_cached_dns_hash(domain)
        cached = self.load_cached_content(content_hash) if content_hash else None
        if not cached:
            self.display_content_error("Not Found")
            return
        cached['contract_violation'] = True
        cached['contract_violation_reason'] = reason
        cached['contract_blocked'] = True
        cached['local_only'] = True
        cached['contracts'] = data.get('contracts', [])
        cached['certifier'] = data.get('certifier', '')
        cached['original_owner'] = data.get('original_owner', cached.get('username', ''))
        self.display_content(cached)

    def handle_content_click(self, event):
        index = self.browser_content.index(f"@{event.x},{event.y}")
        for tag in self.browser_content.tag_names(index):
            if tag == "link":
                line_start = self.browser_content.index(f"{index} linestart")
                line_end = self.browser_content.index(f"{index} lineend")
                line_text = self.browser_content.get(line_start, line_end)
                import re
                match = re.search(r'hps://(\S+)', line_text)
                if match:
                    url = f"hps://{match.group(1)}"
                    self.browser_url_var.set(url)
                    self.browser_navigate()
                break

    def show_security_dialog(self):
        if self.active_section == "dns" and self.current_dns_info:
            DomainSecurityDialog(self.root, self.current_dns_info, self)
        elif self.current_content_info:
            ContentSecurityDialog(self.root, self.current_content_info, self)
        else:
            messagebox.showinfo("Segurança", "Nenhum conteúdo carregado para verificar.")

    def show_network_content(self):
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        self.browser_content.insert(tk.END, "Rede P2P Hsyst", "title")
        self.browser_content.insert(tk.END, "Bem-vindo à rede descentralizada Hsyst!")
        self.browser_content.insert(tk.END, "Recursos disponíveis:")
        self.browser_content.insert(tk.END, "• Navegar por conteúdo publicado")
        self.browser_content.insert(tk.END, "• Pesquisar por palavras-chave")
        self.browser_content.insert(tk.END, "• Acessar via DNS personalizado")
        self.browser_content.insert(tk.END, "• Upload de novos conteúdos")
        self.browser_content.insert(tk.END, "Use a barra de endereços para navegar:")
        self.browser_content.insert(tk.END, "• hps://rede - Esta página")
        self.browser_content.insert(tk.END, "• hps://<hash> - Conteúdo específico")
        self.browser_content.insert(tk.END, "• hps://dns:<domínio> - Via DNS")
        self.browser_content.config(state=tk.DISABLED)

    def request_content_by_hash(self, content_hash):
        self.add_to_history(f"hps://{content_hash}")
        asyncio.run_coroutine_threadsafe(self._request_content_by_hash(content_hash), self.loop)

    async def _request_content_by_hash(self, content_hash, allow_legacy=False):
        if not self.connected:
            return
            
        await self.sio.emit('request_content', {'content_hash': content_hash, 'allow_legacy': allow_legacy})

    def resolve_dns_url(self, domain):
        self.add_to_history(f"hps://dns:{domain}")
        asyncio.run_coroutine_threadsafe(self._resolve_dns(domain), self.loop)

    def save_content_to_storage(self, content_hash, content, metadata=None):
        content_dir = os.path.join(self.crypto_dir, "content")
        os.makedirs(content_dir, exist_ok=True)
        
        file_path = os.path.join(content_dir, f"{content_hash}.dat")
        with open(file_path, 'wb') as f:
            f.write(content)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_content_cache 
                    (content_hash, file_path, file_name, mime_type, size, last_accessed, title, description, username, signature, public_key, verified) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    content_hash, file_path, f"{content_hash}.dat", 
                    metadata.get('mime_type', 'application/octet-stream'), 
                    len(content), time.time(),
                    metadata.get('title', ''),
                    metadata.get('description', ''),
                    metadata.get('username', ''),
                    metadata.get('signature', ''),
                    metadata.get('public_key', ''),
                    metadata.get('verified', 0)
                ))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_content_cache 
                    (content_hash, file_path, file_name, mime_type, size, last_accessed) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (content_hash, file_path, f"{content_hash}.dat", 'application/octet-stream', len(content), time.time()))
            conn.commit()
            
        logger.info(f"Conteúdo salvo em: {file_path}")

    def load_cached_content(self, content_hash):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT file_path, title, description, mime_type, username, signature, public_key, verified
                              FROM browser_content_cache WHERE content_hash = ?''', (content_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            file_path, title, description, mime_type, username, signature, public_key, verified = row
        if not file_path or not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            actual_hash = hashlib.sha256(content).hexdigest()
            integrity_ok = actual_hash == content_hash
            return {
                'title': title or 'Sem título',
                'description': description or '',
                'mime_type': mime_type or 'application/octet-stream',
                'username': username or 'Desconhecido',
                'signature': signature or '',
                'public_key': public_key or '',
                'verified': bool(verified),
                'content': content,
                'content_hash': content_hash,
                'reputation': 0,
                'integrity_ok': integrity_ok
            }
        except Exception:
            return None

    def save_ddns_to_storage(self, domain, ddns_content, metadata=None):
        ddns_dir = os.path.join(self.crypto_dir, "ddns")
        os.makedirs(ddns_dir, exist_ok=True)
        
        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
        file_path = os.path.join(ddns_dir, f"{ddns_hash}.ddns")
        with open(file_path, 'wb') as f:
            f.write(ddns_content)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_ddns_cache 
                    (domain, ddns_hash, content_hash, username, verified, timestamp, signature, public_key) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    domain, ddns_hash,
                    metadata.get('content_hash', ''),
                    metadata.get('username', ''),
                    metadata.get('verified', 0),
                    time.time(),
                    metadata.get('signature', ''),
                    metadata.get('public_key', '')
                ))
            conn.commit()
            
        logger.info(f"DDNS salvo em: {file_path}")
        return ddns_hash

    def save_contract_to_storage(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        contract_content = contract_info.get('contract_content')
        contract_text = None
        if isinstance(contract_content, bytes):
            contract_text = contract_content.decode('utf-8', errors='replace')
        elif isinstance(contract_content, str):
            contract_text = contract_content

        if contract_text:
            contracts_dir = os.path.join(self.crypto_dir, "contracts")
            os.makedirs(contracts_dir, exist_ok=True)
            contract_path = os.path.join(contracts_dir, f"{contract_id}.contract")
            with open(contract_path, 'wb') as f:
                f.write(contract_text.encode('utf-8'))

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            verified_value = contract_info.get('integrity_ok')
            if verified_value is None:
                verified_value = contract_info.get('verified')
            cursor.execute('''
                INSERT OR REPLACE INTO browser_contracts_cache
                (contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                contract_id,
                contract_info.get('action_type', ''),
                contract_info.get('content_hash'),
                contract_info.get('domain'),
                contract_info.get('username', ''),
                contract_info.get('signature', ''),
                contract_info.get('timestamp', time.time()),
                1 if verified_value else 0,
                contract_text
            ))
            conn.commit()

    def store_contracts(self, contracts):
        for contract_info in contracts or []:
            self.save_contract_to_storage(contract_info)

    def create_ddns_file(self, domain, content_hash):
        ddns_content = f"""# HSYST P2P SERVICE
### START:
# USER: {self.current_user}
# KEY: {base64.b64encode(self.public_key_pem).decode('utf-8')}
### :END START
### DNS:
# DNAME: {domain} = {content_hash}
### :END DNS
"""
        return ddns_content.encode('utf-8')

    def build_contract_template(self, action_type, details):
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            f"# ACTION: {action_type}"
        ]
        for key, value in details:
            lines.append(f"# {key}: {value}")
        lines.extend([
            "### :END DETAILS",
            "### START:",
            f"# USER: {self.current_user}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def build_hps_transfer_title(self, transfer_type, target_user, app_name=None):
        if transfer_type == "api_app" and app_name:
            return f"(HPS!transfer){{type={transfer_type}, to={target_user}, app={app_name}}}"
        return f"(HPS!transfer){{type={transfer_type}, to={target_user}}}"

    def build_hps_api_title(self, app_name):
        return f'(HPS!api){{app}}:{{"{app_name}"}}'

    def build_hps_dns_change_title(self):
        return "(HPS!dns_change){change_dns_owner=true, proceed=true}"

    def build_domain_transfer_payload(self, domain, new_owner):
        username = self.current_user or self.username_var.get().strip()
        lines = [
            "# HSYST P2P SERVICE",
            "### START:",
            f"# USER: {username}",
            "### :END START",
            "### DNS:",
            f"# NEW_DNAME: DOMAIN = {domain}",
            f"# NEW_DOWNER: OWNER = {new_owner}",
            "### :END DNS",
            "### MODIFY:",
            "# change_dns_owner = true",
            "# proceed = true",
            "### :END MODIFY"
        ]
        return "\n".join(lines).encode("utf-8")

    def apply_hps_action_template(self):
        action = self.hps_action_var.get()
        target_user = self.hps_target_user_var.get().strip()
        app_name = self.hps_app_name_var.get().strip()
        domain = self.hps_domain_var.get().strip()
        new_owner = self.hps_new_owner_var.get().strip()
        content_hash = self.hps_content_hash_var.get().strip()

        if action == "Transferir arquivo":
            if not target_user:
                messagebox.showwarning("Aviso", "Informe o usuario destino.")
                return
            if not content_hash or len(content_hash) < 32:
                messagebox.showwarning("Aviso", "Informe o hash do conteudo para transferir.")
                return
            cached = self.load_cached_content(content_hash)
            if not cached:
                messagebox.showwarning("Aviso", "Conteudo nao encontrado no cache local. Baixe o arquivo antes de transferir.")
                return
            temp_path = os.path.join(tempfile.gettempdir(), f"hps_transfer_{content_hash}.dat")
            with open(temp_path, "wb") as f:
                f.write(cached['content'])
            self.upload_title_var.set(self.build_hps_transfer_title("file", target_user))
            self.upload_file_var.set(temp_path)
            self.upload_mime_var.set(cached.get('mime_type', 'application/octet-stream'))
            self.upload_description_var.set(cached.get('description', ''))
            self.show_upload()
            return
        if action == "Transferir API App":
            if not target_user or not app_name:
                messagebox.showwarning("Aviso", "Informe o usuario destino e o nome do app.")
                return
            self.upload_title_var.set(self.build_hps_transfer_title("api_app", target_user, app_name))
            self.show_upload()
            return
        if action == "Criar/Atualizar API App":
            if not app_name:
                messagebox.showwarning("Aviso", "Informe o nome do app.")
                return
            self.upload_title_var.set(self.build_hps_api_title(app_name))
            self.show_upload()
            return
        if action == "Transferir dominio":
            if not domain or not new_owner:
                messagebox.showwarning("Aviso", "Informe o dominio e o novo dono.")
                return
            self.upload_title_var.set(self.build_hps_dns_change_title())
            payload = self.build_domain_transfer_payload(domain, new_owner)
            temp_path = os.path.join(tempfile.gettempdir(), f"hps_domain_transfer_{domain}.txt")
            with open(temp_path, "wb") as f:
                f.write(payload)
            self.upload_file_var.set(temp_path)
            self.upload_mime_var.set("text/plain")
            self.show_upload()
            return
        if action == "Transferir HPS":
            self.start_hps_transfer()
            return

    def start_hps_transfer(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede para transferir HPS.")
            return
        target_user = self.hps_target_user_var.get().strip()
        if not target_user:
            messagebox.showwarning("Aviso", "Informe o usuario destino.")
            return
        try:
            amount = int(float(self.hps_transfer_amount_var.get().strip() or "0"))
        except ValueError:
            amount = 0
        if amount <= 0:
            messagebox.showwarning("Aviso", "Informe um valor HPS valido.")
            return
        issuer = self.current_server or ""
        voucher_ids, total = self.select_hps_vouchers_for_cost(amount, issuer)
        if total < amount:
            messagebox.showwarning("Saldo insuficiente", f"Saldo HPS insuficiente. Necessário: {amount} HPS.")
            return
        self.reserve_local_vouchers(voucher_ids)

        details = [
            ("TRANSFER_TO", target_user),
            ("AMOUNT", str(amount)),
            ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
        ]
        contract_template = self.build_contract_template("transfer_hps", details)
        signed_text, _ = self.apply_contract_signature(contract_template)
        contract_text = signed_text
        valid, error = self.validate_contract_text_allowed(contract_text, ["transfer_hps"])
        if not valid:
            messagebox.showerror("Erro", error)
            return

        def start_pow():
            def do_transfer(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self._send_hps_transfer(target_user, amount, voucher_ids, contract_text, pow_nonce, hashrate_observed),
                    self.loop
                )
            self.hps_transfer_callback = do_transfer
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("hps_transfer"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self._send_hps_transfer(target_user, amount, voucher_ids, contract_text, "", 0.0, hps_payment=hps_payment),
                self.loop
            )

        self.run_pow_or_hps("hps_transfer", start_pow, start_hps, exclude_ids=voucher_ids)

    async def _send_hps_transfer(self, target_user, amount, voucher_ids, contract_text, pow_nonce, hashrate_observed, hps_payment=None):
        if not self.connected:
            return
        data = {
            'target_user': target_user,
            'amount': int(amount),
            'voucher_ids': voucher_ids,
            'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed
        }
        if hps_payment:
            data['hps_payment'] = hps_payment
        await self.sio.emit('transfer_hps', data)

    def build_usage_contract_template(self, terms_text, contract_hash):
        username = self.current_user or self.username_var.get().strip()
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: accept_usage",
            f"# USAGE_CONTRACT_HASH: {contract_hash}",
            "### :END DETAILS",
            "### TERMS:"
        ]
        for line in terms_text.splitlines():
            lines.append(f"# {line}")
        lines.extend([
            "### :END TERMS",
            "### START:",
            f"# USER: {username}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def start_usage_contract_flow(self, data):
        terms_text = data.get('contract_text', '') or ""
        contract_hash = data.get('contract_hash', '')
        if not contract_hash:
            messagebox.showerror("Contrato de Uso", "Contrato de uso nao disponivel no servidor.")
            return
        contract_template = self.build_usage_contract_template(terms_text, contract_hash)
        contract_dialog = ContractDialog(
            self.root,
            contract_template,
            title_suffix="(Contrato de Uso)",
            signer=lambda text: self.apply_contract_signature(text)[0]
        )
        self.root.wait_window(contract_dialog.window)
        if not contract_dialog.confirmed:
            self.update_login_status("Contrato de uso nao aceito. Login cancelado.")
            return
        contract_text = contract_dialog.current_text.strip()
        valid, error = self.validate_contract_text_allowed(contract_text, ["accept_usage"])
        if not valid:
            messagebox.showerror("Erro", error)
            return

        def start_pow():
            def do_accept(pow_nonce, hashrate_observed):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('accept_usage_contract', {
                    'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'client_identifier': self.client_identifier,
                    'username': self.username_var.get().strip(),
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed
                }),
                    self.loop
                )
            self.usage_contract_callback = do_accept
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("usage_contract"), self.loop)

        def start_hps(hps_payment):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('accept_usage_contract', {
                    'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'client_identifier': self.client_identifier,
                    'username': self.username_var.get().strip(),
                    'pow_nonce': "",
                    'hashrate_observed': 0.0,
                    'hps_payment': hps_payment
                }),
                self.loop
            )

        self.run_pow_or_hps("usage_contract", start_pow, start_hps)

    def build_certify_contract_template(self, target_type, target_id, reason=None,
                                        contract_id=None, original_owner=None, original_action=None):
        details = [
            ("TARGET_TYPE", target_type),
            ("TARGET_ID", target_id)
        ]
        if reason:
            details.append(("REASON", reason))
        if contract_id:
            details.append(("SOURCE_CONTRACT", contract_id))
        if original_owner:
            details.append(("ORIGINAL_OWNER", original_owner))
        if original_action:
            details.append(("ORIGINAL_ACTION", original_action))
        return self.build_contract_template("certify_contract", details)

    def open_contract_certification_dialog(self, target_type, target_id, reason=None,
                                           title_suffix="", contract_id=None,
                                           original_owner=None, original_action=None):
        contract_template = self.build_certify_contract_template(
            target_type=target_type,
            target_id=target_id,
            reason=reason,
            contract_id=contract_id,
            original_owner=original_owner,
            original_action=original_action
        )
        contract_dialog = ContractDialog(
            self.root,
            contract_template,
            title_suffix=title_suffix,
            signer=lambda text: self.apply_contract_signature(text)[0]
        )
        self.root.wait_window(contract_dialog.window)
        if not contract_dialog.confirmed:
            return
        contract_text = contract_dialog.current_text.strip()
        valid, error = self.validate_contract_text_allowed(contract_text, ["certify_contract"])
        if not valid:
            messagebox.showerror("Erro", error)
            return

        def emit_certify(pow_nonce, hashrate_observed, hps_payment=None):
            payload = {
                'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            if hps_payment:
                payload['hps_payment'] = hps_payment
            if contract_id:
                payload['contract_id'] = contract_id
                event = 'certify_contract'
            else:
                payload['target_type'] = target_type
                payload['target_id'] = target_id
                event = 'certify_missing_contract'
            asyncio.run_coroutine_threadsafe(self.sio.emit(event, payload), self.loop)

        def start_pow():
            def do_certify(pow_nonce, hashrate_observed):
                emit_certify(pow_nonce, hashrate_observed)
            if contract_id:
                self.contract_certify_callback = do_certify
            else:
                self.missing_contract_certify_callback = do_certify
            asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_certify"), self.loop)

        def start_hps(hps_payment):
            emit_certify("", 0.0, hps_payment=hps_payment)

        self.run_pow_or_hps("contract_certify", start_pow, start_hps)

    def parse_contract_info(self, contract_text):
        info = {'action': None, 'user': None, 'signature': None}
        current_section = None
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    current_section = line[4:-1].lower()
            elif line.startswith("### :END "):
                current_section = None
            elif line.startswith("# "):
                if current_section == "details" and line.startswith("# ACTION:"):
                    info['action'] = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# USER:"):
                    info['user'] = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# SIGNATURE:"):
                    info['signature'] = line.split(":", 1)[1].strip()
        return info

    def validate_contract_text(self, contract_text, expected_action):
        if not contract_text.startswith("# HSYST P2P SERVICE"):
            return False, "Cabeçalho HSYST não encontrado"
        if "## :END CONTRACT" not in contract_text:
            return False, "Final do contrato não encontrado"
        info = self.parse_contract_info(contract_text)
        if not info['action']:
            return False, "Ação não informada no contrato"
        if info['action'] != expected_action:
            return False, f"Ação inválida no contrato (esperado {expected_action})"
        if not info['user']:
            return False, "Usuário não informado no contrato"
        expected_user = self.current_user or self.username_var.get().strip()
        if info['user'] != expected_user:
            return False, "Usuário do contrato não corresponde ao usuário logado"
        return True, ""

    def validate_contract_text_allowed(self, contract_text, allowed_actions):
        if not contract_text.startswith("# HSYST P2P SERVICE"):
            return False, "Cabeçalho HSYST não encontrado"
        if "## :END CONTRACT" not in contract_text:
            return False, "Final do contrato não encontrado"
        info = self.parse_contract_info(contract_text)
        if not info['action']:
            return False, "Ação não informada no contrato"
        if info['action'] not in allowed_actions:
            return False, f"Ação inválida no contrato (permitido: {', '.join(allowed_actions)})"
        if not info['user']:
            return False, "Usuário não informado no contrato"
        expected_user = self.current_user or self.username_var.get().strip()
        if info['user'] != expected_user:
            return False, "Usuário do contrato não corresponde ao usuário logado"
        return True, ""

    def apply_contract_signature(self, contract_text):
        lines = contract_text.splitlines()
        signature_index = None
        signed_lines = []
        for idx, line in enumerate(lines):
            if line.strip().startswith("# SIGNATURE:"):
                signature_index = idx
                continue
            signed_lines.append(line)
        if signature_index is None:
            raise ValueError("Linha de assinatura não encontrada no contrato")
        signed_text = "\n".join(signed_lines)
        signature = self.private_key.sign(
            signed_text.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        lines[signature_index] = f"# SIGNATURE: {signature_b64}"
        return "\n".join(lines).strip() + "\n", signature_b64

    def extract_app_name(self, title):
        match = re.search(r'\(HPS!api\)\{app\}:\{"([^"]+)"\}', title)
        if match:
            return match.group(1).strip()
        return None

    def parse_transfer_title(self, title):
        if not title:
            return None, None, None
        match = re.search(r'\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}', title)
        if match:
            transfer_type = match.group(1).strip().lower()
            target_user = match.group(2).strip()
            app_name = match.group(3).strip() if match.group(3) else None
            return transfer_type, target_user, app_name
        return None, None, None

    def parse_domain_transfer_target(self, content):
        try:
            content_str = content.decode('utf-8')
        except Exception:
            return None, None
        domain = None
        new_owner = None
        in_dns_section = False
        for line in content_str.splitlines():
            line = line.strip()
            if line == '### DNS:':
                in_dns_section = True
                continue
            if line == '### :END DNS':
                in_dns_section = False
                continue
            if in_dns_section and line.startswith('# NEW_DNAME:'):
                tail = line.split(':', 1)[1].strip()
                if '=' in tail:
                    domain = tail.split('=', 1)[1].strip()
                else:
                    domain = tail.strip()
            if line.startswith('# NEW_DOWNER:'):
                tail = line.split(':', 1)[1].strip()
                if '=' in tail:
                    new_owner = tail.split('=', 1)[1].strip()
                else:
                    new_owner = tail.strip()
        return domain, new_owner

    def extract_content_hash_from_ddns(self, ddns_content):
        try:
            lines = ddns_content.decode('utf-8').splitlines()
            in_dns_section = False
            for line in lines:
                if line.strip() == '### DNS:':
                    in_dns_section = True
                    continue
                if line.strip() == '### :END DNS':
                    break
                if in_dns_section and line.strip().startswith('# DNAME:'):
                    parts = line.strip().split('=')
                    if len(parts) == 2:
                        return parts[1].strip()
            return None
        except Exception as e:
            logger.error(f"Erro ao extrair hash do conteúdo do DDNS: {e}")
            return None

    def select_upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.upload_file_var.set(file_path)
            file_name = os.path.basename(file_path)
            if not self.upload_title_var.get().strip():
                self.upload_title_var.set(file_name)
            
            mime_type, _ = mimetypes.guess_type(file_name)
            if not mime_type:
                mime_type = 'application/octet-stream'
            self.upload_mime_var.set(mime_type)

    def select_dns_content_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                content_hash = hashlib.sha256(content).hexdigest()
                self.dns_content_hash_var.set(content_hash)
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao ler arquivo: {e}")

    def upload_file(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Por favor, conecte-se à rede primeiro.")
            return
            
        file_path = self.upload_file_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Aviso", "Por favor, selecione um arquivo válido.")
            return
            
        title = self.upload_title_var.get()
        if not title:
            messagebox.showwarning("Aviso", "Por favor, insira um título.")
            return
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_upload_size:
                messagebox.showwarning("Aviso", f"Arquivo muito grande. Tamanho máximo: {self.max_upload_size // (1024*1024)}MB")
                return
            with open(file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao ler arquivo: {e}")
            return
        
        file_hash = hashlib.sha256(content).hexdigest()
        details = [
            ("FILE_NAME", os.path.basename(file_path)),
            ("FILE_SIZE", str(len(content))),
            ("FILE_HASH", file_hash),
            ("TITLE", title),
            ("MIME", self.upload_mime_var.get()),
            ("DESCRIPTION", self.upload_description_var.get()),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        app_name = self.extract_app_name(title)
        if app_name:
            details.append(("APP", app_name))
        transfer_type, transfer_to, transfer_app = self.parse_transfer_title(title)
        if transfer_type in ("file", "api_app") and not transfer_to:
            messagebox.showwarning("Aviso", "Informe o usuario destino para a transferencia.")
            return
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            domain, new_owner = self.parse_domain_transfer_target(content)
            if new_owner:
                transfer_type = "domain"
                transfer_to = new_owner
            if domain:
                details.append(("DOMAIN", domain))
        if transfer_to:
            details.append(("TRANSFER_TO", transfer_to))
        if transfer_type:
            details.append(("TRANSFER_TYPE", transfer_type))
        if transfer_app:
            details.append(("APP", transfer_app))
        
        allowed_actions = ["upload_file"]
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            allowed_actions = ["transfer_domain"]
        elif transfer_type == "file":
            allowed_actions = ["transfer_content"]
        elif transfer_type == "api_app":
            allowed_actions = ["transfer_api_app"]
        elif title.startswith('(HPS!api)'):
            allowed_actions = ["upload_file", "change_api_app"]
        
        contract_template = self.build_contract_template(allowed_actions[0], details)
        contract_dialog = ContractDialog(
            self.root,
            contract_template,
            title_suffix="(Upload)",
            signer=lambda text: self.apply_contract_signature(text)[0]
        )
        self.root.wait_window(contract_dialog.window)
        if not contract_dialog.confirmed:
            return
        
        contract_text = contract_dialog.current_text
        valid, error = self.validate_contract_text_allowed(contract_text, allowed_actions)
        if not valid:
            messagebox.showerror("Erro", error)
            return
        
        full_content = content + contract_text.encode('utf-8')
        content_hash = hashlib.sha256(content).hexdigest()
        signature = self.private_key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        self.upload_window = UploadProgressWindow(self.root)
        
        def upload_thread():
            try:
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(30, "Hash calculado", content_hash, len(content))
                    self.upload_window.log_message(f"Hash do conteúdo: {content_hash}")
                    self.upload_window.update_progress(70, "Contrato anexado")
                    self.upload_window.log_message("Contrato confirmado e anexado ao arquivo")
                
                self.save_content_to_storage(content_hash, content, {
                    'title': title,
                    'description': self.upload_description_var.get(),
                    'mime_type': self.upload_mime_var.get(),
                    'username': self.current_user,
                    'signature': base64.b64encode(signature).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'verified': True
                })
                
                self.local_files[content_hash] = {
                    'name': os.path.basename(file_path),
                    'path': file_path,
                    'size': len(content),
                    'content': content,
                    'published': True
                }
                
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(90, "Solicitando PoW...")
                    self.upload_window.log_message("Solicitando prova de trabalho para upload...")

                self.root.after(0, lambda: self.update_upload_status("Solicitando PoW para upload..."))

                def start_pow():
                    def do_upload(pow_nonce, hashrate_observed):
                        asyncio.run_coroutine_threadsafe(
                            self._upload_file(
                                content_hash, title, self.upload_description_var.get(),
                                self.upload_mime_var.get(), len(content),
                                signature, full_content, pow_nonce, hashrate_observed
                            ), self.loop
                        )
                    self.upload_callback = do_upload
                    asyncio.run_coroutine_threadsafe(self.request_pow_challenge("upload"), self.loop)

                def start_hps(hps_payment):
                    self.root.after(0, lambda: self.update_upload_status("Usando saldo HPS para pular PoW..."))
                    asyncio.run_coroutine_threadsafe(
                        self._upload_file(
                            content_hash, title, self.upload_description_var.get(),
                            self.upload_mime_var.get(), len(content),
                            signature, full_content, "", 0.0, hps_payment=hps_payment
                        ), self.loop
                    )

                self.root.after(0, lambda: self.run_pow_or_hps("upload", start_pow, start_hps))
                
            except Exception as e:
                logger.error(f"Erro no upload: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no upload: {e}"))
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
        
        threading.Thread(target=upload_thread, daemon=True).start()

    def upload_content_bytes(self, title, description, mime_type, content):
        if not self.connected:
            messagebox.showwarning("Aviso", "Por favor, conecte-se à rede primeiro.")
            return
        if not title:
            messagebox.showwarning("Aviso", "Titulo nao informado.")
            return
        file_hash = hashlib.sha256(content).hexdigest()
        details = [
            ("FILE_NAME", title),
            ("FILE_SIZE", str(len(content))),
            ("FILE_HASH", file_hash),
            ("TITLE", title),
            ("MIME", mime_type),
            ("DESCRIPTION", description),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        app_name = self.extract_app_name(title)
        if app_name:
            details.append(("APP", app_name))
        transfer_type, transfer_to, transfer_app = self.parse_transfer_title(title)
        if transfer_type in ("file", "api_app") and not transfer_to:
            messagebox.showwarning("Aviso", "Informe o usuario destino para a transferencia.")
            return
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            domain, new_owner = self.parse_domain_transfer_target(content)
            if new_owner:
                transfer_type = "domain"
                transfer_to = new_owner
            if domain:
                details.append(("DOMAIN", domain))
        if transfer_to:
            details.append(("TRANSFER_TO", transfer_to))
        if transfer_type:
            details.append(("TRANSFER_TYPE", transfer_type))
        if transfer_app:
            details.append(("APP", transfer_app))
        allowed_actions = ["upload_file"]
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            allowed_actions = ["transfer_domain"]
        elif transfer_type == "file":
            allowed_actions = ["transfer_content"]
        elif transfer_type == "api_app":
            allowed_actions = ["transfer_api_app"]
        elif title.startswith('(HPS!api)'):
            allowed_actions = ["upload_file", "change_api_app"]
        contract_template = self.build_contract_template(allowed_actions[0], details)
        signed_text, _ = self.apply_contract_signature(contract_template)
        contract_text = signed_text
        valid, error = self.validate_contract_text_allowed(contract_text, allowed_actions)
        if not valid:
            messagebox.showerror("Erro", error)
            return
        full_content = content + contract_text.encode('utf-8')
        content_hash = hashlib.sha256(content).hexdigest()
        signature = self.private_key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.upload_window = UploadProgressWindow(self.root)

        def upload_thread():
            try:
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(30, "Hash calculado", content_hash, len(content))
                    self.upload_window.log_message(f"Hash do conteúdo: {content_hash}")
                    self.upload_window.update_progress(70, "Contrato anexado")
                    self.upload_window.log_message("Contrato confirmado e anexado ao arquivo")
                self.save_content_to_storage(content_hash, content, {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': self.current_user,
                    'signature': base64.b64encode(signature).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'verified': True
                })
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(90, "Solicitando PoW...")
                    self.upload_window.log_message("Solicitando prova de trabalho para upload...")
                self.root.after(0, lambda: self.update_upload_status("Solicitando PoW para upload..."))
                def start_pow():
                    def do_upload(pow_nonce, hashrate_observed):
                        asyncio.run_coroutine_threadsafe(
                            self._upload_file(
                                content_hash, title, description,
                                mime_type, len(content),
                                signature, full_content, pow_nonce, hashrate_observed
                            ), self.loop
                        )
                    self.upload_callback = do_upload
                    asyncio.run_coroutine_threadsafe(self.request_pow_challenge("upload"), self.loop)

                def start_hps(hps_payment):
                    self.root.after(0, lambda: self.update_upload_status("Usando saldo HPS para pular PoW..."))
                    asyncio.run_coroutine_threadsafe(
                        self._upload_file(
                            content_hash, title, description,
                            mime_type, len(content),
                            signature, full_content, "", 0.0, hps_payment=hps_payment
                        ), self.loop
                    )

                self.root.after(0, lambda: self.run_pow_or_hps("upload", start_pow, start_hps))
            except Exception as e:
                logger.error(f"Erro no upload: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no upload: {e}"))
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None

        threading.Thread(target=upload_thread, daemon=True).start()

    async def _upload_file(self, content_hash, title, description, mime_type, size, signature,
                           full_content, pow_nonce, hashrate_observed, hps_payment=None):
        if not self.connected:
            return
            
        try:
            content_b64 = base64.b64encode(full_content).decode('utf-8')
            data = {
                'content_hash': content_hash,
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'size': size,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'content_b64': content_b64,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            if hps_payment:
                data['hps_payment'] = hps_payment
            
            await self.sio.emit('publish_content', data)
            
        except Exception as e:
            logger.error(f"Erro no upload: {e}")
            self.root.after(0, lambda: self.update_upload_status(f"Erro no upload: {e}"))

    def register_dns(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Por favor, conecte-se à rede primeiro.")
            return
            
        domain = self.dns_domain_var.get().lower().strip()
        content_hash = self.dns_content_hash_var.get().strip()
        
        if not domain:
            messagebox.showwarning("Aviso", "Por favor, insira um domínio.")
            return
            
        if not content_hash:
            messagebox.showwarning("Aviso", "Por favor, insira um hash de conteúdo.")
            return
            
        if not self.is_valid_domain(domain):
            messagebox.showwarning("Aviso", "Domínio inválido. Use apenas letras, números e hífens.")
            return
        
        details = [
            ("DOMAIN", domain),
            ("CONTENT_HASH", content_hash),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        contract_template = self.build_contract_template("register_dns", details)
        contract_dialog = ContractDialog(
            self.root,
            contract_template,
            title_suffix="(DNS)",
            signer=lambda text: self.apply_contract_signature(text)[0]
        )
        self.root.wait_window(contract_dialog.window)
        if not contract_dialog.confirmed:
            return
        
        contract_text = contract_dialog.current_text
        valid, error = self.validate_contract_text(contract_text, "register_dns")
        if not valid:
            messagebox.showerror("Erro", error)
            return
        
        self.ddns_window = DDNSProgressWindow(self.root)
        self.ddns_window.update_progress(10, "Criando arquivo DDNS...", domain, content_hash)
        
        def register_thread():
            try:
                self.ddns_window.log_message(f"Criando arquivo DDNS para domínio: {domain}")
                ddns_content = self.create_ddns_file(domain, content_hash)
                ddns_content_full = ddns_content + contract_text.encode('utf-8')
                ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                
                self.ddns_window.update_progress(30, "Assinando arquivo DDNS...", domain, ddns_hash)
                self.ddns_window.log_message(f"Hash do arquivo DDNS: {ddns_hash}")
                
                header_end = b'### :END START'
                if header_end in ddns_content:
                    _, ddns_data_signed = ddns_content.split(header_end, 1)
                else:
                    ddns_data_signed = ddns_content
                
                signature = self.private_key.sign(
                    ddns_data_signed,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.save_ddns_to_storage(domain, ddns_content, {
                    'content_hash': content_hash,
                    'username': self.current_user,
                    'verified': True,
                    'signature': base64.b64encode(signature).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                })
                
                self.ddns_window.update_progress(50, "Preparando envio...", domain, content_hash)
                self.ddns_window.log_message("Arquivo DDNS assinado com sucesso")
                
                self.root.after(0, lambda: self.update_dns_status("Solicitando PoW para registro DNS..."))

                def start_pow():
                    def do_register(pow_nonce, hashrate_observed):
                        asyncio.run_coroutine_threadsafe(
                            self._register_dns(domain, ddns_content_full, signature, pow_nonce, hashrate_observed),
                            self.loop
                        )
                    self.dns_callback = do_register
                    asyncio.run_coroutine_threadsafe(self.request_pow_challenge("dns"), self.loop)

                def start_hps(hps_payment):
                    self.root.after(0, lambda: self.update_dns_status("Usando saldo HPS para pular PoW..."))
                    asyncio.run_coroutine_threadsafe(
                        self._register_dns(domain, ddns_content_full, signature, "", 0.0, hps_payment=hps_payment),
                        self.loop
                    )

                self.root.after(0, lambda: self.run_pow_or_hps("dns", start_pow, start_hps))
                
            except Exception as e:
                logger.error(f"Erro no registro DNS: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no registro DNS: {e}"))
                if self.ddns_window and self.ddns_window.winfo_exists():
                    self.ddns_window.destroy()
                    self.ddns_window = None
        
        threading.Thread(target=register_thread, daemon=True).start()

    async def _register_dns(self, domain, ddns_content, signature, pow_nonce, hashrate_observed, hps_payment=None):
        if not self.connected:
            return
            
        try:
            ddns_content_b64 = base64.b64encode(ddns_content).decode('utf-8')
            data = {
                'domain': domain,
                'ddns_content': ddns_content_b64,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            if hps_payment:
                data['hps_payment'] = hps_payment
            await self.sio.emit('register_dns', data)
        except Exception as e:
            logger.error(f"Erro no registro DNS: {e}")
            self.root.after(0, lambda: self.update_dns_status(f"Erro no registro DNS: {e}"))

    def resolve_dns(self):
        domain = self.dns_domain_var.get().lower().strip()
        if not domain:
            messagebox.showwarning("Aviso", "Por favor, insira um domínio para resolver.")
            return
            
        self.root.after(0, lambda: self.update_dns_status("Resolvendo DNS..."))
        asyncio.run_coroutine_threadsafe(self._resolve_dns(domain), self.loop)

    async def _resolve_dns(self, domain):
        if not self.connected:
            return
            
        await self.sio.emit('resolve_dns', {'domain': domain})

    def is_valid_domain(self, domain):
        import re
        pattern = r'^[a-z0-9-]+(\.[a-z0-9-]+)*$'
        return re.match(pattern, domain) is not None

    def refresh_dns_records(self):
        for item in self.dns_tree.get_children():
            self.dns_tree.delete(item)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, content_hash, verified FROM browser_dns_records ORDER BY timestamp DESC LIMIT 100')
            rows = cursor.fetchall()
            for row in rows:
                domain, content_hash, verified = row
                verified_text = "Sim" if verified else "Não"
                self.dns_tree.insert("", tk.END, values=(
                    domain,
                    content_hash[:20] + "...",
                    verified_text
                ))

    def open_dns_content(self, event):
        selection = self.dns_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        domain = self.dns_tree.item(item, 'values')[0]
        self.browser_url_var.set(f"hps://dns:{domain}")
        self.browser_navigate()

    def refresh_network(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        asyncio.run_coroutine_threadsafe(self._refresh_network(), self.loop)

    async def _refresh_network(self):
        if not self.connected:
            return
            
        await self.sio.emit('get_network_state', {})
        await self.sio.emit('get_servers', {})

    def sync_network(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        if messagebox.askyesno("Confirmar Sincronização", "Deseja sincronizar com a rede P2P? Isso pode levar alguns minutos e consumir dados."):
            self.sync_dialog = NetworkSyncDialog(self.root, self)
            self.sync_dialog.log_message("Iniciando sincronização com a rede...")
            
            def sync_thread():
                async def async_sync():
                    try:
                        self.sync_dialog.log_message("Solicitando lista de servidores conhecidos...")
                        await self.sio.emit('get_servers', {})
                        await asyncio.sleep(1)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                            
                        self.sync_dialog.log_message("Enviando lista de servidores locais para a rede...")
                        await self.sio.emit('sync_servers', {'servers': self.known_servers})
                        await asyncio.sleep(1)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                            
                        self.sync_dialog.log_message("Sincronizando arquivos locais com a rede...")
                        await self.sync_client_files()
                        await asyncio.sleep(2)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                        
                        self.sync_dialog.log_message("Sincronizando DNS locais com a rede...")
                        await self.sync_client_dns_files()
                        await asyncio.sleep(1)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                        
                        self.sync_dialog.log_message("Sincronizando contratos locais com a rede...")
                        await self.sync_client_contracts()
                        await asyncio.sleep(1)
                        
                        self.sync_dialog.log_message("Sincronização concluída!")
                        
                    except Exception as e:
                        if self.sync_dialog and self.sync_dialog.window.winfo_exists():
                            self.sync_dialog.update_status("Erro na sincronização")
                            self.sync_dialog.log_message(f"Erro durante sincronização: {e}")
                
                asyncio.run_coroutine_threadsafe(async_sync(), self.loop)
                        
            threading.Thread(target=sync_thread, daemon=True).start()

    async def _sync_network_full(self):
        if not self.connected:
            return
            
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Solicitando lista de servidores conhecidos...")
        await self.sio.emit('get_servers', {})
        await asyncio.sleep(1)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Enviando lista de servidores locais para a rede...")
        await self.sio.emit('sync_servers', {'servers': self.known_servers})
        await asyncio.sleep(1)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Sincronizando arquivos locais com a rede...")
        await self.sync_client_files()
        await asyncio.sleep(2)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
        
        self.sync_dialog.log_message("Sincronizando DNS locais com a rede...")
        await self.sync_client_dns_files()
        await asyncio.sleep(1)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
        
        self.sync_dialog.log_message("Sincronizando contratos locais com a rede...")
        await self.sync_client_contracts()
        await asyncio.sleep(1)
        
        self.sync_dialog.log_message("Sincronização concluída!")

    def update_network_stats(self, online_nodes, total_content, total_dns, node_types):
        self.network_stats_var.set(f"Nós: {online_nodes} | Conteúdo: {total_content} | DNS: {total_dns}")
        
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT node_id, address, node_type, reputation, status FROM browser_network_nodes ORDER BY last_seen DESC LIMIT 50')
            rows = cursor.fetchall()
            for row in rows:
                node_id, address, node_type, reputation, status = row
                self.network_tree.insert("", tk.END, values=(
                    node_id[:16] + "...",
                    address,
                    node_type,
                    reputation,
                    status
                ))

    def show_my_node(self):
        messagebox.showinfo("Meu Nó", f"""
ID do Nó: {self.node_id}
ID do Cliente: {self.client_identifier}
ID da Sessão: {self.session_id}
Usuário: {self.current_user or 'Não logado'}
Reputação: {self.reputation}
Tipo: {self.node_type}
Conectado: {'Sim' if self.connected else 'Não'}
Servidor: {self.current_server or 'Nenhum'}
        """)

    def refresh_servers(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        asyncio.run_coroutine_threadsafe(self._refresh_servers(), self.loop)

    async def _refresh_servers(self):
        if not self.connected:
            return
            
        await self.sio.emit('get_servers', {})

    def update_servers_list(self, servers):
        for item in self.servers_tree.get_children():
            self.servers_tree.delete(item)
            
        for server in servers:
            address = server['address']
            status = server.get('status', 'Desconhecido')
            reputation = server.get('reputation', 100)
            self.servers_tree.insert("", tk.END, values=(
                address,
                status,
                reputation
            ))

    def add_server(self):
        server_address = self.new_server_var.get().strip()
        if not server_address:
            messagebox.showwarning("Aviso", "Por favor, insira um endereço de servidor.")
            return
            
        if server_address not in self.known_servers:
            self.known_servers.append(server_address)
            self.server_combo['values'] = self.known_servers
            self.new_server_var.set("")
            self.save_known_servers()
            messagebox.showinfo("Sucesso", f"Servidor {server_address} adicionado com sucesso!")
            self.refresh_servers()
        else:
            messagebox.showinfo("Info", "Este servidor já está na lista.")

    def remove_server(self):
        selection = self.servers_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor para remover.")
            return
            
        item = selection[0]
        address = self.servers_tree.item(item, 'values')[0]
        
        if messagebox.askyesno("Confirmar", f"Remover servidor {address}?"):
            if address in self.known_servers:
                self.known_servers.remove(address)
                self.server_combo['values'] = self.known_servers
                self.save_known_servers()
                self.refresh_servers()
                messagebox.showinfo("Sucesso", f"Servidor {address} removido com sucesso!")

    def connect_selected_server(self):
        selection = self.servers_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor para conectar.")
            return
            
        item = selection[0]
        address = self.servers_tree.item(item, 'values')[0]
        self.server_var.set(address)
        self.current_server = address
        self.root.after(0, lambda: self.update_login_status("Conectando..."))
        asyncio.run_coroutine_threadsafe(self._connect_to_server(address), self.loop)

    def update_stats(self):
        session_duration = time.time() - self.stats_data['session_start']
        hours = int(session_duration // 3600)
        minutes = int((session_duration % 3600) // 60)
        seconds = int(session_duration % 60)
        
        self.stats_vars["Tempo de Sessão:"].set(f"{hours}h {minutes}m {seconds}s")
        self.stats_vars["Dados Enviados:"].set(f"{self.stats_data['data_sent'] // (1024*1024)} MB")
        self.stats_vars["Dados Recebidos:"].set(f"{self.stats_data['data_received'] // (1024*1024)} MB")
        self.stats_vars["Conteúdo Baixado:"].set(f"{self.stats_data['content_downloaded']} arquivos")
        self.stats_vars["Conteúdo Publicado:"].set(f"{self.stats_data['content_uploaded']} arquivos")
        self.stats_vars["DNS Registrados:"].set(f"{self.stats_data['dns_registered']} domínios")
        self.stats_vars["PoW Resolvidos:"].set(f"{self.stats_data['pow_solved']}")
        self.stats_vars["Tempo Total PoW:"].set(f"{int(self.stats_data['pow_time'])}s")
        self.stats_vars["Conteúdos Reportados:"].set(f"{self.stats_data['content_reported']}")

    def pow_solution_found(self, nonce, solve_time, hashrate):
        self.stats_data['pow_solved'] += 1
        self.stats_data['pow_time'] += solve_time
        
        if self.upload_callback:
            self.upload_callback(nonce, hashrate)
            self.upload_callback = None
        elif self.dns_callback:
            self.dns_callback(nonce, hashrate)
            self.dns_callback = None
        elif self.report_callback:
            self.report_callback(nonce, hashrate)
            self.report_callback = None
        elif self.contract_reset_callback:
            self.contract_reset_callback(nonce, hashrate)
            self.contract_reset_callback = None
        elif self.contract_certify_callback:
            self.contract_certify_callback(nonce, hashrate)
            self.contract_certify_callback = None
        elif self.contract_transfer_callback:
            self.contract_transfer_callback(nonce, hashrate)
            self.contract_transfer_callback = None
        elif self.missing_contract_certify_callback:
            self.missing_contract_certify_callback(nonce, hashrate)
            self.missing_contract_certify_callback = None
        elif self.usage_contract_callback:
            self.usage_contract_callback(nonce, hashrate)
            self.usage_contract_callback = None
        elif self.hps_transfer_callback:
            self.hps_transfer_callback(nonce, hashrate)
            self.hps_transfer_callback = None
        elif self.hps_mint_callback:
            self.hps_mint_callback(nonce, hashrate)
            self.hps_mint_callback = None
            self.hps_mint_requested_at = None
            self.record_hps_mint_success(solve_time, hashrate)
        else:
            asyncio.run_coroutine_threadsafe(self.send_authentication(nonce, hashrate), self.loop)

    def pow_solution_failed(self):
        if self.upload_callback:
            self.upload_callback = None
        elif self.dns_callback:
            self.dns_callback = None
        elif self.report_callback:
            self.report_callback = None
        elif self.contract_reset_callback:
            self.contract_reset_callback = None
        elif self.contract_certify_callback:
            self.contract_certify_callback = None
        elif self.contract_transfer_callback:
            self.contract_transfer_callback = None
        elif self.missing_contract_certify_callback:
            self.missing_contract_certify_callback = None
        elif self.usage_contract_callback:
            self.usage_contract_callback = None
        elif self.hps_transfer_callback:
            self.hps_transfer_callback = None
        elif self.hps_mint_callback:
            self.hps_mint_callback = None
            self.hps_mint_requested_at = None
            self.record_hps_mint_failure()
        self.root.after(0, lambda: self.update_login_status("Falha na solução do PoW"))
        self.schedule_auto_mint()

    def report_content_action(self, content_hash, reported_user):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar logado para reportar conteúdo.")
            return
            
        if reported_user == self.current_user:
            messagebox.showwarning("Aviso", "Você não pode reportar seu próprio conteúdo.")
            return
        
        details = [
            ("CONTENT_HASH", content_hash),
            ("REPORTED_USER", reported_user)
        ]
        contract_template = self.build_contract_template("report_content", details)
        contract_dialog = ContractDialog(
            self.root,
            contract_template,
            title_suffix="(Reporte)",
            signer=lambda text: self.apply_contract_signature(text)[0]
        )
        self.root.wait_window(contract_dialog.window)
        if not contract_dialog.confirmed:
            return
        
        contract_text = contract_dialog.current_text
        valid, error = self.validate_contract_text(contract_text, "report_content")
        if not valid:
            messagebox.showerror("Erro", error)
            return
            
        self.report_window = ReportProgressWindow(self.root)
        self.report_window.update_progress(10, "Iniciando processo de reporte...", content_hash, reported_user, self.reputation)
        
        def report_thread():
            try:
                self.report_window.log_message(f"Validando dados para reporte...")
                self.report_window.log_message(f"Conteúdo: {content_hash}")
                self.report_window.log_message(f"Usuário reportado: {reported_user}")
                self.report_window.log_message(f"Sua reputação: {self.reputation}")
                
                if self.reputation < 20:
                    self.root.after(0, lambda: messagebox.showwarning("Aviso", "Sua reputação é muito baixa para reportar conteúdo."))
                    if self.report_window and self.report_window.window.winfo_exists():
                        self.report_window.destroy()
                        self.report_window = None
                    return
                    
                self.report_window.update_progress(30, "Validando informações...", content_hash, reported_user, self.reputation)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT COUNT(*) FROM browser_reports 
                        WHERE reporter_user = ? AND content_hash = ?
                    ''', (self.current_user, content_hash))
                    count = cursor.fetchone()[0]
                    if count > 0:
                        self.root.after(0, lambda: messagebox.showwarning("Aviso", "Você já reportou este conteúdo."))
                        if self.report_window and self.report_window.window.winfo_exists():
                            self.report_window.destroy()
                            self.report_window = None
                        return
                        
                self.report_window.update_progress(50, "Preparando solicitação...", content_hash, reported_user, self.reputation)
                self.report_window.log_message("Dados validados com sucesso")
                
                self.root.after(0, lambda: self.update_status("Solicitando PoW para reporte..."))

                def start_pow():
                    def do_report(pow_nonce, hashrate_observed):
                        asyncio.run_coroutine_threadsafe(
                            self._report_content(content_hash, reported_user, contract_text, pow_nonce, hashrate_observed),
                            self.loop
                        )
                    self.report_callback = do_report
                    asyncio.run_coroutine_threadsafe(self.request_pow_challenge("report"), self.loop)

                def start_hps(hps_payment):
                    self.root.after(0, lambda: self.update_status("Usando saldo HPS para pular PoW..."))
                    asyncio.run_coroutine_threadsafe(
                        self._report_content(content_hash, reported_user, contract_text, "", 0.0, hps_payment=hps_payment),
                        self.loop
                    )

                self.root.after(0, lambda: self.run_pow_or_hps("report", start_pow, start_hps))
                
            except Exception as e:
                logger.error(f"Erro no processo de reporte: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no reporte: {e}"))
                if self.report_window and self.report_window.window.winfo_exists():
                    self.report_window.destroy()
                    self.report_window = None
                    
        threading.Thread(target=report_thread, daemon=True).start()

    async def _report_content(self, content_hash, reported_user, contract_text, pow_nonce, hashrate_observed, hps_payment=None):
        if not self.connected:
            return
            
        try:
            report_id = hashlib.sha256(f"{content_hash}{reported_user}{self.current_user}{time.time()}".encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO browser_reports 
                    (report_id, content_hash, reported_user, reporter_user, timestamp, status, reason) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (report_id, content_hash, reported_user, self.current_user, time.time(), 'pending', ''))
                conn.commit()
                
            data = {
                'content_hash': content_hash,
                'reported_user': reported_user,
                'reporter': self.current_user,
                'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            if hps_payment:
                data['hps_payment'] = hps_payment
            await self.sio.emit('report_content', data)
            
        except Exception as e:
            logger.error(f"Erro no envio do reporte: {e}")
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no envio do reporte: {e}"))

if __name__ == "__main__":
    root = tk.Tk()
    app = HPSBrowser(root)
    root.mainloop()
