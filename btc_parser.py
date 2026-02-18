# -*- coding: utf-8 -*-
"""
Bitcoin Balance Parser - GUI Application
Генерация и проверка случайных ID длиной 30 символов для bitcoinco.org
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import random
import string
import re
import time
import hashlib
from datetime import datetime
import sys
from decimal import Decimal

try:
    import requests
except ImportError:
    try:
        _root = tk.Tk()
        _root.withdraw()
        messagebox.showerror(
            "Ошибка",
            "Модуль requests не установлен. Установите: pip install requests",
        )
        _root.destroy()
    except Exception:
        print(
            "Ошибка: модуль requests не установлен. Установите: pip install requests",
            file=sys.stderr,
        )
    raise SystemExit(1)


class BitcoinParserApp:
    """GUI приложение для парсинга Bitcoin адресов"""
    
    BASE_URL = "https://bitcoinco.org/ru/"
    RESULTS_FILE = "results.txt"
    ID_LENGTH = 30
    DEFAULT_CHARS = string.ascii_letters + string.digits
    API_PROVIDERS = {
        "Blockstream": "https://blockstream.info",
        "Mempool.space": "https://mempool.space",
    }

    # secp256k1 constants (for deriving P2PKH address from passcode like bitcoinco.org does in JS)
    _SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _SECP_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    _SECP_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    
    def __init__(self, root):
        self.root = root
        self.root.title("Bitcoin Balance Parser")
        self.root.geometry("750x700")
        self.root.resizable(True, True)
        
        self.num_ids = tk.StringVar(value="100")
        self.threads = tk.StringVar(value="10")
        self.timeout = tk.StringVar(value="10")
        self.api_rps = tk.StringVar(value="4")
        self.api_pause_429 = tk.StringVar(value="30")
        self.api_provider = tk.StringVar(value="Blockstream")
        self.api_custom_base_url = tk.StringVar(value="")
        self.single_input = tk.StringVar(value="")
        self.is_running = False
        self.stop_event = threading.Event()
        
        self.checked_count = 0
        self.found_count = 0
        self.total_count = 0
        self.results_saved = False
        
        self.log_queue = queue.Queue()
        self.results = []
        self.results_lock = threading.Lock()
        self.api_semaphore = threading.BoundedSemaphore(3)
        self.api_rate_lock = threading.Lock()
        self.api_next_time = 0.0
        self.api_min_interval = 0.25
        self.api_pause_seconds = 30.0
        self.api_pause_until = 0.0
        self.api_last_429_log_time = 0.0
        
        self._setup_ui()
        self.root.after(100, self._poll_log_queue)
    
    def _generate_random_id(self, length=30):
        """Генерация случайного ID из букв и цифр"""
        return ''.join(random.choices(self.DEFAULT_CHARS, k=length))
    
    def _setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        title_label = ttk.Label(main_frame, text="Bitcoin Balance Parser", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        info_label = ttk.Label(main_frame, text="Генерация случайных ID (30 символов) и проверка баланса", 
                              font=("Arial", 10))
        info_label.grid(row=1, column=0, columnspan=3, pady=5)
        
        settings_frame = ttk.LabelFrame(main_frame, text="Настройки", padding="10")
        settings_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        settings_frame.columnconfigure(1, weight=1)
        
        ttk.Label(settings_frame, text="Количество ID для проверки:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.num_ids, width=20).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(settings_frame, text="Потоков:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.threads, width=20).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(settings_frame, text="Таймаут (сек):").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.timeout, width=20).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(settings_frame, text="Длина ID:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_frame, text="30 символов (a-z, A-Z, 0-9)", foreground="gray").grid(row=3, column=1, sticky=tk.W, padx=5)

        ttk.Label(settings_frame, text="Проверить адрес/URL:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.single_entry = ttk.Entry(settings_frame, textvariable=self.single_input, width=45)
        self.single_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5)
        self.check_button = ttk.Button(settings_frame, text="Проверить", command=self._start_single_check)
        self.check_button.grid(row=4, column=2, sticky=tk.W, padx=5)
        self.single_entry.bind("<Return>", lambda _e: self._start_single_check())
        self._setup_entry_clipboard(self.single_entry)

        ttk.Label(settings_frame, text="Провайдер API:").grid(row=5, column=0, sticky=tk.W, pady=5)
        provider_values = list(self.API_PROVIDERS.keys()) + ["Custom (Esplora)"]
        self.provider_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.api_provider,
            values=provider_values,
            state="readonly",
            width=20,
        )
        self.provider_combo.grid(row=5, column=1, sticky=tk.W, padx=5)

        ttk.Label(settings_frame, text="Custom API base URL:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.custom_url_entry = ttk.Entry(settings_frame, textvariable=self.api_custom_base_url, width=45)
        self.custom_url_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), padx=5)
        self._setup_entry_clipboard(self.custom_url_entry)

        ttk.Label(settings_frame, text="Запросов/сек (API):").grid(row=7, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.api_rps, width=20).grid(row=7, column=1, sticky=tk.W, padx=5)

        ttk.Label(settings_frame, text="Пауза при 429 (сек):").grid(row=8, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.api_pause_429, width=20).grid(row=8, column=1, sticky=tk.W, padx=5)
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.start_button = ttk.Button(buttons_frame, text="Старт", command=self._start_parsing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Стоп", command=self._stop_parsing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Статистика", padding="10")
        stats_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="Проверено: 0 | Найдено: 0 | Всего: 0")
        self.stats_label.pack()
        
        log_frame = ttk.LabelFrame(main_frame, text="Лог (можно выделять и копировать)", padding="10")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        main_frame.rowconfigure(5, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            width=80,
            wrap=tk.WORD,
            undo=False,
            autoseparators=False,
            maxundo=0,
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.configure(state=tk.DISABLED)
        self._setup_log_copy_menu()
        
        self.status_label = ttk.Label(main_frame, text="Готов к работе", relief=tk.SUNKEN)
        self.status_label.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
    
    def _log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        self.log_queue.put((full_message, level))

    def _setup_log_copy_menu(self):
        self._log_menu = tk.Menu(self.root, tearoff=0)
        self._log_menu.add_command(label="Копировать", command=self._copy_log_selection)
        self._log_menu.add_command(label="Выделить всё", command=self._select_all_log)

        self.log_text.bind("<Button-3>", self._show_log_menu)
        self.log_text.bind("<Control-a>", self._select_all_log_event)
        self.log_text.bind("<Control-A>", self._select_all_log_event)
        self.log_text.bind("<Control-c>", self._copy_log_selection_event)
        self.log_text.bind("<Control-C>", self._copy_log_selection_event)

    def _show_log_menu(self, event):
        try:
            self._log_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._log_menu.grab_release()

    def _select_all_log(self):
        self.log_text.focus_set()
        self.log_text.tag_add(tk.SEL, "1.0", tk.END)
        self.log_text.mark_set(tk.INSERT, "1.0")
        self.log_text.see(tk.INSERT)

    def _select_all_log_event(self, event):
        self._select_all_log()
        return "break"

    def _copy_log_selection(self):
        try:
            self.log_text.event_generate("<<Copy>>")
        except Exception:
            pass

    def _copy_log_selection_event(self, event):
        self._copy_log_selection()
        return "break"

    def _setup_entry_clipboard(self, entry):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Вставить", command=lambda: entry.event_generate("<<Paste>>"))
        menu.add_command(label="Копировать", command=lambda: entry.event_generate("<<Copy>>"))
        menu.add_command(label="Вырезать", command=lambda: entry.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="Выделить всё", command=lambda: self._select_all_entry(entry))

        def show_menu(event):
            try:
                entry.focus_set()
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        entry.bind("<Button-3>", show_menu)
        entry.bind("<Control-v>", lambda e: (entry.event_generate("<<Paste>>"), "break")[1])
        entry.bind("<Control-V>", lambda e: (entry.event_generate("<<Paste>>"), "break")[1])
        entry.bind("<Shift-Insert>", lambda e: (entry.event_generate("<<Paste>>"), "break")[1])

    def _select_all_entry(self, entry):
        entry.focus_set()
        entry.selection_range(0, tk.END)
        entry.icursor(tk.END)

    def _poll_log_queue(self):
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self.log_text.configure(state=tk.NORMAL)
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
                self.log_text.configure(state=tk.DISABLED)
        except queue.Empty:
            pass
        
        self._update_stats()
        self.root.after(100, self._poll_log_queue)
    
    def _update_stats(self):
        self.stats_label.config(text=f"Проверено: {self.checked_count} | Найдено: {self.found_count} | Всего: {self.total_count}")

    def _apply_api_settings_from_ui(self):
        try:
            rps = float(self.api_rps.get())
            pause_429 = float(self.api_pause_429.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Поля 'Запросов/сек (API)' и 'Пауза при 429' должны быть числовыми")
            return False

        if rps <= 0 or rps > 50:
            messagebox.showerror("Ошибка", "Запросов/сек (API) должно быть > 0 и <= 50")
            return False

        if pause_429 < 1 or pause_429 > 3600:
            messagebox.showerror("Ошибка", "Пауза при 429 должна быть от 1 до 3600 секунд")
            return False

        self.api_min_interval = 1.0 / rps
        self.api_pause_seconds = pause_429
        return True

    def _get_provider_base_urls(self):
        selected = (self.api_provider.get() or "").strip()
        bases = []

        if selected == "Custom (Esplora)":
            custom = (self.api_custom_base_url.get() or "").strip()
            if not custom:
                raise ValueError("Укажите Custom API base URL (например https://mempool.space)")
            bases.append(custom.rstrip("/"))
        else:
            base = self.API_PROVIDERS.get(selected)
            if base:
                bases.append(base)

        # fallback providers (только для сетевых/5xx ошибок; не используем для обхода 429)
        for base in self.API_PROVIDERS.values():
            if base not in bases:
                bases.append(base)
        return bases

    def _start_single_check(self):
        raw = (self.single_input.get() or "").strip()
        if not raw:
            messagebox.showerror("Ошибка", "Введите bitcoinco URL/ID или Bitcoin-адрес")
            return

        if not self._apply_api_settings_from_ui():
            return

        t = threading.Thread(target=self._single_check_worker, args=(raw,))
        t.daemon = True
        t.start()

    def _single_check_worker(self, raw):
        try:
            kind, value = self._classify_input(raw)
            if kind == "wallet_id":
                has_balance, balance, url, address, sats, error = self._check_balance(value)
                address_display = address if address else "N/A"
                if error:
                    self._log(f"[РУЧНАЯ] Address: {address_display} | ERROR: {error} | URL: {url}", "error")
                else:
                    self._log(
                        f"[РУЧНАЯ] Address: {address_display} | Balance: {balance} BTC ({sats} sats) | URL: {url}",
                        "info" if not has_balance else "found",
                    )
                    if has_balance:
                        with self.results_lock:
                            self.results.append(
                                f"{url} | Address: {address_display} | Balance: {balance} BTC ({sats} sats)"
                            )
            elif kind == "btc_address":
                sats, btc_text = self._check_btc_address_balance(value)
                level = "found" if sats > 0 else "info"
                self._log(f"[РУЧНАЯ] BTC Address: {value} | Balance: {btc_text} BTC ({sats} sats)", level)
                if sats > 0:
                    with self.results_lock:
                        self.results.append(f"BTC Address: {value} | Balance: {btc_text} BTC ({sats} sats)")
            else:
                self._log(f"[РУЧНАЯ] Неподдерживаемый ввод: {raw}", "error")
        except Exception as e:
            self._log(f"[РУЧНАЯ] Ошибка проверки: {str(e)}", "error")

    def _classify_input(self, raw):
        text = raw.strip()
        if text.lower().startswith("http://") or text.lower().startswith("https://"):
            if "#" in text:
                frag = text.split("#", 1)[1].strip()
                if re.fullmatch(r"[A-Za-z0-9]{%d}" % self.ID_LENGTH, frag):
                    return "wallet_id", frag
            raise ValueError("URL должен содержать #ID длиной 30 символов")

        if re.fullmatch(r"[A-Za-z0-9]{%d}" % self.ID_LENGTH, text):
            return "wallet_id", text

        if re.fullmatch(r"(bc1[0-9a-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})", text):
            return "btc_address", text

        raise ValueError("Не похоже ни на ID, ни на Bitcoin-адрес")

    def _check_btc_address_balance(self, address):
        timeout_val = int(self.timeout.get()) if self.timeout.get() else 10

        last_error = None
        for base_url in self._get_provider_base_urls():
            try:
                data = self._fetch_esplora_address_json(base_url, address, timeout_val)
                chain = data.get("chain_stats") or {}
                mempool = data.get("mempool_stats") or {}
                sats = int(chain.get("funded_txo_sum", 0)) - int(chain.get("spent_txo_sum", 0))
                sats += int(mempool.get("funded_txo_sum", 0)) - int(mempool.get("spent_txo_sum", 0))
                btc = (Decimal(sats) / Decimal(100_000_000)).quantize(Decimal("0.00000000"))
                return sats, format(btc, "f")
            except Exception as e:
                last_error = e
                if self._is_fallback_eligible_error(e):
                    continue
                raise

        raise RuntimeError(f"All providers failed: {last_error}")

    def _is_fallback_eligible_error(self, exc):
        # Разрешаем fallback только на сетевых/5xx ошибках, НЕ на 429 (чтобы не использовать это как обход лимитов)
        msg = str(exc)
        if "HTTP 429" in msg or "Too Many Requests" in msg:
            return False
        if isinstance(exc, requests.exceptions.Timeout):
            return True
        if isinstance(exc, requests.exceptions.ConnectionError):
            return True
        if isinstance(exc, requests.exceptions.HTTPError):
            try:
                status = exc.response.status_code if exc.response is not None else None
            except Exception:
                status = None
            return bool(status and 500 <= status <= 599)
        return False

    def _fetch_esplora_address_json(self, base_url, address, timeout_val):
        last_error = None

        for attempt in range(5):
            with self.api_semaphore:
                now = time.monotonic()
                with self.api_rate_lock:
                    wait = self.api_next_time - now
                    if wait > 0:
                        time.sleep(wait)
                    self.api_next_time = max(self.api_next_time, time.monotonic()) + self.api_min_interval

                try:
                    url = f"{base_url.rstrip('/')}/api/address/{address}"
                    resp = requests.get(
                        url,
                        timeout=timeout_val,
                        headers={"User-Agent": "btc-parser/1.0"},
                    )

                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        try:
                            retry_after_s = float(retry_after) if retry_after else None
                        except ValueError:
                            retry_after_s = None

                        base_pause = float(self.api_pause_seconds) if self.api_pause_seconds else 30.0
                        sleep_s = max(base_pause, retry_after_s or 0.0)
                        last_error = RuntimeError("HTTP 429 Too Many Requests")

                        pause_until = time.monotonic() + sleep_s
                        with self.api_rate_lock:
                            self.api_next_time = max(self.api_next_time, pause_until)
                            if pause_until > self.api_pause_until:
                                self.api_pause_until = pause_until
                                if time.monotonic() - self.api_last_429_log_time > 5:
                                    self.api_last_429_log_time = time.monotonic()
                                    self._log(
                                        f"API лимит (429) на {base_url}. Пауза {sleep_s:.1f} сек, затем продолжу…",
                                        "warning",
                                    )
                        time.sleep(sleep_s)
                        continue

                    resp.raise_for_status()
                    return resp.json()
                except Exception as e:
                    last_error = e
                    time.sleep(0.5 * (2**attempt))

        raise RuntimeError(f"Provider error ({base_url}): {last_error}")

    def _derive_btc_address_from_wallet_id(self, wallet_id):
        # Mirrors bitcoinco.org logic (see app.js): sha256(passcode) -> secp256k1 key -> P2PKH address
        digest = hashlib.sha256(wallet_id.encode("utf-8")).digest()
        k = int.from_bytes(digest, "big") % self._SECP_N
        if k == 0:
            k = 1

        x, y = self._secp256k1_mul_base(k)
        pub = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")  # uncompressed
        h160 = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
        return self._base58check_encode(b"\x00" + h160)

    def _base58check_encode(self, payload):
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return self._b58encode(payload + checksum)

    def _b58encode(self, b):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = int.from_bytes(b, "big")
        chars = []
        while n > 0:
            n, rem = divmod(n, 58)
            chars.append(alphabet[rem])
        prefix = 0
        for byte in b:
            if byte == 0:
                prefix += 1
            else:
                break
        return ("1" * prefix) + "".join(reversed(chars or ["1"]))

    def _secp256k1_mul_base(self, k):
        # scalar multiplication k*G in Jacobian coords, mixed-add with affine G
        p = self._SECP_P
        gx = self._SECP_GX
        gy = self._SECP_GY

        x, y, z = 0, 1, 0  # infinity
        qx, qy = gx, gy

        for bit in bin(k)[2:]:
            x, y, z = self._jacobian_double(x, y, z, p)
            if bit == "1":
                x, y, z = self._jacobian_add_mixed(x, y, z, qx, qy, p)

        return self._jacobian_to_affine(x, y, z, p)

    def _jacobian_double(self, x1, y1, z1, p):
        if z1 == 0 or y1 == 0:
            return 0, 1, 0
        yy = (y1 * y1) % p
        s = (4 * x1 * yy) % p
        m = (3 * x1 * x1) % p
        x3 = (m * m - 2 * s) % p
        y3 = (m * (s - x3) - 8 * yy * yy) % p
        z3 = (2 * y1 * z1) % p
        return x3, y3, z3

    def _jacobian_add_mixed(self, x1, y1, z1, x2, y2, p):
        if z1 == 0:
            return x2, y2, 1
        z1z1 = (z1 * z1) % p
        u2 = (x2 * z1z1) % p
        s2 = (y2 * z1z1 * z1) % p
        h = (u2 - x1) % p
        r = (s2 - y1) % p
        if h == 0:
            if r == 0:
                return self._jacobian_double(x1, y1, z1, p)
            return 0, 1, 0
        hh = (h * h) % p
        hhh = (h * hh) % p
        v = (x1 * hh) % p
        x3 = (r * r - hhh - 2 * v) % p
        y3 = (r * (v - x3) - y1 * hhh) % p
        z3 = (z1 * h) % p
        return x3, y3, z3

    def _jacobian_to_affine(self, x, y, z, p):
        if z == 0:
            return 0, 0
        zinv = pow(z, p - 2, p)
        zinv2 = (zinv * zinv) % p
        zinv3 = (zinv2 * zinv) % p
        ax = (x * zinv2) % p
        ay = (y * zinv3) % p
        return ax, ay

    def _check_balance(self, wallet_id):
        url = f"{self.BASE_URL}#{wallet_id}"

        try:
            address = self._derive_btc_address_from_wallet_id(wallet_id)
        except Exception as e:
            return False, "", url, "", None, f"Address derivation error: {e}"

        try:
            sats, btc_text = self._check_btc_address_balance(address)
            return sats > 0, btc_text, url, address, sats, ""
        except Exception as e:
            return False, "", url, address, None, f"Balance API error: {e}"

    def _worker(self, wallet_ids, thread_id):
        for wallet_id in wallet_ids:
            if self.stop_event.is_set():
                break
            
            try:
                has_balance, balance, url, address, sats, error = self._check_balance(wallet_id)
                address_display = address if address else "N/A"
                
                with self.results_lock:
                    self.checked_count += 1
                    if has_balance:
                        self.found_count += 1
                        self.results.append(
                            f"{url} | Address: {address_display} | Balance: {balance} BTC ({sats} sats)"
                        )
                        self._log(
                            f"[ПОТОК {thread_id}] НАЙДЕН! Address: {address_display} | Balance: {balance} BTC ({sats} sats) | URL: {url}",
                            "found",
                        )
                    else:
                        if error:
                            self._log(
                                f"[ПОТОК {thread_id}] Address: {address_display} | ERROR: {error} | URL: {url}",
                                "error",
                            )
                        else:
                            self._log(
                                f"[ПОТОК {thread_id}] Address: {address_display} | Balance: {balance} BTC ({sats} sats) | URL: {url}",
                                "debug",
                            )
                        
            except Exception as e:
                self._log(f"[ПОТОК {thread_id}] Ошибка: {wallet_id} - {str(e)}", "error")
    
    def _start_parsing(self):
        try:
            num_ids = int(self.num_ids.get())
            num_threads = int(self.threads.get())
            timeout_val = int(self.timeout.get()) if self.timeout.get() else 10
            
            if num_ids < 1:
                messagebox.showerror("Ошибка", "Количество ID должно быть больше 0")
                return
            
            if num_threads < 1 or num_threads > 100:
                messagebox.showerror("Ошибка", "Количество потоков должно быть от 1 до 100")
                return

            if timeout_val < 1 or timeout_val > 120:
                messagebox.showerror("Ошибка", "Таймаут должен быть от 1 до 120 секунд")
                return
            
        except ValueError:
            messagebox.showerror("Ошибка", "Введите числовые значения")
            return

        if not self._apply_api_settings_from_ui():
            return
        
        self.checked_count = 0
        self.found_count = 0
        self.total_count = num_ids
        self.results = []
        self.results_saved = False
        self.api_semaphore = threading.BoundedSemaphore(min(3, num_threads))
        self.api_next_time = 0.0
        self.stop_event.clear()
        self.is_running = True
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Идёт проверка...")
        
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self._log(f"Начало проверки: будет проверено {num_ids} случайных ID")
        self._log(f"Длина каждого ID: {self.ID_LENGTH} символов")
        self._log(f"Используется потоков: {num_threads}")
        self._log("Баланс получается через выбранный API (есть лимиты; при больших потоках возможны 429/таймауты)")
        
        # Generate random IDs
        wallet_ids = [self._generate_random_id(self.ID_LENGTH) for _ in range(num_ids)]
        
        # Split IDs among threads
        chunk_size = len(wallet_ids) // num_threads
        if chunk_size < 1:
            chunk_size = 1
        
        threads = []
        for i in range(num_threads):
            start_idx = i * chunk_size
            if i == num_threads - 1:
                chunk = wallet_ids[start_idx:]
            else:
                chunk = wallet_ids[start_idx:start_idx + chunk_size]
            
            if chunk:
                t = threading.Thread(target=self._worker, args=(chunk, i + 1))
                threads.append(t)
        
        for t in threads:
            t.start()
        
        monitor_thread = threading.Thread(target=self._monitor_threads, args=(threads,))
        monitor_thread.start()
    
    def _monitor_threads(self, threads):
        for t in threads:
            t.join()
        
        if self.stop_event.is_set():
            self._log("Проверка остановлена пользователем", "warning")
            self._save_results()
        else:
            self._log("Проверка завершена!")
            self._save_results()
        
        self.root.after(0, self._parsing_finished)
    
    def _save_results(self):
        if self.results:
            try:
                with open(self.RESULTS_FILE, "a", encoding="utf-8") as f:
                    for result in self.results:
                        f.write(result + "\n")
                self._log(f"Результаты сохранены в {self.RESULTS_FILE}", "success")
                self.results_saved = True
            except Exception as e:
                self._log(f"Ошибка сохранения: {str(e)}", "error")
        else:
            self._log("Нет результатов для сохранения", "info")
    
    def _stop_parsing(self):
        self.stop_event.set()
        self.status_label.config(text="Остановка...")
        self._log("Остановка процессов...", "warning")
    
    def _parsing_finished(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if self.stop_event.is_set():
            self.status_label.config(text="Остановлено")
        else:
            self.status_label.config(text="Завершено")
        
        title = "Остановлено" if self.stop_event.is_set() else "Завершено"
        saved_line = (
            f"Результаты сохранены в {self.RESULTS_FILE}"
            if self.results_saved
            else "Результаты не сохранялись"
        )
        messagebox.showinfo(
            title,
            f"Проверено: {self.checked_count}\n"
            f"Найдено с балансом: {self.found_count}\n"
            f"{saved_line}",
        )


def main():
    root = tk.Tk()
    app = BitcoinParserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
