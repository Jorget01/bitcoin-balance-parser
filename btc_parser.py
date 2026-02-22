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

    PROXY_SOURCES = [
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    ]
    PROXY_REFRESH_INTERVAL = 300  # seconds

    I18N = {
        "ru": {
            "app_title": "Bitcoin Balance Parser",
            "info": "Генерация случайных ID (30 символов) и проверка баланса",
            "settings": "Настройки",
            "language": "Язык:",
            "lang_ru": "Русский",
            "lang_en": "English",
            "num_ids": "Количество ID для проверки:",
            "threads": "Потоков:",
            "timeout": "Таймаут (сек):",
            "id_length": "Длина ID:",
            "id_length_value": "30 символов (a-z, A-Z, 0-9)",
            "check_input": "Проверить адрес/URL:",
            "check_btn": "Проверить",
            "api_provider": "Провайдер API:",
            "custom_api": "Custom API base URL:",
            "api_rps": "Запросов/сек (API):",
            "api_pause_429": "Пауза при 429 (сек):",
            "use_proxies": "Использовать прокси (ротация при 429)",
            "refresh_proxies": "Обновить список прокси",
            "proxy_off": "Прокси: выключено",
            "proxy_on_no_pick": "Прокси: включено (не выбрано)",
            "proxy_on_empty": "Прокси: включено (список пуст)",
            "proxy_current": "Прокси: {proxy}",
            "my_proxies": "Мои прокси (по одному в строке):",
            "apply_my_proxies": "Применить мои прокси",
            "clear": "Очистить",
            "found_wallets": "Найденные кошельки",
            "tab_balance": "С балансом",
            "tab_tx": "С транзакциями",
            "counts": "С балансом: {pos} | С транзакциями: {tx}",
            "start": "Старт",
            "stop": "Стоп",
            "stats_frame": "Статистика",
            "stats": "Проверено: {checked} | Найдено: {found} | Всего: {total}",
            "log_frame": "Лог (можно выделять и копировать)",
            "status_ready": "Готов к работе",
            "status_running": "Идёт проверка...",
            "status_stopping": "Остановка...",
            "status_stopped": "Остановлено",
            "status_done": "Завершено",
            "menu_copy": "Копировать",
            "menu_select_all": "Выделить всё",
            "menu_copy_line": "Копировать строку",
            "menu_copy_addr": "Копировать адрес",
            "menu_paste": "Вставить",
            "menu_cut": "Вырезать",
            "menu_copy2": "Копировать",
            "msg_error": "Ошибка",
            "msg_info": "Информация",
            "err_api_numeric": "Поля 'Запросов/сек (API)' и 'Пауза при 429' должны быть числовыми",
            "err_api_rps_range": "Запросов/сек (API) должно быть > 0 и <= 50",
            "err_api_pause_range": "Пауза при 429 должна быть от 1 до 3600 секунд",
            "err_single_input": "Введите bitcoinco URL/ID или Bitcoin-адрес",
            "err_num_ids": "Количество ID должно быть больше 0",
            "err_threads_range": "Количество потоков должно быть от 1 до 100",
            "err_timeout_range": "Таймаут должен быть от 1 до 120 секунд",
            "err_numeric": "Введите числовые значения",
            "saved_to": "Результаты сохранены в {file}",
            "not_saved": "Результаты не сохранялись",
            "summary_checked": "Проверено: {checked}",
            "summary_found": "Найдено с балансом: {found}",
        },
        "en": {
            "app_title": "Bitcoin Balance Parser",
            "info": "Generate random IDs (30 chars) and check balance",
            "settings": "Settings",
            "language": "Language:",
            "lang_ru": "Russian",
            "lang_en": "English",
            "num_ids": "IDs to check:",
            "threads": "Threads:",
            "timeout": "Timeout (sec):",
            "id_length": "ID length:",
            "id_length_value": "30 chars (a-z, A-Z, 0-9)",
            "check_input": "Check address/URL:",
            "check_btn": "Check",
            "api_provider": "API provider:",
            "custom_api": "Custom API base URL:",
            "api_rps": "Requests/sec (API):",
            "api_pause_429": "Pause on 429 (sec):",
            "use_proxies": "Use proxies (rotate on 429)",
            "refresh_proxies": "Refresh proxy list",
            "proxy_off": "Proxy: off",
            "proxy_on_no_pick": "Proxy: on (not selected)",
            "proxy_on_empty": "Proxy: on (empty list)",
            "proxy_current": "Proxy: {proxy}",
            "my_proxies": "My proxies (one per line):",
            "apply_my_proxies": "Apply my proxies",
            "clear": "Clear",
            "found_wallets": "Found wallets",
            "tab_balance": "With balance",
            "tab_tx": "With transactions",
            "counts": "With balance: {pos} | With tx: {tx}",
            "start": "Start",
            "stop": "Stop",
            "stats_frame": "Stats",
            "stats": "Checked: {checked} | Found: {found} | Total: {total}",
            "log_frame": "Log (select & copy)",
            "status_ready": "Ready",
            "status_running": "Checking...",
            "status_stopping": "Stopping...",
            "status_stopped": "Stopped",
            "status_done": "Finished",
            "menu_copy": "Copy",
            "menu_select_all": "Select all",
            "menu_copy_line": "Copy line",
            "menu_copy_addr": "Copy address",
            "menu_paste": "Paste",
            "menu_cut": "Cut",
            "menu_copy2": "Copy",
            "msg_error": "Error",
            "msg_info": "Info",
            "err_api_numeric": "Fields 'Requests/sec (API)' and 'Pause on 429' must be numeric",
            "err_api_rps_range": "'Requests/sec (API)' must be > 0 and <= 50",
            "err_api_pause_range": "'Pause on 429' must be between 1 and 3600 seconds",
            "err_single_input": "Enter a bitcoinco URL/ID or a Bitcoin address",
            "err_num_ids": "Number of IDs must be greater than 0",
            "err_threads_range": "Thread count must be between 1 and 100",
            "err_timeout_range": "Timeout must be between 1 and 120 seconds",
            "err_numeric": "Enter numeric values",
            "saved_to": "Results saved to {file}",
            "not_saved": "Results were not saved",
            "summary_checked": "Checked: {checked}",
            "summary_found": "Found with balance: {found}",
        },
    }

    # secp256k1 constants (for deriving P2PKH address from passcode like bitcoinco.org does in JS)
    _SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _SECP_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    _SECP_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    
    def __init__(self, root):
        self.root = root
        self.language_code = tk.StringVar(value="ru")
        self.root.title(self._t("app_title"))
        self.root.geometry("1100x700")
        self.root.resizable(True, True)
        
        self.num_ids = tk.StringVar(value="100")
        self.threads = tk.StringVar(value="10")
        self.timeout = tk.StringVar(value="10")
        self.api_rps = tk.StringVar(value="4")
        self.api_pause_429 = tk.StringVar(value="30")
        self.api_provider = tk.StringVar(value="Blockstream")
        self.api_custom_base_url = tk.StringVar(value="")
        self.single_input = tk.StringVar(value="")
        self.use_proxy = tk.BooleanVar(value=False)
        self.is_running = False
        self.stop_event = threading.Event()
        
        self.checked_count = 0
        self.found_count = 0
        self.total_count = 0
        self.results_saved = False
        
        self.log_queue = queue.Queue()
        self.results = []
        self.results_lock = threading.Lock()

        # Sidebar lists
        self.positive_wallets = []
        self.tx_wallets = []
        self.positive_wallets_seen = set()
        self.tx_wallets_seen = set()
        self._positive_rendered = 0
        self._tx_rendered = 0
        self.api_semaphore = threading.BoundedSemaphore(3)
        self.api_rate_lock = threading.Lock()
        self.api_next_time = 0.0
        self.api_min_interval = 0.25
        self.api_pause_seconds = 30.0
        self.api_pause_until = 0.0
        self.api_last_429_log_time = 0.0

        self.proxy_lock = threading.Lock()
        self.proxy_pool_http_public = []
        self.proxy_pool_socks5_public = []
        self.proxy_pool_http_personal = []
        self.proxy_pool_socks5_personal = []
        self.personal_proxies_set = set()

        self.proxy_pool_http = []
        self.proxy_pool_socks5 = []
        self.proxy_index_http = 0
        self.proxy_index_socks5 = 0
        self.current_proxy = None
        self.proxy_loaded = False
        self.proxy_last_refresh = 0.0
        self.proxy_ban_until = {}
        self.proxy_fail_count = {}
        self.proxy_last_rotate_log_time = 0.0
        self.proxy_disable_socks = False
        
        self._setup_ui()
        self._apply_language()
        self.root.after(100, self._poll_log_queue)

    def _t(self, key, **kwargs):
        try:
            code = (self.language_code.get() or "ru").strip().lower()
        except Exception:
            code = "ru"
        d = self.I18N.get(code) or self.I18N["ru"]
        text = d.get(key) or self.I18N["ru"].get(key) or key
        if kwargs:
            try:
                return text.format(**kwargs)
            except Exception:
                return text
        return text

    def _set_language(self, code):
        code = (code or "").strip().lower()
        if code not in ("ru", "en"):
            code = "ru"
        self.language_code.set(code)
        self._apply_language()

    def _on_language_selected(self, _event=None):
        val = (self.language_display.get() or "").strip().lower()
        if val.startswith("eng"):
            self._set_language("en")
        else:
            self._set_language("ru")

    def _apply_language(self):
        try:
            self.root.title(self._t("app_title"))
        except Exception:
            pass

        if getattr(self, "language_display", None):
            self.language_display.set("English" if self.language_code.get() == "en" else "Русский")

        for attr, key in [
            ("title_label", "app_title"),
            ("info_label", "info"),
            ("settings_frame", "settings"),
            ("lang_label", "language"),
            ("label_num_ids", "num_ids"),
            ("label_threads", "threads"),
            ("label_timeout", "timeout"),
            ("label_id_length", "id_length"),
            ("label_id_length_value", "id_length_value"),
            ("label_check", "check_input"),
            ("check_button", "check_btn"),
            ("label_api_provider", "api_provider"),
            ("label_custom_api", "custom_api"),
            ("label_api_rps", "api_rps"),
            ("label_api_pause_429", "api_pause_429"),
            ("use_proxy_check", "use_proxies"),
            ("refresh_proxies_button", "refresh_proxies"),
            ("label_my_proxies", "my_proxies"),
            ("apply_my_proxies_button", "apply_my_proxies"),
            ("clear_my_proxies_button", "clear"),
            ("sidebar_frame", "found_wallets"),
            ("stats_frame", "stats_frame"),
            ("log_frame", "log_frame"),
            ("start_button", "start"),
            ("stop_button", "stop"),
        ]:
            w = getattr(self, attr, None)
            if not w:
                continue
            try:
                if isinstance(w, ttk.LabelFrame):
                    w.config(text=self._t(key))
                else:
                    w.config(text=self._t(key))
            except Exception:
                pass

        try:
            self.sidebar_tabs.tab(0, text=self._t("tab_balance"))
            self.sidebar_tabs.tab(1, text=self._t("tab_tx"))
        except Exception:
            pass

        self._update_proxy_status()
        self._update_stats()
        try:
            self._refresh_sidebar_lists()
        except Exception:
            pass

        try:
            self._setup_log_copy_menu()
            self._setup_sidebar_copy_menu(self.positive_listbox)
            self._setup_sidebar_copy_menu(self.tx_listbox)
        except Exception:
            pass

        try:
            self._setup_entry_clipboard(self.single_entry)
            self._setup_entry_clipboard(self.custom_url_entry)
            self._setup_text_clipboard(self.personal_proxy_text)
        except Exception:
            pass
    
    def _generate_random_id(self, length=30):
        """Генерация случайного ID из букв и цифр"""
        return ''.join(random.choices(self.DEFAULT_CHARS, k=length))
    
    def _setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(3, weight=0, minsize=320)
        
        self.title_label = ttk.Label(main_frame, text=self._t("app_title"), font=("Arial", 16, "bold"))
        self.title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        self.info_label = ttk.Label(main_frame, text=self._t("info"), font=("Arial", 10))
        self.info_label.grid(row=1, column=0, columnspan=3, pady=5)
        
        self.settings_frame = ttk.LabelFrame(main_frame, text=self._t("settings"), padding="10")
        self.settings_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        self.settings_frame.columnconfigure(1, weight=1)
        
        self.lang_label = ttk.Label(self.settings_frame, text=self._t("language"))
        self.lang_label.grid(row=0, column=2, sticky=tk.E, padx=(10, 0), pady=5)
        self.language_display = tk.StringVar(value="Русский" if self.language_code.get() == "ru" else "English")
        self.lang_combo = ttk.Combobox(
            self.settings_frame,
            textvariable=self.language_display,
            values=["Русский", "English"],
            state="readonly",
            width=10,
        )
        self.lang_combo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_language_selected)

        self.label_num_ids = ttk.Label(self.settings_frame, text=self._t("num_ids"))
        self.label_num_ids.grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.num_ids, width=20).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.label_threads = ttk.Label(self.settings_frame, text=self._t("threads"))
        self.label_threads.grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.threads, width=20).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        self.label_timeout = ttk.Label(self.settings_frame, text=self._t("timeout"))
        self.label_timeout.grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.timeout, width=20).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        self.label_id_length = ttk.Label(self.settings_frame, text=self._t("id_length"))
        self.label_id_length.grid(row=3, column=0, sticky=tk.W, pady=5)
        self.label_id_length_value = ttk.Label(self.settings_frame, text=self._t("id_length_value"), foreground="gray")
        self.label_id_length_value.grid(row=3, column=1, sticky=tk.W, padx=5)

        self.label_check = ttk.Label(self.settings_frame, text=self._t("check_input"))
        self.label_check.grid(row=4, column=0, sticky=tk.W, pady=5)
        self.single_entry = ttk.Entry(self.settings_frame, textvariable=self.single_input, width=45)
        self.single_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5)
        self.check_button = ttk.Button(self.settings_frame, text=self._t("check_btn"), command=self._start_single_check)
        self.check_button.grid(row=4, column=2, sticky=tk.W, padx=5)
        self.single_entry.bind("<Return>", lambda _e: self._start_single_check())
        self._setup_entry_clipboard(self.single_entry)

        self.label_api_provider = ttk.Label(self.settings_frame, text=self._t("api_provider"))
        self.label_api_provider.grid(row=5, column=0, sticky=tk.W, pady=5)
        provider_values = list(self.API_PROVIDERS.keys()) + ["Custom (Esplora)"]
        self.provider_combo = ttk.Combobox(
            self.settings_frame,
            textvariable=self.api_provider,
            values=provider_values,
            state="readonly",
            width=20,
        )
        self.provider_combo.grid(row=5, column=1, sticky=tk.W, padx=5)

        self.label_custom_api = ttk.Label(self.settings_frame, text=self._t("custom_api"))
        self.label_custom_api.grid(row=6, column=0, sticky=tk.W, pady=5)
        self.custom_url_entry = ttk.Entry(self.settings_frame, textvariable=self.api_custom_base_url, width=45)
        self.custom_url_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), padx=5)
        self._setup_entry_clipboard(self.custom_url_entry)

        self.label_api_rps = ttk.Label(self.settings_frame, text=self._t("api_rps"))
        self.label_api_rps.grid(row=7, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.api_rps, width=20).grid(row=7, column=1, sticky=tk.W, padx=5)

        self.label_api_pause_429 = ttk.Label(self.settings_frame, text=self._t("api_pause_429"))
        self.label_api_pause_429.grid(row=8, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.api_pause_429, width=20).grid(row=8, column=1, sticky=tk.W, padx=5)

        self.use_proxy_check = ttk.Checkbutton(
            self.settings_frame,
            text=self._t("use_proxies"),
            variable=self.use_proxy,
            command=self._update_proxy_status,
        )
        self.use_proxy_check.grid(row=9, column=0, columnspan=2, sticky=tk.W, pady=5)

        self.refresh_proxies_button = ttk.Button(self.settings_frame, text=self._t("refresh_proxies"), command=self._refresh_proxies)
        self.refresh_proxies_button.grid(row=10, column=0, sticky=tk.W, pady=5)
        self.proxy_status_label = ttk.Label(self.settings_frame, text=self._t("proxy_off"), foreground="gray")
        self.proxy_status_label.grid(row=10, column=1, sticky=tk.W, padx=5, pady=5)
        self._update_proxy_status()

        self.label_my_proxies = ttk.Label(self.settings_frame, text=self._t("my_proxies"))
        self.label_my_proxies.grid(row=11, column=0, sticky=tk.W, pady=5)
        self.personal_proxy_text = scrolledtext.ScrolledText(self.settings_frame, height=4, width=45, wrap=tk.NONE)
        self.personal_proxy_text.grid(row=12, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=3)
        self._setup_text_clipboard(self.personal_proxy_text)

        self.apply_my_proxies_button = ttk.Button(self.settings_frame, text=self._t("apply_my_proxies"), command=self._apply_personal_proxies)
        self.apply_my_proxies_button.grid(row=13, column=0, sticky=tk.W, pady=5)
        self.clear_my_proxies_button = ttk.Button(self.settings_frame, text=self._t("clear"), command=lambda: self.personal_proxy_text.delete("1.0", tk.END))
        self.clear_my_proxies_button.grid(row=13, column=1, sticky=tk.W, pady=5)

        self.sidebar_frame = ttk.LabelFrame(main_frame, text=self._t("found_wallets"), padding="10")
        self.sidebar_frame.grid(row=2, column=3, rowspan=6, sticky=(tk.N, tk.S, tk.E, tk.W), padx=(10, 0), pady=5)
        self.sidebar_frame.columnconfigure(0, weight=1)
        self.sidebar_frame.rowconfigure(1, weight=1)

        self.sidebar_counts_label = ttk.Label(self.sidebar_frame, text=self._t("counts", pos=0, tx=0), foreground="gray")
        self.sidebar_counts_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))

        self.sidebar_tabs = ttk.Notebook(self.sidebar_frame)
        self.sidebar_tabs.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        positive_tab = ttk.Frame(self.sidebar_tabs)
        tx_tab = ttk.Frame(self.sidebar_tabs)
        self.sidebar_tabs.add(positive_tab, text=self._t("tab_balance"))
        self.sidebar_tabs.add(tx_tab, text=self._t("tab_tx"))

        self.positive_listbox = tk.Listbox(positive_tab, height=20, exportselection=False)
        pos_scroll = ttk.Scrollbar(positive_tab, orient=tk.VERTICAL, command=self.positive_listbox.yview)
        self.positive_listbox.configure(yscrollcommand=pos_scroll.set)
        self.positive_listbox.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        pos_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        positive_tab.columnconfigure(0, weight=1)
        positive_tab.rowconfigure(0, weight=1)

        self.tx_listbox = tk.Listbox(tx_tab, height=20, exportselection=False)
        tx_scroll = ttk.Scrollbar(tx_tab, orient=tk.VERTICAL, command=self.tx_listbox.yview)
        self.tx_listbox.configure(yscrollcommand=tx_scroll.set)
        self.tx_listbox.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        tx_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tx_tab.columnconfigure(0, weight=1)
        tx_tab.rowconfigure(0, weight=1)

        self._setup_sidebar_copy_menu(self.positive_listbox)
        self._setup_sidebar_copy_menu(self.tx_listbox)
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.start_button = ttk.Button(buttons_frame, text=self._t("start"), command=self._start_parsing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text=self._t("stop"), command=self._stop_parsing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.stats_frame = ttk.LabelFrame(main_frame, text=self._t("stats_frame"), padding="10")
        self.stats_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_label = ttk.Label(self.stats_frame, text=self._t("stats", checked=0, found=0, total=0))
        self.stats_label.pack()
        
        self.log_frame = ttk.LabelFrame(main_frame, text=self._t("log_frame"), padding="10")
        self.log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        
        main_frame.rowconfigure(5, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
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
        
        self.status_label = ttk.Label(main_frame, text=self._t("status_ready"), relief=tk.SUNKEN)
        self.status_label.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

    def _setup_sidebar_copy_menu(self, listbox):
        menu = tk.Menu(self.root, tearoff=0)

        def copy_line():
            try:
                sel = listbox.curselection()
                if not sel:
                    return
                line = listbox.get(sel[0])
                self.root.clipboard_clear()
                self.root.clipboard_append(line)
            except Exception:
                pass

        def copy_address():
            try:
                sel = listbox.curselection()
                if not sel:
                    return
                line = listbox.get(sel[0])
                address = (line.split(" | ", 1)[0] or "").strip()
                if not address:
                    return
                self.root.clipboard_clear()
                self.root.clipboard_append(address)
            except Exception:
                pass

        menu.add_command(label=self._t("menu_copy_line"), command=copy_line)
        menu.add_command(label=self._t("menu_copy_addr"), command=copy_address)

        def popup(event):
            try:
                listbox.focus_set()
                index = listbox.nearest(event.y)
                if index >= 0:
                    listbox.selection_clear(0, tk.END)
                    listbox.selection_set(index)
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        listbox.bind("<Button-3>", popup)
        listbox.bind("<Double-Button-1>", lambda _e: (copy_address(), "break")[1])
    
    def _log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        self.log_queue.put((full_message, level))

    def _setup_log_copy_menu(self):
        self._log_menu = tk.Menu(self.root, tearoff=0)
        self._log_menu.add_command(label=self._t("menu_copy"), command=self._copy_log_selection)
        self._log_menu.add_command(label=self._t("menu_select_all"), command=self._select_all_log)

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
        menu.add_command(label=self._t("menu_paste"), command=lambda: entry.event_generate("<<Paste>>"))
        menu.add_command(label=self._t("menu_copy2"), command=lambda: entry.event_generate("<<Copy>>"))
        menu.add_command(label=self._t("menu_cut"), command=lambda: entry.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label=self._t("menu_select_all"), command=lambda: self._select_all_entry(entry))

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

    def _setup_text_clipboard(self, text_widget):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=self._t("menu_paste"), command=lambda: text_widget.event_generate("<<Paste>>"))
        menu.add_command(label=self._t("menu_copy2"), command=lambda: text_widget.event_generate("<<Copy>>"))
        menu.add_command(label=self._t("menu_cut"), command=lambda: text_widget.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label=self._t("menu_select_all"), command=lambda: text_widget.tag_add(tk.SEL, "1.0", tk.END))

        def show_menu(event):
            try:
                text_widget.focus_set()
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        text_widget.bind("<Button-3>", show_menu)
        text_widget.bind("<Control-a>", lambda _e: (text_widget.tag_add(tk.SEL, "1.0", tk.END), "break")[1])
        text_widget.bind("<Control-A>", lambda _e: (text_widget.tag_add(tk.SEL, "1.0", tk.END), "break")[1])

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
        self._refresh_sidebar_lists()
        self.root.after(100, self._poll_log_queue)

    def _refresh_sidebar_lists(self):
        try:
            with self.results_lock:
                pos_new = self.positive_wallets[self._positive_rendered:]
                tx_new = self.tx_wallets[self._tx_rendered:]
                self._positive_rendered = len(self.positive_wallets)
                self._tx_rendered = len(self.tx_wallets)
                pos_count = len(self.positive_wallets)
                tx_count = len(self.tx_wallets)

            for line in pos_new:
                self.positive_listbox.insert(tk.END, line)
            for line in tx_new:
                self.tx_listbox.insert(tk.END, line)

            self.sidebar_counts_label.config(text=self._t("counts", pos=pos_count, tx=tx_count))
        except Exception:
            pass
    
    def _update_stats(self):
        self.stats_label.config(
            text=self._t("stats", checked=self.checked_count, found=self.found_count, total=self.total_count)
        )

    def _apply_api_settings_from_ui(self):
        try:
            rps = float(self.api_rps.get())
            pause_429 = float(self.api_pause_429.get())
        except ValueError:
            messagebox.showerror(self._t("msg_error"), self._t("err_api_numeric"))
            return False

        if rps <= 0 or rps > 50:
            messagebox.showerror(self._t("msg_error"), self._t("err_api_rps_range"))
            return False

        if pause_429 < 1 or pause_429 > 3600:
            messagebox.showerror(self._t("msg_error"), self._t("err_api_pause_range"))
            return False

        self.api_min_interval = 1.0 / rps
        self.api_pause_seconds = pause_429
        return True

    def _supports_socks_proxies(self):
        if self.proxy_disable_socks:
            return False
        try:
            import socks  # noqa: F401
            return True
        except Exception:
            return False

    def _update_proxy_status(self):
        if not getattr(self, "proxy_status_label", None):
            return
        if not self.use_proxy.get():
            self.proxy_status_label.config(text=self._t("proxy_off"))
            return
        with self.proxy_lock:
            proxy = self.current_proxy
            loaded = self.proxy_loaded and (bool(self.proxy_pool_http) or bool(self.proxy_pool_socks5))
        if proxy:
            self.proxy_status_label.config(text=self._t("proxy_current", proxy=proxy))
        elif loaded:
            self.proxy_status_label.config(text=self._t("proxy_on_no_pick"))
        else:
            self.proxy_status_label.config(text=self._t("proxy_on_empty"))

    def _proxy_scheme(self, proxy):
        p = (proxy or "").lower()
        if p.startswith("socks5://") or p.startswith("socks5h://"):
            return "socks5"
        return "http"

    def _parse_proxy_lines(self, text, scheme):
        out = []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "://" in line:
                proxy = line
            else:
                proxy = f"{scheme}://{line}"
            out.append(proxy)
        return out

    def _read_personal_proxies_from_ui(self):
        try:
            raw = self.personal_proxy_text.get("1.0", tk.END)
        except Exception:
            return []
        return [line.strip() for line in (raw or "").splitlines() if line.strip() and not line.strip().startswith("#")]

    def _set_personal_proxies(self, proxy_lines):
        proxies_http = []
        proxies_socks5 = []
        for line in proxy_lines:
            if "://" in line:
                scheme = "socks5" if line.lower().startswith("socks5") else "http"
                parsed = self._parse_proxy_lines(line, scheme)
            else:
                parsed = self._parse_proxy_lines(line, "http")
            for p in parsed:
                if p.lower().startswith("socks5://") or p.lower().startswith("socks5h://"):
                    proxies_socks5.append(p)
                else:
                    proxies_http.append(p)

        random.shuffle(proxies_http)
        random.shuffle(proxies_socks5)
        with self.proxy_lock:
            self.proxy_pool_http_personal = proxies_http
            self.proxy_pool_socks5_personal = proxies_socks5
            self.personal_proxies_set = set(proxies_http + proxies_socks5)
            self._rebuild_proxy_pools_locked(keep_current=False)

    def _apply_personal_proxies(self):
        lines = self._read_personal_proxies_from_ui()
        self._set_personal_proxies(lines)
        with self.proxy_lock:
            total = len(self.proxy_pool_http_personal) + len(self.proxy_pool_socks5_personal)
        self._log(f"Мои прокси применены: {total}", "info")
        self.root.after(0, self._update_proxy_status)

    def _rebuild_proxy_pools_locked(self, keep_current):
        def merge(personal, public):
            seen = set()
            out = []
            for p in list(personal) + list(public):
                if p in seen:
                    continue
                seen.add(p)
                out.append(p)
            return out

        current = self.current_proxy
        self.proxy_pool_http = merge(self.proxy_pool_http_personal, self.proxy_pool_http_public)
        self.proxy_pool_socks5 = merge(self.proxy_pool_socks5_personal, self.proxy_pool_socks5_public)

        if keep_current and current and (current in self.proxy_pool_http or current in self.proxy_pool_socks5):
            self.current_proxy = current
        else:
            self.current_proxy = None

    def _refresh_proxies(self, force=False):
        now = time.monotonic()
        if not force:
            with self.proxy_lock:
                if self.proxy_loaded and (now - self.proxy_last_refresh) < self.PROXY_REFRESH_INTERVAL:
                    return

        try:
            timeout_val = int(self.timeout.get()) if self.timeout.get() else 10
        except Exception:
            timeout_val = 10

        proxies_http = []
        proxies_socks5 = []
        socks_supported = self._supports_socks_proxies()
        for url in self.PROXY_SOURCES:
            try:
                resp = requests.get(url, timeout=min(20, timeout_val), headers={"User-Agent": "btc-parser/1.0"})
                resp.raise_for_status()
                scheme = "http" if "/http/" in url else "socks5"
                if scheme == "socks5" and not socks_supported:
                    continue
                parsed = self._parse_proxy_lines(resp.text, scheme)
                if scheme == "socks5":
                    proxies_socks5.extend(parsed)
                else:
                    proxies_http.extend(parsed)
            except Exception as e:
                self._log(f"Не удалось загрузить прокси из {url}: {e}", "warning")

        random.shuffle(proxies_http)
        random.shuffle(proxies_socks5)
        with self.proxy_lock:
            self.proxy_pool_http_public = proxies_http
            self.proxy_pool_socks5_public = proxies_socks5
            self.proxy_loaded = True
            self.proxy_last_refresh = now
            self.proxy_index_http = 0
            self.proxy_index_socks5 = 0
            self.proxy_ban_until = {}
            self.proxy_fail_count = {}
            self._rebuild_proxy_pools_locked(keep_current=True)
        self._log(f"Загружено прокси: {len(proxies_http) + len(proxies_socks5)}", "info")
        self.root.after(0, self._update_proxy_status)

    def _pick_next_proxy_locked(self, prefer_socks):
        now = time.monotonic()
        pools = []
        if prefer_socks:
            pools = [("socks5", self.proxy_pool_socks5), ("http", self.proxy_pool_http)]
        else:
            pools = [("http", self.proxy_pool_http), ("socks5", self.proxy_pool_socks5)]

        for scheme, pool in pools:
            if not pool:
                continue
            n = len(pool)
            for _ in range(n):
                idx = self.proxy_index_socks5 if scheme == "socks5" else self.proxy_index_http
                proxy = pool[idx % n]
                if scheme == "socks5":
                    self.proxy_index_socks5 += 1
                else:
                    self.proxy_index_http += 1

                until = self.proxy_ban_until.get(proxy, 0.0)
                if until and until > now:
                    continue
                if proxy not in self.personal_proxies_set and self.proxy_fail_count.get(proxy, 0) >= 3:
                    continue
                return proxy
        return None

    def _get_requests_proxies(self, target_url):
        if not self.use_proxy.get():
            return None

        with self.proxy_lock:
            has_any = bool(
                self.proxy_pool_http_personal
                or self.proxy_pool_socks5_personal
                or self.proxy_pool_http_public
                or self.proxy_pool_socks5_public
            )
        if has_any:
            self._refresh_proxies(force=False)
        else:
            self._refresh_proxies(force=True)

        prefer_socks = str(target_url or "").lower().startswith("https://")
        with self.proxy_lock:
            if not self.current_proxy:
                self.current_proxy = self._pick_next_proxy_locked(prefer_socks=prefer_socks)
            proxy = self.current_proxy
        if not proxy:
            return None
        self.root.after(0, self._update_proxy_status)
        return {"http": proxy, "https": proxy}

    def _drop_proxy_locked(self, proxy):
        if not proxy:
            return
        if proxy in self.personal_proxies_set:
            return
        scheme = self._proxy_scheme(proxy)
        if scheme == "socks5":
            self.proxy_pool_socks5_public = [p for p in self.proxy_pool_socks5_public if p != proxy]
        else:
            self.proxy_pool_http_public = [p for p in self.proxy_pool_http_public if p != proxy]

        self.proxy_ban_until.pop(proxy, None)
        self.proxy_fail_count.pop(proxy, None)
        if self.current_proxy == proxy:
            self.current_proxy = None
        self._rebuild_proxy_pools_locked(keep_current=True)

    def _rotate_proxy(self, ban_seconds, reason, prefer_socks):
        if not self.use_proxy.get():
            return None

        self._refresh_proxies(force=False)
        now = time.monotonic()
        with self.proxy_lock:
            if self.current_proxy:
                self.proxy_ban_until[self.current_proxy] = max(
                    self.proxy_ban_until.get(self.current_proxy, 0.0), now + float(ban_seconds or 0.0)
                )
                self.proxy_fail_count[self.current_proxy] = self.proxy_fail_count.get(self.current_proxy, 0) + 1
                if self.proxy_fail_count.get(self.current_proxy, 0) >= 3:
                    self._drop_proxy_locked(self.current_proxy)
            next_proxy = self._pick_next_proxy_locked(prefer_socks=prefer_socks)
            self.current_proxy = next_proxy
            should_log = (now - self.proxy_last_rotate_log_time) > 5.0
            if should_log:
                self.proxy_last_rotate_log_time = now

        if should_log and next_proxy:
            self._log(f"Смена прокси ({reason}): {next_proxy}", "warning")
        self.root.after(0, self._update_proxy_status)
        return next_proxy

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
            messagebox.showerror(self._t("msg_error"), self._t("err_single_input"))
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
                has_balance, balance, url, address, sats, error, tx_count = self._check_balance(value)
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
                            if address and address not in self.positive_wallets_seen:
                                self.positive_wallets_seen.add(address)
                                self.positive_wallets.append(
                                    f"{address} | Balance: {balance} BTC ({sats} sats) | TX: {tx_count} | {url}"
                                )

                if address and tx_count > 0:
                    with self.results_lock:
                        if address not in self.tx_wallets_seen:
                            self.tx_wallets_seen.add(address)
                            self.tx_wallets.append(
                                f"{address} | TX: {tx_count} | Balance: {balance} BTC ({sats} sats) | {url}"
                            )
            elif kind == "btc_address":
                sats, btc_text, tx_count = self._check_btc_address_balance(value)
                level = "found" if sats > 0 else "info"
                self._log(f"[РУЧНАЯ] BTC Address: {value} | Balance: {btc_text} BTC ({sats} sats)", level)
                if sats > 0:
                    with self.results_lock:
                        self.results.append(f"BTC Address: {value} | Balance: {btc_text} BTC ({sats} sats)")
                        if value not in self.positive_wallets_seen:
                            self.positive_wallets_seen.add(value)
                            self.positive_wallets.append(
                                f"{value} | Balance: {btc_text} BTC ({sats} sats) | TX: {tx_count}"
                            )

                if tx_count > 0:
                    with self.results_lock:
                        if value not in self.tx_wallets_seen:
                            self.tx_wallets_seen.add(value)
                            self.tx_wallets.append(
                                f"{value} | TX: {tx_count} | Balance: {btc_text} BTC ({sats} sats)"
                            )
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
                tx_count = int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))
                return sats, format(btc, "f"), tx_count
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
                    if self.api_pause_until and now < self.api_pause_until:
                        time.sleep(self.api_pause_until - now)
                        now = time.monotonic()
                    wait = self.api_next_time - now
                    if wait > 0:
                        time.sleep(wait)
                    self.api_next_time = max(self.api_next_time, time.monotonic()) + self.api_min_interval

                try:
                    url = f"{base_url.rstrip('/')}/api/address/{address}"
                    prefer_socks = str(url).lower().startswith("https://")
                    req_proxies = self._get_requests_proxies(url)
                    resp = requests.get(
                        url,
                        timeout=timeout_val,
                        headers={"User-Agent": "btc-parser/1.0"},
                        proxies=req_proxies,
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

                        rotated = False
                        if self.use_proxy.get():
                            rotated = bool(self._rotate_proxy(ban_seconds=sleep_s, reason="HTTP 429", prefer_socks=prefer_socks))
                        if rotated:
                            time.sleep(min(1.0, retry_after_s or 0.5))
                            continue

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
                    msg = str(e)
                    if self.use_proxy.get() and (
                        isinstance(e, requests.exceptions.ProxyError)
                        or isinstance(e, requests.exceptions.SSLError)
                        or isinstance(e, requests.exceptions.ConnectionError)
                        or "socks" in msg.lower()
                    ):
                        if "Missing dependencies for SOCKS support" in msg or ("InvalidSchema" in msg and "socks" in msg.lower()):
                            self.proxy_disable_socks = True
                            self._log("SOCKS5 прокси недоступны (установите requests[socks]) — отключаю socks5.", "warning")
                            with self.proxy_lock:
                                self.current_proxy = None
                                self.proxy_pool_socks5_public = []
                                self.proxy_pool_socks5_personal = []
                                self.personal_proxies_set = {p for p in self.personal_proxies_set if not p.lower().startswith("socks5")}
                                self._rebuild_proxy_pools_locked(keep_current=False)
                        self._rotate_proxy(ban_seconds=30.0, reason="proxy error", prefer_socks=prefer_socks)
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
            return False, "", url, "", None, f"Address derivation error: {e}", 0

        try:
            sats, btc_text, tx_count = self._check_btc_address_balance(address)
            return sats > 0, btc_text, url, address, sats, "", tx_count
        except Exception as e:
            return False, "", url, address, None, f"Balance API error: {e}", 0

    def _worker(self, wallet_ids, thread_id):
        for wallet_id in wallet_ids:
            if self.stop_event.is_set():
                break
            
            try:
                has_balance, balance, url, address, sats, error, tx_count = self._check_balance(wallet_id)
                address_display = address if address else "N/A"
                
                with self.results_lock:
                    self.checked_count += 1
                    if has_balance:
                        self.found_count += 1
                        self.results.append(
                            f"{url} | Address: {address_display} | Balance: {balance} BTC ({sats} sats)"
                        )
                        if address:
                            key = address
                            if key not in self.positive_wallets_seen:
                                self.positive_wallets_seen.add(key)
                                self.positive_wallets.append(
                                    f"{address} | Balance: {balance} BTC ({sats} sats) | TX: {tx_count} | {url}"
                                )
                        self._log(
                            f"[ПОТОК {thread_id}] НАЙДЕН! Address: {address_display} | Balance: {balance} BTC ({sats} sats) | TX: {tx_count} | URL: {url}",
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
                                f"[ПОТОК {thread_id}] Address: {address_display} | Balance: {balance} BTC ({sats} sats) | TX: {tx_count} | URL: {url}",
                                "debug",
                            )

                    if address and tx_count > 0:
                        key = address
                        if key not in self.tx_wallets_seen:
                            self.tx_wallets_seen.add(key)
                            self.tx_wallets.append(
                                f"{address} | TX: {tx_count} | Balance: {balance} BTC ({sats} sats) | {url}"
                            )
                        
            except Exception as e:
                self._log(f"[ПОТОК {thread_id}] Ошибка: {wallet_id} - {str(e)}", "error")
    
    def _start_parsing(self):
        try:
            num_ids = int(self.num_ids.get())
            num_threads = int(self.threads.get())
            timeout_val = int(self.timeout.get()) if self.timeout.get() else 10
            
            if num_ids < 1:
                messagebox.showerror(self._t("msg_error"), self._t("err_num_ids"))
                return
            
            if num_threads < 1 or num_threads > 100:
                messagebox.showerror(self._t("msg_error"), self._t("err_threads_range"))
                return

            if timeout_val < 1 or timeout_val > 120:
                messagebox.showerror(self._t("msg_error"), self._t("err_timeout_range"))
                return
            
        except ValueError:
            messagebox.showerror(self._t("msg_error"), self._t("err_numeric"))
            return

        if not self._apply_api_settings_from_ui():
            return
        
        self.checked_count = 0
        self.found_count = 0
        self.total_count = num_ids
        self.results = []
        self.results_saved = False
        with self.results_lock:
            self.positive_wallets = []
            self.tx_wallets = []
            self.positive_wallets_seen = set()
            self.tx_wallets_seen = set()
            self._positive_rendered = 0
            self._tx_rendered = 0
        try:
            self.positive_listbox.delete(0, tk.END)
            self.tx_listbox.delete(0, tk.END)
            self.sidebar_counts_label.config(text=self._t("counts", pos=0, tx=0))
        except Exception:
            pass

        if self.use_proxy.get():
            self._refresh_proxies(force=False)
        self.api_semaphore = threading.BoundedSemaphore(min(3, num_threads))
        self.api_next_time = 0.0
        self.stop_event.clear()
        self.is_running = True
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text=self._t("status_running"))
        
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
        self.status_label.config(text=self._t("status_stopping"))
        self._log("Остановка процессов...", "warning")
    
    def _parsing_finished(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if self.stop_event.is_set():
            self.status_label.config(text=self._t("status_stopped"))
        else:
            self.status_label.config(text=self._t("status_done"))
        
        title = self._t("status_stopped") if self.stop_event.is_set() else self._t("status_done")
        saved_line = (
            self._t("saved_to", file=self.RESULTS_FILE)
            if self.results_saved
            else self._t("not_saved")
        )
        messagebox.showinfo(
            title,
            f"{self._t('summary_checked', checked=self.checked_count)}\n"
            f"{self._t('summary_found', found=self.found_count)}\n"
            f"{saved_line}",
        )


def main():
    root = tk.Tk()
    app = BitcoinParserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
