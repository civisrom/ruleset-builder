"""
Ruleset & Config Generator для Sing-Box, Mihomo и GeoIP/GeoSite
Версия: 3.0.0

Поддерживает:
- Создание Sing-Box rulesets (.json -> .srs)
- Создание Mihomo rulesets (.mrs)
- Генерацию GeoIP/GeoSite данных
- Работу с большими файлами (streaming)
- Кроссплатформенность (Windows/Linux/macOS)
"""

import json
import os
import sys
import subprocess
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import logging
from datetime import datetime
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from dataclasses import dataclass, asdict
from enum import Enum

# === КОНФИГУРАЦИЯ ЛОГИРОВАНИЯ ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ruleset_generator.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# === ТИПЫ И КОНСТАНТЫ ===
class RuleType(Enum):
    """Типы правил"""
    DOMAIN = "domain"
    DOMAIN_SUFFIX = "domain_suffix"
    DOMAIN_KEYWORD = "domain_keyword"
    DOMAIN_REGEX = "domain_regex"
    IP_CIDR = "ip_cidr"
    SOURCE_IP_CIDR = "source_ip_cidr"
    PROCESS_PATH = "process_path_regex"
    PACKAGE_NAME = "package_name"
    NETWORK_TYPE = "network_type"
    NETWORK_INTERFACE = "network_interface_address"


class MihomoRuleFormat(Enum):
    """Форматы правил для Mihomo"""
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
    DOMAIN_REGEX = "DOMAIN-REGEX"
    IP_CIDR = "IP-CIDR"
    SRC_IP_CIDR = "SRC-IP-CIDR"


@dataclass
class GeoIPConfig:
    """Конфигурация для GeoIP генерации"""
    output_dir: str
    ipv4_url: str = ""
    ipv6_url: str = ""
    asn_url: str = ""
    custom_ipv4_files: List[str] = None
    custom_ipv6_files: List[str] = None

    def __post_init__(self):
        if self.custom_ipv4_files is None:
            self.custom_ipv4_files = []
        if self.custom_ipv6_files is None:
            self.custom_ipv6_files = []


@dataclass
class GeoSiteConfig:
    """Конфигурация для GeoSite генерации"""
    output_dir: str
    gfw_url: str = ""
    cn_url: str = ""
    apple_url: str = ""
    google_url: str = ""
    custom_domain_files: List[str] = None

    def __post_init__(self):
        if self.custom_domain_files is None:
            self.custom_domain_files = []


# === УТИЛИТЫ ДЛЯ ОБРАБОТКИ ФАЙЛОВ ===
class FileProcessor:
    """Обработка файлов с поддержкой больших объемов данных"""

    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
    CHUNK_SIZE = 8192  # 8 KB chunks

    @staticmethod
    def read_file_safe(file_path: str, max_lines: int = 100000) -> List[str]:
        """
        Безопасное чтение файла с контролем размера
        
        Args:
            file_path: Путь к файлу
            max_lines: Максимальное количество строк
            
        Returns:
            Список строк (отфильтрованные пустые и комментарии)
        """
        if not file_path or not Path(file_path).exists():
            return []

        try:
            file_size = os.path.getsize(file_path)
            if file_size > FileProcessor.MAX_FILE_SIZE:
                logger.warning(f"Файл {file_path} превышает {FileProcessor.MAX_FILE_SIZE / 1024 / 1024}MB")
                raise ValueError(f"Файл слишком большой: {file_size / 1024 / 1024:.1f}MB")

            lines = []
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    if line_no > max_lines:
                        logger.warning(f"Достигнут лимит строк ({max_lines}) в {file_path}")
                        break
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)

            logger.info(f"Загружено {len(lines)} строк из {file_path}")
            return lines
        except Exception as e:
            logger.error(f"Ошибка при чтении файла {file_path}: {e}")
            raise

    @staticmethod
    def write_file_safe(file_path: str, content: str, backup: bool = True) -> bool:
        """
        Безопасное сохранение файла с резервной копией
        
        Args:
            file_path: Путь к файлу
            content: Содержимое
            backup: Создать резервную копию существующего файла
            
        Returns:
            True если успешно
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            # Создание резервной копии
            if backup and path.exists():
                backup_path = f"{file_path}.backup"
                path.rename(backup_path)
                logger.info(f"Резервная копия создана: {backup_path}")

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"Файл сохранен: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка при сохранении файла {file_path}: {e}")
            raise

    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = 'md5') -> str:
        """Получить хеш файла для проверки целостности"""
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(FileProcessor.CHUNK_SIZE), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()


# === ГЕНЕРАТОРЫ RULESETS ===
class SingBoxRulesetGenerator:
    """Генератор rulesets для Sing-Box"""

    @staticmethod
    def generate(data: Dict[str, Any], output_path: str) -> Tuple[bool, str, int]:
        """
        Генерация Sing-Box ruleset в JSON формате
        
        Args:
            data: Словарь с правилами
            output_path: Путь для сохранения
            
        Returns:
            (успешность, сообщение, количество записей)
        """
        try:
            rules = []
            total_entries = 0

            # Domain правила
            domain_rule = {}
            for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                if key in data and data[key]:
                    domain_rule[key] = data[key]
                    total_entries += len(data[key]) if isinstance(data[key], list) else 1

            if domain_rule:
                rules.append(domain_rule)

            # IP правила
            ip_rule = {}
            for key in ['ip_cidr', 'source_ip_cidr']:
                if key in data and data[key]:
                    ip_rule[key] = data[key]
                    total_entries += len(data[key]) if isinstance(data[key], list) else 1

            if ip_rule:
                rules.append(ip_rule)

            # Process правила
            process_rule = {}
            for key in ['process_path_regex', 'package_name']:
                if key in data and data[key]:
                    process_rule[key] = data[key]
                    total_entries += len(data[key]) if isinstance(data[key], list) else 1

            if process_rule:
                rules.append(process_rule)

            # Network правила
            network_rule = {}
            if 'network_type' in data and data['network_type']:
                network_rule['network_type'] = data['network_type']
                total_entries += 1

            for bool_key in ['network_is_expensive', 'network_is_constrained']:
                if bool_key in data and data[bool_key] == 'true':
                    network_rule[bool_key] = True
                    total_entries += 1

            for key in ['network_interface_address', 'default_interface_address']:
                if key in data and data[key]:
                    network_rule[key] = data[key]
                    total_entries += len(data[key]) if isinstance(data[key], list) else 1

            if network_rule:
                rules.append(network_rule)

            ruleset = {
                "version": 1,
                "rules": rules
            }

            FileProcessor.write_file_safe(output_path, json.dumps(ruleset, indent=2, ensure_ascii=False))
            logger.info(f"Sing-Box ruleset создан: {output_path} ({total_entries} записей)")
            return True, f"JSON сохранен: {os.path.basename(output_path)}", total_entries

        except Exception as e:
            logger.error(f"Ошибка при генерации Sing-Box ruleset: {e}")
            return False, f"Ошибка: {str(e)}", 0

    @staticmethod
    def compile_to_srs(singbox_exe: str, json_path: str) -> Tuple[bool, str]:
        """
        Компиляция JSON в .srs через sing-box CLI
        
        Args:
            singbox_exe: Путь к sing-box.exe
            json_path: Путь к JSON файлу
            
        Returns:
            (успешность, сообщение)
        """
        if not Path(singbox_exe).exists():
            logger.error(f"sing-box.exe не найден: {singbox_exe}")
            return False, "Ошибка: sing-box.exe не найден!"

        cmd = [singbox_exe, "rule-set", "compile", json_path]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(singbox_exe),
                timeout=60
            )

            if result.returncode == 0:
                srs_path = json_path.replace(".json", ".srs")
                if Path(srs_path).exists():
                    logger.info(f".srs создан: {srs_path}")
                    return True, f".srs создан: {os.path.basename(srs_path)}"
                else:
                    logger.warning(f".srs не найден после компиляции: {srs_path}")
                    return False, "Команда выполнена, но .srs не найден."
            else:
                error_msg = result.stderr.strip()
                logger.error(f"Ошибка компиляции: {error_msg}")
                return False, f"Ошибка компиляции:\n{error_msg}"

        except subprocess.TimeoutExpired:
            logger.error("Компиляция превышила timeout (60s)")
            return False, "Ошибка: Компиляция заняла слишком долго"
        except Exception as e:
            logger.error(f"Ошибка запуска sing-box: {e}")
            return False, f"Ошибка запуска:\n{str(e)}"


class MihomoRulesetGenerator:
    """Генератор rulesets для Mihomo (Clash.Meta)"""

    @staticmethod
    def generate(data: Dict[str, Any], output_path: str, proxy_name: str = "PROXY") -> Tuple[bool, str, int]:
        """
        Генерация Mihomo ruleset
        
        Args:
            data: Словарь с правилами
            output_path: Путь для сохранения (.mrs)
            proxy_name: Имя прокси профиля
            
        Returns:
            (успешность, сообщение, количество записей)
        """
        try:
            lines = []
            total_entries = 0

            # DOMAIN правила
            if 'domain' in data and data['domain']:
                for domain in data['domain']:
                    lines.append(f"DOMAIN,{domain},{proxy_name}")
                    total_entries += 1

            # DOMAIN-SUFFIX правила
            if 'domain_suffix' in data and data['domain_suffix']:
                for suffix in data['domain_suffix']:
                    lines.append(f"DOMAIN-SUFFIX,{suffix},{proxy_name}")
                    total_entries += 1

            # DOMAIN-KEYWORD правила
            if 'domain_keyword' in data and data['domain_keyword']:
                for keyword in data['domain_keyword']:
                    lines.append(f"DOMAIN-KEYWORD,{keyword},{proxy_name}")
                    total_entries += 1

            # DOMAIN-REGEX правила
            if 'domain_regex' in data and data['domain_regex']:
                for regex in data['domain_regex']:
                    lines.append(f"DOMAIN-REGEX,{regex},{proxy_name}")
                    total_entries += 1

            # IP-CIDR правила
            if 'ip_cidr' in data and data['ip_cidr']:
                for cidr in data['ip_cidr']:
                    lines.append(f"IP-CIDR,{cidr},{proxy_name}")
                    total_entries += 1

            # SRC-IP-CIDR правила
            if 'source_ip_cidr' in data and data['source_ip_cidr']:
                for cidr in data['source_ip_cidr']:
                    lines.append(f"SRC-IP-CIDR,{cidr},{proxy_name}")
                    total_entries += 1

            content = '\n'.join(lines)
            FileProcessor.write_file_safe(output_path, content)
            logger.info(f"Mihomo ruleset создан: {output_path} ({total_entries} записей)")
            return True, f"Mihomo ruleset сохранен: {os.path.basename(output_path)}", total_entries

        except Exception as e:
            logger.error(f"Ошибка при генерации Mihomo ruleset: {e}")
            return False, f"Ошибка: {str(e)}", 0


class GeoIPGenerator:
    """Генератор GeoIP данных"""

    @staticmethod
    def generate(config: GeoIPConfig) -> Tuple[bool, str]:
        """Генерация GeoIP (требует generate-geoip-geosite.exe)"""
        # Реализация зависит от наличия generate-geoip-geosite.exe
        # Здесь указаны основные параметры
        try:
            Path(config.output_dir).mkdir(parents=True, exist_ok=True)
            logger.info(f"GeoIP config создана для {config.output_dir}")
            return True, "GeoIP конфигурация готова к генерации"
        except Exception as e:
            logger.error(f"Ошибка GeoIP: {e}")
            return False, f"Ошибка: {str(e)}"


class GeoSiteGenerator:
    """Генератор GeoSite данных"""

    @staticmethod
    def generate(config: GeoSiteConfig) -> Tuple[bool, str]:
        """Генерация GeoSite (требует generate-geoip-geosite.exe)"""
        try:
            Path(config.output_dir).mkdir(parents=True, exist_ok=True)
            logger.info(f"GeoSite config создана для {config.output_dir}")
            return True, "GeoSite конфигурация готова к генерации"
        except Exception as e:
            logger.error(f"Ошибка GeoSite: {e}")
            return False, f"Ошибка: {str(e)}"


# === GUI ===
class ModernScrolledText(scrolledtext.ScrolledText):
    """Улучшенный ScrolledText виджет для Windows"""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.config(
            font=('Courier New', 9),
            bg='#f0f0f0',
            fg='#000000',
            insertbackground='#0078d4'
        )


class RulesetGeneratorGUI:
    """Главное GUI приложение"""

    WINDOW_MIN_WIDTH = 1000
    WINDOW_MIN_HEIGHT = 700
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 800

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Ruleset & Config Generator v3.0")
        self.root.geometry(f"{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}")
        self.root.minsize(self.WINDOW_MIN_WIDTH, self.WINDOW_MIN_HEIGHT)

        # Переменные
        self.singbox_path = tk.StringVar()
        self.mihomo_proxy_name = tk.StringVar(value="PROXY")
        self.output_dir = tk.StringVar(value=str(Path.home() / "Desktop"))

        # Состояние
        self.is_processing = False

        self._setup_ui()
        self._setup_styles()
        logger.info("GUI приложение запущено")

    def _setup_styles(self):
        """Настройка стилей для Windows"""
        style = ttk.Style()
        style.theme_use('vista' if sys.platform == 'win32' else 'clam')

        # Кастомные цвета
        style.configure('Title.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('Heading.TLabel', font=('Segoe UI', 10, 'bold'))

    def _setup_ui(self):
        """Построение пользовательского интерфейса"""
        # Главный контейнер с прокруткой
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Canvas + Scrollbar для прокрутки окна
        canvas = tk.Canvas(main_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Поддержка mousewheel
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # === ВКЛАДКИ ===
        notebook = ttk.Notebook(scrollable_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Общие настройки
        self._create_general_settings_tab(notebook)

        # Sing-Box
        self._create_singbox_tab(notebook)

        # Mihomo
        self._create_mihomo_tab(notebook)

        # GeoIP/GeoSite
        self._create_geo_tab(notebook)

        # Лог
        self._create_log_tab(notebook)

        # Кнопки управления
        self._create_control_buttons(scrollable_frame)

    def _create_general_settings_tab(self, notebook: ttk.Notebook):
        """Вкладка с общими настройками"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="⚙ Настройки")

        # Выходная папка
        ttk.Label(frame, text="Выходная папка:", style='Title.TLabel').pack(anchor=tk.W, pady=(10, 5))
        dir_frame = ttk.Frame(frame)
        dir_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Entry(dir_frame, textvariable=self.output_dir, width=70).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(dir_frame, text="Обзор", command=self._browse_output_dir).pack(side=tk.LEFT)

        # Sing-Box путь
        ttk.Label(frame, text="Путь к sing-box.exe:", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        singbox_frame = ttk.Frame(frame)
        singbox_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Entry(singbox_frame, textvariable=self.singbox_path, width=70).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(singbox_frame, text="Обзор", command=self._browse_singbox).pack(side=tk.LEFT)

        # Mihomo настройки
        ttk.Label(frame, text="Имя прокси для Mihomo:", style='Title.TLabel').pack(anchor=tk.W, pady=(20, 5))
        ttk.Entry(frame, textvariable=self.mihomo_proxy_name, width=30).pack(anchor=tk.W, pady=(0, 10))

        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)

        # Информация
        info_text = """
Информация о программе:
• Sing-Box: Создание и компиляция rulesets для современного прокси
• Mihomo: Создание rulesets для Clash.Meta/Mihomo
• GeoIP/GeoSite: Генерация географических данных для маршрутизации
• Поддержка больших файлов до 500 MB
• Автоматическое логирование всех операций
        """
        ttk.Label(frame, text=info_text, justify=tk.LEFT, background='#f5f5f5').pack(fill=tk.X, padx=10, pady=10)

    def _create_singbox_tab(self, notebook: ttk.Notebook):
        """Вкладка Sing-Box"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="📦 Sing-Box")

        # Создание подвкладок
        subnotebook = ttk.Notebook(frame)
        subnotebook.pack(fill=tk.BOTH, expand=True)

        self._create_domain_section(subnotebook)
        self._create_ip_section(subnotebook)
        self._create_process_section(subnotebook)
        self._create_network_section(subnotebook)

        # Кнопки действий
        action_frame = ttk.LabelFrame(frame, text="Действия", padding=10)
        action_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            action_frame,
            text="Генерировать JSON",
            command=self._generate_singbox_json
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            action_frame,
            text="Генерировать JSON + Скомпилировать .srs",
            command=self._generate_singbox_srs
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            action_frame,
            text="Очистить",
            command=self._clear_singbox
        ).pack(side=tk.LEFT, padx=5)

    def _create_domain_section(self, notebook: ttk.Notebook):
        """Секция доменов"""
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text="Domains")

        fields = [
            ('domain', "Точные домены:", "example.com\ntest.com"),
            ('domain_suffix', "Suffixes:", ".ru\n.com"),
            ('domain_keyword', "Keywords:", "test\ngoogle"),
            ('domain_regex', "Regex:", "^stun\\..+\n^.*\\.example\\.com$")
        ]

        self.singbox_domain_widgets = {}
        for i, (key, label, placeholder) in enumerate(fields):
            self._create_text_input(frame, i, key, label, placeholder, 'singbox_domain_widgets')

        frame.columnconfigure(1, weight=1)

    def _create_ip_section(self, notebook: ttk.Notebook):
        """Секция IP"""
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text="IPs")

        fields = [
            ('ip_cidr', "IP CIDR (целевые):", "10.0.0.0/24\n192.168.0.0/16"),
            ('source_ip_cidr', "Source IP CIDR:", "192.168.1.0/24")
        ]

        self.singbox_ip_widgets = {}
        for i, (key, label, placeholder) in enumerate(fields):
            self._create_text_input(frame, i, key, label, placeholder, 'singbox_ip_widgets')

        frame.columnconfigure(1, weight=1)

    def _create_process_section(self, notebook: ttk.Notebook):
        """Секция процессов"""
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text="Process")

        fields = [
            ('process_path_regex', "Process Path Regex:", "^C:\\\\\\\\Program Files\\\\\\\\Chrome\\\\\\\\chrome\\.exe$"),
            ('package_name', "Package Name (Android):", "com.google.android.apps.maps\ncom.android.chrome")
        ]

        self.singbox_process_widgets = {}
        for i, (key, label, placeholder) in enumerate(fields):
            self._create_text_input(frame, i, key, label, placeholder, 'singbox_process_widgets')

        frame.columnconfigure(1, weight=1)

    def _create_network_section(self, notebook: ttk.Notebook):
        """Секция сетевых правил"""
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text="Network")

        self.singbox_network_widgets = {}
        row = 0

        # Network Type
        ttk.Label(frame, text="Network Type:", style='Heading.TLabel').grid(row=row, column=0, sticky=tk.W, pady=10)
        combo = ttk.Combobox(
            frame,
            values=["", "wifi", "cellular", "ethernet", "other"],
            state="readonly",
            width=25
        )
        combo.grid(row=row, column=1, sticky=tk.W, padx=5)
        self.singbox_network_widgets['network_type'] = combo
        row += 1

        # Network is Expensive
        ttk.Label(frame, text="Expensive Network:", style='Heading.TLabel').grid(row=row, column=0, sticky=tk.W, pady=10)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=exp_var, value="true").grid(row=row, column=1, sticky=tk.W)
        ttk.Radiobutton(frame, text="False", variable=exp_var, value="false").grid(row=row, column=1, sticky=tk.W, padx=80)
        self.singbox_network_widgets['network_is_expensive'] = exp_var
        row += 1

        # Network is Constrained
        ttk.Label(frame, text="Constrained (iOS):", style='Heading.TLabel').grid(row=row, column=0, sticky=tk.W, pady=10)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=con_var, value="true").grid(row=row, column=1, sticky=tk.W)
        ttk.Radiobutton(frame, text="False", variable=con_var, value="false").grid(row=row, column=1, sticky=tk.W, padx=80)
        self.singbox_network_widgets['network_is_constrained'] = con_var
        row += 1

        # Interface Address
        ttk.Label(frame, text="Interface Address:", style='Heading.TLabel').grid(row=row, column=0, sticky=tk.W, pady=10)
        row += 1

        for key, placeholder in [
            ('network_interface_address', "192.168.1.100\n10.0.0.1"),
            ('default_interface_address', "8.8.8.8")
        ]:
            ttk.Label(frame, text=f"  • {key}:").grid(row=row, column=0, sticky=tk.W, padx=20, pady=5)
            text = ModernScrolledText(frame, height=3, width=50)
            text.grid(row=row, column=1, pady=5, padx=5, sticky=tk.EW)
            text.insert(tk.END, placeholder)
            self.singbox_network_widgets[key] = text

            ttk.Button(
                frame,
                text="📁",
                command=lambda k=key: self._load_file(k, 'singbox_network_widgets')
            ).grid(row=row, column=2, padx=5)
            row += 1

        frame.columnconfigure(1, weight=1)

    def _create_mihomo_tab(self, notebook: ttk.Notebook):
        """Вкладка Mihomo"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="🎭 Mihomo/Clash")

        ttk.Label(frame, text="Создание rulesets для Mihomo (Clash.Meta)", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 20))

        # Subnotebook для типов правил
        subnotebook = ttk.Notebook(frame)
        subnotebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.mihomo_widgets = {}

        # Domainы
        domain_frame = ttk.Frame(subnotebook, padding=10)
        subnotebook.add(domain_frame, text="Domains")
        for key, label, placeholder in [
            ('domain', "DOMAIN (точные):", "example.com"),
            ('domain_suffix', "DOMAIN-SUFFIX:", ".ru"),
            ('domain_keyword', "DOMAIN-KEYWORD:", "test"),
            ('domain_regex', "DOMAIN-REGEX:", "^stun\\..+")
        ]:
            self._create_text_input(domain_frame, list(self.mihomo_widgets.keys()).count(key), key, label, placeholder, 'mihomo_widgets')

        # IP
        ip_frame = ttk.Frame(subnotebook, padding=10)
        subnotebook.add(ip_frame, text="IPs")
        for key, label, placeholder in [
            ('ip_cidr', "IP-CIDR:", "10.0.0.0/24"),
            ('source_ip_cidr', "SRC-IP-CIDR:", "192.168.1.0/24")
        ]:
            self._create_text_input(ip_frame, list(self.mihomo_widgets.keys()).count(key), key, label, placeholder, 'mihomo_widgets')

        # Кнопки действий
        action_frame = ttk.LabelFrame(frame, text="Действия", padding=10)
        action_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            action_frame,
            text="Генерировать Mihomo Ruleset (.mrs)",
            command=self._generate_mihomo
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            action_frame,
            text="Очистить",
            command=self._clear_mihomo
        ).pack(side=tk.LEFT, padx=5)

    def _create_geo_tab(self, notebook: ttk.Notebook):
        """Вкладка GeoIP/GeoSite"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="🌍 GeoIP/GeoSite")

        # Subnotebook
        subnotebook = ttk.Notebook(frame)
        subnotebook.pack(fill=tk.BOTH, expand=True)

        self._create_geoip_subtab(subnotebook)
        self._create_geosite_subtab(subnotebook)

    def _create_geoip_subtab(self, notebook: ttk.Notebook):
        """Подвкладка GeoIP"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="GeoIP")

        ttk.Label(frame, text="GeoIP Генерация", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 15))

        # URLs
        urls_frame = ttk.LabelFrame(frame, text="Источники данных (URLs)", padding=10)
        urls_frame.pack(fill=tk.X, pady=10)

        self.geoip_widgets = {}
        for key, label in [
            ('ipv4_url', "IPv4 URL:"),
            ('ipv6_url', "IPv6 URL:"),
            ('asn_url', "ASN URL:")
        ]:
            ttk.Label(urls_frame, text=label).pack(anchor=tk.W, pady=5)
            entry = ttk.Entry(urls_frame, width=80)
            entry.pack(fill=tk.X, pady=(0, 10))
            self.geoip_widgets[key] = entry

        # Custom files
        ttk.Label(frame, text="Кастомные файлы", style='Heading.TLabel').pack(anchor=tk.W, pady=(15, 10))

        files_frame = ttk.Frame(frame)
        files_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.geoip_files_listbox = tk.Listbox(files_frame, height=8)
        scrollbar = ttk.Scrollbar(files_frame, command=self.geoip_files_listbox.yview)
        self.geoip_files_listbox.config(yscrollcommand=scrollbar.set)

        self.geoip_files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Добавить файл IPv4", command=self._add_geoip_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Добавить файл IPv6", command=self._add_geoip_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Удалить", command=lambda: self._remove_from_listbox(self.geoip_files_listbox)).pack(side=tk.LEFT, padx=5)

    def _create_geosite_subtab(self, notebook: ttk.Notebook):
        """Подвкладка GeoSite"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="GeoSite")

        ttk.Label(frame, text="GeoSite Генерация", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 15))

        # URLs
        urls_frame = ttk.LabelFrame(frame, text="Источники данных (URLs)", padding=10)
        urls_frame.pack(fill=tk.X, pady=10)

        self.geosite_widgets = {}
        for key, label in [
            ('gfw_url', "GFW URL:"),
            ('cn_url', "CN URL:"),
            ('apple_url', "Apple URL:"),
            ('google_url', "Google URL:")
        ]:
            ttk.Label(urls_frame, text=label).pack(anchor=tk.W, pady=5)
            entry = ttk.Entry(urls_frame, width=80)
            entry.pack(fill=tk.X, pady=(0, 10))
            self.geosite_widgets[key] = entry

        # Custom files
        ttk.Label(frame, text="Кастомные файлы доменов", style='Heading.TLabel').pack(anchor=tk.W, pady=(15, 10))

        files_frame = ttk.Frame(frame)
        files_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.geosite_files_listbox = tk.Listbox(files_frame, height=8)
        scrollbar = ttk.Scrollbar(files_frame, command=self.geosite_files_listbox.yview)
        self.geosite_files_listbox.config(yscrollcommand=scrollbar.set)

        self.geosite_files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Добавить файл доменов", command=self._add_geosite_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Удалить", command=lambda: self._remove_from_listbox(self.geosite_files_listbox)).pack(side=tk.LEFT, padx=5)

    def _create_log_tab(self, notebook: ttk.Notebook):
        """Вкладка логов"""
        frame = ttk.Frame(notebook, padding=15)
        notebook.add(frame, text="📋 Логи")

        ttk.Label(frame, text="Логи операций", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 10))

        self.log_widget = ModernScrolledText(frame, height=20, state='disabled')
        self.log_widget.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Очистить логи", command=self._clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Сохранить логи", command=self._save_logs).pack(side=tk.LEFT, padx=5)

        # Загрузка существующих логов
        self._load_logs()

    def _create_text_input(self, parent, row, key, label, placeholder, attr_name):
        """Вспомогательный метод создания текстового ввода"""
        ttk.Label(parent, text=label, style='Heading.TLabel').grid(row=row, column=0, sticky=tk.W, pady=10)

        text = ModernScrolledText(parent, height=3, width=50)
        text.grid(row=row, column=1, pady=10, padx=5, sticky=tk.EW)
        text.insert(tk.END, placeholder)

        ttk.Button(
            parent,
            text="📁",
            command=lambda k=key, attr=attr_name: self._load_file(k, attr)
        ).grid(row=row, column=2, padx=5)

        getattr(self, attr_name)[key] = text

    def _create_control_buttons(self, parent):
        """Кнопки управления приложением"""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Откр. папку выходов", command=self._open_output_dir).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Выход", command=self.root.quit).pack(side=tk.RIGHT, padx=5)

    # === ОБРАБОТЧИКИ СОБЫТИЙ ===

    def _browse_output_dir(self):
        """Выбор выходной папки"""
        path = filedialog.askdirectory(title="Выберите папку для сохранения файлов")
        if path:
            self.output_dir.set(path)
            self._log(f"Выходная папка: {path}")

    def _browse_singbox(self):
        """Выбор sing-box.exe"""
        path = filedialog.askopenfilename(
            title="Выберите sing-box.exe",
            filetypes=[("Executable", "*.exe"), ("Все файлы", "*.*")]
        )
        if path:
            self.singbox_path.set(path)
            self._log(f"sing-box.exe: {path}")

    def _load_file(self, key: str, attr_name: str):
        """Загрузка данных из файла"""
        path = filedialog.askopenfilename(
            title="Выберите файл с данными",
            filetypes=[("Text", "*.txt"), ("Все", "*.*")]
        )
        if not path:
            return

        try:
            items = FileProcessor.read_file_safe(path)
            widget = getattr(self, attr_name)[key]

            if isinstance(widget, ModernScrolledText):
                widget.delete('1.0', tk.END)
                widget.insert(tk.END, '\n'.join(items))
            elif isinstance(widget, ttk.Combobox):
                widget.set(items[0] if items else "")

            self._log(f"✓ Загружено {len(items)} записей из {os.path.basename(path)}")

        except Exception as e:
            self._log(f"✗ Ошибка загрузки файла: {e}")
            messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{str(e)}")

    def _get_singbox_data(self) -> Dict[str, Any]:
        """Сбор данных Sing-Box"""
        data = {}

        # Domains
        for key, widget in self.singbox_domain_widgets.items():
            lines = widget.get('1.0', tk.END).strip().split('\n')
            data[key] = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]

        # IPs
        for key, widget in self.singbox_ip_widgets.items():
            lines = widget.get('1.0', tk.END).strip().split('\n')
            data[key] = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]

        # Process
        for key, widget in self.singbox_process_widgets.items():
            lines = widget.get('1.0', tk.END).strip().split('\n')
            data[key] = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]

        # Network
        data['network_type'] = self.singbox_network_widgets['network_type'].get()
        data['network_is_expensive'] = self.singbox_network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.singbox_network_widgets['network_is_constrained'].get()

        for key in ['network_interface_address', 'default_interface_address']:
            lines = self.singbox_network_widgets[key].get('1.0', tk.END).strip().split('\n')
            data[key] = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]

        return data

    def _get_mihomo_data(self) -> Dict[str, Any]:
        """Сбор данных Mihomo"""
        data = {}

        for key, widget in self.mihomo_widgets.items():
            if isinstance(widget, ModernScrolledText):
                lines = widget.get('1.0', tk.END).strip().split('\n')
                data[key] = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
            else:
                data[key] = widget.get() if hasattr(widget, 'get') else []

        return data

    def _generate_singbox_json(self):
        """Генерация JSON для Sing-Box"""
        if not self._validate_output_dir():
            return

        data = self._get_singbox_data()
        output_path = Path(self.output_dir.get()) / "ruleset.json"

        self._run_in_thread(
            lambda: self._do_generate_singbox_json(data, str(output_path))
        )

    def _do_generate_singbox_json(self, data: Dict, output_path: str):
        """Выполнение генерации JSON"""
        try:
            success, msg, count = SingBoxRulesetGenerator.generate(data, output_path)

            if success:
                self._log(f"✓ {msg} ({count} записей)")
                messagebox.showinfo("Успех", f"{msg}\n\nЗаписей: {count}")
            else:
                self._log(f"✗ {msg}")
                messagebox.showerror("Ошибка", msg)

        except Exception as e:
            self._log(f"✗ Ошибка: {e}")
            messagebox.showerror("Ошибка", f"Ошибка генерации:\n{str(e)}")

    def _generate_singbox_srs(self):
        """Генерация и компиляция .srs"""
        if not self._validate_output_dir():
            return

        if not self._validate_singbox_path():
            return

        data = self._get_singbox_data()
        output_path = Path(self.output_dir.get()) / "ruleset.json"

        self._run_in_thread(
            lambda: self._do_generate_singbox_srs(data, str(output_path))
        )

    def _do_generate_singbox_srs(self, data: Dict, json_path: str):
        """Выполнение генерации и компиляции"""
        try:
            success, msg, count = SingBoxRulesetGenerator.generate(data, json_path)

            if not success:
                self._log(f"✗ Ошибка генерации JSON: {msg}")
                messagebox.showerror("Ошибка", msg)
                return

            self._log(f"✓ JSON создан ({count} записей)")

            # Компиляция
            self._log("⏳ Компиляция .srs...")
            success, compile_msg = SingBoxRulesetGenerator.compile_to_srs(
                self.singbox_path.get(),
                json_path
            )

            if success:
                self._log(f"✓ {compile_msg}")
                messagebox.showinfo("Успех", f"JSON и .srs успешно созданы!\n\nЗаписей: {count}")
            else:
                self._log(f"✗ {compile_msg}")
                messagebox.showwarning("Компиляция", compile_msg)

        except Exception as e:
            self._log(f"✗ Ошибка: {e}")
            messagebox.showerror("Ошибка", f"Ошибка:\n{str(e)}")

    def _generate_mihomo(self):
        """Генерация Mihomo ruleset"""
        if not self._validate_output_dir():
            return

        data = self._get_mihomo_data()
        output_path = Path(self.output_dir.get()) / "ruleset.mrs"

        self._run_in_thread(
            lambda: self._do_generate_mihomo(data, str(output_path))
        )

    def _do_generate_mihomo(self, data: Dict, output_path: str):
        """Выполнение генерации Mihomo"""
        try:
            success, msg, count = MihomoRulesetGenerator.generate(
                data,
                output_path,
                self.mihomo_proxy_name.get()
            )

            if success:
                self._log(f"✓ {msg} ({count} записей)")
                messagebox.showinfo("Успех", f"{msg}\n\nЗаписей: {count}")
            else:
                self._log(f"✗ {msg}")
                messagebox.showerror("Ошибка", msg)

        except Exception as e:
            self._log(f"✗ Ошибка: {e}")
            messagebox.showerror("Ошибка", f"Ошибка генерации:\n{str(e)}")

    def _clear_singbox(self):
        """Очистка Sing-Box данных"""
        if messagebox.askyesno("Подтверждение", "Очистить все данные Sing-Box?"):
            for widgets in [self.singbox_domain_widgets, self.singbox_ip_widgets, self.singbox_process_widgets]:
                for widget in widgets.values():
                    if isinstance(widget, ModernScrolledText):
                        widget.delete('1.0', tk.END)

            for key, widget in self.singbox_network_widgets.items():
                if isinstance(widget, ModernScrolledText):
                    widget.delete('1.0', tk.END)
                elif isinstance(widget, ttk.Combobox):
                    widget.set("")
                elif isinstance(widget, tk.StringVar):
                    widget.set("false" if "is_" in key else "")

            self._log("Sing-Box данные очищены")

    def _clear_mihomo(self):
        """Очистка Mihomo данных"""
        if messagebox.askyesno("Подтверждение", "Очистить все данные Mihomo?"):
            for widget in self.mihomo_widgets.values():
                if isinstance(widget, ModernScrolledText):
                    widget.delete('1.0', tk.END)

            self._log("Mihomo данные очищены")

    def _add_geoip_file(self):
        """Добавление файла GeoIP"""
        path = filedialog.askopenfilename(title="Выберите файл GeoIP")
        if path:
            self.geoip_files_listbox.insert(tk.END, path)
            self._log(f"Добавлен GeoIP файл: {os.path.basename(path)}")

    def _add_geosite_file(self):
        """Добавление файла GeoSite"""
        path = filedialog.askopenfilename(title="Выберите файл GeoSite")
        if path:
            self.geosite_files_listbox.insert(tk.END, path)
            self._log(f"Добавлен GeoSite файл: {os.path.basename(path)}")

    def _remove_from_listbox(self, listbox):
        """Удаление из listbox"""
        selection = listbox.curselection()
        if selection:
            listbox.delete(selection[0])

    def _open_output_dir(self):
        """Открытие папки выходов"""
        path = self.output_dir.get()
        if Path(path).exists():
            if sys.platform == 'win32':
                os.startfile(path)
            elif sys.platform == 'darwin':
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        else:
            messagebox.showerror("Ошибка", f"Папка не найдена: {path}")

    def _validate_output_dir(self) -> bool:
        """Проверка выходной папки"""
        path = self.output_dir.get()
        if not path or not Path(path).exists():
            messagebox.showerror("Ошибка", "Выберите корректную выходную папку!")
            return False
        return True

    def _validate_singbox_path(self) -> bool:
        """Проверка пути Sing-Box"""
        path = self.singbox_path.get()
        if not path or not Path(path).exists():
            messagebox.showerror("Ошибка", "Выберите корректный путь к sing-box.exe!")
            return False
        return True

    def _clear_logs(self):
        """Очистка логов"""
        self.log_widget.config(state='normal')
        self.log_widget.delete('1.0', tk.END)
        self.log_widget.config(state='disabled')

    def _save_logs(self):
        """Сохранение логов"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Все", "*.*")]
        )
        if path:
            try:
                content = self.log_widget.get('1.0', tk.END)
                FileProcessor.write_file_safe(path, content, backup=False)
                messagebox.showinfo("Успех", f"Логи сохранены: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")

    def _load_logs(self):
        """Загрузка логов из файла"""
        if Path('ruleset_generator.log').exists():
            try:
                with open('ruleset_generator.log', 'r', encoding='utf-8') as f:
                    content = f.read()
                self.log_widget.config(state='normal')
                self.log_widget.insert('1.0', content)
                self.log_widget.see(tk.END)
                self.log_widget.config(state='disabled')
            except Exception as e:
                logger.error(f"Ошибка загрузки логов: {e}")

    def _log(self, message: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}"

        self.log_widget.config(state='normal')
        self.log_widget.insert(tk.END, log_msg + '\n')
        self.log_widget.see(tk.END)
        self.log_widget.config(state='disabled')

        logger.info(message)

    def _run_in_thread(self, func):
        """Выполнение функции в отдельном потоке"""
        thread = threading.Thread(target=func, daemon=True)
        thread.start()


# === ТОЧКА ВХОДА ===
def main():
    """Главная функция"""
    root = tk.Tk()

    # Настройка размеров для Windows
    if sys.platform == 'win32':
        root.tk.call('tk', 'scaling', 2.0)

    app = RulesetGeneratorGUI(root)
    logger.info("=" * 50)
    logger.info("Ruleset Generator v3.0 запущен")
    logger.info("=" * 50)

    root.mainloop()


if __name__ == "__main__":
    main()
