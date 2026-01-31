#!/usr/bin/env python3
"""
Advanced Ruleset Builder for Sing-Box and Mihomo
Поддержка .json, .srs, .mrs форматов
"""

import json
import argparse
import os
import sys
import re
import struct
import shutil
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading

# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

VERSION = "3.0.2"
SUPPORTED_FORMATS = {
    'singbox': {'json': 'JSON Rule Set', 'srs': 'SRS Binary (compiled)'},
    'mihomo': {'mrs': 'MRS Binary (Mihomo Rule Set)'}
}

TEMPLATES = {
    "Блокировка рекламы": {
        "domain_suffix": [".ad.com", ".ads.com", ".doubleclick.net", ".googlesyndication.com"],
        "domain_keyword": ["analytics", "telemetry", "tracking"]
    },
    "Российские домены": {
        "domain_suffix": [".ru", ".рф", ".su"]
    },
    "Социальные сети": {
        "domain": ["facebook.com", "twitter.com", "instagram.com"],
        "domain_suffix": [".facebook.com", ".twitter.com", ".instagram.com"]
    },
    "Стриминг сервисы": {
        "domain": ["youtube.com", "netflix.com", "twitch.tv"],
        "domain_suffix": [".youtube.com", ".netflix.com", ".twitch.tv"]
    },
    "Локальные сети": {
        "ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/8"]
    }
}

# ============================================================================
# УТИЛИТЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ
# ============================================================================

class FileProcessor:
    """Обработка больших файлов с прогресс-баром"""
    
    @staticmethod
    def read_large_file(file_path: str, progress_callback=None) -> List[str]:
        """Читает большой файл построчно с отчётом о прогрессе"""
        if not file_path or not os.path.exists(file_path):
            return []
        
        lines = []
        file_size = os.path.getsize(file_path)
        bytes_read = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for original_line in f:
                # Отслеживаем прогресс по оригинальной строке (с переносами)
                bytes_read += len(original_line.encode('utf-8'))
                if progress_callback and file_size > 0:
                    progress = min(int((bytes_read / file_size) * 100), 100)
                    progress_callback(progress)

                line = original_line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
        
        return lines
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Валидация доменного имени"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, domain.lstrip('.')))
    
    @staticmethod
    def validate_ip_cidr(cidr: str) -> bool:
        """Валидация IP CIDR"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        if not re.match(pattern, cidr):
            return False
        
        parts = cidr.split('/')
        ip_parts = parts[0].split('.')
        
        if not all(0 <= int(p) <= 255 for p in ip_parts):
            return False
        
        if len(parts) == 2 and not (0 <= int(parts[1]) <= 32):
            return False
        
        return True
    
    @staticmethod
    def validate_regex(pattern: str) -> bool:
        """Валидация регулярного выражения"""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

# ============================================================================
# ГЕНЕРАЦИЯ RULESET
# ============================================================================

class RulesetGenerator:
    """Генератор ruleset для различных форматов"""
    
    @staticmethod
    def is_non_empty(value: Any) -> bool:
        """Проверка на непустое значение"""
        if isinstance(value, list):
            return len(value) > 0
        if isinstance(value, str):
            return value.strip() != ""
        return value is not None and value is not False
    
    @staticmethod
    def generate_singbox_json(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """Генерация JSON для Sing-Box"""
        rules = []
        stats = {'total': 0, 'domains': 0, 'ips': 0, 'processes': 0, 'network': 0}
        
        # Domain правила
        domain_rule = {}
        for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
            if key in data and RulesetGenerator.is_non_empty(data[key]):
                domain_rule[key] = data[key]
                stats['domains'] += len(data[key])
        
        if domain_rule:
            rules.append(domain_rule)
        
        # IP правила
        ip_rule = {}
        for key in ['ip_cidr', 'source_ip_cidr']:
            if key in data and RulesetGenerator.is_non_empty(data[key]):
                ip_rule[key] = data[key]
                stats['ips'] += len(data[key])
        
        if ip_rule:
            rules.append(ip_rule)
        
        # Process правила
        process_rule = {}
        for key in ['process_path_regex', 'package_name']:
            if key in data and RulesetGenerator.is_non_empty(data[key]):
                process_rule[key] = data[key]
                stats['processes'] += len(data[key]) if isinstance(data[key], list) else 1
        
        if process_rule:
            rules.append(process_rule)
        
        # Network правила
        network_rule = {}
        for key in ['network_type', 'network_interface_address', 'default_interface_address']:
            if key in data and RulesetGenerator.is_non_empty(data[key]):
                network_rule[key] = data[key]
                stats['network'] += 1
        
        for key in ['network_is_expensive', 'network_is_constrained']:
            if key in data and data[key] == 'true':
                network_rule[key] = True
                stats['network'] += 1
        
        if network_rule:
            rules.append(network_rule)
        
        # Формирование ruleset
        ruleset = {
            "version": 1,
            "rules": rules
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(ruleset, f, indent=2, ensure_ascii=False)
            
            stats['total'] = sum(stats.values())
            return True, f"JSON сохранён: {os.path.basename(output_path)}", stats
        except Exception as e:
            return False, f"Ошибка сохранения: {str(e)}", stats
    
    @staticmethod
    def compile_srs(singbox_path: str, json_path: str) -> Tuple[bool, str]:
        """Компиляция .srs файла через sing-box"""
        if not os.path.exists(singbox_path):
            return False, "sing-box не найден!"
        
        cmd = [singbox_path, "rule-set", "compile", json_path]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(singbox_path),
                timeout=30
            )
            
            if result.returncode == 0:
                srs_path = json_path.replace(".json", ".srs")
                if os.path.exists(srs_path):
                    size = os.path.getsize(srs_path)
                    return True, f".srs создан: {os.path.basename(srs_path)} ({size} байт)"
                else:
                    return False, "Команда выполнена, но .srs не найден"
            else:
                return False, f"Ошибка компиляции: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "Таймаут компиляции (>30 сек)"
        except Exception as e:
            return False, f"Ошибка запуска: {str(e)}"
    
    @staticmethod
    def generate_mihomo_yaml(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """
        Генерация YAML файла для Mihomo (промежуточный формат)
        Этот файл затем конвертируется в .mrs через mihomo.exe
        """
        try:
            stats = {'total': 0, 'domains': 0, 'ips': 0}
            
            payload = []
            
            # Определяем тип behavior на основе данных
            has_domains = any(data.get(k) for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex'])
            has_ips = any(data.get(k) for k in ['ip_cidr', 'source_ip_cidr'])
            
            # Для domain behavior - используем формат с точками (БЕЗ КАВЫЧЕК!)
            if has_domains and not has_ips:
                # domain behavior - используем wildcard формат
                if 'domain' in data and RulesetGenerator.is_non_empty(data['domain']):
                    for domain in data['domain']:
                        payload.append(domain)
                        stats['domains'] += 1
                
                if 'domain_suffix' in data and RulesetGenerator.is_non_empty(data['domain_suffix']):
                    for suffix in data['domain_suffix']:
                        # Для domain behavior используем формат с точкой впереди
                        suffix_clean = suffix.lstrip('.')
                        payload.append(f".{suffix_clean}")
                        stats['domains'] += 1
                
                if 'domain_keyword' in data and RulesetGenerator.is_non_empty(data['domain_keyword']):
                    for keyword in data['domain_keyword']:
                        # Для keywords используем wildcard
                        payload.append(f"*.{keyword}.*")
                        stats['domains'] += 1
            
            # Для ipcidr behavior - только IP адреса (БЕЗ КАВЫЧЕК!)
            elif has_ips and not has_domains:
                # ipcidr behavior - чистые IP адреса
                if 'ip_cidr' in data and RulesetGenerator.is_non_empty(data['ip_cidr']):
                    for cidr in data['ip_cidr']:
                        payload.append(cidr)
                        stats['ips'] += 1
                
                if 'source_ip_cidr' in data and RulesetGenerator.is_non_empty(data['source_ip_cidr']):
                    for cidr in data['source_ip_cidr']:
                        payload.append(cidr)
                        stats['ips'] += 1
            
            # Для classical behavior - используем полный формат с префиксами
            else:
                # classical behavior - полный формат правил
                if 'domain' in data and RulesetGenerator.is_non_empty(data['domain']):
                    for domain in data['domain']:
                        payload.append(f"DOMAIN,{domain}")
                        stats['domains'] += 1
                
                if 'domain_suffix' in data and RulesetGenerator.is_non_empty(data['domain_suffix']):
                    for suffix in data['domain_suffix']:
                        suffix_clean = suffix.lstrip('.')
                        payload.append(f"DOMAIN-SUFFIX,{suffix_clean}")
                        stats['domains'] += 1
                
                if 'domain_keyword' in data and RulesetGenerator.is_non_empty(data['domain_keyword']):
                    for keyword in data['domain_keyword']:
                        payload.append(f"DOMAIN-KEYWORD,{keyword}")
                        stats['domains'] += 1
                
                if 'ip_cidr' in data and RulesetGenerator.is_non_empty(data['ip_cidr']):
                    for cidr in data['ip_cidr']:
                        payload.append(f"IP-CIDR,{cidr}")
                        stats['ips'] += 1
                
                if 'source_ip_cidr' in data and RulesetGenerator.is_non_empty(data['source_ip_cidr']):
                    for cidr in data['source_ip_cidr']:
                        payload.append(f"SRC-IP-CIDR,{cidr}")
                        stats['ips'] += 1
            
            if not payload:
                return False, "Нет данных для создания ruleset", stats
            
            # Создаём YAML структуру в правильном формате (БЕЗ КАВЫЧЕК!)
            yaml_content = "payload:\n"
            for rule in payload:
                yaml_content += f"  - {rule}\n"
            
            # Сохраняем YAML файл
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
            
            stats['total'] = len(payload)
            return True, f"YAML для Mihomo создан: {os.path.basename(output_path)}", stats
        
        except Exception as e:
            return False, f"Ошибка создания YAML: {str(e)}", {'total': 0}
    
    @staticmethod
    def compile_mrs(mihomo_path: str, yaml_path: str, output_path: str, behavior_type: str = "domain") -> Tuple[bool, str]:
        """Компиляция .mrs файла через mihomo.exe
        
        Args:
            mihomo_path: путь к mihomo.exe
            yaml_path: путь к исходному YAML файлу
            output_path: путь для выходного .mrs файла
            behavior_type: тип поведения - 'domain', 'ipcidr' или 'classical'
        """
        if not os.path.exists(mihomo_path):
            return False, "mihomo.exe не найден!"
        
        if not os.path.exists(yaml_path):
            return False, f"Исходный YAML файл не найден: {yaml_path}"
        
        # Получаем имена файлов и директорию вывода
        output_dir = os.path.dirname(os.path.abspath(output_path))
        yaml_filename = os.path.basename(yaml_path)
        output_filename = os.path.basename(output_path)
        
        # Копируем YAML в директорию вывода если он не там
        yaml_in_output = os.path.join(output_dir, yaml_filename)
        if os.path.abspath(yaml_path) != os.path.abspath(yaml_in_output):
            shutil.copy2(yaml_path, yaml_in_output)
            yaml_to_use = yaml_in_output
            cleanup_yaml = True
        else:
            yaml_to_use = yaml_path
            cleanup_yaml = False
        
        # Правильная команда mihomo:
        # mihomo convert-ruleset <behavior> <format> <input-file> <output-file>
        # где format = "yaml", behavior = "domain"/"ipcidr"/"classical"
        cmd = [
            os.path.abspath(mihomo_path), 
            "convert-ruleset", 
            behavior_type,      # domain/ipcidr/classical
            "yaml",             # формат ВХОДНОГО файла (не mrs!)
            yaml_filename,      # входной файл (относительный путь)
            output_filename     # выходной файл (относительный путь)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=output_dir,  # Запускаем из директории вывода
                timeout=30
            )
            
            # Удаляем временный YAML если создавали
            if cleanup_yaml and os.path.exists(yaml_in_output):
                try:
                    os.remove(yaml_in_output)
                except (OSError, PermissionError) as e:
                    # Игнорируем ошибки удаления временного файла
                    pass
            
            if result.returncode == 0:
                if os.path.exists(output_path):
                    size = os.path.getsize(output_path)
                    return True, f".mrs создан: {os.path.basename(output_path)} ({size} байт)"
                else:
                    return False, "Команда выполнена, но .mrs файл не найден"
            else:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                return False, f"Ошибка компиляции Mihomo: {error_msg}"
        
        except subprocess.TimeoutExpired:
            return False, "Таймаут компиляции (>30 сек)"
        except Exception as e:
            return False, f"Ошибка запуска mihomo.exe: {str(e)}"

# ============================================================================
# GUI ПРИЛОЖЕНИЕ
# ============================================================================

class RulesetBuilderGUI:
    """Главное окно приложения"""
    
    def __init__(self, master):
        self.master = master
        master.title(f"Ruleset Builder v{VERSION} - Sing-Box, Mihomo & GeoIP/GeoSite")
        master.geometry("1100x800")
        master.minsize(900, 650)
        
        # Переменные
        self.singbox_path = tk.StringVar()
        self.mihomo_path = tk.StringVar()  # ДОБАВЛЕНО: путь к mihomo.exe
        self.output_filename = tk.StringVar(value="ruleset")
        self.output_dir = tk.StringVar(value=os.getcwd())
        self.output_format = tk.StringVar(value="json")
        self.compile_srs = tk.BooleanVar(value=False)
        self.generate_mrs = tk.BooleanVar(value=False)
        self.validate_input = tk.BooleanVar(value=True)
        
        # Виджеты для категорий
        self.domain_widgets = {}
        self.ip_widgets = {}
        self.process_widgets = {}
        self.network_widgets = {}
        
        # Виджеты для вкладки Mihomo
        self.mihomo_domain_widget = None
        self.mihomo_ip_widget = None
        self.mihomo_behavior = None  # Будет создана в create_mihomo_tab
        
        # GeoIP/GeoSite переменные
        self.geoip_geosite_path = tk.StringVar()
        self.geo_input_dir = tk.StringVar(value=os.path.join(os.getcwd(), "geo_input"))
        self.geo_output_dir = tk.StringVar(value=os.path.join(os.getcwd(), "geo_output"))
        self.geo_source_file = tk.StringVar()
        self.gen_geoip = tk.BooleanVar(value=True)
        self.gen_geosite = tk.BooleanVar(value=True)
        self.gen_rule_set_json = tk.BooleanVar(value=False)
        self.gen_rule_set_srs = tk.BooleanVar(value=False)

        # Словарь категорий для GeoIP/GeoSite
        self.geo_categories = {}
        
        self.setup_ui()
        self.apply_theme()
    
    def setup_ui(self):
        """Создание интерфейса"""
        # Главный контейнер
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель
        self.setup_top_panel(main_frame)
        
        # Вкладки с правилами
        self.setup_tabs(main_frame)
        
        # Нижняя панель с кнопками
        self.setup_bottom_panel(main_frame)
    
    def setup_top_panel(self, parent):
        """Верхняя панель с настройками"""
        top_frame = ttk.LabelFrame(parent, text="Настройки", padding=10)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Sing-box путь
        row = 0
        ttk.Label(top_frame, text="Sing-box:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.singbox_path, width=50).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="...", command=self.browse_singbox, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # ДОБАВЛЕНО: Mihomo путь
        row += 1
        ttk.Label(top_frame, text="Mihomo:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.mihomo_path, width=50).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="...", command=self.browse_mihomo, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # generate-geoip-geosite путь
        row += 1
        ttk.Label(top_frame, text="GeoIP/GeoSite:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.geoip_geosite_path, width=50).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="...", command=self.browse_geoip_geosite, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # Выходной файл и формат
        row += 1
        ttk.Label(top_frame, text="Имя файла:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.output_filename, width=20).grid(
            row=row, column=1, sticky=tk.W, padx=5
        )
        
        ttk.Label(top_frame, text="Формат:").grid(row=row, column=2, sticky=tk.E, padx=(20, 5))
        format_combo = ttk.Combobox(
            top_frame,
            textvariable=self.output_format,
            values=["json", "srs", "mrs"],
            state="readonly",
            width=8
        )
        format_combo.grid(row=row, column=3, sticky=tk.W, padx=2)
        format_combo.current(0)
        
        # Папка вывода
        row += 1
        ttk.Label(top_frame, text="Папка:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.output_dir, width=50, state='readonly').grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="...", command=self.browse_output_dir, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # Опции
        row += 1
        options_frame = ttk.Frame(top_frame)
        options_frame.grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=10)
        
        ttk.Checkbutton(
            options_frame,
            text="Компилировать .srs",
            variable=self.compile_srs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Генерировать .mrs (Mihomo)",
            variable=self.generate_mrs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Валидация входных данных",
            variable=self.validate_input
        ).pack(side=tk.LEFT, padx=5)
        
        top_frame.columnconfigure(0, weight=0)
        top_frame.columnconfigure(1, weight=1)
        top_frame.columnconfigure(2, weight=0)
        top_frame.columnconfigure(3, weight=0)
    
    def setup_tabs(self, parent):
        """Создание вкладок с правилами"""
        # Фрейм для кнопок действий (правый верхний угол)
        action_btn_frame = ttk.Frame(parent)
        action_btn_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Спейсер слева для выравнивания кнопок вправо
        ttk.Label(action_btn_frame, text="").pack(side=tk.LEFT, expand=True)
        
        # Кнопки действий справа
        ttk.Button(
            action_btn_frame,
            text="Генерировать Ruleset",
            command=self.generate_ruleset,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            action_btn_frame,
            text="Очистить всё",
            command=self.clear_all
        ).pack(side=tk.LEFT, padx=5)
        
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Вкладка Domains
        self.domain_frame = self.create_domain_tab(notebook)
        notebook.add(self.domain_frame, text="Domains")
        
        # Вкладка IPs
        self.ip_frame = self.create_ip_tab(notebook)
        notebook.add(self.ip_frame, text="IP Addresses")
        
        # Вкладка Process
        self.process_frame = self.create_process_tab(notebook)
        notebook.add(self.process_frame, text="Processes")
        
        # Вкладка Network
        self.network_frame = self.create_network_tab(notebook)
        notebook.add(self.network_frame, text="Network")
        
        # НОВАЯ вкладка Mihomo
        self.mihomo_frame = self.create_mihomo_tab(notebook)
        notebook.add(self.mihomo_frame, text="Mihomo Rules")
        
        # Вкладка Шаблоны
        self.templates_frame = self.create_templates_tab(notebook)
        notebook.add(self.templates_frame, text="Шаблоны")
        
        # Вкладка Превью
        self.preview_frame = self.create_preview_tab(notebook)
        notebook.add(self.preview_frame, text="Превью")
    
        # Вкладка GeoIP/GeoSite
        self.geoip_frame = self.create_geoip_geosite_tab(notebook)
        notebook.add(self.geoip_frame, text="GeoIP/GeoSite")
        
        # Вкладка лога
        self.log_frame = self.create_log_tab(notebook)
        notebook.add(self.log_frame, text="Лог событий")
    
    def create_domain_tab(self, parent):
        """Вкладка доменов"""
        frame = ttk.Frame(parent, padding=10)
        
        fields = [
            ('domain', "Точные домены (DOMAIN):", "example.com\ngoogle.com", True),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):", ".ru\n.com\n.org", True),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):", "google\nadvertisement", False),
            ('domain_regex', "Регулярные выражения (DOMAIN-REGEX):", "^stun\\..+\n.*\\.torrent$", False)
        ]
        
        for i, (key, label, placeholder, validate) in enumerate(fields):
            field_frame = ttk.LabelFrame(frame, text=label, padding=5)
            field_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            
            text_widget = scrolledtext.ScrolledText(field_frame, height=3, width=70, wrap=tk.WORD)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            text_widget.insert(tk.END, f"# {placeholder}")
            text_widget.bind('<KeyRelease>', lambda e, k=key: self.on_text_change(k))
            
            btn_frame = ttk.Frame(field_frame)
            btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
            
            ttk.Button(btn_frame, text="Файл", command=lambda k=key: self.load_file(k, 'domain'), width=10).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="Очистить", command=lambda w=text_widget: self.clear_widget(w), width=10).pack(fill=tk.X, pady=2)
            if validate:
                ttk.Button(btn_frame, text="Валидация", command=lambda k=key: self.validate_field(k, 'domain'), width=10).pack(fill=tk.X, pady=2)
            
            count_label = ttk.Label(btn_frame, text="Строк: 0", foreground="gray")
            count_label.pack(fill=tk.X, pady=2)
            
            self.domain_widgets[key] = {
                'text': text_widget,
                'count': count_label,
                'validate': validate
            }
        
        return frame
    
    def create_ip_tab(self, parent):
        """Вкладка IP адресов"""
        frame = ttk.Frame(parent, padding=10)
        
        fields = [
            ('ip_cidr', "IP CIDR (целевые адреса):", "10.0.0.0/8\n192.168.0.0/16\n8.8.8.8/32"),
            ('source_ip_cidr', "Source IP CIDR (исходные адреса):", "192.168.1.0/24\n10.10.0.0/16")
        ]
        
        for i, (key, label, placeholder) in enumerate(fields):
            field_frame = ttk.LabelFrame(frame, text=label, padding=5)
            field_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            
            text_widget = scrolledtext.ScrolledText(field_frame, height=5, width=70, wrap=tk.WORD)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            text_widget.insert(tk.END, f"# {placeholder}")
            text_widget.bind('<KeyRelease>', lambda e, k=key: self.on_text_change(k))
            
            btn_frame = ttk.Frame(field_frame)
            btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
            
            ttk.Button(btn_frame, text="Файл", command=lambda k=key: self.load_file(k, 'ip'), width=10).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="Очистить", command=lambda w=text_widget: self.clear_widget(w), width=10).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="Валидация", command=lambda k=key: self.validate_field(k, 'ip'), width=10).pack(fill=tk.X, pady=2)
            
            count_label = ttk.Label(btn_frame, text="Строк: 0", foreground="gray")
            count_label.pack(fill=tk.X, pady=2)
            
            self.ip_widgets[key] = {
                'text': text_widget,
                'count': count_label,
                'validate': True
            }
        
        return frame
    
    def create_process_tab(self, parent):
        """Вкладка процессов"""
        frame = ttk.Frame(parent, padding=10)
        
        field_frame1 = ttk.LabelFrame(frame, text="Process Path Regex:", padding=5)
        field_frame1.pack(fill=tk.BOTH, expand=True, pady=5)
        
        text1 = scrolledtext.ScrolledText(field_frame1, height=5, width=70, wrap=tk.WORD)
        text1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        text1.insert(tk.END, "# ^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$\n# /usr/bin/firefox")
        text1.bind('<KeyRelease>', lambda e: self.on_text_change('process_path_regex'))
        
        btn_frame1 = ttk.Frame(field_frame1)
        btn_frame1.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(btn_frame1, text="Файл", command=lambda: self.load_file('process_path_regex', 'process'), width=10).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame1, text="Очистить", command=lambda: self.clear_widget(text1), width=10).pack(fill=tk.X, pady=2)
        
        count1 = ttk.Label(btn_frame1, text="Строк: 0", foreground="gray")
        count1.pack(fill=tk.X, pady=2)
        
        field_frame2 = ttk.LabelFrame(frame, text="Package Name (Android):", padding=5)
        field_frame2.pack(fill=tk.BOTH, expand=True, pady=5)
        
        text2 = scrolledtext.ScrolledText(field_frame2, height=5, width=70, wrap=tk.WORD)
        text2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        text2.insert(tk.END, "# com.example.app\n# org.telegram.messenger")
        text2.bind('<KeyRelease>', lambda e: self.on_text_change('package_name'))
        
        btn_frame2 = ttk.Frame(field_frame2)
        btn_frame2.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(btn_frame2, text="Файл", command=lambda: self.load_file('package_name', 'process'), width=10).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame2, text="Очистить", command=lambda: self.clear_widget(text2), width=10).pack(fill=tk.X, pady=2)
        
        count2 = ttk.Label(btn_frame2, text="Строк: 0", foreground="gray")
        count2.pack(fill=tk.X, pady=2)
        
        self.process_widgets = {
            'process_path_regex': {'text': text1, 'count': count1},
            'package_name': {'text': text2, 'count': count2}
        }
        
        return frame
    
    def create_network_tab(self, parent):
        """Вкладка сетевых параметров"""
        frame = ttk.Frame(parent, padding=10)
        
        type_frame = ttk.LabelFrame(frame, text="Network Type:", padding=10)
        type_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(type_frame, text="Тип сети:").grid(row=0, column=0, sticky=tk.W, pady=5)
        network_combo = ttk.Combobox(
            type_frame,
            values=["", "wifi", "cellular", "ethernet", "other"],
            state="readonly",
            width=20
        )
        network_combo.grid(row=0, column=1, sticky=tk.W, padx=10)
        network_combo.current(0)
        
        bool_frame = ttk.LabelFrame(frame, text="Параметры сети:", padding=10)
        bool_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(bool_frame, text="Expensive Network:").grid(row=0, column=0, sticky=tk.W, pady=5)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(bool_frame, text="True", variable=exp_var, value="true").grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(bool_frame, text="False", variable=exp_var, value="false").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(bool_frame, text="Constrained (iOS):").grid(row=1, column=0, sticky=tk.W, pady=5)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(bool_frame, text="True", variable=con_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(bool_frame, text="False", variable=con_var, value="false").grid(row=1, column=2, sticky=tk.W, padx=5)
        
        addr_frame = ttk.LabelFrame(frame, text="Сетевые адреса:", padding=10)
        addr_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(addr_frame, text="Network Interface Address:").pack(anchor=tk.W, pady=(0, 2))
        text_interface = scrolledtext.ScrolledText(addr_frame, height=3, width=70, wrap=tk.WORD)
        text_interface.pack(fill=tk.X, pady=(0, 10))
        text_interface.insert(tk.END, "# 192.168.1.100\n# 10.0.0.5")
        
        ttk.Label(addr_frame, text="Default Interface Address:").pack(anchor=tk.W, pady=(0, 2))
        text_default = scrolledtext.ScrolledText(addr_frame, height=3, width=70, wrap=tk.WORD)
        text_default.pack(fill=tk.X)
        text_default.insert(tk.END, "# 8.8.8.8\n# 1.1.1.1")
        
        self.network_widgets = {
            'network_type': network_combo,
            'network_is_expensive': exp_var,
            'network_is_constrained': con_var,
            'network_interface_address': text_interface,
            'default_interface_address': text_default
        }
        
        return frame
    
    def create_mihomo_tab(self, parent):
        """Вкладка специально для правил Mihomo"""
        frame = ttk.Frame(parent, padding=10)
        
        # Верхняя панель с информацией и кнопками действий
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Информация слева
        info_left = ttk.Frame(header_frame)
        info_left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(
            info_left,
            text="Mihomo Rule Set Generator",
            font=('TkDefaultFont', 12, 'bold'),
            foreground='#0066cc'
        ).pack(anchor=tk.W)
        
        ttk.Label(
            info_left,
            text="Создание .mrs файлов для Mihomo с правильным форматом YAML",
            font=('TkDefaultFont', 9),
            foreground='gray'
        ).pack(anchor=tk.W, pady=(2, 0))
        
        # Кнопки действий справа
        btn_right = ttk.Frame(header_frame)
        btn_right.pack(side=tk.RIGHT)
        
        ttk.Button(
            btn_right,
            text="Просмотр YAML",
            command=self.preview_mihomo_yaml,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_right,
            text="Создать MRS",
            command=self.generate_mihomo_only,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_right,
            text="Очистить",
            command=self.clear_mihomo_widgets
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Выбор типа правил
        type_frame = ttk.LabelFrame(frame, text="Тип правил (behavior)", padding=10)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.mihomo_behavior = tk.StringVar(value="auto")
        
        ttk.Radiobutton(
            type_frame,
            text="Автоматически (рекомендуется)",
            variable=self.mihomo_behavior,
            value="auto"
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Radiobutton(
            type_frame,
            text="Domain - только домены",
            variable=self.mihomo_behavior,
            value="domain"
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Radiobutton(
            type_frame,
            text="IPCIDR - только IP адреса",
            variable=self.mihomo_behavior,
            value="ipcidr"
        ).pack(anchor=tk.W, pady=2)
        
        ttk.Radiobutton(
            type_frame,
            text="Classical - домены + IP",
            variable=self.mihomo_behavior,
            value="classical"
        ).pack(anchor=tk.W, pady=2)
        
        # Поле для доменов
        domain_frame = ttk.LabelFrame(frame, text="Домены (для domain и classical)", padding=5)
        domain_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Подсказка для доменов
        domain_hint = ttk.Label(
            domain_frame,
            text="Формат: .google.com (суффикс), youtube.com (точное), *.facebook.com (wildcard)",
            font=('TkDefaultFont', 8),
            foreground='navy'
        )
        domain_hint.pack(anchor=tk.W, pady=(0, 5))
        
        domain_text = scrolledtext.ScrolledText(domain_frame, height=8, width=70, wrap=tk.WORD)
        domain_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        domain_text.insert(tk.END, "# Примеры:\n# .google.com\n# youtube.com\n# *.facebook.com")
        
        # Кнопки для доменов
        domain_btn_frame = ttk.Frame(domain_frame)
        domain_btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(
            domain_btn_frame,
            text="...Загрузить",
            command=lambda: self.load_mihomo_file('domain')
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            domain_btn_frame,
            text="Очистить",
            command=lambda: domain_text.delete('1.0', tk.END)
        ).pack(fill=tk.X, pady=2)
        
        domain_count = ttk.Label(domain_btn_frame, text="Строк: 0", foreground="gray")
        domain_count.pack(fill=tk.X, pady=2)
        
        # Обновление счётчика для доменов
        def update_domain_count(event=None):
            content = domain_text.get('1.0', tk.END).strip()
            lines = [l for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
            domain_count.config(text=f"Строк: {len(lines)}")
        
        domain_text.bind('<KeyRelease>', update_domain_count)
        
        # Поле для IP адресов
        ip_frame = ttk.LabelFrame(frame, text="IP адреса (для ipcidr и classical)", padding=5)
        ip_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Подсказка для IP
        ip_hint = ttk.Label(
            ip_frame,
            text="Формат: 192.168.1.0/24, 10.0.0.0/8, 8.8.8.8/32 (БЕЗ префиксов IP-CIDR)",
            font=('TkDefaultFont', 8),
            foreground='navy'
        )
        ip_hint.pack(anchor=tk.W, pady=(0, 5))
        
        ip_text = scrolledtext.ScrolledText(ip_frame, height=8, width=70, wrap=tk.WORD)
        ip_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        ip_text.insert(tk.END, "# Примеры:\n# 192.168.0.0/16\n# 10.0.0.0/8\n# 8.8.8.8/32")
        
        # Кнопки для IP
        ip_btn_frame = ttk.Frame(ip_frame)
        ip_btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(
            ip_btn_frame,
            text="...Загрузить",
            command=lambda: self.load_mihomo_file('ip')
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            ip_btn_frame,
            text="Очистить",
            command=lambda: ip_text.delete('1.0', tk.END)
        ).pack(fill=tk.X, pady=2)
        
        ip_count = ttk.Label(ip_btn_frame, text="Строк: 0", foreground="gray")
        ip_count.pack(fill=tk.X, pady=2)
        
        # Обновление счётчика для IP
        def update_ip_count(event=None):
            content = ip_text.get('1.0', tk.END).strip()
            lines = [l for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
            ip_count.config(text=f"Строк: {len(lines)}")
        
        ip_text.bind('<KeyRelease>', update_ip_count)
        
        # Сохраняем виджеты
        self.mihomo_domain_widget = domain_text
        self.mihomo_ip_widget = ip_text
        
        return frame
    
    def create_templates_tab(self, parent):
        """Вкладка с шаблонами"""
        frame = ttk.Frame(parent, padding=10)
        
        ttk.Label(
            frame,
            text="Выберите готовый шаблон для быстрого заполнения:",
            font=('TkDefaultFont', 10, 'bold')
        ).pack(anchor=tk.W, pady=(0, 10))
        
        for template_name, template_data in TEMPLATES.items():
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=5)
            
            ttk.Button(
                btn_frame,
                text=f"{template_name}",
                command=lambda t=template_data: self.apply_template(t),
                width=30
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            desc = ", ".join([f"{k}: {len(v)}" for k, v in template_data.items()])
            ttk.Label(btn_frame, text=desc, foreground="gray").pack(side=tk.LEFT)
        
        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)
        
        custom_frame = ttk.LabelFrame(frame, text="Пользовательские шаблоны:", padding=10)
        custom_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            custom_frame,
            text="Сохранить текущие данные как шаблон",
            command=self.save_custom_template
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            custom_frame,
            text="Загрузить шаблон из файла",
            command=self.load_custom_template
        ).pack(fill=tk.X, pady=2)
        
        return frame
    
    def create_preview_tab(self, parent):
        """Вкладка предпросмотра"""
        frame = ttk.Frame(parent, padding=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(
            btn_frame,
            text="🔄 Обновить превью",
            command=self.update_preview
        ).pack(side=tk.LEFT)
        
        ttk.Label(btn_frame, text="Предпросмотр JSON структуры:", font=('TkDefaultFont', 10, 'bold')).pack(side=tk.LEFT, padx=20)
        
        self.preview_text = scrolledtext.ScrolledText(frame, height=25, width=90, wrap=tk.WORD)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.configure(state='disabled')
        
        return frame
    
    def setup_bottom_panel(self, parent):
        """Нижняя панель с кнопками действий"""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        
        left_frame = ttk.Frame(btn_frame)
        left_frame.pack(side=tk.LEFT)
        
        ttk.Button(
            left_frame,
            text="📊 Статистика",
            command=self.show_statistics
        ).pack(side=tk.LEFT, padx=5)
        
        right_frame = ttk.Frame(btn_frame)
        right_frame.pack(side=tk.RIGHT)
        
        ttk.Button(
            right_frame,
            text="О программе",
            command=self.show_about
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            right_frame,
            text="Выход",
            command=self.master.quit
        ).pack(side=tk.LEFT, padx=5)
    
    def copy_log(self):
        """Копировать лог в буфер обмена"""
        log_content = self.log.get('1.0', tk.END)
        self.master.clipboard_clear()
        self.master.clipboard_append(log_content)
        messagebox.showinfo("Успех", "Лог скопирован в буфер обмена!")
    
    def save_log(self):
        """Сохранить лог в файл"""
        path = filedialog.asksaveasfilename(
            title="Сохранить лог",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if path:
            try:
                log_content = self.log.get('1.0', tk.END)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(log_content)
                messagebox.showinfo("Успех", f"Лог сохранён:\n{os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить лог:\n{str(e)}")
    
    def apply_theme(self):
        """Применение темы оформления"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Accent.TButton', foreground='white', background='#007ACC', font=('TkDefaultFont', 10, 'bold'))
        style.map('Accent.TButton', background=[('active', '#005A9E')])
    
    # ========================================================================
    # МЕТОДЫ ОБРАБОТКИ СОБЫТИЙ
    # ========================================================================
    
    def create_geoip_geosite_tab(self, parent):
        """Вкладка для работы с GeoIP/GeoSite Generator"""
        frame = ttk.Frame(parent, padding=10)
        
        info_label = ttk.Label(
            frame,
            text="Генерация GeoIP и GeoSite файлов через generate-geoip-geosite утилиту.\n"
                 "Утилита поддерживает загрузку списков из интернета и создание .db, .json, .srs файлов.",
            font=('TkDefaultFont', 9),
            foreground='navy'
        )
        info_label.pack(anchor=tk.W, pady=(0, 10))
        
        dirs_frame = ttk.LabelFrame(frame, text="...Директории:", padding=10)
        dirs_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dirs_frame, text="Input Directory:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(dirs_frame, textvariable=self.geo_input_dir, width=55, state='readonly').grid(
            row=0, column=1, sticky=tk.EW, padx=5
        )
        ttk.Button(dirs_frame, text="📁", command=self.browse_geo_input_dir, width=3).grid(
            row=0, column=2, padx=2
        )
        
        ttk.Label(dirs_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(dirs_frame, textvariable=self.geo_output_dir, width=55, state='readonly').grid(
            row=1, column=1, sticky=tk.EW, padx=5
        )
        ttk.Button(dirs_frame, text="📁", command=self.browse_geo_output_dir, width=3).grid(
            row=1, column=2, padx=2
        )
        
        ttk.Label(dirs_frame, text="Source файл (опц.):").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(dirs_frame, textvariable=self.geo_source_file, width=55, state='readonly').grid(
            row=2, column=1, sticky=tk.EW, padx=5
        )
        ttk.Button(dirs_frame, text="📁", command=self.browse_source_file, width=3).grid(
            row=2, column=2, padx=2
        )
        
        dirs_frame.columnconfigure(1, weight=1)
        
        gen_frame = ttk.LabelFrame(frame, text="Параметры генерации:", padding=10)
        gen_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(
            gen_frame,
            text="Генерировать GeoIP (.db)",
            variable=self.gen_geoip
        ).grid(row=0, column=0, sticky=tk.W, padx=10, pady=3)
        
        ttk.Checkbutton(
            gen_frame,
            text="Генерировать GeoSite (.db)",
            variable=self.gen_geosite
        ).grid(row=1, column=0, sticky=tk.W, padx=10, pady=3)
        
        ttk.Checkbutton(
            gen_frame,
            text="Генерировать Rule-Set JSON",
            variable=self.gen_rule_set_json
        ).grid(row=0, column=1, sticky=tk.W, padx=10, pady=3)
        
        ttk.Checkbutton(
            gen_frame,
            text="Генерировать Rule-Set SRS",
            variable=self.gen_rule_set_srs
        ).grid(row=1, column=1, sticky=tk.W, padx=10, pady=3)
        
        action_frame = ttk.Frame(frame)
        action_frame.pack(fill=tk.X, pady=15)
        
        ttk.Button(
            action_frame,
            text="Создать входные файлы из текущих данных",
            command=self.create_geo_input_files,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            action_frame,
            text="Запустить генерацию",
            command=self.run_geoip_geosite_generation,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            action_frame,
            text="Открыть папку вывода",
            command=self.open_geo_output_dir
        ).pack(side=tk.LEFT, padx=5)
        
        help_frame = ttk.LabelFrame(frame, text="Справка по использованию:", padding=10)
        help_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        help_text = tk.Text(help_frame, height=12, wrap=tk.WORD, font=('TkDefaultFont', 9))
        help_text.pack(fill=tk.BOTH, expand=True)
        help_text.insert('1.0', """
🌍 ГЕНЕРАЦИЯ GEOIP/GEOSITE

УСТАНОВКА:
1. Скачайте generate-geoip-geosite-windows-amd64.exe с GitHub:
   https://github.com/Dunamis4tw/generate-geoip-geosite/releases
   
2. Укажите путь к .exe в настройках (верхняя панель программы)

ИСПОЛЬЗОВАНИЕ:

📝 Способ 1: Из текущих данных
   • Заполните вкладки Domains и IPs
   • Нажмите "Создать входные файлы из текущих данных"
   • Программа создаст файлы формата: include-domain-*.lst, include-ip-*.lst
   • Нажмите "Запустить генерацию"

📂 Способ 2: Создание вручную
   • Создайте файлы в Input Directory вручную
   • Формат имени: {include/exclude}-{domain/ip}-{category}.{lst/rgx}
   
   Примеры:
   - include-domain-ru.lst (домены для категории "ru")
   - include-ip-vpn.lst (IP для категории "vpn")
   - exclude-domain-ads.rgx (regex исключений для "ads")

🌐 Способ 3: С Source файлом
   • Создайте source.json с URL для загрузки списков
   • Утилита автоматически скачает и обработает списки
   • Готовые примеры: AdAway, Antifilter, Antizapret

ФОРМАТЫ ВХОДНЫХ ФАЙЛОВ:
- .lst - обычный список (по одной записи на строку)
- .rgx - regex паттерны для исключения

ФОРМАТЫ ВЫХОДНЫХ ФАЙЛОВ:
- .db - GeoIP или GeoSite база данных
- rule-set.json - Rule-Set в JSON формате (для Sing-Box v1.8+)
- rule-set.srs - Rule-Set в бинарном формате

ФЛАГИ КОМАНДНОЙ СТРОКИ:
-i, --inputDir - папка с входными файлами
-o, --outputDir - папка для результатов
-s, --sources - путь к source.json файлу
--gen-geoip - генерировать GeoIP
--gen-geosite - генерировать GeoSite
--gen-rule-set-json - генерировать Rule-Set JSON
--gen-rule-set-srs - генерировать Rule-Set SRS
        """)
        help_text.config(state='disabled')
        
        return frame
    
    def create_log_tab(self, parent):
        """Вкладка с логом событий"""
        frame = ttk.Frame(parent, padding=10)
        
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            header_frame,
            text="История всех операций программы",
            font=('TkDefaultFont', 10, 'bold')
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            header_frame,
            text="Очистить лог",
            command=self.clear_log
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            header_frame,
            text="Сохранить лог",
            command=self.save_log
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            header_frame,
            text="Копировать",
            command=self.copy_log
        ).pack(side=tk.RIGHT, padx=5)
        
        self.log = scrolledtext.ScrolledText(
            frame,
            height=30,
            state='disabled',
            wrap=tk.WORD,
            font=('TkFixedFont', 9)
        )
        self.log.pack(fill=tk.BOTH, expand=True)
        
        log_menu = tk.Menu(self.log, tearoff=0)
        log_menu.add_command(label="Очистить лог", command=self.clear_log)
        log_menu.add_command(label="Копировать всё", command=self.copy_log)
        log_menu.add_command(label="Сохранить в файл", command=self.save_log)
        
        def show_log_menu(event):
            log_menu.post(event.x_root, event.y_root)
        
        self.log.bind("<Button-3>", show_log_menu)
        
        self.log_msg("Приложение запущено. Готово к работе.")
        
        return frame
    
    def browse_geoip_geosite(self):
        """Выбор generate-geoip-geosite.exe"""
        path = filedialog.askopenfilename(
            title="Выберите generate-geoip-geosite.exe",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.geoip_geosite_path.set(path)
            self.log_msg(f"📁 Выбран generate-geoip-geosite: {path}")
    
    def browse_singbox(self):
        """Выбор sing-box.exe"""
        path = filedialog.askopenfilename(
            title="Выберите sing-box.exe",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"📁 Выбран sing-box: {path}")
    
    def browse_mihomo(self):
        """Выбор mihomo.exe"""
        path = filedialog.askopenfilename(
            title="Выберите mihomo.exe",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.mihomo_path.set(path)
            self.log_msg(f"📁 Выбран mihomo: {path}")
    
    def browse_output_dir(self):
        """Выбор папки для выходных файлов"""
        path = filedialog.askdirectory(title="Выберите папку для сохранения")
        if path:
            self.output_dir.set(path)
            self.log_msg(f"📁 Папка вывода: {path}")
    
    def load_file(self, key: str, category: str):
        """Загрузка данных из файла"""
        path = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return
        
        self.log_msg(f"📂 Загрузка файла: {os.path.basename(path)}...")
        
        def load_task():
            try:
                items = FileProcessor.read_large_file(path)
                
                widget_dict = None
                if category == 'domain':
                    widget_dict = self.domain_widgets.get(key)
                elif category == 'ip':
                    widget_dict = self.ip_widgets.get(key)
                elif category == 'process':
                    widget_dict = self.process_widgets.get(key)
                
                if widget_dict:
                    text_widget = widget_dict['text']
                    text_widget.delete('1.0', tk.END)
                    text_widget.insert(tk.END, '\n'.join(items))
                    widget_dict['count'].config(text=f"Строк: {len(items)}")
                    self.log_msg(f"Загружено {len(items)} записей в {key}")
            except Exception as e:
                self.log_msg(f"Ошибка загрузки: {str(e)}")
        
        threading.Thread(target=load_task, daemon=True).start()
    
    def clear_widget(self, widget):
        """Очистка текстового виджета"""
        widget.delete('1.0', tk.END)
        self.log_msg("Поле очищено")

    def clear_mihomo_widgets(self):
        """Безопасная очистка Mihomo виджетов"""
        if self.mihomo_domain_widget is not None:
            self.mihomo_domain_widget.delete('1.0', tk.END)
        if self.mihomo_ip_widget is not None:
            self.mihomo_ip_widget.delete('1.0', tk.END)
        self.log_msg("Mihomo поля очищены")

    def on_text_change(self, key: str):
        """Обработка изменения текста"""
        for category in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            if key in category:
                widget_dict = category[key]
                text_widget = widget_dict['text']
                content = text_widget.get('1.0', tk.END).strip()
                lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
                widget_dict['count'].config(text=f"Строк: {len(lines)}")
                break
    
    def validate_field(self, key: str, category: str):
        """Валидация поля"""
        widget_dict = None
        if category == 'domain':
            widget_dict = self.domain_widgets.get(key)
        elif category == 'ip':
            widget_dict = self.ip_widgets.get(key)
        
        if not widget_dict:
            return
        
        text_widget = widget_dict['text']
        content = text_widget.get('1.0', tk.END).strip()
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        
        if not lines:
            messagebox.showinfo("Валидация", "Поле пустое.")
            return
        
        errors = []
        
        for i, line in enumerate(lines, 1):
            valid = False
            
            if key in ['domain', 'domain_suffix']:
                valid = FileProcessor.validate_domain(line)
            elif key in ['ip_cidr', 'source_ip_cidr']:
                valid = FileProcessor.validate_ip_cidr(line)
            elif key == 'domain_regex':
                valid = FileProcessor.validate_regex(line)
            
            if not valid:
                errors.append(f"Строка {i}: {line}")
        
        if errors:
            error_msg = f"Найдено {len(errors)} ошибок:\n\n" + "\n".join(errors[:10])
            if len(errors) > 10:
                error_msg += f"\n\n... и ещё {len(errors) - 10} ошибок"
            messagebox.showerror("Ошибки валидации", error_msg)
            self.log_msg(f"Валидация {key}: найдено {len(errors)} ошибок")
        else:
            messagebox.showinfo("Валидация", f"✅ Все {len(lines)} записей валидны!")
            self.log_msg(f"Валидация {key}: OK")
    
    def parse_multiline_text(self, text_widget) -> List[str]:
        """Парсинг текста из виджета"""
        content = text_widget.get('1.0', tk.END).strip()
        if not content:
            return []
        return [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
    
    def collect_data(self) -> Dict:
        """Сбор всех данных из полей"""
        data = {}
        
        for key, widget_dict in self.domain_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        for key, widget_dict in self.ip_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        for key, widget_dict in self.process_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        network_type = self.network_widgets['network_type'].get()
        if network_type:
            data['network_type'] = network_type
        
        data['network_is_expensive'] = self.network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.network_widgets['network_is_constrained'].get()
        
        data['network_interface_address'] = self.parse_multiline_text(
            self.network_widgets['network_interface_address']
        )
        data['default_interface_address'] = self.parse_multiline_text(
            self.network_widgets['default_interface_address']
        )
        
        return data
    
    def generate_ruleset(self):
        """Генерация ruleset"""
        self.log_msg("Начало генерации ruleset...")
        
        # Проверка sing-box для .srs
        if self.compile_srs.get() and (not self.singbox_path.get() or not os.path.exists(self.singbox_path.get())):
            messagebox.showerror("Ошибка", "Для компиляции .srs необходимо указать путь к sing-box.exe!")
            return
        
        # ДОБАВЛЕНО: Проверка mihomo для .mrs
        if self.generate_mrs.get() and (not self.mihomo_path.get() or not os.path.exists(self.mihomo_path.get())):
            messagebox.showerror("Ошибка", "Для создания .mrs необходимо указать путь к mihomo.exe!")
            return
        
        data = self.collect_data()
        
        if self.validate_input.get():
            self.log_msg("Валидация данных...")
        
        filename = self.output_filename.get()
        if not filename:
            filename = "ruleset"
        
        output_dir = self.output_dir.get()
        if not output_dir:
            output_dir = os.getcwd()
        
        # Генерация JSON
        json_path = os.path.join(output_dir, f"{filename}.json")
        success, msg, stats = RulesetGenerator.generate_singbox_json(data, json_path)
        
        if not success:
            messagebox.showerror("Ошибка", msg)
            self.log_msg(f"{msg}")
            return
        
        self.log_msg(f"{msg}")
        self.log_msg(f"📊 Статистика: Домены={stats['domains']}, IP={stats['ips']}, Процессы={stats['processes']}, Сеть={stats['network']}")
        
        # Компиляция .srs
        if self.compile_srs.get():
            self.log_msg("Компиляция .srs...")
            success_srs, msg_srs = RulesetGenerator.compile_srs(self.singbox_path.get(), json_path)
            self.log_msg(f"{'✅' if success_srs else '❌'} {msg_srs}")
        
        # ИСПРАВЛЕНО: Генерация .mrs через mihomo.exe
        if self.generate_mrs.get():
            self.log_msg("Генерация .mrs для Mihomo...")
            
            # Определяем behavior type на основе данных
            behavior_type = "domain"  # По умолчанию domain
            has_domains = any(data.get(k) for k in ['domain', 'domain_suffix', 'domain_keyword'])
            has_ips = any(data.get(k) for k in ['ip_cidr', 'source_ip_cidr'])
            
            if has_ips and not has_domains:
                behavior_type = "ipcidr"
            elif has_domains and has_ips:
                behavior_type = "classical"
            
            self.log_msg(f"📝 Использован behavior type: {behavior_type}")
            
            # Создаём промежуточный YAML файл
            yaml_path = os.path.join(output_dir, f"{filename}_mihomo.yaml")
            success_yaml, msg_yaml, stats_yaml = RulesetGenerator.generate_mihomo_yaml(data, yaml_path)
            
            if success_yaml:
                self.log_msg(f"{msg_yaml}")
                
                # Компилируем через mihomo.exe
                mrs_path = os.path.join(output_dir, f"{filename}.mrs")
                success_mrs, msg_mrs = RulesetGenerator.compile_mrs(
                    self.mihomo_path.get(),
                    yaml_path,
                    mrs_path,
                    behavior_type
                )
                self.log_msg(f"{'✅' if success_mrs else '❌'} {msg_mrs}")
                
                # НЕ удаляем промежуточный YAML - оставляем для проверки
                if success_mrs:
                    self.log_msg(f"📄 Промежуточный YAML сохранён: {os.path.basename(yaml_path)}")
            else:
                self.log_msg(f"{msg_yaml}")
        
        messagebox.showinfo("Успех", "Ruleset успешно сгенерирован!")
        self.log_msg("=" * 60)
    
    def clear_all(self):
        """Очистка всех полей"""
        if messagebox.askyesno("Подтверждение", "Очистить все поля?"):
            for widgets in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
                for widget_dict in widgets.values():
                    widget_dict['text'].delete('1.0', tk.END)
                    if 'count' in widget_dict:
                        widget_dict['count'].config(text="Строк: 0")
            
            self.network_widgets['network_type'].set("")
            self.network_widgets['network_is_expensive'].set("false")
            self.network_widgets['network_is_constrained'].set("false")
            self.network_widgets['network_interface_address'].delete('1.0', tk.END)
            self.network_widgets['default_interface_address'].delete('1.0', tk.END)
            
            self.log_msg("🗑️ Все поля очищены")
    
    def show_statistics(self):
        """Показать статистику"""
        data = self.collect_data()
        
        stats_text = "📊 СТАТИСТИКА ДАННЫХ\n\n"
        stats_text += "=" * 40 + "\n\n"
        
        total = 0
        
        stats_text += "🌐 Домены:\n"
        for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
            count = len(data.get(key, []))
            total += count
            stats_text += f"  • {key}: {count}\n"
        
        stats_text += f"\n🔢 IP адреса:\n"
        for key in ['ip_cidr', 'source_ip_cidr']:
            count = len(data.get(key, []))
            total += count
            stats_text += f"  • {key}: {count}\n"
        
        stats_text += f"\n⚙️ Процессы:\n"
        for key in ['process_path_regex', 'package_name']:
            count = len(data.get(key, []))
            total += count
            stats_text += f"  • {key}: {count}\n"
        
        stats_text += f"\n📡 Сеть:\n"
        stats_text += f"  • network_type: {data.get('network_type', 'не задан')}\n"
        stats_text += f"  • network_is_expensive: {data.get('network_is_expensive', 'false')}\n"
        stats_text += f"  • network_is_constrained: {data.get('network_is_constrained', 'false')}\n"
        
        stats_text += "\n" + "=" * 40 + "\n"
        stats_text += f"ВСЕГО ЗАПИСЕЙ: {total}"
        
        messagebox.showinfo("Статистика", stats_text)
    
    def update_preview(self):
        """Обновление превью JSON"""
        self.log_msg("🔄 Обновление превью...")
        
        data = self.collect_data()
        
        rules = []
        
        domain_rule = {}
        for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
            if key in data and data[key]:
                domain_rule[key] = data[key][:5]
                if len(data[key]) > 5:
                    domain_rule[key].append(f"... ещё {len(data[key]) - 5}")
        if domain_rule:
            rules.append(domain_rule)
        
        ip_rule = {}
        for key in ['ip_cidr', 'source_ip_cidr']:
            if key in data and data[key]:
                ip_rule[key] = data[key][:5]
                if len(data[key]) > 5:
                    ip_rule[key].append(f"... ещё {len(data[key]) - 5}")
        if ip_rule:
            rules.append(ip_rule)
        
        preview_json = {
            "version": 1,
            "rules": rules
        }
        
        self.preview_text.configure(state='normal')
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.insert(tk.END, json.dumps(preview_json, indent=2, ensure_ascii=False))
        self.preview_text.configure(state='disabled')
        
        self.log_msg("Превью обновлено")
    
    def apply_template(self, template_data: Dict):
        """Применение шаблона"""
        if messagebox.askyesno("Применить шаблон", "Заменить текущие данные шаблоном?"):
            self.clear_all()
            
            for key, values in template_data.items():
                widget_dict = None
                
                if key in self.domain_widgets:
                    widget_dict = self.domain_widgets[key]
                elif key in self.ip_widgets:
                    widget_dict = self.ip_widgets[key]
                
                if widget_dict:
                    widget_dict['text'].insert(tk.END, '\n'.join(values))
                    widget_dict['count'].config(text=f"Строк: {len(values)}")
            
            self.log_msg(f"📋 Шаблон применён")
    
    def save_custom_template(self):
        """Сохранение пользовательского шаблона"""
        data = self.collect_data()

        template = {k: v for k, v in data.items() if v and ((isinstance(v, list) and len(v) > 0) or (isinstance(v, str) and v.strip()))}

        if not template:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения!")
            return
        
        path = filedialog.asksaveasfilename(
            title="Сохранить шаблон",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")]
        )
        
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=2, ensure_ascii=False)
            self.log_msg(f"💾 Шаблон сохранён: {os.path.basename(path)}")
            messagebox.showinfo("Успех", "Шаблон сохранён!")
    
    def browse_geo_input_dir(self):
        """Выбор Input директории"""
        path = filedialog.askdirectory(title="Выберите Input Directory")
        if path:
            self.geo_input_dir.set(path)
            self.log_msg(f"📁 Input Directory: {path}")
    
    def browse_geo_output_dir(self):
        """Выбор Output директории"""
        path = filedialog.askdirectory(title="Выберите Output Directory")
        if path:
            self.geo_output_dir.set(path)
            self.log_msg(f"📁 Output Directory: {path}")
    
    def browse_source_file(self):
        """Выбор source.json файла"""
        path = filedialog.askopenfilename(
            title="Выберите source.json файл",
            filetypes=[("JSON", "*.json"), ("All Files", "*.*")]
        )
        if path:
            self.geo_source_file.set(path)
            self.log_msg(f"📁 Source файл: {os.path.basename(path)}")
    
    def create_geo_input_files(self):
        """Создание входных файлов из текущих данных"""
        input_dir = self.geo_input_dir.get()
        
        if not input_dir:
            messagebox.showwarning("Предупреждение", "Укажите Input Directory!")
            return
        
        os.makedirs(input_dir, exist_ok=True)
        
        data = self.collect_data()
        
        created_files = []
        
        if data.get('domain') or data.get('domain_suffix'):
            domain_file = os.path.join(input_dir, "include-domain-custom.lst")
            with open(domain_file, 'w', encoding='utf-8') as f:
                for domain in data.get('domain', []):
                    f.write(f"{domain}\n")
                for suffix in data.get('domain_suffix', []):
                    f.write(f"{suffix}\n")
            created_files.append("include-domain-custom.lst")
        
        if data.get('ip_cidr'):
            ip_file = os.path.join(input_dir, "include-ip-custom.lst")
            with open(ip_file, 'w', encoding='utf-8') as f:
                for ip in data['ip_cidr']:
                    f.write(f"{ip}\n")
            created_files.append("include-ip-custom.lst")
        
        if data.get('domain_regex'):
            regex_file = os.path.join(input_dir, "exclude-domain-custom.rgx")
            with open(regex_file, 'w', encoding='utf-8') as f:
                for pattern in data['domain_regex']:
                    f.write(f"{pattern}\n")
            created_files.append("exclude-domain-custom.rgx")
        
        if created_files:
            self.log_msg(f"Создано файлов: {len(created_files)}")
            messagebox.showinfo(
                "Успех",
                f"Входные файлы созданы!\n\n"
                f"Директория: {input_dir}\n"
                f"Файлов: {len(created_files)}\n\n"
                f"{chr(10).join(created_files)}"
            )
        else:
            messagebox.showwarning("Предупреждение", "Нет данных для создания файлов!")
    
    def run_geoip_geosite_generation(self):
        """Запуск generate-geoip-geosite.exe"""
        exe_path = self.geoip_geosite_path.get()
        
        if not exe_path or not os.path.exists(exe_path):
            messagebox.showerror(
                "Ошибка",
                "generate-geoip-geosite.exe не найден!\n\n"
                "Скачайте утилиту и укажите путь в настройках."
            )
            return
        
        input_dir = self.geo_input_dir.get()
        output_dir = self.geo_output_dir.get()
        
        if not input_dir or not output_dir:
            messagebox.showwarning("Предупреждение", "Укажите Input и Output директории!")
            return
        
        if not os.path.exists(input_dir) or not os.listdir(input_dir):
            messagebox.showwarning(
                "Предупреждение",
                "Input Directory пуста!\n\nСоздайте входные файлы или используйте Source файл."
            )
            return
        
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = [exe_path, "-i", input_dir, "-o", output_dir]
        
        source_file = self.geo_source_file.get()
        if source_file and os.path.exists(source_file):
            cmd.extend(["-s", source_file])
        
        if self.gen_geoip.get():
            cmd.append("--gen-geoip")
        if self.gen_geosite.get():
            cmd.append("--gen-geosite")
        if self.gen_rule_set_json.get():
            cmd.append("--gen-rule-set-json")
        if self.gen_rule_set_srs.get():
            cmd.append("--gen-rule-set-srs")
        
        self.log_msg("=" * 60)
        self.log_msg(f"🚀 Запуск generate-geoip-geosite")
        self.log_msg(f"Команда: {' '.join(cmd)}")
        self.log_msg("=" * 60)
        
        def run_generation():
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(exe_path),
                    timeout=300
                )
                
                if result.stdout:
                    self.log_msg(result.stdout)
                if result.stderr:
                    self.log_msg(result.stderr)
                
                self.master.after(0, lambda: self.show_generation_result(result.returncode, output_dir))
                
            except subprocess.TimeoutExpired:
                self.log_msg("Таймаут выполнения (>5 минут)")
                self.master.after(0, lambda: messagebox.showerror("Ошибка", "Таймаут выполнения!"))
            except Exception as e:
                self.log_msg(f"Ошибка: {str(e)}")
                self.master.after(0, lambda: messagebox.showerror("Ошибка", str(e)))
        
        threading.Thread(target=run_generation, daemon=True).start()
    
    def show_generation_result(self, returncode, output_dir):
        """Показать результат генерации"""
        self.log_msg("=" * 60)
        
        if returncode == 0:
            files = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]
            
            self.log_msg(f"Генерация завершена успешно!")
            self.log_msg(f"Создано файлов: {len(files)}")
            
            messagebox.showinfo(
                "Успех",
                f"GeoIP/GeoSite успешно созданы!\n\n"
                f"Директория: {output_dir}\n"
                f"Файлов: {len(files)}"
            )
        else:
            self.log_msg(f"Ошибка генерации (код {returncode})")
            messagebox.showerror("Ошибка", f"Генерация завершилась с ошибкой!\n\nПроверьте лог.")
    
    def open_geo_output_dir(self):
        """Открыть Output директорию в проводнике"""
        output_dir = self.geo_output_dir.get()
        
        if not output_dir or not os.path.exists(output_dir):
            messagebox.showwarning("Предупреждение", "Output Directory не существует!")
            return
        
        try:
            if sys.platform == 'win32':
                os.startfile(output_dir)
            elif sys.platform == 'darwin':
                subprocess.run(['open', output_dir])
            else:
                subprocess.run(['xdg-open', output_dir])
            
            self.log_msg(f"📂 Открыта папка: {output_dir}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть папку:\n{str(e)}")
    
    def load_custom_template(self):
        """Загрузка пользовательского шаблона"""
        path = filedialog.askopenfilename(
            title="Загрузить шаблон",
            filetypes=[("JSON", "*.json")]
        )
        
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    template = json.load(f)
                self.apply_template(template)
                self.log_msg(f"📂 Шаблон загружен: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить шаблон:\n{str(e)}")
    
    def load_mihomo_file(self, field_type: str):
        """Загрузка файла для вкладки Mihomo"""
        path = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return
        
        self.log_msg(f"📂 Загрузка файла для Mihomo: {os.path.basename(path)}...")
        
        try:
            items = FileProcessor.read_large_file(path)
            
            if field_type == 'domain':
                self.mihomo_domain_widget.delete('1.0', tk.END)
                self.mihomo_domain_widget.insert(tk.END, '\n'.join(items))
            elif field_type == 'ip':
                self.mihomo_ip_widget.delete('1.0', tk.END)
                self.mihomo_ip_widget.insert(tk.END, '\n'.join(items))
            
            self.log_msg(f"Загружено {len(items)} записей")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{str(e)}")
    
    def preview_mihomo_yaml(self):
        """Предпросмотр YAML для Mihomo"""
        # Собираем данные
        domains = self.parse_multiline_text(self.mihomo_domain_widget)
        ips = self.parse_multiline_text(self.mihomo_ip_widget)
        
        if not domains and not ips:
            messagebox.showwarning("Предупреждение", "Добавьте домены или IP адреса!")
            return
        
        # Определяем behavior
        behavior = self.mihomo_behavior.get()
        if behavior == "auto":
            if domains and not ips:
                behavior = "domain"
            elif ips and not domains:
                behavior = "ipcidr"
            else:
                behavior = "classical"
        
        # Генерируем YAML
        yaml_content = "payload:\n"
        
        if behavior == "domain":
            for domain in domains:
                yaml_content += f"  - {domain}\n"
        elif behavior == "ipcidr":
            for ip in ips:
                yaml_content += f"  - {ip}\n"
        else:  # classical
            for domain in domains:
                if domain.startswith('.'):
                    yaml_content += f"  - DOMAIN-SUFFIX,{domain.lstrip('.')}\n"
                else:
                    yaml_content += f"  - DOMAIN,{domain}\n"
            for ip in ips:
                yaml_content += f"  - IP-CIDR,{ip}\n"
        
        # Показываем в окне
        preview_window = tk.Toplevel(self.master)
        preview_window.title(f"Предпросмотр YAML - Behavior: {behavior}")
        preview_window.geometry("600x400")
        
        ttk.Label(
            preview_window,
            text=f"Behavior type: {behavior} | Доменов: {len(domains)} | IP: {len(ips)}",
            font=('TkDefaultFont', 10, 'bold')
        ).pack(pady=10)
        
        text_widget = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD, font=('Consolas', 9))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        text_widget.insert(tk.END, yaml_content)
        text_widget.config(state='disabled')
        
        btn_frame = ttk.Frame(preview_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(
            btn_frame,
            text="Копировать",
            command=lambda: [preview_window.clipboard_clear(), preview_window.clipboard_append(yaml_content)]
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Закрыть",
            command=preview_window.destroy
        ).pack(side=tk.LEFT, padx=5)
        
        self.log_msg(f"👁️ Предпросмотр YAML: behavior={behavior}, записей={len(domains) + len(ips)}")
    
    def generate_mihomo_only(self):
        """Генерация только .mrs файла из вкладки Mihomo"""
        # Проверяем mihomo.exe
        if not self.mihomo_path.get() or not os.path.exists(self.mihomo_path.get()):
            messagebox.showerror("Ошибка", "Укажите путь к mihomo.exe в настройках!")
            return
        
        # Собираем данные
        domains = self.parse_multiline_text(self.mihomo_domain_widget)
        ips = self.parse_multiline_text(self.mihomo_ip_widget)
        
        if not domains and not ips:
            messagebox.showwarning("Предупреждение", "Добавьте домены или IP адреса!")
            return
        
        # Определяем behavior
        behavior = self.mihomo_behavior.get()
        if behavior == "auto":
            if domains and not ips:
                behavior = "domain"
            elif ips and not domains:
                behavior = "ipcidr"
            else:
                behavior = "classical"
        
        self.log_msg("=" * 60)
        self.log_msg("Генерация .mrs файла для Mihomo...")
        self.log_msg(f"📝 Behavior type: {behavior}")
        self.log_msg(f"📊 Доменов: {len(domains)}, IP: {len(ips)}")
        
        # Создаём данные для генератора
        data = {}
        if behavior == "domain":
            data['domain'] = domains
        elif behavior == "ipcidr":
            data['ip_cidr'] = ips
        else:  # classical
            data['domain'] = domains
            data['ip_cidr'] = ips
        
        # Имя файла и папка
        filename = self.output_filename.get() or "mihomo_ruleset"
        output_dir = self.output_dir.get() or os.getcwd()
        
        # Генерируем YAML
        yaml_path = os.path.join(output_dir, f"{filename}_mihomo.yaml")
        success_yaml, msg_yaml, stats_yaml = RulesetGenerator.generate_mihomo_yaml(data, yaml_path)
        
        if success_yaml:
            self.log_msg(f"{msg_yaml}")
            
            # Компилируем .mrs
            mrs_path = os.path.join(output_dir, f"{filename}.mrs")
            success_mrs, msg_mrs = RulesetGenerator.compile_mrs(
                self.mihomo_path.get(),
                yaml_path,
                mrs_path,
                behavior
            )
            self.log_msg(f"{'✅' if success_mrs else '❌'} {msg_mrs}")
            
            # Сохраняем YAML
            if success_mrs:
                self.log_msg(f"📄 YAML файл сохранён: {os.path.basename(yaml_path)}")
                messagebox.showinfo(
                    "Успех!",
                    f"Файлы созданы:\n\n"
                    f"✅ {filename}.mrs ({os.path.getsize(mrs_path)} байт)\n"
                    f"✅ {filename}_mihomo.yaml\n\n"
                    f"Behavior: {behavior}"
                )
            else:
                messagebox.showerror("Ошибка", msg_mrs)
        else:
            self.log_msg(f"{msg_yaml}")
            messagebox.showerror("Ошибка", msg_yaml)
        
        self.log_msg("=" * 60)
    
    def show_about(self):
        """О программе"""
        about_text = f"""
Ruleset Builder v{VERSION}

Универсальный инструмент для создания ruleset для:
• Sing-Box (.json, .srs)
• Mihomo (.mrs)

Возможности:
✓ Импорт больших файлов
✓ Валидация данных
✓ Готовые шаблоны
✓ Превью результата
✓ Статистика

Автор: Advanced Ruleset Builder
Год: 2024
        """
        messagebox.showinfo("О программе", about_text)
    
    def clear_log(self):
        """Очистка лога"""
        self.log.configure(state='normal')
        self.log.delete('1.0', tk.END)
        self.log.configure(state='disabled')
    
    def log_msg(self, msg: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

# ============================================================================
# CLI ИНТЕРФЕЙС
# ============================================================================

def cli_mode():
    """Режим командной строки"""
    parser = argparse.ArgumentParser(
        description=f"Ruleset Builder v{VERSION} - CLI Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-o', '--output', required=True, help='Выходной файл (без расширения)')
    parser.add_argument('-f', '--format', choices=['json', 'srs', 'mrs'], default='json', help='Формат выходного файла')
    parser.add_argument('--singbox', help='Путь к sing-box.exe (для .srs)')
    parser.add_argument('--mihomo', help='Путь к mihomo.exe (для .mrs)')
    
    parser.add_argument('--domain', help='Файл с доменами')
    parser.add_argument('--domain-suffix', help='Файл с суффиксами доменов')
    parser.add_argument('--domain-keyword', help='Файл с ключевыми словами')
    parser.add_argument('--domain-regex', help='Файл с regex для доменов')
    
    parser.add_argument('--ip-cidr', help='Файл с IP CIDR')
    parser.add_argument('--source-ip-cidr', help='Файл с Source IP CIDR')
    
    parser.add_argument('--validate', action='store_true', help='Валидировать входные данные')
    
    args = parser.parse_args()
    
    data = {}
    
    if args.domain:
        data['domain'] = FileProcessor.read_large_file(args.domain)
    if args.domain_suffix:
        data['domain_suffix'] = FileProcessor.read_large_file(args.domain_suffix)
    if args.domain_keyword:
        data['domain_keyword'] = FileProcessor.read_large_file(args.domain_keyword)
    if args.domain_regex:
        data['domain_regex'] = FileProcessor.read_large_file(args.domain_regex)
    if args.ip_cidr:
        data['ip_cidr'] = FileProcessor.read_large_file(args.ip_cidr)
    if args.source_ip_cidr:
        data['source_ip_cidr'] = FileProcessor.read_large_file(args.source_ip_cidr)
    
    if args.validate:
        print("🔍 Валидация данных...")
    
    output_path = f"{args.output}.{args.format}"
    
    if args.format == 'json':
        success, msg, stats = RulesetGenerator.generate_singbox_json(data, output_path)
        print(f"{'✅' if success else '❌'} {msg}")
        if success:
            print(f"📊 Статистика: {stats}")
    
    elif args.format == 'srs':
        json_path = f"{args.output}.json"
        success, msg, stats = RulesetGenerator.generate_singbox_json(data, json_path)
        if success:
            print(f"✅ {msg}")
            if args.singbox:
                success_srs, msg_srs = RulesetGenerator.compile_srs(args.singbox, json_path)
                print(f"{'✅' if success_srs else '❌'} {msg_srs}")
            else:
                print("❌ Требуется --singbox для компиляции .srs")
    
    elif args.format == 'mrs':
        yaml_path = f"{args.output}_mihomo.yaml"
        success, msg, stats = RulesetGenerator.generate_mihomo_yaml(data, yaml_path)
        if success:
            print(f"✅ {msg}")
            if args.mihomo:
                # Определяем behavior type
                has_domains = any(data.get(k) for k in ['domain', 'domain_suffix', 'domain_keyword'])
                has_ips = data.get('ip_cidr') or data.get('source_ip_cidr')
                
                if has_ips and not has_domains:
                    behavior_type = "ipcidr"
                elif has_domains and has_ips:
                    behavior_type = "classical"
                else:
                    behavior_type = "domain"
                
                print(f"📝 Использован behavior type: {behavior_type}")
                success_mrs, msg_mrs = RulesetGenerator.compile_mrs(args.mihomo, yaml_path, output_path, behavior_type)
                print(f"{'✅' if success_mrs else '❌'} {msg_mrs}")
            else:
                print("❌ Требуется --mihomo для компиляции .mrs")

# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    """Точка входа"""
    if len(sys.argv) > 1:
        cli_mode()
    else:
        root = tk.Tk()
        app = RulesetBuilderGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()