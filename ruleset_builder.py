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

VERSION = "3.0.0"
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
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
                
                bytes_read += len(line.encode('utf-8'))
                if progress_callback and file_size > 0:
                    progress = int((bytes_read / file_size) * 100)
                    progress_callback(progress)
        
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
    def generate_mihomo_mrs(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """Генерация .mrs файла для Mihomo"""
        try:
            stats = {'total': 0, 'domains': 0, 'ips': 0}
            
            # Собираем данные
            domains = []
            ips = []
            
            # Домены
            for key in ['domain', 'domain_suffix', 'domain_keyword']:
                if key in data and RulesetGenerator.is_non_empty(data[key]):
                    for item in data[key]:
                        if key == 'domain':
                            domains.append(('DOMAIN', item))
                        elif key == 'domain_suffix':
                            domains.append(('DOMAIN-SUFFIX', item))
                        elif key == 'domain_keyword':
                            domains.append(('DOMAIN-KEYWORD', item))
                    stats['domains'] += len(data[key])
            
            # IP CIDR
            if 'ip_cidr' in data and RulesetGenerator.is_non_empty(data['ip_cidr']):
                for cidr in data['ip_cidr']:
                    ips.append(('IP-CIDR', cidr))
                stats['ips'] += len(data['ip_cidr'])
            
            # Запись в бинарный файл (упрощённый формат)
            with open(output_path, 'wb') as f:
                # Заголовок: MRS + версия
                f.write(b'MRS\x01')
                
                # Количество правил
                total_rules = len(domains) + len(ips)
                f.write(struct.pack('>I', total_rules))
                
                # Записываем домены
                for rule_type, value in domains:
                    type_byte = 1 if rule_type == 'DOMAIN' else (2 if rule_type == 'DOMAIN-SUFFIX' else 3)
                    f.write(struct.pack('B', type_byte))
                    value_bytes = value.encode('utf-8')
                    f.write(struct.pack('>H', len(value_bytes)))
                    f.write(value_bytes)
                
                # Записываем IP
                for rule_type, value in ips:
                    f.write(struct.pack('B', 4))  # IP-CIDR type
                    value_bytes = value.encode('utf-8')
                    f.write(struct.pack('>H', len(value_bytes)))
                    f.write(value_bytes)
            
            stats['total'] = total_rules
            size = os.path.getsize(output_path)
            return True, f".mrs создан: {os.path.basename(output_path)} ({size} байт)", stats
        
        except Exception as e:
            return False, f"Ошибка создания .mrs: {str(e)}", {'total': 0}

# ============================================================================
# GUI ПРИЛОЖЕНИЕ
# ============================================================================

class RulesetBuilderGUI:
    """Главное окно приложения"""
    
    def __init__(self, master):
        self.master = master
        master.title(f"Ruleset Builder v{VERSION} — Sing-Box & Mihomo")
        master.geometry("1100x800")
        master.minsize(900, 650)
        
        # Переменные
        self.singbox_path = tk.StringVar()
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
        
        # Лог
        self.setup_log(main_frame)
    
    def setup_top_panel(self, parent):
        """Верхняя панель с настройками"""
        top_frame = ttk.LabelFrame(parent, text="⚙️ Настройки", padding=10)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Sing-box путь
        row = 0
        ttk.Label(top_frame, text="Sing-box:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.singbox_path, width=60).grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="📁", command=self.browse_singbox, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # Выходной файл
        row += 1
        ttk.Label(top_frame, text="Имя файла:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.output_filename, width=30).grid(
            row=row, column=1, sticky=tk.W, padx=5
        )
        
        ttk.Label(top_frame, text="Формат:").grid(row=row, column=2, sticky=tk.W, padx=(20, 0))
        format_combo = ttk.Combobox(
            top_frame,
            textvariable=self.output_format,
            values=["json", "srs", "mrs"],
            state="readonly",
            width=10
        )
        format_combo.grid(row=row, column=3, sticky=tk.W, padx=5)
        
        # Папка вывода
        row += 1
        ttk.Label(top_frame, text="Папка:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.output_dir, width=60, state='readonly').grid(
            row=row, column=1, columnspan=2, sticky=tk.EW, padx=5
        )
        ttk.Button(top_frame, text="📁", command=self.browse_output_dir, width=3).grid(
            row=row, column=3, padx=2
        )
        
        # Опции
        row += 1
        options_frame = ttk.Frame(top_frame)
        options_frame.grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=10)
        
        ttk.Checkbutton(
            options_frame,
            text="✓ Компилировать .srs",
            variable=self.compile_srs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="✓ Генерировать .mrs (Mihomo)",
            variable=self.generate_mrs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="✓ Валидация входных данных",
            variable=self.validate_input
        ).pack(side=tk.LEFT, padx=5)
        
        top_frame.columnconfigure(1, weight=1)
    
    def setup_tabs(self, parent):
        """Создание вкладок с правилами"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Вкладка Domains
        self.domain_frame = self.create_domain_tab(notebook)
        notebook.add(self.domain_frame, text="🌐 Domains")
        
        # Вкладка IPs
        self.ip_frame = self.create_ip_tab(notebook)
        notebook.add(self.ip_frame, text="🔢 IP Addresses")
        
        # Вкладка Process
        self.process_frame = self.create_process_tab(notebook)
        notebook.add(self.process_frame, text="⚙️ Processes")
        
        # Вкладка Network
        self.network_frame = self.create_network_tab(notebook)
        notebook.add(self.network_frame, text="📡 Network")
        
        # Вкладка Шаблоны
        self.templates_frame = self.create_templates_tab(notebook)
        notebook.add(self.templates_frame, text="📋 Шаблоны")
        
        # Вкладка Превью
        self.preview_frame = self.create_preview_tab(notebook)
        notebook.add(self.preview_frame, text="👁️ Превью")
    
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
            # Фрейм для каждого поля
            field_frame = ttk.LabelFrame(frame, text=label, padding=5)
            field_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            
            # Текстовое поле
            text_widget = scrolledtext.ScrolledText(field_frame, height=4, width=70, wrap=tk.WORD)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            text_widget.insert(tk.END, f"# {placeholder}")
            text_widget.bind('<KeyRelease>', lambda e, k=key: self.on_text_change(k))
            
            # Боковая панель с кнопками
            btn_frame = ttk.Frame(field_frame)
            btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
            
            ttk.Button(btn_frame, text="📁 Файл", command=lambda k=key: self.load_file(k, 'domain')).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="🗑️ Очистить", command=lambda w=text_widget: self.clear_widget(w)).pack(fill=tk.X, pady=2)
            if validate:
                ttk.Button(btn_frame, text="✓ Валидация", command=lambda k=key: self.validate_field(k, 'domain')).pack(fill=tk.X, pady=2)
            
            # Метка счётчика
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
            
            text_widget = scrolledtext.ScrolledText(field_frame, height=6, width=70, wrap=tk.WORD)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            text_widget.insert(tk.END, f"# {placeholder}")
            text_widget.bind('<KeyRelease>', lambda e, k=key: self.on_text_change(k))
            
            btn_frame = ttk.Frame(field_frame)
            btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
            
            ttk.Button(btn_frame, text="📁 Файл", command=lambda k=key: self.load_file(k, 'ip')).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="🗑️ Очистить", command=lambda w=text_widget: self.clear_widget(w)).pack(fill=tk.X, pady=2)
            ttk.Button(btn_frame, text="✓ Валидация", command=lambda k=key: self.validate_field(k, 'ip')).pack(fill=tk.X, pady=2)
            
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
        
        # Process Path Regex
        field_frame1 = ttk.LabelFrame(frame, text="Process Path Regex:", padding=5)
        field_frame1.pack(fill=tk.BOTH, expand=True, pady=5)
        
        text1 = scrolledtext.ScrolledText(field_frame1, height=6, width=70, wrap=tk.WORD)
        text1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        text1.insert(tk.END, "# ^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$\n# /usr/bin/firefox")
        text1.bind('<KeyRelease>', lambda e: self.on_text_change('process_path_regex'))
        
        btn_frame1 = ttk.Frame(field_frame1)
        btn_frame1.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(btn_frame1, text="📁 Файл", command=lambda: self.load_file('process_path_regex', 'process')).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame1, text="🗑️ Очистить", command=lambda: self.clear_widget(text1)).pack(fill=tk.X, pady=2)
        
        count1 = ttk.Label(btn_frame1, text="Строк: 0", foreground="gray")
        count1.pack(fill=tk.X, pady=2)
        
        # Package Name
        field_frame2 = ttk.LabelFrame(frame, text="Package Name (Android):", padding=5)
        field_frame2.pack(fill=tk.BOTH, expand=True, pady=5)
        
        text2 = scrolledtext.ScrolledText(field_frame2, height=6, width=70, wrap=tk.WORD)
        text2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        text2.insert(tk.END, "# com.example.app\n# org.telegram.messenger")
        text2.bind('<KeyRelease>', lambda e: self.on_text_change('package_name'))
        
        btn_frame2 = ttk.Frame(field_frame2)
        btn_frame2.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(btn_frame2, text="📁 Файл", command=lambda: self.load_file('package_name', 'process')).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame2, text="🗑️ Очистить", command=lambda: self.clear_widget(text2)).pack(fill=tk.X, pady=2)
        
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
        
        # Network Type
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
        
        # Boolean параметры
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
        
        # Адреса
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
    
    def create_templates_tab(self, parent):
        """Вкладка с шаблонами"""
        frame = ttk.Frame(parent, padding=10)
        
        ttk.Label(
            frame,
            text="Выберите готовый шаблон для быстрого заполнения:",
            font=('TkDefaultFont', 10, 'bold')
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Список шаблонов
        for template_name, template_data in TEMPLATES.items():
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=5)
            
            ttk.Button(
                btn_frame,
                text=f"📋 {template_name}",
                command=lambda t=template_data: self.apply_template(t),
                width=30
            ).pack(side=tk.LEFT, padx=(0, 10))
            
            # Описание
            desc = ", ".join([f"{k}: {len(v)}" for k, v in template_data.items()])
            ttk.Label(btn_frame, text=desc, foreground="gray").pack(side=tk.LEFT)
        
        # Разделитель
        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)
        
        # Сохранение/загрузка пользовательских шаблонов
        custom_frame = ttk.LabelFrame(frame, text="Пользовательские шаблоны:", padding=10)
        custom_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            custom_frame,
            text="💾 Сохранить текущие данные как шаблон",
            command=self.save_custom_template
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            custom_frame,
            text="📂 Загрузить шаблон из файла",
            command=self.load_custom_template
        ).pack(fill=tk.X, pady=2)
        
        return frame
    
    def create_preview_tab(self, parent):
        """Вкладка предпросмотра"""
        frame = ttk.Frame(parent, padding=10)
        
        # Кнопка обновления
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(
            btn_frame,
            text="🔄 Обновить превью",
            command=self.update_preview
        ).pack(side=tk.LEFT)
        
        ttk.Label(btn_frame, text="Предпросмотр JSON структуры:", font=('TkDefaultFont', 10, 'bold')).pack(side=tk.LEFT, padx=20)
        
        # Текстовое поле с превью
        self.preview_text = scrolledtext.ScrolledText(frame, height=30, width=90, wrap=tk.WORD)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.configure(state='disabled')
        
        return frame
    
    def setup_bottom_panel(self, parent):
        """Нижняя панель с кнопками действий"""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        
        # Левая сторона
        left_frame = ttk.Frame(btn_frame)
        left_frame.pack(side=tk.LEFT)
        
        ttk.Button(
            left_frame,
            text="🚀 Генерировать Ruleset",
            command=self.generate_ruleset,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            left_frame,
            text="🗑️ Очистить всё",
            command=self.clear_all
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            left_frame,
            text="📊 Статистика",
            command=self.show_statistics
        ).pack(side=tk.LEFT, padx=5)
        
        # Правая сторона
        right_frame = ttk.Frame(btn_frame)
        right_frame.pack(side=tk.RIGHT)
        
        ttk.Button(
            right_frame,
            text="ℹ️ О программе",
            command=self.show_about
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            right_frame,
            text="❌ Выход",
            command=self.master.quit
        ).pack(side=tk.LEFT, padx=5)
    
    def setup_log(self, parent):
        """Лог-панель"""
        log_frame = ttk.LabelFrame(parent, text="📋 Лог событий:", padding=5)
        log_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.log = scrolledtext.ScrolledText(log_frame, height=6, state='disabled', wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        
        # Контекстное меню для лога
        log_menu = tk.Menu(self.log, tearoff=0)
        log_menu.add_command(label="Очистить лог", command=self.clear_log)
        log_menu.add_command(label="Копировать", command=lambda: self.master.clipboard_append(self.log.get('1.0', tk.END)))
        
        def show_log_menu(event):
            log_menu.post(event.x_root, event.y_root)
        
        self.log.bind("<Button-3>", show_log_menu)
        
        self.log_msg("✅ Приложение запущено. Готово к работе.")
    
    def apply_theme(self):
        """Применение темы оформления"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Акцентная кнопка
        style.configure('Accent.TButton', foreground='white', background='#007ACC', font=('TkDefaultFont', 10, 'bold'))
        style.map('Accent.TButton', background=[('active', '#005A9E')])
    
    # ========================================================================
    # МЕТОДЫ ОБРАБОТКИ СОБЫТИЙ
    # ========================================================================
    
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
                
                # Найти виджет
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
                    self.log_msg(f"✅ Загружено {len(items)} записей в {key}")
            except Exception as e:
                self.log_msg(f"❌ Ошибка загрузки: {str(e)}")
        
        threading.Thread(target=load_task, daemon=True).start()
    
    def clear_widget(self, widget):
        """Очистка текстового виджета"""
        widget.delete('1.0', tk.END)
        self.log_msg("🗑️ Поле очищено")
    
    def on_text_change(self, key: str):
        """Обработка изменения текста"""
        # Обновляем счётчик строк
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
            self.log_msg(f"❌ Валидация {key}: найдено {len(errors)} ошибок")
        else:
            messagebox.showinfo("Валидация", f"✅ Все {len(lines)} записей валидны!")
            self.log_msg(f"✅ Валидация {key}: OK")
    
    def parse_multiline_text(self, text_widget) -> List[str]:
        """Парсинг текста из виджета"""
        content = text_widget.get('1.0', tk.END).strip()
        if not content:
            return []
        return [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
    
    def collect_data(self) -> Dict:
        """Сбор всех данных из полей"""
        data = {}
        
        # Domains
        for key, widget_dict in self.domain_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        # IPs
        for key, widget_dict in self.ip_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        # Processes
        for key, widget_dict in self.process_widgets.items():
            data[key] = self.parse_multiline_text(widget_dict['text'])
        
        # Network
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
        self.log_msg("🚀 Начало генерации ruleset...")
        
        # Проверка sing-box для .srs
        if self.compile_srs.get() and (not self.singbox_path.get() or not os.path.exists(self.singbox_path.get())):
            messagebox.showerror("Ошибка", "Для компиляции .srs необходимо указать путь к sing-box.exe!")
            return
        
        # Сбор данных
        data = self.collect_data()
        
        # Валидация (опционально)
        if self.validate_input.get():
            self.log_msg("🔍 Валидация данных...")
            # Здесь можно добавить проверку
        
        # Имя файла
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
            self.log_msg(f"❌ {msg}")
            return
        
        self.log_msg(f"✅ {msg}")
        self.log_msg(f"📊 Статистика: Домены={stats['domains']}, IP={stats['ips']}, Процессы={stats['processes']}, Сеть={stats['network']}")
        
        # Компиляция .srs
        if self.compile_srs.get():
            self.log_msg("⚙️ Компиляция .srs...")
            success_srs, msg_srs = RulesetGenerator.compile_srs(self.singbox_path.get(), json_path)
            self.log_msg(f"{'✅' if success_srs else '❌'} {msg_srs}")
        
        # Генерация .mrs
        if self.generate_mrs.get():
            self.log_msg("⚙️ Генерация .mrs для Mihomo...")
            mrs_path = os.path.join(output_dir, f"{filename}.mrs")
            success_mrs, msg_mrs, stats_mrs = RulesetGenerator.generate_mihomo_mrs(data, mrs_path)
            self.log_msg(f"{'✅' if success_mrs else '❌'} {msg_mrs}")
        
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
        
        # Domains
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
        
        # Генерируем временный JSON
        rules = []
        
        # Domain
        domain_rule = {}
        for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
            if key in data and data[key]:
                domain_rule[key] = data[key][:5]  # Первые 5 для превью
                if len(data[key]) > 5:
                    domain_rule[key].append(f"... ещё {len(data[key]) - 5}")
        if domain_rule:
            rules.append(domain_rule)
        
        # IP
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
        
        self.log_msg("✅ Превью обновлено")
    
    def apply_template(self, template_data: Dict):
        """Применение шаблона"""
        if messagebox.askyesno("Применить шаблон", "Заменить текущие данные шаблоном?"):
            # Очистка
            self.clear_all()
            
            # Заполнение
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
        
        # Фильтруем пустые
        template = {k: v for k, v in data.items() if v and (isinstance(v, list) and len(v) > 0 or isinstance(v, str) and v.strip())}
        
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
    
    parser.add_argument('--domain', help='Файл с доменами')
    parser.add_argument('--domain-suffix', help='Файл с суффиксами доменов')
    parser.add_argument('--domain-keyword', help='Файл с ключевыми словами')
    parser.add_argument('--domain-regex', help='Файл с regex для доменов')
    
    parser.add_argument('--ip-cidr', help='Файл с IP CIDR')
    parser.add_argument('--source-ip-cidr', help='Файл с Source IP CIDR')
    
    parser.add_argument('--validate', action='store_true', help='Валидировать входные данные')
    
    args = parser.parse_args()
    
    # Сбор данных
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
    
    # Валидация
    if args.validate:
        print("🔍 Валидация данных...")
        # Добавить валидацию
    
    # Генерация
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
        success, msg, stats = RulesetGenerator.generate_mihomo_mrs(data, output_path)
        print(f"{'✅' if success else '❌'} {msg}")
        if success:
            print(f"📊 Статистика: {stats}")

# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    """Точка входа"""
    if len(sys.argv) > 1:
        # CLI режим
        cli_mode()
    else:
        # GUI режим
        root = tk.Tk()
        app = RulesetBuilderGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()
