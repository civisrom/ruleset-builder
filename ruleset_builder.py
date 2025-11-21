#!/usr/bin/env python3
"""
Advanced Ruleset Builder v3.5
Поддержка: Sing-Box, Mihomo, Generate-GeoIP-GeoSite
"""

import json
import argparse
import os
import sys
import re
import struct
import subprocess
import threading
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ============================================================================
# КОНСТАНТЫ
# ============================================================================

VERSION = "3.5.0"

# Шаблоны для быстрого заполнения
TEMPLATES = {
    "Блокировка рекламы": {
        "domain_suffix": [".ad.com", ".ads.com", ".doubleclick.net", ".googlesyndication.com"],
        "domain_keyword": ["analytics", "telemetry", "tracking", "advertisement"]
    },
    "Российские домены": {
        "domain_suffix": [".ru", ".рф", ".su"]
    },
    "Социальные сети": {
        "domain": ["facebook.com", "twitter.com", "instagram.com", "vk.com"],
        "domain_suffix": [".facebook.com", ".twitter.com", ".instagram.com"]
    },
    "Китайские домены": {
        "domain_suffix": [".cn", ".com.cn", ".net.cn"],
        "domain_keyword": ["baidu", "taobao", "alibaba", "qq"]
    }
}

# ============================================================================
# КЛАССЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ
# ============================================================================

class FileProcessor:
    """Обработка файлов с валидацией"""
    
    @staticmethod
    def read_large_file(file_path: str, progress_callback=None) -> List[str]:
        """Построчное чтение больших файлов"""
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
        """Валидация домена"""
        if not domain:
            return False
        domain = domain.lstrip('.')
        if not domain:
            return False
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, domain))
    
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

# ============================================================================
# ГЕНЕРАТОРЫ ДЛЯ РАЗНЫХ ФОРМАТОВ
# ============================================================================

class SingBoxGenerator:
    """Генератор для Sing-Box"""
    
    @staticmethod
    def generate_json(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """Генерация JSON ruleset"""
        rules = []
        stats = {'total': 0, 'domains': 0, 'ips': 0}
        
        # Домены
        domain_rule = {}
        for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
            if key in data and data[key]:
                domain_rule[key] = data[key]
                stats['domains'] += len(data[key])
        if domain_rule:
            rules.append(domain_rule)
        
        # IP
        ip_rule = {}
        for key in ['ip_cidr', 'source_ip_cidr']:
            if key in data and data[key]:
                ip_rule[key] = data[key]
                stats['ips'] += len(data[key])
        if ip_rule:
            rules.append(ip_rule)
        
        ruleset = {"version": 1, "rules": rules}
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(ruleset, f, indent=2, ensure_ascii=False)
            stats['total'] = stats['domains'] + stats['ips']
            return True, f"✅ JSON создан: {os.path.basename(output_path)}", stats
        except Exception as e:
            return False, f"❌ Ошибка: {str(e)}", stats
    
    @staticmethod
    def compile_srs(singbox_path: str, json_path: str) -> Tuple[bool, str]:
        """Компиляция .srs через sing-box"""
        if not os.path.exists(singbox_path):
            return False, "❌ sing-box.exe не найден!"
        
        cmd = [singbox_path, "rule-set", "compile", json_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  cwd=os.path.dirname(singbox_path), timeout=30)
            
            if result.returncode == 0:
                srs_path = json_path.replace(".json", ".srs")
                if os.path.exists(srs_path):
                    size = os.path.getsize(srs_path)
                    return True, f"✅ .srs создан: {os.path.basename(srs_path)} ({size} байт)"
                else:
                    return False, "❌ .srs файл не создан"
            else:
                return False, f"❌ Ошибка: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "❌ Таймаут компиляции"
        except Exception as e:
            return False, f"❌ Ошибка: {str(e)}"

class MihomoGenerator:
    """Генератор для Mihomo"""
    
    @staticmethod
    def generate_yaml(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """Генерация YAML для Mihomo"""
        rules = []
        stats = {'total': 0}
        
        # Домены
        if 'domain' in data:
            for d in data['domain']:
                rules.append(f"  - DOMAIN,{d}")
                stats['total'] += 1
        
        if 'domain_suffix' in data:
            for d in data['domain_suffix']:
                rules.append(f"  - DOMAIN-SUFFIX,{d.lstrip('.')}")
                stats['total'] += 1
        
        if 'domain_keyword' in data:
            for d in data['domain_keyword']:
                rules.append(f"  - DOMAIN-KEYWORD,{d}")
                stats['total'] += 1
        
        # IP
        if 'ip_cidr' in data:
            for ip in data['ip_cidr']:
                rules.append(f"  - IP-CIDR,{ip}")
                stats['total'] += 1
        
        yaml_content = "payload:\n" + "\n".join(rules)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
            return True, f"✅ YAML создан: {os.path.basename(output_path)}", stats
        except Exception as e:
            return False, f"❌ Ошибка: {str(e)}", stats
    
    @staticmethod
    def generate_mrs(data: Dict, output_path: str) -> Tuple[bool, str, Dict]:
        """Генерация бинарного .mrs"""
        try:
            stats = {'total': 0}
            
            with open(output_path, 'wb') as f:
                # Заголовок
                f.write(b'MRS\x01')
                
                # Подсчёт правил
                total_rules = 0
                if 'domain' in data:
                    total_rules += len(data['domain'])
                if 'domain_suffix' in data:
                    total_rules += len(data['domain_suffix'])
                if 'ip_cidr' in data:
                    total_rules += len(data['ip_cidr'])
                
                f.write(struct.pack('>I', total_rules))
                
                # Домены
                if 'domain' in data:
                    for domain in data['domain']:
                        f.write(struct.pack('B', 1))  # DOMAIN type
                        value_bytes = domain.encode('utf-8')
                        f.write(struct.pack('>H', len(value_bytes)))
                        f.write(value_bytes)
                
                if 'domain_suffix' in data:
                    for suffix in data['domain_suffix']:
                        f.write(struct.pack('B', 2))  # DOMAIN-SUFFIX type
                        value_bytes = suffix.encode('utf-8')
                        f.write(struct.pack('>H', len(value_bytes)))
                        f.write(value_bytes)
                
                if 'ip_cidr' in data:
                    for ip in data['ip_cidr']:
                        f.write(struct.pack('B', 4))  # IP-CIDR type
                        value_bytes = ip.encode('utf-8')
                        f.write(struct.pack('>H', len(value_bytes)))
                        f.write(value_bytes)
            
            stats['total'] = total_rules
            size = os.path.getsize(output_path)
            return True, f"✅ .mrs создан: {os.path.basename(output_path)} ({size} байт)", stats
        except Exception as e:
            return False, f"❌ Ошибка: {str(e)}", {'total': 0}

class GeoIPGeoSiteGenerator:
    """Генератор через generate-geoip-geosite.exe"""
    
    @staticmethod
    def run_generator(exe_path: str, config: Dict) -> Tuple[bool, str]:
        """Запуск generate-geoip-geosite.exe"""
        if not os.path.exists(exe_path):
            return False, "❌ generate-geoip-geosite.exe не найден!"
        
        # Создаём временный конфигурационный файл
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            config_path = f.name
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        try:
            # Запускаем программу
            cmd = [exe_path, "-c", config_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return True, f"✅ Генерация завершена успешно\n{result.stdout}"
            else:
                return False, f"❌ Ошибка:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "❌ Таймаут (>60 сек)"
        except Exception as e:
            return False, f"❌ Ошибка: {str(e)}"
        finally:
            # Удаляем временный файл
            try:
                os.remove(config_path)
            except:
                pass

# ============================================================================
# ГЛАВНОЕ GUI ПРИЛОЖЕНИЕ
# ============================================================================

class RulesetBuilderGUI:
    """Главное окно с вкладками для каждого инструмента"""
    
    def __init__(self, master):
        self.master = master
        master.title(f"Ruleset Builder v{VERSION}")
        
        # Делаем окно масштабируемым и с прокруткой
        master.state('zoomed')  # Максимизируем окно на Windows
        
        # Главный контейнер с прокруткой
        self.main_canvas = tk.Canvas(master)
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        )
        
        self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Прокрутка мышью
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Переменные
        self.singbox_path = tk.StringVar()
        self.mihomo_path = tk.StringVar()
        self.geoipgeosite_path = tk.StringVar()
        self.output_dir = tk.StringVar(value=os.getcwd())
        
        self.setup_ui()
    
    def _on_mousewheel(self, event):
        """Прокрутка колесом мыши"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def setup_ui(self):
        """Создание интерфейса"""
        main_frame = ttk.Frame(self.scrollable_frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(title_frame, text=f"🚀 Ruleset Builder v{VERSION}", 
                 font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="Sing-Box | Mihomo | Generate-GeoIP-GeoSite", 
                 font=('Arial', 10), foreground='gray').pack(side=tk.LEFT, padx=20)
        
        # Основные вкладки
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Вкладка Sing-Box
        self.singbox_frame = self.create_singbox_tab()
        self.notebook.add(self.singbox_frame, text="📦 Sing-Box")
        
        # Вкладка Mihomo
        self.mihomo_frame = self.create_mihomo_tab()
        self.notebook.add(self.mihomo_frame, text="🔷 Mihomo")
        
        # Вкладка Generate-GeoIP-GeoSite
        self.geogen_frame = self.create_geogen_tab()
        self.notebook.add(self.geogen_frame, text="🌍 Generate-GeoIP-GeoSite")
        
        # Вкладка шаблонов
        self.templates_frame = self.create_templates_tab()
        self.notebook.add(self.templates_frame, text="📋 Шаблоны")
        
        # Лог
        self.setup_log(main_frame)
        
        # Нижняя панель
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="❌ Выход", command=self.master.quit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Очистить лог", command=self.clear_log).pack(side=tk.RIGHT, padx=5)
    
    def create_singbox_tab(self):
        """Вкладка Sing-Box"""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # Canvas для прокрутки внутри вкладки
        canvas = tk.Canvas(frame, height=600)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Настройки Sing-Box
        settings_frame = ttk.LabelFrame(scrollable, text="⚙️ Настройки Sing-Box", padding=10)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="Путь к sing-box.exe:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.singbox_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(settings_frame, text="📁", command=self.browse_singbox, width=3).grid(row=0, column=2)
        
        ttk.Label(settings_frame, text="Папка вывода:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.output_dir, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(settings_frame, text="📁", command=self.browse_output_dir, width=3).grid(row=1, column=2)
        
        self.singbox_filename = tk.StringVar(value="ruleset")
        ttk.Label(settings_frame, text="Имя файла:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.singbox_filename, width=30).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        self.singbox_compile_srs = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="✓ Компилировать в .srs", 
                       variable=self.singbox_compile_srs).grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Поля ввода данных
        data_frame = ttk.LabelFrame(scrollable, text="📝 Правила", padding=10)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.singbox_widgets = {}
        
        fields = [
            ('domain', "Домены (DOMAIN):"),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):"),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):"),
            ('domain_regex', "Regex (DOMAIN-REGEX):"),
            ('ip_cidr', "IP CIDR:"),
        ]
        
        for i, (key, label) in enumerate(fields):
            ttk.Label(data_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            
            text = scrolledtext.ScrolledText(data_frame, height=3, width=50)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            
            ttk.Button(data_frame, text="📁", command=lambda k=key: self.load_file_singbox(k)).grid(row=i, column=2)
            
            self.singbox_widgets[key] = text
        
        data_frame.columnconfigure(1, weight=1)
        
        # Кнопка генерации
        ttk.Button(scrollable, text="🚀 Генерировать Sing-Box Ruleset", 
                  command=self.generate_singbox, 
                  style='Accent.TButton').pack(pady=10, fill=tk.X)
        
        return frame
    
    def create_mihomo_tab(self):
        """Вкладка Mihomo"""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # Canvas для прокрутки
        canvas = tk.Canvas(frame, height=600)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Настройки Mihomo
        settings_frame = ttk.LabelFrame(scrollable, text="⚙️ Настройки Mihomo", padding=10)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="Папка вывода:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.output_dir, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(settings_frame, text="📁", command=self.browse_output_dir, width=3).grid(row=0, column=2)
        
        self.mihomo_filename = tk.StringVar(value="mihomo_rules")
        ttk.Label(settings_frame, text="Имя файла:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.mihomo_filename, width=30).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        self.mihomo_format = tk.StringVar(value="yaml")
        ttk.Label(settings_frame, text="Формат:").grid(row=2, column=0, sticky=tk.W, pady=5)
        format_frame = ttk.Frame(settings_frame)
        format_frame.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(format_frame, text="YAML", variable=self.mihomo_format, value="yaml").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="MRS (binary)", variable=self.mihomo_format, value="mrs").pack(side=tk.LEFT, padx=5)
        
        # Поля данных
        data_frame = ttk.LabelFrame(scrollable, text="📝 Правила", padding=10)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.mihomo_widgets = {}
        
        fields = [
            ('domain', "Домены (DOMAIN):"),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):"),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):"),
            ('ip_cidr', "IP CIDR:"),
        ]
        
        for i, (key, label) in enumerate(fields):
            ttk.Label(data_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            
            text = scrolledtext.ScrolledText(data_frame, height=3, width=50)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            
            ttk.Button(data_frame, text="📁", command=lambda k=key: self.load_file_mihomo(k)).grid(row=i, column=2)
            
            self.mihomo_widgets[key] = text
        
        data_frame.columnconfigure(1, weight=1)
        
        # Кнопка генерации
        ttk.Button(scrollable, text="🚀 Генерировать Mihomo Ruleset", 
                  command=self.generate_mihomo,
                  style='Accent.TButton').pack(pady=10, fill=tk.X)
        
        return frame
    
    def create_geogen_tab(self):
        """Вкладка Generate-GeoIP-GeoSite"""
        frame = ttk.Frame(self.notebook, padding=10)
        
        # Canvas для прокрутки
        canvas = tk.Canvas(frame, height=600)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Настройки
        settings_frame = ttk.LabelFrame(scrollable, text="⚙️ Настройки Generate-GeoIP-GeoSite", padding=10)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="Путь к generate-geoip-geosite.exe:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.geoipgeosite_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(settings_frame, text="📁", command=self.browse_geoipgeosite, width=3).grid(row=0, column=2)
        
        ttk.Label(settings_frame, text="Папка вывода:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.output_dir, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(settings_frame, text="📁", command=self.browse_output_dir, width=3).grid(row=1, column=2)
        
        # Конфигурация
        config_frame = ttk.LabelFrame(scrollable, text="📋 Конфигурация", padding=10)
        config_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # GeoIP настройки
        geoip_frame = ttk.LabelFrame(config_frame, text="🌍 GeoIP", padding=5)
        geoip_frame.pack(fill=tk.X, pady=5)
        
        self.geogen_enable_geoip = tk.BooleanVar(value=True)
        ttk.Checkbutton(geoip_frame, text="Включить GeoIP", variable=self.geogen_enable_geoip).pack(anchor=tk.W)
        
        ttk.Label(geoip_frame, text="Источники IP (по одному на строку):").pack(anchor=tk.W, pady=(5, 0))
        self.geogen_geoip_sources = scrolledtext.ScrolledText(geoip_frame, height=4, width=60)
        self.geogen_geoip_sources.pack(fill=tk.X, pady=5)
        self.geogen_geoip_sources.insert('1.0', "https://raw.githubusercontent.com/v2fly/geoip/release/geoip.dat\n")
        
        # GeoSite настройки
        geosite_frame = ttk.LabelFrame(config_frame, text="🌐 GeoSite", padding=5)
        geosite_frame.pack(fill=tk.X, pady=5)
        
        self.geogen_enable_geosite = tk.BooleanVar(value=True)
        ttk.Checkbutton(geosite_frame, text="Включить GeoSite", variable=self.geogen_enable_geosite).pack(anchor=tk.W)
        
        ttk.Label(geosite_frame, text="Источники доменов (по одному на строку):").pack(anchor=tk.W, pady=(5, 0))
        self.geogen_geosite_sources = scrolledtext.ScrolledText(geosite_frame, height=4, width=60)
        self.geogen_geosite_sources.pack(fill=tk.X, pady=5)
        self.geogen_geosite_sources.insert('1.0', "https://raw.githubusercontent.com/v2fly/domain-list-community/release/dlc.dat\n")
        
        # Дополнительные домены
        custom_frame = ttk.LabelFrame(config_frame, text="➕ Дополнительные правила", padding=5)
        custom_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(custom_frame, text="Домены для включения:").pack(anchor=tk.W)
        self.geogen_custom_domains = scrolledtext.ScrolledText(custom_frame, height=3, width=60)
        self.geogen_custom_domains.pack(fill=tk.X, pady=2)
        
        ttk.Label(custom_frame, text="IP для включения:").pack(anchor=tk.W, pady=(5, 0))
        self.geogen_custom_ips = scrolledtext.ScrolledText(custom_frame, height=3, width=60)
        self.geogen_custom_ips.pack(fill=tk.X, pady=2)
        
        # Формат вывода
        output_frame = ttk.LabelFrame(config_frame, text="📦 Формат вывода", padding=5)
        output_frame.pack(fill=tk.X, pady=5)
        
        self.geogen_output_format = tk.StringVar(value="dat")
        format_opts = ttk.Frame(output_frame)
        format_opts.pack(anchor=tk.W)
        
        ttk.Radiobutton(format_opts, text="DAT (V2Ray)", variable=self.geogen_output_format, value="dat").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_opts, text="DB (SagerNet)", variable=self.geogen_output_format, value="db").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_opts, text="MMDB (MaxMind)", variable=self.geogen_output_format, value="mmdb").pack(side=tk.LEFT, padx=5)
        
        # Кнопка запуска
        ttk.Button(scrollable, text="🚀 Запустить Generate-GeoIP-GeoSite", 
                  command=self.run_geoipgeosite,
                  style='Accent.TButton').pack(pady=10, fill=tk.X)
        
        return frame
    
    def create_templates_tab(self):
        """Вкладка шаблонов"""
        frame = ttk.Frame(self.notebook, padding=10)
        
        ttk.Label(frame, text="📋 Готовые шаблоны для быстрого заполнения", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        for template_name, template_data in TEMPLATES.items():
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=5)
            
            ttk.Button(btn_frame, text=f"📋 {template_name}", 
                      command=lambda t=template_data: self.apply_template(t),
                      width=30).pack(side=tk.LEFT, padx=5)
            
            desc = ", ".join([f"{k}: {len(v)}" for k, v in template_data.items()])
            ttk.Label(btn_frame, text=desc, foreground="gray").pack(side=tk.LEFT)
        
        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=20)
        
        custom_frame = ttk.LabelFrame(frame, text="Пользовательские шаблоны", padding=10)
        custom_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(custom_frame, text="💾 Сохранить текущие данные", 
                  command=self.save_template).pack(fill=tk.X, pady=2)
        ttk.Button(custom_frame, text="📂 Загрузить шаблон", 
                  command=self.load_template).pack(fill=tk.X, pady=2)
        
        return frame
    
    def setup_log(self, parent):
        """Панель лога"""
        log_frame = ttk.LabelFrame(parent, text="📋 Лог событий", padding=5)
        log_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.log = scrolledtext.ScrolledText(log_frame, height=8, state='disabled', wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        
        self.log_msg("✅ Приложение запущено")
    
    # ========================================================================
    # ОБРАБОТЧИКИ СОБЫТИЙ
    # ========================================================================
    
    def browse_singbox(self):
        path = filedialog.askopenfilename(title="Выберите sing-box.exe", 
                                         filetypes=[("Executable", "*.exe"), ("All Files", "*.*")])
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"📁 sing-box: {path}")
    
    def browse_geoipgeosite(self):
        path = filedialog.askopenfilename(title="Выберите generate-geoip-geosite.exe",
                                         filetypes=[("Executable", "*.exe"), ("All Files", "*.*")])
        if path:
            self.geoipgeosite_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"📁 generate-geoip-geosite: {path}")
    
    def browse_output_dir(self):
        path = filedialog.askdirectory(title="Выберите папку вывода")
        if path:
            self.output_dir.set(path)
            self.log_msg(f"📁 Папка вывода: {path}")
    
    def load_file_singbox(self, key):
        self._load_file_generic(key, self.singbox_widgets)
    
    def load_file_mihomo(self, key):
        self._load_file_generic(key, self.mihomo_widgets)
    
    def _load_file_generic(self, key, widgets_dict):
        path = filedialog.askopenfilename(title="Выберите файл", 
                                         filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        
        self.log_msg(f"📂 Загрузка: {os.path.basename(path)}...")
        
        def load_task():
            try:
                items = FileProcessor.read_large_file(path)
                widget = widgets_dict.get(key)
                if widget:
                    widget.delete('1.0', tk.END)
                    widget.insert(tk.END, '\n'.join(items))
                    self.log_msg(f"✅ Загружено {len(items)} записей в {key}")
            except Exception as e:
                self.log_msg(f"❌ Ошибка: {str(e)}")
        
        threading.Thread(target=load_task, daemon=True).start()
    
    def parse_text_widget(self, widget) -> List[str]:
        """Извлечение строк из текстового поля"""
        content = widget.get('1.0', tk.END).strip()
        if not content:
            return []
        return [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
    
    def collect_data(self, widgets_dict) -> Dict:
        """Сбор данных из виджетов"""
        data = {}
        for key, widget in widgets_dict.items():
            items = self.parse_text_widget(widget)
            if items:
                data[key] = items
        return data
    
    def generate_singbox(self):
        """Генерация Sing-Box ruleset"""
        self.log_msg("🚀 Генерация Sing-Box ruleset...")
        
        # Сбор данных
        data = self.collect_data(self.singbox_widgets)
        
        if not data:
            messagebox.showwarning("Предупреждение", "Нет данных для генерации!")
            return
        
        # Генерация JSON
        filename = self.singbox_filename.get() or "ruleset"
        json_path = os.path.join(self.output_dir.get(), f"{filename}.json")
        
        success, msg, stats = SingBoxGenerator.generate_json(data, json_path)
        self.log_msg(msg)
        
        if not success:
            messagebox.showerror("Ошибка", msg)
            return
        
        self.log_msg(f"📊 Домены: {stats['domains']}, IP: {stats['ips']}")
        
        # Компиляция .srs
        if self.singbox_compile_srs.get():
            if not self.singbox_path.get():
                messagebox.showerror("Ошибка", "Укажите путь к sing-box.exe!")
                return
            
            self.log_msg("⚙️ Компиляция .srs...")
            success_srs, msg_srs = SingBoxGenerator.compile_srs(self.singbox_path.get(), json_path)
            self.log_msg(msg_srs)
        
        messagebox.showinfo("Успех", "Sing-Box ruleset создан!")
    
    def generate_mihomo(self):
        """Генерация Mihomo ruleset"""
        self.log_msg("🚀 Генерация Mihomo ruleset...")
        
        data = self.collect_data(self.mihomo_widgets)
        
        if not data:
            messagebox.showwarning("Предупреждение", "Нет данных для генерации!")
            return
        
        filename = self.mihomo_filename.get() or "mihomo_rules"
        format_type = self.mihomo_format.get()
        
        if format_type == "yaml":
            output_path = os.path.join(self.output_dir.get(), f"{filename}.yaml")
            success, msg, stats = MihomoGenerator.generate_yaml(data, output_path)
        else:  # mrs
            output_path = os.path.join(self.output_dir.get(), f"{filename}.mrs")
            success, msg, stats = MihomoGenerator.generate_mrs(data, output_path)
        
        self.log_msg(msg)
        
        if success:
            self.log_msg(f"📊 Всего правил: {stats['total']}")
            messagebox.showinfo("Успех", "Mihomo ruleset создан!")
        else:
            messagebox.showerror("Ошибка", msg)
    
    def run_geoipgeosite(self):
        """Запуск generate-geoip-geosite"""
        self.log_msg("🚀 Запуск Generate-GeoIP-GeoSite...")
        
        if not self.geoipgeosite_path.get():
            messagebox.showerror("Ошибка", "Укажите путь к generate-geoip-geosite.exe!")
            return
        
        # Формирование конфигурации
        config = {
            "output": self.output_dir.get(),
            "format": self.geogen_output_format.get()
        }
        
        if self.geogen_enable_geoip.get():
            sources = self.parse_text_widget(self.geogen_geoip_sources)
            if sources:
                config['geoip'] = {'sources': sources}
                
                custom_ips = self.parse_text_widget(self.geogen_custom_ips)
                if custom_ips:
                    config['geoip']['custom'] = custom_ips
        
        if self.geogen_enable_geosite.get():
            sources = self.parse_text_widget(self.geogen_geosite_sources)
            if sources:
                config['geosite'] = {'sources': sources}
                
                custom_domains = self.parse_text_widget(self.geogen_custom_domains)
                if custom_domains:
                    config['geosite']['custom'] = custom_domains
        
        self.log_msg("⏳ Обработка... (это может занять время)")
        
        def run_task():
            success, msg = GeoIPGeoSiteGenerator.run_generator(self.geoipgeosite_path.get(), config)
            self.log_msg(msg)
            
            if success:
                messagebox.showinfo("Успех", "Generate-GeoIP-GeoSite завершён!")
            else:
                messagebox.showerror("Ошибка", msg)
        
        threading.Thread(target=run_task, daemon=True).start()
    
    def apply_template(self, template_data):
        """Применение шаблона к текущей вкладке"""
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 0:  # Sing-Box
            widgets = self.singbox_widgets
        elif current_tab == 1:  # Mihomo
            widgets = self.mihomo_widgets
        else:
            messagebox.showinfo("Информация", "Выберите вкладку Sing-Box или Mihomo")
            return
        
        for key, values in template_data.items():
            if key in widgets:
                widget = widgets[key]
                widget.delete('1.0', tk.END)
                widget.insert(tk.END, '\n'.join(values))
        
        self.log_msg(f"📋 Шаблон применён")
    
    def save_template(self):
        """Сохранение текущих данных как шаблон"""
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 0:
            data = self.collect_data(self.singbox_widgets)
        elif current_tab == 1:
            data = self.collect_data(self.mihomo_widgets)
        else:
            messagebox.showinfo("Информация", "Выберите вкладку Sing-Box или Mihomo")
            return
        
        if not data:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения!")
            return
        
        path = filedialog.asksaveasfilename(defaultextension=".json", 
                                           filetypes=[("JSON", "*.json")])
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.log_msg(f"💾 Шаблон сохранён: {os.path.basename(path)}")
    
    def load_template(self):
        """Загрузка шаблона"""
        path = filedialog.askopenfilename(title="Загрузить шаблон", 
                                         filetypes=[("JSON", "*.json")])
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    template = json.load(f)
                self.apply_template(template)
                self.log_msg(f"📂 Шаблон загружен: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить: {str(e)}")
    
    def log_msg(self, msg: str):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')
    
    def clear_log(self):
        """Очистка лога"""
        self.log.configure(state='normal')
        self.log.delete('1.0', tk.END)
        self.log.configure(state='disabled')
        self.log_msg("🗑️ Лог очищен")

# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    """Точка входа"""
    root = tk.Tk()
    
    # Настройка стиля
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('Accent.TButton', foreground='white', background='#007ACC', 
                   font=('Arial', 10, 'bold'), padding=5)
    
    app = RulesetBuilderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
