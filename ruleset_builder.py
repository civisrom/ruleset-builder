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
import ipaddress
import queue
import tempfile
import shutil
from typing import Dict, List, Any, Tuple
from pathlib import Path
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    tk = None
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

DOMAIN_FIELDS = ('domain', 'domain_suffix', 'domain_keyword', 'domain_regex')
IP_FIELDS = ('ip_cidr', 'source_ip_cidr')
PROCESS_FIELDS = ('process_path_regex', 'package_name')
NETWORK_TYPES = ('wifi', 'cellular', 'ethernet', 'other')
NETWORK_FLAGS = ('network_is_expensive', 'network_is_constrained')


class FileProcessor:
    """Чтение UTF-8 списков и проверка входных данных."""

    @staticmethod
    def read_large_file(file_path: str, progress_callback=None) -> List[str]:
        lines = []
        file_size = os.path.getsize(file_path)
        bytes_read = 0
        last_progress = -1
        with open(file_path, 'r', encoding='utf-8-sig') as file:
            for original_line in file:
                bytes_read += len(original_line.encode('utf-8'))
                progress = min(int(bytes_read * 100 / file_size), 100) if file_size else 100
                if progress_callback and progress != last_progress:
                    progress_callback(progress)
                    last_progress = progress
                line = original_line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
        if progress_callback and last_progress != 100:
            progress_callback(100)
        return lines

    @staticmethod
    def normalize_domain(domain: str, suffix=False, wildcard=False) -> str:
        prefix = ''
        if wildcard and domain.startswith('+.'):
            prefix, domain = '+.', domain[2:]
        elif (suffix or wildcard) and domain.startswith('.'):
            prefix, domain = '.', domain[1:]
        labels = []
        for label in domain.split('.'):
            if wildcard and label == '*':
                labels.append(label)
                continue
            ascii_label = label.encode('idna').decode('ascii').lower()
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', ascii_label):
                raise ValueError(f'Некорректный домен: {prefix}{domain}')
            labels.append(ascii_label)
        normalized = '.'.join(labels)
        if len(normalized) > 253:
            raise ValueError('Домен длиннее 253 символов')
        return prefix + normalized

    @staticmethod
    def validate_domain(domain: str) -> bool:
        try:
            FileProcessor.normalize_domain(domain, suffix=True)
            return True
        except (ValueError, UnicodeError):
            return False

    @staticmethod
    def validate_ip_cidr(cidr: str) -> bool:
        try:
            if '%' in cidr:
                return False
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def normalize_data(data: Dict) -> Dict:
        """Проверяет схему поддерживаемых полей без изменения смысла условий."""
        if not isinstance(data, dict):
            raise ValueError('Шаблон должен содержать JSON-объект')
        known = set(DOMAIN_FIELDS + IP_FIELDS + PROCESS_FIELDS + NETWORK_FLAGS)
        known.update(('network_type', 'network_interface_address', 'default_interface_address'))
        unknown = set(data) - known
        if unknown:
            raise ValueError('Неизвестные поля: ' + ', '.join(sorted(unknown)))
        normalized = {}
        for key in DOMAIN_FIELDS + IP_FIELDS + PROCESS_FIELDS + ('default_interface_address',):
            values = data.get(key, [])
            if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f'{key}: ожидается список непустых строк')
            cleaned = []
            for index, value in enumerate(values, 1):
                value = value.strip()
                try:
                    if key in ('domain', 'domain_suffix'):
                        value = FileProcessor.normalize_domain(value, suffix=(key == 'domain_suffix'))
                    elif key in IP_FIELDS + ('default_interface_address',):
                        if not FileProcessor.validate_ip_cidr(value):
                            raise ValueError('некорректный IPv4/IPv6 адрес или CIDR')
                        value = str(ipaddress.ip_network(value, strict=False))
                except (ValueError, UnicodeError) as error:
                    raise ValueError(f'{key}, запись {index}: {error}') from error
                cleaned.append(value)
            if cleaned:
                normalized[key] = list(dict.fromkeys(cleaned))
        network_type = data.get('network_type', '')
        if network_type:
            types = [network_type] if isinstance(network_type, str) else network_type
            if not isinstance(types, list) or any(value not in NETWORK_TYPES for value in types):
                raise ValueError('network_type: допустимы wifi, cellular, ethernet, other')
            normalized['network_type'] = list(dict.fromkeys(types))
        for key in NETWORK_FLAGS:
            value = data.get(key, False)
            if type(value) is not bool and (not isinstance(value, str) or value not in ('true', 'false')):
                raise ValueError(f'{key}: ожидается true или false')
            if value is True or value == 'true':
                normalized[key] = True
        interfaces = data.get('network_interface_address', {})
        if not isinstance(interfaces, dict):
            raise ValueError('network_interface_address: требуется объект с типами сети и списками CIDR')
        if interfaces:
            normalized['network_interface_address'] = {}
            for name, addresses in interfaces.items():
                if name not in NETWORK_TYPES or not isinstance(addresses, list) or not addresses:
                    raise ValueError('Адреса интерфейсов: укажите тип сети и непустой список CIDR')
                for address in addresses:
                    if not isinstance(address, str) or not FileProcessor.validate_ip_cidr(address):
                        raise ValueError(f'Некорректный адрес интерфейса {name}: {address}')
                normalized['network_interface_address'][name] = list(dict.fromkeys(
                    str(ipaddress.ip_network(address, strict=False)) for address in addresses))
        return normalized


class RulesetGenerator:
    """Генератор ruleset для Sing-box и Mihomo."""

    @staticmethod
    def is_non_empty(value: Any) -> bool:
        return bool(value) and value != 'false'

    @staticmethod
    def build_singbox_ruleset(data: Dict) -> Tuple[Dict, Dict]:
        data = FileProcessor.normalize_data(data)
        if not data:
            raise ValueError('Нет данных для создания ruleset')
        # Поля — независимые альтернативы (ИЛИ). Внутри поля значения тоже объединяются по ИЛИ.
        rules = [{key: value} for key, value in data.items()]
        version = 1
        if data.get('process_path_regex'):
            version = 2
        if any(key in data for key in ('network_type',) + NETWORK_FLAGS):
            version = 3
        if any(key in data for key in ('network_interface_address', 'default_interface_address')):
            version = 4
        stats = {'total': 0, 'domains': 0, 'ips': 0, 'processes': 0, 'network': 0}
        for key, value in data.items():
            group = 'domains' if key in DOMAIN_FIELDS else 'ips' if key in IP_FIELDS else 'processes' if key in PROCESS_FIELDS else 'network'
            stats[group] += len(value) if isinstance(value, list) else 1
        stats['total'] = sum(stats.values())
        return {'version': version, 'rules': rules}, stats

    @staticmethod
    def write_text(output_path: str, content: str):
        """Атомарная замена: ошибка записи не повреждает прежний ruleset."""
        output = Path(output_path).absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                             dir=output.parent, suffix='.tmp', delete=False) as file:
                temporary = Path(file.name)
                file.write(content)
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def generate_singbox_json(data: Dict, output_path: str, singbox_path: str = '') -> Tuple[bool, str, Dict]:
        stats = {'total': 0, 'domains': 0, 'ips': 0, 'processes': 0, 'network': 0}
        try:
            ruleset, stats = RulesetGenerator.build_singbox_ruleset(data)
            content = json.dumps(ruleset, indent=2, ensure_ascii=False) + '\n'
            # Python re и Go regexp несовместимы: регулярные выражения проверяет сам Sing-box.
            if singbox_path or data.get('domain_regex') or data.get('process_path_regex'):
                if not singbox_path:
                    raise ValueError('Для проверки регулярных выражений укажите путь к Sing-box')
                with tempfile.TemporaryDirectory(prefix='ruleset-check-') as directory:
                    source = Path(directory) / 'rules.json'
                    source.write_text(content, encoding='utf-8')
                    success, message = RulesetGenerator.check_singbox(singbox_path, str(source))
                    if not success:
                        raise ValueError(message)
            RulesetGenerator.write_text(output_path, content)
            return True, f'JSON сохранён: {Path(output_path).name}', stats
        except (OSError, ValueError, TypeError) as error:
            return False, f'Ошибка создания JSON: {error}', stats

    @staticmethod
    def resolve_executable(executable: str) -> str:
        resolved = shutil.which(executable) if executable else None
        if resolved is None:
            raise ValueError(f'Исполняемый файл не найден: {executable or "путь не задан"}')
        return str(Path(resolved).absolute())

    @staticmethod
    def _compile(executable: str, source_path: str, output_path: str, arguments: List[str]) -> Tuple[bool, str]:
        try:
            executable = RulesetGenerator.resolve_executable(executable)
            source = Path(source_path).absolute()
            output = Path(output_path).absolute()
            if not source.is_file():
                raise ValueError(f'Исходный файл не найден: {source}')
            if source == output:
                raise ValueError('Исходный и выходной файлы должны различаться')
            output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='.ruleset-', dir=output.parent) as directory:
                target = Path(directory) / output.name
                cmd = [executable] + [str(source) if arg == '{source}' else str(target) if arg == '{output}' else arg for arg in arguments]
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                        timeout=60, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                if result.returncode:
                    return False, 'Ошибка компиляции: ' + (result.stderr.strip() or result.stdout.strip() or str(result.returncode))
                if not target.is_file() or target.stat().st_size == 0:
                    return False, 'Компилятор не создал непустой выходной файл'
                size = target.stat().st_size
                os.replace(target, output)
            return True, f'Создан {output.name} ({size} байт)'
        except subprocess.TimeoutExpired:
            return False, 'Таймаут компиляции (>60 сек)'
        except (OSError, ValueError) as error:
            return False, f'Ошибка запуска: {error}'

    @staticmethod
    def check_singbox(singbox_path: str, json_path: str) -> Tuple[bool, str]:
        """Загрузка правил движком: compile сам по себе не проверяет Go regexp."""
        try:
            executable = RulesetGenerator.resolve_executable(singbox_path)
            with tempfile.TemporaryDirectory(prefix='ruleset-validate-') as directory:
                config = Path(directory) / 'config.json'
                config.write_text(json.dumps({'route': {'rule_set': [
                    {'tag': 'validation', 'type': 'local', 'format': 'source', 'path': str(Path(json_path).absolute())}
                ]}}), encoding='utf-8')
                result = subprocess.run([executable, '--disable-color', 'check', '--config', str(config)],
                                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if result.returncode:
                return False, 'Sing-box отклонил правила: ' + (result.stderr.strip() or result.stdout.strip())
            return True, 'Правила проверены движком Sing-box'
        except subprocess.TimeoutExpired:
            return False, 'Таймаут проверки Sing-box (>60 сек)'
        except (OSError, ValueError) as error:
            return False, f'Ошибка проверки Sing-box: {error}'

    @staticmethod
    def compile_srs(singbox_path: str, json_path: str) -> Tuple[bool, str]:
        success, message = RulesetGenerator.check_singbox(singbox_path, json_path)
        if not success:
            return False, message
        return RulesetGenerator._compile(singbox_path, json_path, str(Path(json_path).with_suffix('.srs')),
                                         ['rule-set', 'compile', '--output', '{output}', '{source}'])

    @staticmethod
    def build_mihomo_yaml(data: Dict, behavior_type: str = 'auto') -> Tuple[str, str, Dict]:
        if not isinstance(data, dict):
            raise ValueError('Ожидается объект с полями правил')
        unsupported = [key for key, value in data.items()
                       if key not in ('domain', 'domain_suffix', 'ip_cidr') and RulesetGenerator.is_non_empty(value)]
        if unsupported:
            raise ValueError('MRS не поддерживает поля: ' + ', '.join(unsupported) + '. Используйте Sing-box JSON/SRS.')
        domains = []
        for key in ('domain', 'domain_suffix'):
            values = data.get(key, [])
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise ValueError(f'{key}: ожидается список строк')
            for value in values:
                value = FileProcessor.normalize_domain(value.strip(), suffix=(key == 'domain_suffix'), wildcard=(key == 'domain'))
                # Sing-box: .example.com — только поддомены; example.com — также корневой домен.
                if key == 'domain_suffix' and not value.startswith('.'):
                    value = '+.' + value
                domains.append(value)
        ips = data.get('ip_cidr', [])
        if not isinstance(ips, list) or any(not isinstance(value, str) or not FileProcessor.validate_ip_cidr(value) for value in ips):
            raise ValueError('ip_cidr: некорректный список IPv4/IPv6 адресов или CIDR')
        if domains and ips:
            raise ValueError('Один MRS не может содержать домены и IP. Создайте два отдельных набора domain и ipcidr.')
        if not domains and not ips:
            raise ValueError('Нет данных для создания MRS')
        behavior = 'domain' if domains else 'ipcidr'
        if behavior_type not in ('auto', behavior):
            raise ValueError(f'MRS поддерживает только domain и ipcidr; для этих данных нужен {behavior}')
        payload = list(dict.fromkeys(domains if domains else [str(ipaddress.ip_network(value, strict=False)) for value in ips]))
        # JSON-строки допустимы в YAML и защищают *, #, true, null и прочие специальные значения.
        content = 'payload:\n' + ''.join('  - ' + json.dumps(value, ensure_ascii=False) + '\n' for value in payload)
        stats = {'total': len(payload), 'domains': len(payload) if domains else 0, 'ips': len(payload) if ips else 0}
        return content, behavior, stats

    @staticmethod
    def generate_mihomo_yaml(data: Dict, output_path: str, behavior_type: str = 'auto') -> Tuple[bool, str, Dict]:
        try:
            content, _, stats = RulesetGenerator.build_mihomo_yaml(data, behavior_type)
            RulesetGenerator.write_text(output_path, content)
            return True, f'YAML сохранён: {Path(output_path).name}', stats
        except (OSError, ValueError, TypeError) as error:
            return False, f'Ошибка создания YAML: {error}', {'total': 0}

    @staticmethod
    def compile_mrs(mihomo_path: str, yaml_path: str, output_path: str, behavior_type: str = 'domain') -> Tuple[bool, str]:
        if behavior_type not in ('domain', 'ipcidr'):
            return False, 'MRS поддерживает только domain и ipcidr'
        return RulesetGenerator._compile(mihomo_path, yaml_path, output_path,
                                         ['convert-ruleset', behavior_type, 'yaml', '{source}', '{output}'])

    @staticmethod
    def export(data: Dict, output_base: str, formats, singbox_path='', mihomo_path='', validate=False,
               behavior_type='auto') -> Tuple[bool, List[str]]:
        """Общий путь экспорта для GUI и CLI с предварительной проверкой всех форматов."""
        messages = []
        try:
            formats = set(formats)
            if not formats or formats - {'json', 'srs', 'mrs'}:
                raise ValueError('Выберите JSON, SRS или MRS')
            base = Path(output_base).absolute()
            if base.suffix.lower() in ('.json', '.srs', '.mrs'):
                base = base.with_suffix('')
            needs_singbox = bool(formats & {'json', 'srs'})
            if needs_singbox:
                RulesetGenerator.build_singbox_ruleset(data)
                if 'srs' in formats or validate or data.get('domain_regex') or data.get('process_path_regex'):
                    singbox_path = RulesetGenerator.resolve_executable(singbox_path)
            if 'mrs' in formats:
                yaml_content, behavior, _ = RulesetGenerator.build_mihomo_yaml(data, behavior_type)
                mihomo_path = RulesetGenerator.resolve_executable(mihomo_path)
            if needs_singbox:
                json_path = str(base) + '.json'
                check_path = singbox_path if validate or data.get('domain_regex') or data.get('process_path_regex') else ''
                success, message, _ = RulesetGenerator.generate_singbox_json(data, json_path, check_path)
                messages.append(message)
                if not success:
                    return False, messages
                if 'srs' in formats:
                    success, message = RulesetGenerator.compile_srs(singbox_path, json_path)
                    messages.append(message)
                    if not success:
                        return False, messages
            if 'mrs' in formats:
                yaml_path = str(base) + '_mihomo.yaml'
                RulesetGenerator.write_text(yaml_path, yaml_content)
                messages.append(f'YAML сохранён: {Path(yaml_path).name}; behavior: {behavior}')
                success, message = RulesetGenerator.compile_mrs(mihomo_path, yaml_path, str(base) + '.mrs', behavior)
                messages.append(message)
                if not success:
                    return False, messages
            return True, messages
        except (OSError, ValueError, TypeError) as error:
            messages.append(str(error))
            return False, messages

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

        # Установка иконки приложения
        self._set_icon(master)

        # Переменные
        self.singbox_path = tk.StringVar()
        self.mihomo_path = tk.StringVar()  # ДОБАВЛЕНО: путь к mihomo.exe
        self.output_filename = tk.StringVar(value="ruleset")
        self.output_dir = tk.StringVar(value=os.getcwd())
        self.output_format = tk.StringVar(value="json")
        self.compile_srs = tk.BooleanVar(value=False)
        self.generate_mrs = tk.BooleanVar(value=False)
        self.validate_input = tk.BooleanVar(value=False)
        
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
        
        self._ui_events = queue.Queue()
        self._busy = False
        self._closed = False
        self._disabled_widgets = []
        self.status_text = tk.StringVar(value="Готово")
        self.setup_ui()
        self.apply_theme()
        master.protocol('WM_DELETE_WINDOW', self.on_close)
        self._poll_id = master.after(50, self.poll_tasks)
    
    def setup_ui(self):
        """Панель состояния всегда видна, вкладки занимают оставшееся место."""
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        self.setup_top_panel(main_frame)
        self.setup_bottom_panel(main_frame)
        self.setup_tabs(main_frame)
    
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
        ttk.Label(top_frame, text="Папка вывода:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(top_frame, textvariable=self.output_dir, width=50).grid(
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
            text="Дополнительно SRS",
            variable=self.compile_srs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Дополнительно MRS",
            variable=self.generate_mrs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Проверять JSON через Sing-box",
            variable=self.validate_input
        ).pack(side=tk.LEFT, padx=5)
        
        top_frame.columnconfigure(0, weight=0)
        top_frame.columnconfigure(1, weight=1)
        top_frame.columnconfigure(2, weight=0)
        top_frame.columnconfigure(3, weight=0)
    
    def setup_tabs(self, parent):
        """Создание вкладок и прокрутки длинных форм."""
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(action_frame, text="Поля объединяются по ИЛИ; пустые поля пропускаются.").pack(side=tk.LEFT)
        ttk.Button(action_frame, text="Очистить всё", command=self.clear_all).pack(side=tk.RIGHT, padx=5)
        ttk.Button(action_frame, text="Создать ruleset", command=self.generate_ruleset,
                   style='Accent.TButton').pack(side=tk.RIGHT, padx=5)
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        tabs = [
            ('domain_frame', self.create_domain_tab, 'Домены', True),
            ('ip_frame', self.create_ip_tab, 'IP-адреса', True),
            ('process_frame', self.create_process_tab, 'Процессы', True),
            ('network_frame', self.create_network_tab, 'Сеть', True),
            ('mihomo_frame', self.create_mihomo_tab, 'Mihomo', True),
            ('templates_frame', self.create_templates_tab, 'Шаблоны', True),
            ('preview_frame', self.create_preview_tab, 'Превью', False),
            ('geoip_frame', self.create_geoip_geosite_tab, 'GeoIP/GeoSite', True),
            ('log_frame', self.create_log_tab, 'Журнал', False),
        ]
        for name, builder, title, scroll in tabs:
            frame = self.scrollable_tab(builder) if scroll else builder(self.notebook)
            setattr(self, name, frame)
            self.notebook.add(frame, text=title)
        for widgets in (self.domain_widgets, self.ip_widgets, self.process_widgets):
            for widget in widgets.values():
                self.bind_counter(widget['text'], widget['count'])
    
    def create_domain_tab(self, parent):
        """Вкладка доменов"""
        frame = ttk.Frame(parent, padding=10)
        
        fields = [
            ('domain', "Точные домены (DOMAIN):", "example.com\ngoogle.com", True),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):", ".ru\n.com\n.org", True),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):", "google\nadvertisement", False),
            ('domain_regex', "Регулярные выражения (DOMAIN-REGEX):", "^stun\\..+\n.*\\.torrent$", False)
        ]
        
        for column in range(2):
            frame.columnconfigure(column, weight=1, uniform='domain')
            frame.rowconfigure(column, weight=1)
        for i, (key, label, placeholder, validate) in enumerate(fields):
            field_frame = ttk.LabelFrame(frame, text=label, padding=5)
            field_frame.grid(row=i // 2, column=i % 2, sticky=tk.NSEW, padx=4, pady=5)
            
            text_widget = scrolledtext.ScrolledText(field_frame, height=3, width=30, wrap=tk.WORD)
            text_widget.insert(tk.END, "\n".join("# " + line for line in placeholder.splitlines()))

            
            btn_frame = ttk.Frame(field_frame)
            btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            
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
            text_widget.insert(tk.END, "\n".join("# " + line for line in placeholder.splitlines()))

            
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
        
        ttk.Label(type_frame, text="Типы сети (через запятую):").grid(row=0, column=0, sticky=tk.W, pady=5)
        network_combo = ttk.Combobox(
            type_frame,
            values=["", "wifi", "cellular", "ethernet", "other"],
            state="normal",
            width=20
        )
        network_combo.grid(row=0, column=1, sticky=tk.W, padx=10)
        network_combo.current(0)
        
        bool_frame = ttk.LabelFrame(frame, text="Параметры сети:", padding=10)
        bool_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(bool_frame, text="Expensive Network:").grid(row=0, column=0, sticky=tk.W, pady=5)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(bool_frame, text="Да", variable=exp_var, value="true").grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(bool_frame, text="Не учитывать", variable=exp_var, value="false").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(bool_frame, text="Constrained (iOS):").grid(row=1, column=0, sticky=tk.W, pady=5)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(bool_frame, text="Да", variable=con_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(bool_frame, text="Не учитывать", variable=con_var, value="false").grid(row=1, column=2, sticky=tk.W, padx=5)
        
        addr_frame = ttk.LabelFrame(frame, text="Сетевые адреса:", padding=10)
        addr_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(addr_frame, text="Адреса интерфейсов: тип сети=CIDR (Sing-box 1.13+)").pack(anchor=tk.W, pady=(0, 2))
        text_interface = scrolledtext.ScrolledText(addr_frame, height=3, width=70, wrap=tk.WORD)
        text_interface.pack(fill=tk.X, pady=(0, 10))
        text_interface.insert(tk.END, "# wifi=192.168.1.0/24\n# cellular=2001:db8::/32")
        
        ttk.Label(addr_frame, text="Адреса интерфейса по умолчанию: CIDR (Sing-box 1.13+)").pack(anchor=tk.W, pady=(0, 2))
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
        selectors = ttk.Frame(type_frame)
        selectors.pack(fill=tk.X)
        for text, value in [('Авто', 'auto'), ('Домены', 'domain'), ('IP-адреса', 'ipcidr')]:
            ttk.Radiobutton(selectors, text=text, variable=self.mihomo_behavior, value=value).pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(type_frame, text="Для смешанных данных создайте два набора: домены и IP.",
                  wraplength=750).pack(anchor=tk.W, pady=(8, 0))

        # Поле для доменов
        domain_frame = ttk.LabelFrame(frame, text="Домены (behavior: domain)", padding=5)
        domain_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Подсказка для доменов
        domain_hint = ttk.Label(
            domain_frame,
            text="example.com — точное; .example.com — поддомены; +.example.com — домен и поддомены; * — одна метка",
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
        
        self.bind_counter(domain_text, domain_count)
        
        # Поле для IP адресов
        ip_frame = ttk.LabelFrame(frame, text="IPv4 / IPv6 (behavior: ipcidr)", padding=5)
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
        
        self.bind_counter(ip_text, ip_count)
        
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
            text="Обновить превью",
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
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        left_frame = ttk.Frame(btn_frame)
        left_frame.pack(side=tk.LEFT)
        
        ttk.Button(
            left_frame,
            text="Статистика",
            command=self.show_statistics
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(btn_frame, textvariable=self.status_text).pack(side=tk.LEFT, padx=10)
        self.progress = ttk.Progressbar(btn_frame, mode='indeterminate', length=130)
        self.progress.pack(side=tk.LEFT, padx=5)
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
            command=self.on_close
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

    def _set_icon(self, window):
        """Установка иконки приложения"""
        try:
            # Попытка загрузить иконку из файла
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.png')

            if os.path.exists(icon_path):
                # Для Windows, Linux и macOS
                try:
                    icon = tk.PhotoImage(file=icon_path)
                    window.iconphoto(True, icon)
                    # Сохраняем ссылку чтобы избежать garbage collection
                    window._icon = icon
                except Exception as e:
                    # Если не удалось загрузить PNG, пробуем ICO (только Windows)
                    if sys.platform == 'win32':
                        icon_ico = icon_path.replace('.png', '.ico')
                        if os.path.exists(icon_ico):
                            window.iconbitmap(icon_ico)
        except Exception:
            # Игнорируем ошибки загрузки иконки - не критично
            pass

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
            self.log_msg(f"Выбран generate-geoip-geosite: {path}")
    
    def browse_singbox(self):
        """Выбор sing-box.exe"""
        path = filedialog.askopenfilename(
            title="Выберите sing-box.exe",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.singbox_path.set(path)
            self.log_msg(f"Выбран sing-box: {path}")
    
    def browse_mihomo(self):
        """Выбор mihomo.exe"""
        path = filedialog.askopenfilename(
            title="Выберите mihomo.exe",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")]
        )
        if path:
            self.mihomo_path.set(path)
            self.log_msg(f"Выбран mihomo: {path}")
    
    def browse_output_dir(self):
        """Выбор папки для выходных файлов"""
        path = filedialog.askdirectory(title="Выберите папку для сохранения")
        if path:
            self.output_dir.set(path)
            self.log_msg(f"Папка вывода: {path}")
    
    def load_file(self, key: str, category: str):
        path = filedialog.askopenfilename(title="Выберите UTF-8 список", filetypes=[("Текст", "*.txt *.lst"), ("Все файлы", "*.*")])
        if path:
            widgets = {'domain': self.domain_widgets, 'ip': self.ip_widgets, 'process': self.process_widgets}
            self.load_into_widget(path, widgets[category][key]['text'])
    
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
        widgets = {'domain': self.domain_widgets, 'ip': self.ip_widgets, 'process': self.process_widgets}
        data = {key: self.parse_multiline_text(widgets[category][key]['text'])}
        try:
            normalized = FileProcessor.normalize_data(data)
            if not normalized:
                messagebox.showinfo("Проверка", "Поле пустое")
                return
        except ValueError as error:
            messagebox.showerror("Ошибка данных", str(error))
            return
        messagebox.showinfo("Проверка", f"Корректных записей: {len(normalized[key])}")
    
    def parse_multiline_text(self, text_widget) -> List[str]:
        """Парсинг текста из виджета"""
        content = text_widget.get('1.0', tk.END).strip()
        if not content:
            return []
        return [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
    
    def collect_data(self) -> Dict:
        data = {}
        for widgets in (self.domain_widgets, self.ip_widgets, self.process_widgets):
            for key, widget in widgets.items():
                data[key] = self.parse_multiline_text(widget['text'])
        data['network_type'] = [value.strip() for value in self.network_widgets['network_type'].get().split(',') if value.strip()]
        for key in NETWORK_FLAGS:
            data[key] = self.network_widgets[key].get()
        interfaces = {}
        for index, line in enumerate(self.parse_multiline_text(self.network_widgets['network_interface_address']), 1):
            name, separator, address = line.partition('=')
            if not separator:
                raise ValueError(f'Адреса интерфейсов, запись {index}: используйте тип=CIDR, например wifi=192.168.0.0/16')
            interfaces.setdefault(name.strip(), []).append(address.strip())
        data['network_interface_address'] = interfaces
        data['default_interface_address'] = self.parse_multiline_text(self.network_widgets['default_interface_address'])
        return data
    
    def generate_ruleset(self):
        try:
            data = self.collect_data()
            base = self.get_output_base()
            formats = {self.output_format.get()}
            if self.compile_srs.get():
                formats.add('srs')
            if self.generate_mrs.get():
                formats.add('mrs')
            singbox = self.singbox_path.get().strip()
            mihomo = self.mihomo_path.get().strip()
            validate = self.validate_input.get()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return
        self.run_task("Создание ruleset…", lambda: RulesetGenerator.export(data, base, formats, singbox, mihomo, validate),
                      self.show_export_result)
    
    def clear_all(self, confirm=True, include_mihomo=True):
        if confirm and not messagebox.askyesno("Очистить", "Очистить все поля правил?"):
            return
        for widgets in (self.domain_widgets, self.ip_widgets, self.process_widgets):
            for widget in widgets.values():
                widget['text'].delete('1.0', tk.END)
        self.network_widgets['network_type'].set('')
        for key in NETWORK_FLAGS:
            self.network_widgets[key].set('false')
        for key in ('network_interface_address', 'default_interface_address'):
            self.network_widgets[key].delete('1.0', tk.END)
        if include_mihomo:
            self.clear_mihomo_widgets()
        self.preview_text.configure(state='normal')
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.configure(state='disabled')
        self.log_msg("Поля очищены")
    
    def show_statistics(self):
        try:
            data = FileProcessor.normalize_data(self.collect_data())
            stats = RulesetGenerator.build_singbox_ruleset(data)[1] if data else dict.fromkeys(('domains', 'ips', 'processes', 'network', 'total'), 0)
        except ValueError as error:
            messagebox.showerror('Ошибка данных', str(error))
            return
        messagebox.showinfo('Статистика', '\n'.join(f'{label}: {stats[key]}' for key, label in [
            ('domains', 'Домены'), ('ips', 'IP-адреса'), ('processes', 'Процессы'),
            ('network', 'Сетевые условия'), ('total', 'Всего')]))

    def update_preview(self):
        try:
            data = FileProcessor.normalize_data(self.collect_data())
            ruleset = RulesetGenerator.build_singbox_ruleset(data)[0] if data else {'version': 1, 'rules': []}
        except ValueError as error:
            messagebox.showerror("Ошибка данных", str(error))
            return
        self.preview_text.configure(state='normal')
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.insert('1.0', json.dumps(ruleset, indent=2, ensure_ascii=False))
        self.preview_text.configure(state='disabled')
        self.log_msg("Превью содержит полный JSON; регулярные выражения проверяются Sing-box при экспорте.")
    
    def apply_template(self, template_data: Dict):
        try:
            data = FileProcessor.normalize_data(template_data)
        except (ValueError, TypeError) as error:
            messagebox.showerror("Ошибка шаблона", str(error))
            return
        if not messagebox.askyesno("Применить шаблон", "Заменить поля Sing-box данными шаблона?"):
            return
        self.clear_all(confirm=False, include_mihomo=False)
        for widgets in (self.domain_widgets, self.ip_widgets, self.process_widgets):
            for key, widget in widgets.items():
                widget['text'].insert('1.0', '\n'.join(data.get(key, [])))
        self.network_widgets['network_type'].set(', '.join(data.get('network_type', [])))
        for key in NETWORK_FLAGS:
            self.network_widgets[key].set('true' if data.get(key) else 'false')
        lines = [f'{name}={address}' for name, addresses in data.get('network_interface_address', {}).items() for address in addresses]
        self.network_widgets['network_interface_address'].insert('1.0', '\n'.join(lines))
        self.network_widgets['default_interface_address'].insert('1.0', '\n'.join(data.get('default_interface_address', [])))
        self.log_msg("Шаблон применён")
    
    def save_custom_template(self):
        try:
            data = FileProcessor.normalize_data(self.collect_data())
            if not data:
                messagebox.showwarning("Шаблон", "Нет данных для сохранения")
                return
            path = filedialog.asksaveasfilename(title="Сохранить шаблон", defaultextension='.json', filetypes=[('JSON', '*.json')])
            if path:
                RulesetGenerator.write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')
                self.log_msg(f"Шаблон сохранён: {Path(path).name}")
        except (ValueError, OSError) as error:
            messagebox.showerror("Ошибка сохранения", str(error))
    
    def browse_geo_input_dir(self):
        """Выбор Input директории"""
        path = filedialog.askdirectory(title="Выберите Input Directory")
        if path:
            self.geo_input_dir.set(path)
            self.log_msg(f"Input Directory: {path}")
    
    def browse_geo_output_dir(self):
        """Выбор Output директории"""
        path = filedialog.askdirectory(title="Выберите Output Directory")
        if path:
            self.geo_output_dir.set(path)
            self.log_msg(f"Output Directory: {path}")
    
    def browse_source_file(self):
        """Выбор source.json файла"""
        path = filedialog.askopenfilename(
            title="Выберите source.json файл",
            filetypes=[("JSON", "*.json"), ("All Files", "*.*")]
        )
        if path:
            self.geo_source_file.set(path)
            self.log_msg(f"Source файл: {os.path.basename(path)}")
    
    def create_geo_input_files(self):
        try:
            data = FileProcessor.normalize_data(self.collect_data())
            unsupported = set(data) - {'domain', 'domain_suffix', 'ip_cidr'}
            if unsupported:
                raise ValueError('Эти поля нельзя перенести в GeoIP/GeoSite списки без изменения смысла: ' + ', '.join(sorted(unsupported)))
            if not data:
                raise ValueError('Нет данных для создания файлов')
            input_dir = Path(self.geo_input_dir.get())
            files = []
            domains = data.get('domain', []) + data.get('domain_suffix', [])
            for filename, values in [('include-domain-custom.lst', domains), ('include-ip-custom.lst', data.get('ip_cidr', []))]:
                if values:
                    RulesetGenerator.write_text(str(input_dir / filename), '\n'.join(values) + '\n')
                    files.append(filename)
            self.log_msg('Созданы файлы: ' + ', '.join(files))
            messagebox.showinfo('Готово', '\n'.join(files))
        except (ValueError, OSError) as error:
            messagebox.showerror('Ошибка', str(error))
    
    def run_geoip_geosite_generation(self):
        try:
            executable = RulesetGenerator.resolve_executable(self.geoip_geosite_path.get().strip())
            input_dir = Path(self.geo_input_dir.get()).absolute()
            output_dir = Path(self.geo_output_dir.get()).absolute()
            source_file = self.geo_source_file.get().strip()
            if source_file and not Path(source_file).is_file():
                raise ValueError('Source файл не найден')
            if not source_file and (not input_dir.is_dir() or not any(input_dir.iterdir())):
                raise ValueError('Укажите Source файл или непустую входную папку')
            flags = [flag for variable, flag in [
                (self.gen_geoip, '--gen-geoip'), (self.gen_geosite, '--gen-geosite'),
                (self.gen_rule_set_json, '--gen-rule-set-json'), (self.gen_rule_set_srs, '--gen-rule-set-srs')
            ] if variable.get()]
            if not flags:
                raise ValueError('Выберите хотя бы один формат результата')
            cmd = [executable, '-i', str(input_dir), '-o', str(output_dir)] + flags
            if source_file:
                cmd += ['-s', str(Path(source_file).absolute())]
        except (ValueError, OSError) as error:
            messagebox.showerror("Ошибка", str(error))
            return
        def generate():
            input_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            return subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                  timeout=300, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        def finished(result):
            if result.stdout:
                self.log_msg(result.stdout)
            if result.stderr:
                self.log_msg(result.stderr)
            self.show_generation_result(result.returncode, str(output_dir))
        self.run_task('Создание GeoIP/GeoSite…', generate, finished)
    
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
            
            self.log_msg(f"Открыта папка: {output_dir}")
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
                self.log_msg(f"Шаблон загружен: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить шаблон:\n{str(e)}")
    
    def load_mihomo_file(self, field_type: str):
        path = filedialog.askopenfilename(title="Выберите UTF-8 список", filetypes=[("Текст", "*.txt *.lst"), ("Все файлы", "*.*")])
        if path:
            widget = self.mihomo_domain_widget if field_type == 'domain' else self.mihomo_ip_widget
            self.load_into_widget(path, widget)
    
    def preview_mihomo_yaml(self):
        try:
            content, behavior, stats = RulesetGenerator.build_mihomo_yaml(self.collect_mihomo_data(), self.mihomo_behavior.get())
        except ValueError as error:
            messagebox.showerror("Ошибка MRS", str(error))
            return
        window = tk.Toplevel(self.master)
        window.title(f"Mihomo YAML — {behavior}")
        window.geometry("720x460")
        ttk.Label(window, text=f"behavior: {behavior} | Записей: {stats['total']}").pack(pady=10)
        text = scrolledtext.ScrolledText(window, wrap=tk.NONE, font='TkFixedFont')
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert('1.0', content)
        text.configure(state='disabled')
        ttk.Button(window, text="Копировать", command=lambda: [window.clipboard_clear(), window.clipboard_append(content)]).pack(pady=10)
    
    def generate_mihomo_only(self):
        try:
            data = self.collect_mihomo_data()
            base = self.get_output_base()
            behavior = self.mihomo_behavior.get()
            mihomo = self.mihomo_path.get().strip()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return
        self.run_task("Создание MRS…", lambda: RulesetGenerator.export(data, base, ['mrs'], mihomo_path=mihomo,
                                                                       behavior_type=behavior), self.show_export_result)
    
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
        if threading.current_thread() is not threading.main_thread():
            self._ui_events.put(('log', msg))
            return
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log.configure(state='normal')
        self.log.insert(tk.END, f'[{timestamp}] {msg}\n')
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def scrollable_tab(self, builder):
        outer = ttk.Frame(self.notebook)
        canvas = tk.Canvas(outer, highlightthickness=0, height=1)
        scrollbar = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        inner = builder(canvas)
        item = canvas.create_window(0, 0, anchor=tk.NW, window=inner)
        def resize(event=None):
            canvas.itemconfigure(item, width=canvas.winfo_width(), height=max(canvas.winfo_height(), inner.winfo_reqheight()))
            canvas.configure(scrollregion=canvas.bbox('all'))
        canvas.bind('<Configure>', resize)
        inner.bind('<Configure>', lambda event: canvas.configure(scrollregion=canvas.bbox('all')))
        def scroll(event):
            step = -1 if getattr(event, 'num', None) == 4 or getattr(event, 'delta', 0) > 0 else 1
            canvas.yview_scroll(step * 3, 'units')
            return 'break'
        def bind_children(widget):
            if not isinstance(widget, (tk.Text, ttk.Combobox)):
                for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
                    widget.bind(sequence, scroll, add='+')
            for child in widget.winfo_children():
                bind_children(child)
        bind_children(outer)
        return outer

    def bind_counter(self, text, label):
        def changed(event=None):
            if text.edit_modified():
                label.configure(text=f'Строк: {len(self.parse_multiline_text(text))}')
                text.edit_modified(False)
        text.bind('<<Modified>>', changed)
        changed()

    def get_output_base(self):
        filename = self.output_filename.get().strip() or 'ruleset'
        if filename in ('.', '..') or re.search(r'[<>:"/\\|?*\x00-\x1f]', filename) or filename.endswith(('.', ' ')):
            raise ValueError('Укажите имя файла без пути и специальных символов')
        return str(Path(self.output_dir.get().strip() or os.getcwd()) / filename)

    def collect_mihomo_data(self):
        return {'domain': self.parse_multiline_text(self.mihomo_domain_widget),
                'ip_cidr': self.parse_multiline_text(self.mihomo_ip_widget)}

    def load_into_widget(self, path, widget):
        def finished(items):
            widget.delete('1.0', tk.END)
            widget.insert('1.0', '\n'.join(items))
            self.log_msg(f'Загружено записей: {len(items)}')
        self.run_task('Чтение файла…', lambda: FileProcessor.read_large_file(path), finished)

    def set_busy(self, busy):
        self._busy = busy
        if busy:
            self._disabled_widgets = []
            def disable(widget):
                if isinstance(widget, (ttk.Button, ttk.Entry, ttk.Checkbutton, ttk.Radiobutton, tk.Text)):
                    self._disabled_widgets.append((widget, widget.cget('state')))
                    widget.configure(state='disabled')
                for child in widget.winfo_children():
                    disable(child)
            disable(self.master)
            self.progress.start(12)
        else:
            self.progress.stop()
            for widget, state in self._disabled_widgets:
                if widget.winfo_exists():
                    widget.configure(state=state)
            self._disabled_widgets = []

    def run_task(self, title, function, finished):
        if self._busy:
            return
        self.set_busy(True)
        self.status_text.set(title)
        self.log_msg(title)
        def worker():
            try:
                self._ui_events.put(('done', finished, function(), None))
            except Exception as error:
                self._ui_events.put(('done', finished, None, str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def poll_tasks(self):
        try:
            while True:
                event = self._ui_events.get_nowait()
                if event[0] == 'log':
                    self.log_msg(event[1])
                    continue
                _, finished, result, error = event
                self.set_busy(False)
                self.status_text.set('Ошибка' if error else 'Готово')
                if error:
                    self.log_msg(error)
                    messagebox.showerror('Ошибка операции', error)
                else:
                    finished(result)
        except queue.Empty:
            pass
        finally:
            if not self._closed:
                self._poll_id = self.master.after(50, self.poll_tasks)

    def show_export_result(self, result):
        success, messages = result
        for message in messages:
            self.log_msg(message)
        self.status_text.set('Файлы созданы' if success else 'Ошибка экспорта')
        if success:
            messagebox.showinfo('Готово', '\n'.join(messages))
        else:
            self.notebook.select(self.log_frame)
            messagebox.showerror('Ошибка экспорта', '\n'.join(messages))

    def on_close(self):
        if self._busy:
            messagebox.showinfo('Операция выполняется', 'Дождитесь завершения текущей операции перед закрытием.')
            return
        self._closed = True
        self.master.after_cancel(self._poll_id)
        self.master.destroy()

# ============================================================================
# CLI ИНТЕРФЕЙС
# ============================================================================

def cli_mode(argv=None):
    """Режим командной строки: ненулевой код завершения при любой ошибке."""
    parser = argparse.ArgumentParser(description=f'Ruleset Builder v{VERSION}')
    parser.add_argument('-o', '--output', required=True, help='Выходной путь (расширение необязательно)')
    parser.add_argument('-f', '--format', choices=['json', 'srs', 'mrs'], default='json')
    parser.add_argument('--singbox', default='', help='Путь к Sing-box или имя в PATH')
    parser.add_argument('--mihomo', default='', help='Путь к Mihomo или имя в PATH')
    for name in DOMAIN_FIELDS + IP_FIELDS:
        parser.add_argument('--' + name.replace('_', '-'), help='Файл UTF-8, одна запись на строку')
    parser.add_argument('--validate', action='store_true', help='Дополнительно проверить JSON компилятором --singbox')
    args = parser.parse_args(argv)
    try:
        data = {key: FileProcessor.read_large_file(getattr(args, key))
                for key in DOMAIN_FIELDS + IP_FIELDS if getattr(args, key)}
        success, messages = RulesetGenerator.export(data, args.output, [args.format],
                                                    args.singbox, args.mihomo, args.validate)
    except (OSError, UnicodeError) as error:
        success, messages = False, [f'Ошибка чтения: {error}']
    for message in messages:
        print(f'{"[OK]" if success else "[ERROR]"} {message}', file=sys.stdout if success else sys.stderr)
    return 0 if success else 1


def main():
    """Точка входа."""
    if len(sys.argv) > 1:
        return cli_mode()
    if tk is None:
        print('Для GUI необходим Tkinter. В Debian/Ubuntu установите python3-tk; CLI работает без него.', file=sys.stderr)
        return 1
    try:
        root = tk.Tk()
    except tk.TclError as error:
        print(f'Не удалось открыть GUI: {error}. Для CLI используйте --help.', file=sys.stderr)
        return 1
    RulesetBuilderGUI(root)
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
