import json
import yaml
import argparse
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
from pathlib import Path
import threading

# === УТИЛИТЫ ===
def read_list_from_file(file_path):
    """Читает список из файла, игнорируя комментарии"""
    if not file_path or not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

def parse_multiline_text(text_widget):
    """Парсит текст из виджета в список строк"""
    content = text_widget.get('1.0', tk.END).strip()
    if not content:
        return []
    return [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]

def is_non_empty(value):
    """Проверяет, что значение не пустое"""
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, str):
        return value.strip() != ""
    return value is not None and value is not False

# === SING-BOX ФУНКЦИИ ===
def generate_singbox_ruleset(data, output_path):
    """Генерирует JSON ruleset для Sing-Box"""
    rules = []

    domain_rule = {}
    ip_rule = {}
    process_rule = {}
    network_rule = {}

    # Domain
    for key in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
        if key in data and is_non_empty(data[key]):
            domain_rule[key] = data[key]

    # IP
    for key in ['ip_cidr', 'source_ip_cidr']:
        if key in data and is_non_empty(data[key]):
            ip_rule[key] = data[key]

    # Process
    if 'process_path_regex' in data and is_non_empty(data['process_path_regex']):
        process_rule['process_path_regex'] = data['process_path_regex']
    if 'package_name' in data and is_non_empty(data['package_name']):
        process_rule['package_name'] = data['package_name']

    # Network
    if 'network_type' in data and is_non_empty(data['network_type']):
        network_rule['network_type'] = data['network_type']
    if 'network_is_expensive' in data and data['network_is_expensive'] == 'true':
        network_rule['network_is_expensive'] = True
    if 'network_is_constrained' in data and data['network_is_constrained'] == 'true':
        network_rule['network_is_constrained'] = True
    if 'network_interface_address' in data and is_non_empty(data['network_interface_address']):
        network_rule['network_interface_address'] = data['network_interface_address']
    if 'default_interface_address' in data and is_non_empty(data['default_interface_address']):
        network_rule['default_interface_address'] = data['default_interface_address']

    if domain_rule: rules.append(domain_rule)
    if ip_rule: rules.append(ip_rule)
    if process_rule: rules.append(process_rule)
    if network_rule: rules.append(network_rule)

    ruleset = {"version": 1, "rules": rules}

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(ruleset, f, indent=2, ensure_ascii=False)

    total = sum(len(v) if isinstance(v, list) else 1 for r in rules for v in r.values())
    return f"JSON сохранён: {os.path.basename(output_path)}\nЗаписей: {total or '0'}"

def compile_to_srs(singbox_path, json_path):
    """Компилирует JSON в .srs через sing-box"""
    if not os.path.exists(singbox_path):
        return "Ошибка: sing-box.exe не найден!"

    cmd = [singbox_path, "rule-set", "compile", json_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(singbox_path))
        if result.returncode == 0:
            srs_path = json_path.replace(".json", ".srs")
            if os.path.exists(srs_path):
                return f".srs создан: {os.path.basename(srs_path)}"
            else:
                return "Команда выполнена, но .srs не найден."
        else:
            return f"Ошибка компиляции:\n{result.stderr.strip()}"
    except Exception as e:
        return f"Ошибка запуска sing-box:\n{str(e)}"

# === MIHOMO ФУНКЦИИ ===
def generate_mihomo_ruleset(data, output_path, format_type='yaml'):
    """Генерирует YAML или MRS ruleset для Mihomo"""
    payload = []
    
    # Domains
    if 'domain' in data and is_non_empty(data['domain']):
        for domain in data['domain']:
            payload.append(f"DOMAIN,{domain}")
    
    if 'domain_suffix' in data and is_non_empty(data['domain_suffix']):
        for suffix in data['domain_suffix']:
            payload.append(f"DOMAIN-SUFFIX,{suffix}")
    
    if 'domain_keyword' in data and is_non_empty(data['domain_keyword']):
        for keyword in data['domain_keyword']:
            payload.append(f"DOMAIN-KEYWORD,{keyword}")
    
    # IP CIDR
    if 'ip_cidr' in data and is_non_empty(data['ip_cidr']):
        for cidr in data['ip_cidr']:
            payload.append(f"IP-CIDR,{cidr}")
    
    # IP CIDR6
    if 'ip_cidr6' in data and is_non_empty(data['ip_cidr6']):
        for cidr6 in data['ip_cidr6']:
            payload.append(f"IP-CIDR6,{cidr6}")
    
    # Process
    if 'process_name' in data and is_non_empty(data['process_name']):
        for process in data['process_name']:
            payload.append(f"PROCESS-NAME,{process}")
    
    if format_type == 'yaml':
        # YAML формат
        ruleset = {"payload": payload}
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(ruleset, f, allow_unicode=True, default_flow_style=False)
        return f"YAML сохранён: {os.path.basename(output_path)}\nПравил: {len(payload)}"
    else:
        # Текстовый формат для последующей конвертации в MRS
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(payload))
        return f"Текстовый ruleset сохранён: {os.path.basename(output_path)}\nПравил: {len(payload)}"

def compile_to_mrs(mihomo_path, txt_path):
    """Компилирует текстовый ruleset в .mrs через mihomo"""
    if not os.path.exists(mihomo_path):
        return "Ошибка: mihomo.exe не найден!"
    
    mrs_path = txt_path.replace(".txt", ".mrs")
    cmd = [mihomo_path, "convert-ruleset", "domain", "text", txt_path, mrs_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(mihomo_path))
        if result.returncode == 0:
            if os.path.exists(mrs_path):
                return f".mrs создан: {os.path.basename(mrs_path)}"
            else:
                return "Команда выполнена, но .mrs не найден."
        else:
            return f"Ошибка компиляции:\n{result.stderr.strip()}"
    except Exception as e:
        return f"Ошибка запуска mihomo:\n{str(e)}"

# === GENERATE-GEOIP-GEOSITE ФУНКЦИИ ===
def run_geoip_geosite(exe_path, config_path, log_callback):
    """Запускает generate-geoip-geosite.exe с конфигурацией"""
    if not os.path.exists(exe_path):
        return "Ошибка: generate-geoip-geosite.exe не найден!"
    
    if not os.path.exists(config_path):
        return "Ошибка: Файл конфигурации не найден!"
    
    cmd = [exe_path, "-c", config_path]
    
    try:
        log_callback("Запуск generate-geoip-geosite...\n")
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            cwd=os.path.dirname(exe_path)
        )
        
        for line in iter(process.stdout.readline, ''):
            if line:
                log_callback(line.strip())
        
        process.wait()
        
        if process.returncode == 0:
            return "✓ Генерация завершена успешно!"
        else:
            return f"Процесс завершился с кодом {process.returncode}"
            
    except Exception as e:
        return f"Ошибка запуска: {str(e)}"

# === ГЛАВНОЕ GUI ===
class RulesetBuilderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Ruleset Builder v3.0 - Sing-Box | Mihomo | GeoIP/GeoSite")
        
        # Устанавливаем размеры окна
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        
        # 90% от высоты экрана, но не больше 900px
        window_height = min(int(screen_height * 0.9), 900)
        window_width = 1000
        
        master.geometry(f"{window_width}x{window_height}")
        master.minsize(900, 600)
        
        # Создаем главный фрейм с прокруткой
        self.main_canvas = tk.Canvas(master)
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        )
        
        self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Биндинг прокрутки колесом мыши
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Основные переменные
        self.singbox_path = tk.StringVar()
        self.mihomo_path = tk.StringVar()
        self.geoip_exe_path = tk.StringVar()
        self.output_dir = tk.StringVar(value=os.getcwd())
        
        self.setup_ui()
    
    def _on_mousewheel(self, event):
        """Прокрутка колесом мыши"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def setup_ui(self):
        """Настройка интерфейса"""
        main_frame = ttk.Frame(self.scrollable_frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        title_label = ttk.Label(
            main_frame, 
            text="🛠️ Ruleset Builder - Multi-Tool", 
            font=('Arial', 14, 'bold')
        )
        title_label.pack(pady=10)
        
        # Создаем вкладки
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Вкладка Sing-Box
        self.singbox_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.singbox_tab, text="📦 Sing-Box")
        self.setup_singbox_tab()
        
        # Вкладка Mihomo
        self.mihomo_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.mihomo_tab, text="🔥 Mihomo")
        self.setup_mihomo_tab()
        
        # Вкладка Generate-GeoIP-GeoSite
        self.geoip_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.geoip_tab, text="🌐 GeoIP/GeoSite")
        self.setup_geoip_tab()
        
        # Общий лог (внизу)
        log_frame = ttk.LabelFrame(main_frame, text="📋 Общий лог", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.main_log = scrolledtext.ScrolledText(log_frame, height=8, state='disabled', wrap=tk.WORD)
        self.main_log.pack(fill=tk.BOTH, expand=True)
        self.log_main("Приложение запущено. Выберите вкладку для работы.")
    
    # === SING-BOX TAB ===
    def setup_singbox_tab(self):
        """Настройка вкладки Sing-Box"""
        frame = ttk.Frame(self.singbox_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Путь к sing-box.exe
        exe_frame = ttk.LabelFrame(frame, text="Исполняемый файл", padding=5)
        exe_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(exe_frame, textvariable=self.singbox_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(exe_frame, text="Выбрать sing-box.exe", command=self.browse_singbox).grid(row=0, column=1, padx=5)
        
        # Настройки вывода
        output_frame = ttk.LabelFrame(frame, text="Выходные файлы", padding=5)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Имя файла:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.sb_filename = tk.StringVar(value="ruleset.json")
        ttk.Entry(output_frame, textvariable=self.sb_filename, width=30).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        self.sb_compile_srs = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            output_frame,
            text="Компилировать в .srs",
            variable=self.sb_compile_srs
        ).grid(row=0, column=2, padx=10)
        
        # Вкладки для правил
        rules_notebook = ttk.Notebook(frame)
        rules_notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Domain
        self.sb_domain_frame = self.create_sb_domain_tab(rules_notebook)
        rules_notebook.add(self.sb_domain_frame, text="Domains")
        
        # IP
        self.sb_ip_frame = self.create_sb_ip_tab(rules_notebook)
        rules_notebook.add(self.sb_ip_frame, text="IPs")
        
        # Process
        self.sb_process_frame = self.create_sb_process_tab(rules_notebook)
        rules_notebook.add(self.sb_process_frame, text="Process/App")
        
        # Network
        self.sb_network_frame = self.create_sb_network_tab(rules_notebook)
        rules_notebook.add(self.sb_network_frame, text="Network")
        
        # Кнопки действий
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="🚀 Генерировать Ruleset", 
            command=self.generate_singbox
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="🗑️ Очистить поля", 
            command=self.clear_singbox
        ).pack(side=tk.LEFT, padx=5)
    
    def create_sb_domain_tab(self, parent):
        return self._create_text_tab(parent, [
            ('domain', "Точные домены (DOMAIN):", "example.com"),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):", ".ru"),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):", "test"),
            ('domain_regex', "Regex (DOMAIN-REGEX):", "^stun\\..+")
        ], 'sb_domain')
    
    def create_sb_ip_tab(self, parent):
        return self._create_text_tab(parent, [
            ('ip_cidr', "IP CIDR (целевые):", "10.0.0.0/24"),
            ('source_ip_cidr', "Source IP CIDR:", "192.168.1.0/24")
        ], 'sb_ip')
    
    def create_sb_process_tab(self, parent):
        return self._create_text_tab(parent, [
            ('process_path_regex', "Process Path Regex:", "^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$"),
            ('package_name', "Package Name (Android):", "com.example.app")
        ], 'sb_process')
    
    def create_sb_network_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.sb_network_widgets = {}
        
        # Network Type
        ttk.Label(frame, text="Network Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        combo = ttk.Combobox(
            frame, 
            values=["", "wifi", "cellular", "ethernet", "other"], 
            state="readonly", 
            width=20
        )
        combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.sb_network_widgets['network_type'] = combo
        
        # Expensive Network
        ttk.Label(frame, text="Expensive Network:").grid(row=1, column=0, sticky=tk.W, pady=5)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=exp_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=exp_var, value="false").grid(row=1, column=1, sticky=tk.W, padx=80)
        self.sb_network_widgets['network_is_expensive'] = exp_var
        
        # Constrained
        ttk.Label(frame, text="Constrained (iOS):").grid(row=2, column=0, sticky=tk.W, pady=5)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=con_var, value="true").grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=con_var, value="false").grid(row=2, column=1, sticky=tk.W, padx=80)
        self.sb_network_widgets['network_is_constrained'] = con_var
        
        # Interface addresses
        for i, (key, label, placeholder) in enumerate([
            ('network_interface_address', "Interface Address:", "192.168.1.100"),
            ('default_interface_address', "Default Interface IP:", "8.8.8.8")
        ], start=3):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=5)
            text = scrolledtext.ScrolledText(frame, height=3, width=60)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW, columnspan=2)
            text.insert(tk.END, f"# {placeholder}")
            self.sb_network_widgets[key] = text
            ttk.Button(
                frame, 
                text="📂", 
                width=3,
                command=lambda k=key: self.load_file_sb(k, 'network')
            ).grid(row=i, column=3, padx=2)
        
        frame.columnconfigure(1, weight=1)
        return frame
    
    def _create_text_tab(self, parent, fields, prefix):
        """Создает вкладку с текстовыми полями"""
        frame = ttk.Frame(parent, padding=10)
        widgets = {}
        
        for i, (key, label, placeholder) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=5)
            text = scrolledtext.ScrolledText(frame, height=4, width=60)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            widgets[key] = text
            ttk.Button(
                frame, 
                text="📂", 
                width=3,
                command=lambda k=key, p=prefix: self.load_file_sb(k, p)
            ).grid(row=i, column=2, padx=2)
        
        frame.columnconfigure(1, weight=1)
        setattr(self, f"{prefix}_widgets", widgets)
        return frame
    
    def browse_singbox(self):
        """Выбор sing-box.exe"""
        path = filedialog.askopenfilename(
            title="Выберите sing-box.exe", 
            filetypes=[("EXE", "*.exe"), ("All files", "*.*")]
        )
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_main(f"✓ Sing-box: {path}")
    
    def load_file_sb(self, key, category):
        """Загрузка данных из файла для Sing-Box"""
        path = filedialog.askopenfilename(title="Выберите файл со списком")
        if not path:
            return
        
        items = read_list_from_file(path)
        widget = None
        
        if category == 'sb_domain':
            widget = self.sb_domain_widgets[key]
        elif category == 'sb_ip':
            widget = self.sb_ip_widgets[key]
        elif category == 'sb_process':
            widget = self.sb_process_widgets[key]
        elif category == 'network':
            widget = self.sb_network_widgets[key]
        
        if widget:
            widget.delete('1.0', tk.END)
            widget.insert(tk.END, '\n'.join(items))
            self.log_main(f"✓ Загружено {len(items)} записей → {key}")
    
    def generate_singbox(self):
        """Генерация Sing-Box ruleset"""
        if not self.singbox_path.get() or not os.path.exists(self.singbox_path.get()):
            messagebox.showerror("Ошибка", "Выберите валидный sing-box.exe!")
            return
        
        json_path = os.path.join(self.output_dir.get(), self.sb_filename.get())
        
        # Сбор данных
        data = {}
        
        for widgets in [self.sb_domain_widgets, self.sb_ip_widgets, self.sb_process_widgets]:
            for key, widget in widgets.items():
                data[key] = parse_multiline_text(widget)
        
        # Network
        if self.sb_network_widgets['network_type'].get():
            data['network_type'] = self.sb_network_widgets['network_type'].get()
        data['network_is_expensive'] = self.sb_network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.sb_network_widgets['network_is_constrained'].get()
        for key in ['network_interface_address', 'default_interface_address']:
            data[key] = parse_multiline_text(self.sb_network_widgets[key])
        
        # Генерация JSON
        try:
            msg1 = generate_singbox_ruleset(data, json_path)
            self.log_main(msg1)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать JSON:\n{str(e)}")
            return
        
        # Компиляция в .srs
        if self.sb_compile_srs.get():
            self.log_main("Компиляция в .srs...")
            msg2 = compile_to_srs(self.singbox_path.get(), json_path)
            self.log_main(msg2)
            
            if "создан" in msg2:
                messagebox.showinfo("Успех", f"{msg1}\n{msg2}")
            else:
                messagebox.showwarning("Внимание", msg2)
        else:
            messagebox.showinfo("Готово", msg1)
    
    def clear_singbox(self):
        """Очистка полей Sing-Box"""
        for w in [self.sb_domain_widgets, self.sb_ip_widgets, self.sb_process_widgets]:
            for t in w.values():
                t.delete('1.0', tk.END)
        
        self.sb_network_widgets['network_type'].set("")
        self.sb_network_widgets['network_is_expensive'].set("false")
        self.sb_network_widgets['network_is_constrained'].set("false")
        
        for key in ['network_interface_address', 'default_interface_address']:
            self.sb_network_widgets[key].delete('1.0', tk.END)
        
        self.log_main("🗑️ Поля Sing-Box очищены")
    
    # === MIHOMO TAB ===
    def setup_mihomo_tab(self):
        """Настройка вкладки Mihomo"""
        frame = ttk.Frame(self.mihomo_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Путь к mihomo.exe
        exe_frame = ttk.LabelFrame(frame, text="Исполняемый файл", padding=5)
        exe_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(exe_frame, textvariable=self.mihomo_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(exe_frame, text="Выбрать mihomo.exe", command=self.browse_mihomo).grid(row=0, column=1, padx=5)
        
        # Настройки формата
        format_frame = ttk.LabelFrame(frame, text="Формат вывода", padding=5)
        format_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(format_frame, text="Имя файла:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.mh_filename = tk.StringVar(value="ruleset.yaml")
        ttk.Entry(format_frame, textvariable=self.mh_filename, width=30).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        self.mh_format = tk.StringVar(value="yaml")
        ttk.Radiobutton(
            format_frame, 
            text="YAML", 
            variable=self.mh_format, 
            value="yaml"
        ).grid(row=0, column=2, padx=10)
        
        ttk.Radiobutton(
            format_frame, 
            text="MRS (binary)", 
            variable=self.mh_format, 
            value="mrs"
        ).grid(row=0, column=3, padx=5)
        
        # Вкладки для правил
        rules_notebook = ttk.Notebook(frame)
        rules_notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Domain
        self.mh_domain_frame = self.create_mh_domain_tab(rules_notebook)
        rules_notebook.add(self.mh_domain_frame, text="Domains")
        
        # IP
        self.mh_ip_frame = self.create_mh_ip_tab(rules_notebook)
        rules_notebook.add(self.mh_ip_frame, text="IPs")
        
        # Process
        self.mh_process_frame = self.create_mh_process_tab(rules_notebook)
        rules_notebook.add(self.mh_process_frame, text="Process")
        
        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="🚀 Генерировать Ruleset", 
            command=self.generate_mihomo
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="🗑️ Очистить поля", 
            command=self.clear_mihomo
        ).pack(side=tk.LEFT, padx=5)
    
    def create_mh_domain_tab(self, parent):
        return self._create_text_tab(parent, [
            ('domain', "Точные домены (DOMAIN):", "example.com"),
            ('domain_suffix', "Суффиксы (DOMAIN-SUFFIX):", ".ru"),
            ('domain_keyword', "Ключевые слова (DOMAIN-KEYWORD):", "google")
        ], 'mh_domain')
    
    def create_mh_ip_tab(self, parent):
        return self._create_text_tab(parent, [
            ('ip_cidr', "IP CIDR:", "10.0.0.0/24"),
            ('ip_cidr6', "IP CIDR6:", "2001:db8::/32")
        ], 'mh_ip')
    
    def create_mh_process_tab(self, parent):
        return self._create_text_tab(parent, [
            ('process_name', "Process Name:", "chrome.exe")
        ], 'mh_process')
    
    def browse_mihomo(self):
        """Выбор mihomo.exe"""
        path = filedialog.askopenfilename(
            title="Выберите mihomo.exe", 
            filetypes=[("EXE", "*.exe"), ("All files", "*.*")]
        )
        if path:
            self.mihomo_path.set(path)
            if not self.output_dir.get():
                self.output_dir.set(os.path.dirname(path))
            self.log_main(f"✓ Mihomo: {path}")
    
    def generate_mihomo(self):
        """Генерация Mihomo ruleset"""
        format_type = self.mh_format.get()
        
        if format_type == 'mrs' and (not self.mihomo_path.get() or not os.path.exists(self.mihomo_path.get())):
            messagebox.showerror("Ошибка", "Для формата MRS требуется mihomo.exe!")
            return
        
        # Определяем путь к файлу
        if format_type == 'yaml':
            output_path = os.path.join(self.output_dir.get(), self.mh_filename.get())
        else:
            # Для MRS сначала создаем .txt
            txt_filename = self.mh_filename.get().replace('.yaml', '.txt').replace('.mrs', '.txt')
            output_path = os.path.join(self.output_dir.get(), txt_filename)
        
        # Сбор данных
        data = {}
        for widgets in [self.mh_domain_widgets, self.mh_ip_widgets, self.mh_process_widgets]:
            for key, widget in widgets.items():
                data[key] = parse_multiline_text(widget)
        
        # Генерация
        try:
            msg = generate_mihomo_ruleset(data, output_path, format_type)
            self.log_main(msg)
            
            # Если MRS - компилируем
            if format_type == 'mrs':
                self.log_main("Компиляция в .mrs...")
                msg2 = compile_to_mrs(self.mihomo_path.get(), output_path)
                self.log_main(msg2)
                messagebox.showinfo("Готово", f"{msg}\n{msg2}")
            else:
                messagebox.showinfo("Готово", msg)
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать ruleset:\n{str(e)}")
    
    def clear_mihomo(self):
        """Очистка полей Mihomo"""
        for w in [self.mh_domain_widgets, self.mh_ip_widgets, self.mh_process_widgets]:
            for t in w.values():
                t.delete('1.0', tk.END)
        self.log_main("🗑️ Поля Mihomo очищены")
    
    # === GEOIP/GEOSITE TAB ===
    def setup_geoip_tab(self):
        """Настройка вкладки Generate-GeoIP-GeoSite"""
        frame = ttk.Frame(self.geoip_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Путь к exe
        exe_frame = ttk.LabelFrame(frame, text="Исполняемый файл", padding=5)
        exe_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(exe_frame, textvariable=self.geoip_exe_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(
            exe_frame, 
            text="Выбрать generate-geoip-geosite.exe", 
            command=self.browse_geoip_exe
        ).grid(row=0, column=1, padx=5)
        
        # Конфигурация
        config_frame = ttk.LabelFrame(frame, text="Конфигурация (config.json)", padding=5)
        config_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Текстовое поле для конфигурации
        self.geoip_config_text = scrolledtext.ScrolledText(config_frame, height=25, wrap=tk.WORD)
        self.geoip_config_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Шаблон конфигурации
        default_config = '''{
  "input": [
    {
      "type": "text",
      "action": "add",
      "args": {
        "name": "cn",
        "uri": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
        "wantedList": ["cn"]
      }
    },
    {
      "type": "v2rayGeoIPDat",
      "action": "add",
      "args": {
        "name": "geoip.dat",
        "uri": "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
      }
    }
  ],
  "output": [
    {
      "type": "v2rayGeoIPDat",
      "action": "output",
      "args": {
        "outputName": "geoip.dat",
        "wantedList": ["cn", "private"]
      }
    },
    {
      "type": "maxmindMMDB",
      "action": "output",
      "args": {
        "outputName": "Country.mmdb"
      }
    }
  ]
}'''
        self.geoip_config_text.insert(tk.END, default_config)
        
        # Кнопки управления конфигурацией
        config_btn_frame = ttk.Frame(config_frame)
        config_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            config_btn_frame, 
            text="📂 Загрузить config.json", 
            command=self.load_geoip_config
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            config_btn_frame, 
            text="💾 Сохранить config.json", 
            command=self.save_geoip_config
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            config_btn_frame, 
            text="🔄 Сбросить к шаблону", 
            command=lambda: self.reset_geoip_config(default_config)
        ).pack(side=tk.LEFT, padx=5)
        
        # Кнопка запуска
        run_frame = ttk.Frame(frame)
        run_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            run_frame, 
            text="🚀 Запустить генерацию", 
            command=self.run_geoip_generation,
            style='Accent.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Лог генерации
        log_frame = ttk.LabelFrame(frame, text="📋 Лог генерации", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.geoip_log = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', wrap=tk.WORD)
        self.geoip_log.pack(fill=tk.BOTH, expand=True)
    
    def browse_geoip_exe(self):
        """Выбор generate-geoip-geosite.exe"""
        path = filedialog.askopenfilename(
            title="Выберите generate-geoip-geosite.exe", 
            filetypes=[("EXE", "*.exe"), ("All files", "*.*")]
        )
        if path:
            self.geoip_exe_path.set(path)
            self.log_main(f"✓ Generate-GeoIP-GeoSite: {path}")
    
    def load_geoip_config(self):
        """Загрузка конфигурации из файла"""
        path = filedialog.askopenfilename(
            title="Загрузить config.json", 
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.geoip_config_text.delete('1.0', tk.END)
                self.geoip_config_text.insert(tk.END, content)
                self.log_main(f"✓ Конфигурация загружена: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить конфигурацию:\n{str(e)}")
    
    def save_geoip_config(self):
        """Сохранение конфигурации в файл"""
        path = filedialog.asksaveasfilename(
            title="Сохранить config.json",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if path:
            try:
                content = self.geoip_config_text.get('1.0', tk.END).strip()
                # Проверка валидности JSON
                json.loads(content)
                
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log_main(f"✓ Конфигурация сохранена: {os.path.basename(path)}")
            except json.JSONDecodeError as e:
                messagebox.showerror("Ошибка JSON", f"Невалидный JSON:\n{str(e)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию:\n{str(e)}")
    
    def reset_geoip_config(self, default_config):
        """Сброс конфигурации к шаблону"""
        if messagebox.askyesno("Подтверждение", "Сбросить конфигурацию к шаблону?"):
            self.geoip_config_text.delete('1.0', tk.END)
            self.geoip_config_text.insert(tk.END, default_config)
            self.log_main("🔄 Конфигурация сброшена к шаблону")
    
    def run_geoip_generation(self):
        """Запуск генерации GeoIP/GeoSite"""
        if not self.geoip_exe_path.get() or not os.path.exists(self.geoip_exe_path.get()):
            messagebox.showerror("Ошибка", "Выберите валидный generate-geoip-geosite.exe!")
            return
        
        # Сохраняем конфигурацию во временный файл
        try:
            config_content = self.geoip_config_text.get('1.0', tk.END).strip()
            json.loads(config_content)  # Проверка валидности
            
            config_path = os.path.join(os.path.dirname(self.geoip_exe_path.get()), "config.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            # Очищаем лог
            self.geoip_log.configure(state='normal')
            self.geoip_log.delete('1.0', tk.END)
            self.geoip_log.configure(state='disabled')
            
            # Запускаем в отдельном потоке
            def run_thread():
                result = run_geoip_geosite(
                    self.geoip_exe_path.get(), 
                    config_path, 
                    self.log_geoip
                )
                self.log_geoip(result)
                self.log_main(result)
            
            thread = threading.Thread(target=run_thread, daemon=True)
            thread.start()
            
        except json.JSONDecodeError as e:
            messagebox.showerror("Ошибка JSON", f"Невалидный JSON в конфигурации:\n{str(e)}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить генерацию:\n{str(e)}")
    
    def log_geoip(self, msg):
        """Логирование для GeoIP"""
        self.geoip_log.configure(state='normal')
        self.geoip_log.insert(tk.END, msg + '\n')
        self.geoip_log.see(tk.END)
        self.geoip_log.configure(state='disabled')
    
    # === ОБЩИЕ ФУНКЦИИ ===
    def log_main(self, msg):
        """Логирование в главный лог"""
        self.main_log.configure(state='normal')
        self.main_log.insert(tk.END, msg + '\n')
        self.main_log.see(tk.END)
        self.main_log.configure(state='disabled')

# === MAIN ===
if __name__ == "__main__":
    root = tk.Tk()
    
    # Устанавливаем тему (для Windows)
    try:
        root.tk.call("source", "azure.tcl")
        root.tk.call("set_theme", "light")
    except:
        pass
    
    app = RulesetBuilderGUI(root)
    root.mainloop()
