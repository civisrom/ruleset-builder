import json
import argparse
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import urllib.request
import threading
from datetime import datetime

# === УТИЛИТЫ ===
def read_list_from_file(file_path):
    if not file_path or not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

def parse_multiline_text(text_widget):
    content = text_widget.get('1.0', tk.END).strip()
    if not content:
        return []
    return [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]

def is_non_empty(value):
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, str):
        return value.strip() != ""
    return value is not None and value is not False

def generate_ruleset(data, output_path):
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

def download_file(url, output_path, progress_callback=None):
    try:
        def report_hook(block_num, block_size, total_size):
            if progress_callback and total_size > 0:
                downloaded = block_num * block_size
                percent = min(100, (downloaded * 100) // total_size)
                progress_callback(percent)
        
        urllib.request.urlretrieve(url, output_path, reporthook=report_hook)
        return True, f"Загружено: {os.path.basename(output_path)}"
    except Exception as e:
        return False, f"Ошибка загрузки {url}: {str(e)}"

def run_generate_geoip_geosite(exe_path, input_dir, output_dir, source_file=None, flags=None):
    if not os.path.exists(exe_path):
        return False, "generate-geoip-geosite.exe не найден!"
    
    cmd = [exe_path, "-i", input_dir, "-o", output_dir]
    
    if source_file and os.path.exists(source_file):
        cmd.extend(["-s", source_file])
    
    if flags:
        if flags.get('gen_geoip'): cmd.append('--gen-geoip')
        if flags.get('gen_geosite'): cmd.append('--gen-geosite')
        if flags.get('gen_rule_set_json'): cmd.append('--gen-rule-set-json')
        if flags.get('gen_rule_set_srs'): cmd.append('--gen-rule-set-srs')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(exe_path))
        if result.returncode == 0:
            return True, f"Генерация успешна!\n{result.stdout}"
        else:
            return False, f"Ошибка:\n{result.stderr}"
    except Exception as e:
        return False, f"Ошибка запуска: {str(e)}"

# === GUI ===
class SingBoxAdvancedGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sing-Box Advanced Ruleset Builder v3.0")
        master.geometry("1100x800")
        master.minsize(900, 650)

        self.singbox_path = tk.StringVar()
        self.generator_path = tk.StringVar()
        self.output_filename = tk.StringVar(value="ruleset.json")
        self.output_dir = tk.StringVar(value=os.getcwd())
        self.compile_srs = tk.BooleanVar(value=True)

        # Для генератора
        self.gen_input_dir = tk.StringVar(value=os.getcwd())
        self.gen_output_dir = tk.StringVar(value=os.getcwd())
        self.gen_source_file = tk.StringVar()
        self.gen_flags = {
            'gen_geoip': tk.BooleanVar(value=True),
            'gen_geosite': tk.BooleanVar(value=True),
            'gen_rule_set_json': tk.BooleanVar(value=True),
            'gen_rule_set_srs': tk.BooleanVar(value=True)
        }

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # === Главный Notebook ===
        main_notebook = ttk.Notebook(main_frame)
        main_notebook.pack(fill=tk.BOTH, expand=True)

        # === TAB 1: Manual Ruleset Builder ===
        manual_tab = ttk.Frame(main_notebook, padding=10)
        main_notebook.add(manual_tab, text="📝 Manual Ruleset")
        self.setup_manual_tab(manual_tab)

        # === TAB 2: GeoIP/Geosite Generator ===
        generator_tab = ttk.Frame(main_notebook, padding=10)
        main_notebook.add(generator_tab, text="🌐 GeoIP/Geosite Generator")
        self.setup_generator_tab(generator_tab)

        # === TAB 3: Source Downloader ===
        downloader_tab = ttk.Frame(main_notebook, padding=10)
        main_notebook.add(downloader_tab, text="⬇️ Source Downloader")
        self.setup_downloader_tab(downloader_tab)

        # === Лог (общий) ===
        log_frame = ttk.LabelFrame(main_frame, text="Лог операций", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log = scrolledtext.ScrolledText(log_frame, height=8, state='disabled', wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        self.log_msg("Готов к работе. Выберите нужную вкладку.")

    def setup_manual_tab(self, parent):
        # === Sing-box Path ===
        singbox_frame = ttk.LabelFrame(parent, text="Путь к sing-box.exe", padding=5)
        singbox_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(singbox_frame, textvariable=self.singbox_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(singbox_frame, text="Выбрать", command=self.browse_singbox).grid(row=0, column=1)

        # === Output ===
        output_frame = ttk.LabelFrame(parent, text="Выходной файл", padding=5)
        output_frame.pack(fill=tk.X, pady=5)
        ttk.Label(output_frame, text="Имя JSON:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_filename, width=30).grid(row=0, column=1, padx=5)
        ttk.Label(output_frame, text="Папка:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_dir, width=70, state='readonly').grid(row=1, column=1, padx=5)
        ttk.Button(output_frame, text="Изменить", command=self.browse_output_dir).grid(row=1, column=2)

        # === Compile checkbox ===
        ttk.Checkbutton(parent, text="Скомпилировать в .srs", variable=self.compile_srs).pack(anchor=tk.W, pady=5)

        # === Rules Notebook ===
        rules_notebook = ttk.Notebook(parent)
        rules_notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        self.domain_frame = self.create_domain_tab(rules_notebook)
        rules_notebook.add(self.domain_frame, text="Domains")

        self.ip_frame = self.create_ip_tab(rules_notebook)
        rules_notebook.add(self.ip_frame, text="IPs")

        self.process_frame = self.create_process_tab(rules_notebook)
        rules_notebook.add(self.process_frame, text="Process/App")

        self.network_frame = self.create_network_tab(rules_notebook)
        rules_notebook.add(self.network_frame, text="Network")

        # === Buttons ===
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="🚀 Генерировать Ruleset", command=self.generate_and_compile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Очистить", command=self.clear_manual).pack(side=tk.LEFT, padx=5)

    def setup_generator_tab(self, parent):
        # === Generator Path ===
        gen_exe_frame = ttk.LabelFrame(parent, text="Путь к generate-geoip-geosite.exe", padding=5)
        gen_exe_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(gen_exe_frame, textvariable=self.generator_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(gen_exe_frame, text="Выбрать", command=self.browse_generator).grid(row=0, column=1)

        # === Directories ===
        dirs_frame = ttk.LabelFrame(parent, text="Директории", padding=5)
        dirs_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dirs_frame, text="Input Dir (-i):").grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Entry(dirs_frame, textvariable=self.gen_input_dir, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(dirs_frame, text="📁", command=lambda: self.browse_directory(self.gen_input_dir)).grid(row=0, column=2)

        ttk.Label(dirs_frame, text="Output Dir (-o):").grid(row=1, column=0, sticky=tk.W, padx=5)
        ttk.Entry(dirs_frame, textvariable=self.gen_output_dir, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(dirs_frame, text="📁", command=lambda: self.browse_directory(self.gen_output_dir)).grid(row=1, column=2)

        ttk.Label(dirs_frame, text="Source File (-s):").grid(row=2, column=0, sticky=tk.W, padx=5)
        ttk.Entry(dirs_frame, textvariable=self.gen_source_file, width=50).grid(row=2, column=1, padx=5)
        ttk.Button(dirs_frame, text="📄", command=self.browse_source_file).grid(row=2, column=2)

        # === Generation Flags ===
        flags_frame = ttk.LabelFrame(parent, text="Флаги генерации (оставьте пустым для генерации всех)", padding=5)
        flags_frame.pack(fill=tk.X, pady=5)
        
        ttk.Checkbutton(flags_frame, text="--gen-geoip", variable=self.gen_flags['gen_geoip']).grid(row=0, column=0, sticky=tk.W, padx=10)
        ttk.Checkbutton(flags_frame, text="--gen-geosite", variable=self.gen_flags['gen_geosite']).grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Checkbutton(flags_frame, text="--gen-rule-set-json", variable=self.gen_flags['gen_rule_set_json']).grid(row=1, column=0, sticky=tk.W, padx=10)
        ttk.Checkbutton(flags_frame, text="--gen-rule-set-srs", variable=self.gen_flags['gen_rule_set_srs']).grid(row=1, column=1, sticky=tk.W, padx=10)

        # === Info ===
        info_frame = ttk.LabelFrame(parent, text="ℹ️ Справка", padding=5)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        info_text = scrolledtext.ScrolledText(info_frame, height=8, wrap=tk.WORD, state='normal')
        info_text.pack(fill=tk.BOTH, expand=True)
        info_text.insert(tk.END, """Формат файлов в Input Dir:
{include/exclude}-{ip/domain}-{category_name}.{lst/rgx}

Примеры:
- include-domain-vpn.lst
- exclude-ip-local.lst
- include-domain-ads.rgx

Source File (JSON) содержит массив объектов с полями:
- url: откуда скачивать
- category: имя категории
- contentType: тип контента (опц.)
- isExclude: true/false (опц.)

Генератор создаст GeoIP, Geosite и Rule-Set файлы в Output Dir.""")
        info_text.config(state='disabled')

        # === Button ===
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="⚙️ Запустить генератор", command=self.run_generator).pack(side=tk.LEFT, padx=5)

    def setup_downloader_tab(self, parent):
        # === URL List ===
        url_frame = ttk.LabelFrame(parent, text="Список URL для загрузки", padding=5)
        url_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.url_text = scrolledtext.ScrolledText(url_frame, height=12, wrap=tk.WORD)
        self.url_text.pack(fill=tk.BOTH, expand=True)
        self.url_text.insert(tk.END, """# Введите URL по одному на строку:
# https://example.com/list1.txt
# https://example.com/domains.json
""")

        # === Download Dir ===
        dl_dir_frame = ttk.Frame(parent)
        dl_dir_frame.pack(fill=tk.X, pady=5)
        ttk.Label(dl_dir_frame, text="Папка загрузки:").pack(side=tk.LEFT, padx=5)
        self.download_dir = tk.StringVar(value=os.getcwd())
        ttk.Entry(dl_dir_frame, textvariable=self.download_dir, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(dl_dir_frame, text="📁", command=lambda: self.browse_directory(self.download_dir)).pack(side=tk.LEFT)

        # === Progress ===
        self.download_progress = ttk.Progressbar(parent, mode='determinate')
        self.download_progress.pack(fill=tk.X, pady=5)

        # === Buttons ===
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="⬇️ Загрузить все", command=self.start_download).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Очистить список", command=lambda: self.url_text.delete('1.0', tk.END)).pack(side=tk.LEFT, padx=5)

    def create_domain_tab(self, parent):
        return self._create_tab(parent, [
            ('domain', "Domains (точные):", "example.com"),
            ('domain_suffix', "Suffixes:", ".ru"),
            ('domain_keyword', "Keywords:", "test"),
            ('domain_regex', "Regex:", "^stun\\..+")
        ], 'domain')

    def create_ip_tab(self, parent):
        return self._create_tab(parent, [
            ('ip_cidr', "IP CIDR (целевые):", "10.0.0.0/24"),
            ('source_ip_cidr', "Source IP CIDR:", "192.168.1.0/24")
        ], 'ip')

    def create_process_tab(self, parent):
        return self._create_tab(parent, [
            ('process_path_regex', "Process Path Regex:", "^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$"),
            ('package_name', "Package Name (Android):", "com.example.app")
        ], 'process')

    def _create_tab(self, parent, fields, category):
        frame = ttk.Frame(parent, padding=10)
        widgets = {}
        for i, (key, label, placeholder) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=4, width=60)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            widgets[key] = text
            ttk.Button(frame, text="📄", command=lambda k=key, c=category: self.load_file(k, c)).grid(row=i, column=2, padx=2)
        frame.columnconfigure(1, weight=1)
        setattr(self, f"{category}_widgets", widgets)
        return frame

    def create_network_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.network_widgets = {}

        ttk.Label(frame, text="Network Type:").grid(row=0, column=0, sticky=tk.W, pady=2)
        combo = ttk.Combobox(frame, values=["", "wifi", "cellular", "ethernet", "other"], state="readonly", width=15)
        combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.network_widgets['network_type'] = combo

        ttk.Label(frame, text="Expensive Network:").grid(row=1, column=0, sticky=tk.W, pady=2)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=exp_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=exp_var, value="false").grid(row=1, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_expensive'] = exp_var

        ttk.Label(frame, text="Constrained (iOS):").grid(row=2, column=0, sticky=tk.W, pady=2)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=con_var, value="true").grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=con_var, value="false").grid(row=2, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_constrained'] = con_var

        for i, (key, label, placeholder) in enumerate([
            ('network_interface_address', "Interface Address:", "192.168.1.100"),
            ('default_interface_address', "Default Interface IP:", "8.8.8.8")
        ], start=3):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=3, width=60)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            self.network_widgets[key] = text
            ttk.Button(frame, text="📄", command=lambda k=key: self.load_file(k, 'network')).grid(row=i, column=2, padx=2)

        frame.columnconfigure(1, weight=1)
        return frame

    # === Browse Functions ===
    def browse_singbox(self):
        path = filedialog.askopenfilename(title="Выберите sing-box.exe", filetypes=[("EXE", "*.exe")])
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"✓ sing-box.exe: {path}")

    def browse_generator(self):
        path = filedialog.askopenfilename(title="Выберите generate-geoip-geosite.exe", filetypes=[("EXE", "*.exe")])
        if path:
            self.generator_path.set(path)
            self.log_msg(f"✓ Generator: {path}")

    def browse_output_dir(self):
        path = filedialog.askdirectory(title="Выберите папку для output")
        if path:
            self.output_dir.set(path)

    def browse_directory(self, var):
        path = filedialog.askdirectory(title="Выберите папку")
        if path:
            var.set(path)

    def browse_source_file(self):
        path = filedialog.askopenfilename(title="Выберите source.json", filetypes=[("JSON", "*.json")])
        if path:
            self.gen_source_file.set(path)

    def load_file(self, key, category):
        path = filedialog.askopenfilename(title="Выберите файл")
        if not path:
            return
        items = read_list_from_file(path)
        widget = None
        if category == 'domain':
            widget = self.domain_widgets[key]
        elif category == 'ip':
            widget = self.ip_widgets[key]
        elif category == 'process':
            widget = self.process_widgets[key]
        elif category == 'network':
            widget = self.network_widgets[key]
        if widget:
            widget.delete('1.0', tk.END)
            widget.insert(tk.END, '\n'.join(items))
            self.log_msg(f"✓ Загружено {len(items)} записей → {key}")

    # === Manual Ruleset Generation ===
    def generate_and_compile(self):
        if not self.singbox_path.get() or not os.path.exists(self.singbox_path.get()):
            messagebox.showerror("Ошибка", "Выберите валидный sing-box.exe!")
            return

        json_path = os.path.join(self.output_dir.get(), self.output_filename.get())

        data = {}
        for widgets in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            for key, widget in widgets.items():
                data[key] = parse_multiline_text(widget)

        if self.network_widgets['network_type'].get():
            data['network_type'] = self.network_widgets['network_type'].get()
        data['network_is_expensive'] = self.network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.network_widgets['network_is_constrained'].get()
        for key in ['network_interface_address', 'default_interface_address']:
            data[key] = parse_multiline_text(self.network_widgets[key])

        try:
            msg1 = generate_ruleset(data, json_path)
            self.log_msg(f"✓ {msg1}")
        except Exception as e:
            messagebox.showerror("Ошибка JSON", str(e))
            return

        if self.compile_srs.get():
            self.log_msg("⏳ Компиляция .srs...")
            msg2 = compile_to_srs(self.singbox_path.get(), json_path)
            self.log_msg(f"✓ {msg2}")
            if "создан" in msg2:
                messagebox.showinfo("Успех", f"{msg1}\n{msg2}")
            else:
                messagebox.showwarning("Компиляция", msg2)
        else:
            messagebox.showinfo("Готово", msg1)

    def clear_manual(self):
        for w in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            for t in w.values():
                t.delete('1.0', tk.END)
        self.network_widgets['network_type'].set("")
        self.network_widgets['network_is_expensive'].set("false")
        self.network_widgets['network_is_constrained'].set("false")
        for key in ['network_interface_address', 'default_interface_address']:
            self.network_widgets[key].delete('1.0', tk.END)
        self.log_msg("🗑️ Очищено.")

    # === Generator Functions ===
    def run_generator(self):
        if not self.generator_path.get() or not os.path.exists(self.generator_path.get()):
            messagebox.showerror("Ошибка", "Выберите generate-geoip-geosite.exe!")
            return

        if not os.path.exists(self.gen_input_dir.get()):
            messagebox.showerror("Ошибка", "Input директория не существует!")
            return

        os.makedirs(self.gen_output_dir.get(), exist_ok=True)

        flags = {k: v.get() for k, v in self.gen_flags.items()}
        
        self.log_msg("⏳ Запуск генератора...")
        
        def run():
            success, msg = run_generate_geoip_geosite(
                self.generator_path.get(),
                self.gen_input_dir.get(),
                self.gen_output_dir.get(),
                self.gen_source_file.get() if self.gen_source_file.get() else None,
                flags
            )
            self.master.after(0, lambda: self.on_generator_complete(success, msg))
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def on_generator_complete(self, success, msg):
        if success:
            self.log_msg(f"✓ {msg}")
            messagebox.showinfo("Успех", "Генерация завершена успешно!")
        else:
            self.log_msg(f"✗ {msg}")
            messagebox.showerror("Ошибка", msg)

    # === Downloader Functions ===
    def start_download(self):
        urls = parse_multiline_text(self.url_text)
        if not urls:
            messagebox.showwarning("Предупреждение", "Список URL пуст!")
            return

        download_dir = self.download_dir.get()
        os.makedirs(download_dir, exist_ok=True)

        self.log_msg(f"⏳ Начало загрузки {len(urls)} файлов...")
        self.download_progress['value'] = 0
        self.download_progress['maximum'] = len(urls)

        def download_all():
            for i, url in enumerate(urls, 1):
                filename = os.path.basename(url.split('?')[0]) or f"download_{i}.txt"
                output_path = os.path.join(download_dir, filename)
                
                def update_progress(percent):
                    pass  # Можно добавить детальный прогресс
                
                success, msg = download_file(url, output_path, update_progress)
                self.master.after(0, lambda m=msg: self.log_msg(f"  {m}"))
                self.master.after(0, lambda v=i: self.download_progress.config(value=v))
            
            self.master.after(0, lambda: self.log_msg("✓ Все загрузки завершены!"))
            self.master.after(0, lambda: messagebox.showinfo("Готово", f"Загружено {len(urls)} файлов в:\n{download_dir}"))
        
        thread = threading.Thread(target=download_all, daemon=True)
        thread.start()

    # === Logging ===
    def log_msg(self, msg):
        self.log.configure(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

# === MAIN ===
if __name__ == "__main__":
    root = tk.Tk()
    app = SingBoxAdvancedGUI(root)
    root.mainloop()
