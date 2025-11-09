import json
import argparse
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess

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
    return [line.strip() for line in content.split('\n') if line.strip()]

def is_non_empty(value):
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, str):
        return value.strip() != ""
    return value is not None and value is not False

def generate_ruleset(data, output_path):
    rules = []

    # === Собираем только непустые правила ===
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

    # Добавляем только непустые
    if domain_rule: rules.append(domain_rule)
    if ip_rule: rules.append(ip_rule)
    if process_rule: rules.append(process_rule)
    if network_rule: rules.append(network_rule)

    # Если нет ни одного правила — всё равно создаём пустой ruleset
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

# === GUI ===
class SingBoxRulesetGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sing-Box Ruleset Builder v2.1")
        master.geometry("950x750")
        master.minsize(750, 550)

        self.singbox_path = tk.StringVar()
        self.output_filename = tk.StringVar(value="kakdusheugodno.json")
        self.output_dir = tk.StringVar(value=os.getcwd())
        self.compile_srs = tk.BooleanVar(value=True)  # По умолчанию компилировать

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # === Sing-box ===
        singbox_frame = ttk.LabelFrame(main_frame, text="Путь к sing-box.exe", padding=5)
        singbox_frame.pack(fill=tk.X, pady=5)
        ttk.Entry(singbox_frame, textvariable=self.singbox_path, width=65).grid(row=0, column=0, padx=5)
        ttk.Button(singbox_frame, text="Выбрать", command=self.browse_singbox).grid(row=0, column=1)

        # === Выход ===
        output_frame = ttk.LabelFrame(main_frame, text="Выходной файл", padding=5)
        output_frame.pack(fill=tk.X, pady=5)
        ttk.Label(output_frame, text="Имя JSON:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_filename, width=30).grid(row=0, column=1, padx=5)
        ttk.Label(output_frame, text="Папка:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_dir, width=65, state='readonly').grid(row=1, column=1, padx=5)

        # === Компиляция .srs ===
        compile_frame = ttk.Frame(main_frame)
        compile_frame.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(
            compile_frame,
            text="Скомпилировать в .srs (sing-box rule-set compile)",
            variable=self.compile_srs
        ).pack(side=tk.LEFT)

        # === Вкладки ===
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        self.domain_frame = self.create_domain_tab(notebook)
        notebook.add(self.domain_frame, text="Domains")

        self.ip_frame = self.create_ip_tab(notebook)
        notebook.add(self.ip_frame, text="IPs")

        self.process_frame = self.create_process_tab(notebook)
        notebook.add(self.process_frame, text="Process / App")

        self.network_frame = self.create_network_tab(notebook)
        notebook.add(self.network_frame, text="Network")

        # === Кнопки ===
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="Генерировать + Компилировать", command=self.generate_and_compile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Выход", command=self.master.quit).pack(side=tk.RIGHT, padx=5)

        # === Лог ===
        self.log = scrolledtext.ScrolledText(main_frame, height=7, state='disabled', wrap=tk.WORD)
        self.log.pack(fill=tk.X, pady=5)
        self.log_msg("Готов. Выберите sing-box.exe и заполните данные.")

    def create_domain_tab(self, parent): return self._create_tab(parent, [
        ('domain', "Domains (точные):", "example.com"),
        ('domain_suffix', "Suffixes:", ".ru"),
        ('domain_keyword', "Keywords:", "test"),
        ('domain_regex', "Regex:", "^stun\\..+")
    ], 'domain')

    def create_ip_tab(self, parent): return self._create_tab(parent, [
        ('ip_cidr', "IP CIDR (целевые):", "10.0.0.0/24"),
        ('source_ip_cidr', "Source IP CIDR:", "192.168.1.0/24")
    ], 'ip')

    def create_process_tab(self, parent): return self._create_tab(parent, [
        ('process_path_regex', "Process Path Regex:", "^C:\\\\Program Files\\\\Chrome\\\\chrome\\.exe$"),
        ('package_name', "Package Name (Android):", "com.example.app")
    ], 'process')

    def _create_tab(self, parent, fields, category):
        frame = ttk.Frame(parent, padding=10)
        widgets = {}
        for i, (key, label, placeholder) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=4, width=55)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            widgets[key] = text
            ttk.Button(frame, text="Файл", command=lambda k=key, c=category: self.load_file(k, c)).grid(row=i, column=2, padx=2)
        frame.columnconfigure(1, weight=1)
        setattr(self, f"{category}_widgets", widgets)
        return frame

    def create_network_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        self.network_widgets = {}

        # network_type
        ttk.Label(frame, text="Network Type:").grid(row=0, column=0, sticky=tk.W, pady=2)
        combo = ttk.Combobox(frame, values=["", "wifi", "cellular", "ethernet", "other"], state="readonly", width=15)
        combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.network_widgets['network_type'] = combo

        # expensive
        ttk.Label(frame, text="Expensive Network:").grid(row=1, column=0, sticky=tk.W, pady=2)
        exp_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=exp_var, value="true").grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=exp_var, value="false").grid(row=1, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_expensive'] = exp_var

        # constrained
        ttk.Label(frame, text="Constrained (iOS):").grid(row=2, column=0, sticky=tk.W, pady=2)
        con_var = tk.StringVar(value="false")
        ttk.Radiobutton(frame, text="True", variable=con_var, value="true").grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(frame, text="False", variable=con_var, value="false").grid(row=2, column=1, sticky=tk.W, padx=60)
        self.network_widgets['network_is_constrained'] = con_var

        # interface address
        for i, (key, label, placeholder) in enumerate([
            ('network_interface_address', "Interface Address:", "192.168.1.100"),
            ('default_interface_address', "Default Interface IP:", "8.8.8.8")
        ], start=3):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            text = scrolledtext.ScrolledText(frame, height=3, width=55)
            text.grid(row=i, column=1, pady=2, padx=5, sticky=tk.EW)
            text.insert(tk.END, f"# {placeholder}")
            self.network_widgets[key] = text
            ttk.Button(frame, text="Файл", command=lambda k=key: self.load_file(k, 'network')).grid(row=i, column=2, padx=2)

        frame.columnconfigure(1, weight=1)
        return frame

    def browse_singbox(self):
        path = filedialog.askopenfilename(title="Выберите sing-box.exe", filetypes=[("EXE", "*.exe")])
        if path:
            self.singbox_path.set(path)
            self.output_dir.set(os.path.dirname(path))
            self.log_msg(f"sing-box.exe: {path}")

    def load_file(self, key, category):
        path = filedialog.askopenfilename(title="Выберите файл")
        if not path: return
        items = read_list_from_file(path)
        widget = None
        if category == 'domain': widget = self.domain_widgets[key]
        elif category == 'ip': widget = self.ip_widgets[key]
        elif category == 'process': widget = self.process_widgets[key]
        elif category == 'network': widget = self.network_widgets[key]
        if widget:
            widget.delete('1.0', tk.END)
            widget.insert(tk.END, '\n'.join(items))
            self.log_msg(f"Загружено {len(items)} → {key}")

    def generate_and_compile(self):
        if not self.singbox_path.get() or not os.path.exists(self.singbox_path.get()):
            messagebox.showerror("Ошибка", "Выберите валидный sing-box.exe!")
            return

        json_path = os.path.join(self.output_dir.get(), self.output_filename.get())

        # === Сбор данных ===
        data = {}
        for widgets in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            for key, widget in widgets.items():
                data[key] = parse_multiline_text(widget)

        # Network
        if self.network_widgets['network_type'].get():
            data['network_type'] = self.network_widgets['network_type'].get()
        data['network_is_expensive'] = self.network_widgets['network_is_expensive'].get()
        data['network_is_constrained'] = self.network_widgets['network_is_constrained'].get()
        for key in ['network_interface_address', 'default_interface_address']:
            data[key] = parse_multiline_text(self.network_widgets[key])

        # === Генерация JSON ===
        try:
            msg1 = generate_ruleset(data, json_path)
            self.log_msg(msg1)
        except Exception as e:
            messagebox.showerror("Ошибка JSON", str(e))
            return

        # === Компиляция .srs ===
        if self.compile_srs.get():
            self.log_msg("Запуск компиляции .srs...")
            msg2 = compile_to_srs(self.singbox_path.get(), json_path)
            self.log_msg(msg2)
            if "создан" in msg2:
                messagebox.showinfo("Успех", f"{msg1}\n{msg2}")
            else:
                messagebox.showwarning("Компиляция", msg2)
        else:
            messagebox.showinfo("Готово", msg1)

    def clear_all(self):
        for w in [self.domain_widgets, self.ip_widgets, self.process_widgets]:
            for t in w.values():
                t.delete('1.0', tk.END)
        self.network_widgets['network_type'].set("")
        self.network_widgets['network_is_expensive'].set("false")
        self.network_widgets['network_is_constrained'].set("false")
        for key in ['network_interface_address', 'default_interface_address']:
            self.network_widgets[key].delete('1.0', tk.END)
        self.log_msg("Очищено.")

    def log_msg(self, msg):
        self.log.configure(state='normal')
        self.log.insert(tk.END, msg + '\n')
        self.log.see(tk.END)
        self.log.configure(state='disabled')

# === ЗАПУСК ===
if __name__ == "__main__":
    root = tk.Tk()
    app = SingBoxRulesetGUI(root)
    root.mainloop()
