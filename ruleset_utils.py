#!/usr/bin/env python3
"""
Дополнительные утилиты для работы с Ruleset
Конвертация, объединение, анализ
"""

import json
import argparse
import os
from typing import Dict, List, Set
from collections import Counter

# ============================================================================
# КОНВЕРТАЦИЯ ФОРМАТОВ
# ============================================================================

class FormatConverter:
    """Конвертация между различными форматами"""
    
    @staticmethod
    def clash_to_singbox(clash_file: str, output_file: str):
        """Конвертация Clash YAML в Sing-Box JSON"""
        try:
            import yaml
        except ImportError:
            print("❌ Требуется библиотека PyYAML: pip install pyyaml")
            return
        
        with open(clash_file, 'r', encoding='utf-8') as f:
            clash_data = yaml.safe_load(f)
        
        singbox_rules = []
        domain_rule = {}
        ip_rule = {}
        
        # Извлекаем правила из Clash
        if 'rules' in clash_data:
            for rule in clash_data['rules']:
                parts = rule.split(',')
                if len(parts) < 2:
                    continue
                
                rule_type = parts[0]
                value = parts[1]
                
                if rule_type == 'DOMAIN':
                    if 'domain' not in domain_rule:
                        domain_rule['domain'] = []
                    domain_rule['domain'].append(value)
                
                elif rule_type == 'DOMAIN-SUFFIX':
                    if 'domain_suffix' not in domain_rule:
                        domain_rule['domain_suffix'] = []
                    domain_rule['domain_suffix'].append(value if value.startswith('.') else f'.{value}')
                
                elif rule_type == 'DOMAIN-KEYWORD':
                    if 'domain_keyword' not in domain_rule:
                        domain_rule['domain_keyword'] = []
                    domain_rule['domain_keyword'].append(value)
                
                elif rule_type == 'IP-CIDR':
                    if 'ip_cidr' not in ip_rule:
                        ip_rule['ip_cidr'] = []
                    ip_rule['ip_cidr'].append(value)
        
        if domain_rule:
            singbox_rules.append(domain_rule)
        if ip_rule:
            singbox_rules.append(ip_rule)
        
        output = {
            "version": 1,
            "rules": singbox_rules
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Конвертировано из Clash в Sing-Box: {output_file}")
    
    @staticmethod
    def v2ray_to_singbox(v2ray_file: str, output_file: str):
        """Конвертация V2Ray routing rules в Sing-Box JSON"""
        with open(v2ray_file, 'r', encoding='utf-8') as f:
            v2ray_data = json.load(f)
        
        singbox_rules = []
        
        # Обрабатываем правила V2Ray
        if 'routing' in v2ray_data and 'rules' in v2ray_data['routing']:
            for rule in v2ray_data['routing']['rules']:
                domain_rule = {}
                ip_rule = {}
                
                if 'domain' in rule:
                    for domain in rule['domain']:
                        if domain.startswith('domain:'):
                            if 'domain_suffix' not in domain_rule:
                                domain_rule['domain_suffix'] = []
                            domain_rule['domain_suffix'].append(domain.replace('domain:', ''))
                        elif domain.startswith('full:'):
                            if 'domain' not in domain_rule:
                                domain_rule['domain'] = []
                            domain_rule['domain'].append(domain.replace('full:', ''))
                        elif domain.startswith('regexp:'):
                            if 'domain_regex' not in domain_rule:
                                domain_rule['domain_regex'] = []
                            domain_rule['domain_regex'].append(domain.replace('regexp:', ''))
                
                if 'ip' in rule:
                    ip_rule['ip_cidr'] = rule['ip']
                
                if domain_rule:
                    singbox_rules.append(domain_rule)
                if ip_rule:
                    singbox_rules.append(ip_rule)
        
        output = {
            "version": 1,
            "rules": singbox_rules
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Конвертировано из V2Ray в Sing-Box: {output_file}")

# ============================================================================
# ОБЪЕДИНЕНИЕ RULESET
# ============================================================================

class RulesetMerger:
    """Объединение нескольких ruleset в один"""
    
    @staticmethod
    def merge_rulesets(input_files: List[str], output_file: str, deduplicate: bool = True):
        """Объединяет несколько JSON ruleset в один"""
        merged_rules = {
            'domain': [],
            'domain_suffix': [],
            'domain_keyword': [],
            'domain_regex': [],
            'ip_cidr': [],
            'source_ip_cidr': []
        }
        
        for input_file in input_files:
            try:
                with open(input_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if 'rules' not in data:
                    continue
                
                for rule in data['rules']:
                    for key in merged_rules.keys():
                        if key in rule:
                            merged_rules[key].extend(rule[key])
            except Exception as e:
                print(f"⚠️ Ошибка чтения {input_file}: {e}")
        
        # Дедупликация
        if deduplicate:
            for key in merged_rules:
                merged_rules[key] = list(set(merged_rules[key]))
        
        # Формирование выходного ruleset
        output_rules = []
        
        domain_rule = {k: v for k, v in merged_rules.items() if k.startswith('domain') and v}
        if domain_rule:
            output_rules.append(domain_rule)
        
        ip_rule = {k: v for k, v in merged_rules.items() if 'ip' in k and v}
        if ip_rule:
            output_rules.append(ip_rule)
        
        output = {
            "version": 1,
            "rules": output_rules
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        total = sum(len(v) for v in merged_rules.values())
        print(f"✅ Объединено {len(input_files)} файлов в {output_file}")
        print(f"📊 Всего правил: {total}")
        
        return merged_rules

# ============================================================================
# АНАЛИЗ RULESET
# ============================================================================

class RulesetAnalyzer:
    """Анализ и статистика ruleset"""
    
    @staticmethod
    def analyze_ruleset(input_file: str):
        """Детальный анализ ruleset"""
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        stats = {
            'total_rules': 0,
            'domain_count': 0,
            'domain_suffix_count': 0,
            'domain_keyword_count': 0,
            'domain_regex_count': 0,
            'ip_cidr_count': 0,
            'source_ip_cidr_count': 0,
            'top_tlds': Counter(),
            'avg_domain_length': 0,
            'duplicates': 0
        }
        
        all_items = []
        
        if 'rules' in data:
            for rule in data['rules']:
                for key, value in rule.items():
                    if isinstance(value, list):
                        stats[f'{key}_count'] += len(value)
                        all_items.extend(value)
                        
                        # Анализ TLD для доменов
                        if 'domain' in key:
                            for domain in value:
                                if '.' in domain:
                                    tld = domain.split('.')[-1]
                                    stats['top_tlds'][tld] += 1
        
        # Подсчёт дубликатов
        stats['duplicates'] = len(all_items) - len(set(all_items))
        
        # Средняя длина доменов
        domain_items = [item for item in all_items if '.' in str(item)]
        if domain_items:
            stats['avg_domain_length'] = sum(len(d) for d in domain_items) / len(domain_items)
        
        stats['total_rules'] = len(all_items)
        
        # Вывод статистики
        print("\n" + "=" * 60)
        print(f"📊 АНАЛИЗ RULESET: {os.path.basename(input_file)}")
        print("=" * 60)
        print(f"\n📈 Общая статистика:")
        print(f"  Всего правил: {stats['total_rules']}")
        print(f"  Дубликатов: {stats['duplicates']}")
        print(f"\n🌐 Домены:")
        print(f"  Точные домены: {stats['domain_count']}")
        print(f"  Суффиксы: {stats['domain_suffix_count']}")
        print(f"  Ключевые слова: {stats['domain_keyword_count']}")
        print(f"  Regex: {stats['domain_regex_count']}")
        print(f"  Средняя длина: {stats['avg_domain_length']:.1f} символов")
        print(f"\n🔢 IP адреса:")
        print(f"  IP CIDR: {stats['ip_cidr_count']}")
        print(f"  Source IP CIDR: {stats['source_ip_cidr_count']}")
        
        if stats['top_tlds']:
            print(f"\n🏆 Топ-10 доменных зон:")
            for tld, count in stats['top_tlds'].most_common(10):
                print(f"  .{tld}: {count}")
        
        print("=" * 60 + "\n")
        
        return stats
    
    @staticmethod
    def find_duplicates(input_file: str):
        """Поиск дубликатов в ruleset"""
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        all_items = []
        seen = set()
        duplicates = []
        
        if 'rules' in data:
            for rule in data['rules']:
                for key, value in rule.items():
                    if isinstance(value, list):
                        for item in value:
                            if item in seen:
                                duplicates.append((key, item))
                            else:
                                seen.add(item)
                            all_items.append(item)
        
        if duplicates:
            print(f"\n⚠️ Найдено {len(duplicates)} дубликатов:")
            for key, item in duplicates[:20]:  # Первые 20
                print(f"  [{key}] {item}")
            if len(duplicates) > 20:
                print(f"  ... и ещё {len(duplicates) - 20}")
        else:
            print("✅ Дубликатов не найдено")
        
        return duplicates
    
    @staticmethod
    def compare_rulesets(file1: str, file2: str):
        """Сравнение двух ruleset"""
        def extract_items(file):
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            items = set()
            if 'rules' in data:
                for rule in data['rules']:
                    for value in rule.values():
                        if isinstance(value, list):
                            items.update(value)
            return items
        
        items1 = extract_items(file1)
        items2 = extract_items(file2)
        
        only_in_1 = items1 - items2
        only_in_2 = items2 - items1
        common = items1 & items2
        
        print("\n" + "=" * 60)
        print(f"🔍 СРАВНЕНИЕ RULESET")
        print("=" * 60)
        print(f"\n📄 Файл 1: {os.path.basename(file1)}")
        print(f"  Правил: {len(items1)}")
        print(f"\n📄 Файл 2: {os.path.basename(file2)}")
        print(f"  Правил: {len(items2)}")
        print(f"\n📊 Результаты:")
        print(f"  Общих правил: {len(common)} ({len(common)/max(len(items1), len(items2))*100:.1f}%)")
        print(f"  Только в файле 1: {len(only_in_1)}")
        print(f"  Только в файле 2: {len(only_in_2)}")
        
        if only_in_1 and len(only_in_1) <= 10:
            print(f"\n  Примеры уникальных в файле 1:")
            for item in list(only_in_1)[:10]:
                print(f"    • {item}")
        
        if only_in_2 and len(only_in_2) <= 10:
            print(f"\n  Примеры уникальных в файле 2:")
            for item in list(only_in_2)[:10]:
                print(f"    • {item}")
        
        print("=" * 60 + "\n")

# ============================================================================
# ОПТИМИЗАЦИЯ RULESET
# ============================================================================

class RulesetOptimizer:
    """Оптимизация ruleset для уменьшения размера"""
    
    @staticmethod
    def optimize_domains(domains: List[str]) -> Dict[str, List[str]]:
        """Оптимизация списка доменов"""
        # Разделение на exact и suffix
        exact_domains = set()
        suffix_domains = set()
        
        # Сортируем домены по длине (от длинных к коротким)
        sorted_domains = sorted(domains, key=len, reverse=True)
        
        for domain in sorted_domains:
            # Проверяем, не покрывается ли этот домен каким-то суффиксом
            covered = False
            for suffix in suffix_domains:
                if domain.endswith(suffix):
                    covered = True
                    break
            
            if not covered:
                # Проверяем, можно ли этот домен сделать суффиксом
                related = [d for d in sorted_domains if d.endswith(domain) and d != domain]
                if len(related) >= 2:  # Если есть хотя бы 2 поддомена
                    suffix_domains.add('.' + domain if not domain.startswith('.') else domain)
                else:
                    exact_domains.add(domain)
        
        return {
            'domain': list(exact_domains),
            'domain_suffix': list(suffix_domains)
        }
    
    @staticmethod
    def optimize_ruleset(input_file: str, output_file: str):
        """Оптимизация ruleset"""
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        optimized_rules = []
        
        if 'rules' in data:
            all_domains = []
            other_rules = {}
            
            for rule in data['rules']:
                for key, value in rule.items():
                    if key in ['domain', 'domain_suffix']:
                        all_domains.extend(value)
                    else:
                        if key not in other_rules:
                            other_rules[key] = []
                        other_rules[key].extend(value if isinstance(value, list) else [value])
            
            # Оптимизация доменов
            if all_domains:
                optimized = RulesetOptimizer.optimize_domains(all_domains)
                optimized_rules.append(optimized)
            
            # Добавляем остальные правила
            for key, value in other_rules.items():
                optimized_rules.append({key: list(set(value))})
        
        output = {
            "version": 1,
            "rules": optimized_rules
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        original_size = os.path.getsize(input_file)
        optimized_size = os.path.getsize(output_file)
        reduction = ((original_size - optimized_size) / original_size) * 100
        
        print(f"✅ Ruleset оптимизирован: {output_file}")
        print(f"📉 Размер уменьшен на {reduction:.1f}%")
        print(f"   Оригинал: {original_size} байт")
        print(f"   Оптимизированный: {optimized_size} байт")

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Дополнительные утилиты для работы с Ruleset",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Команды')
    
    # Конвертация
    convert_parser = subparsers.add_parser('convert', help='Конвертация форматов')
    convert_parser.add_argument('--from', dest='from_format', choices=['clash', 'v2ray'], required=True)
    convert_parser.add_argument('--input', required=True, help='Входной файл')
    convert_parser.add_argument('--output', required=True, help='Выходной файл')
    
    # Объединение
    merge_parser = subparsers.add_parser('merge', help='Объединение ruleset')
    merge_parser.add_argument('--inputs', nargs='+', required=True, help='Входные файлы')
    merge_parser.add_argument('--output', required=True, help='Выходной файл')
    merge_parser.add_argument('--no-deduplicate', action='store_true', help='Не удалять дубликаты')
    
    # Анализ
    analyze_parser = subparsers.add_parser('analyze', help='Анализ ruleset')
    analyze_parser.add_argument('--input', required=True, help='Файл для анализа')
    analyze_parser.add_argument('--find-duplicates', action='store_true', help='Искать дубликаты')
    
    # Сравнение
    compare_parser = subparsers.add_parser('compare', help='Сравнение ruleset')
    compare_parser.add_argument('--file1', required=True, help='Первый файл')
    compare_parser.add_argument('--file2', required=True, help='Второй файл')
    
    # Оптимизация
    optimize_parser = subparsers.add_parser('optimize', help='Оптимизация ruleset')
    optimize_parser.add_argument('--input', required=True, help='Входной файл')
    optimize_parser.add_argument('--output', required=True, help='Выходной файл')
    
    args = parser.parse_args()
    
    if args.command == 'convert':
        if args.from_format == 'clash':
            FormatConverter.clash_to_singbox(args.input, args.output)
        elif args.from_format == 'v2ray':
            FormatConverter.v2ray_to_singbox(args.input, args.output)
    
    elif args.command == 'merge':
        RulesetMerger.merge_rulesets(args.inputs, args.output, not args.no_deduplicate)
    
    elif args.command == 'analyze':
        RulesetAnalyzer.analyze_ruleset(args.input)
        if args.find_duplicates:
            RulesetAnalyzer.find_duplicates(args.input)
    
    elif args.command == 'compare':
        RulesetAnalyzer.compare_rulesets(args.file1, args.file2)
    
    elif args.command == 'optimize':
        RulesetOptimizer.optimize_ruleset(args.input, args.output)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
