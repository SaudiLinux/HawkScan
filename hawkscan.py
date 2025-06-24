#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
HawkScan - أداة فحص أمان المواقع
تم تطويره بواسطة: Saudi Linux
'''

import argparse
import requests
import socket
import whois
import dns.resolver
import ssl
import concurrent.futures
import json
import os
import sys
import time
from datetime import datetime
from colorama import init, Fore, Style

# تهيئة الألوان
init(autoreset=True)

class HawkScan:
    def __init__(self):
        self.banner()
        self.args = self.parse_arguments()
        self.target = self.args.target
        self.output_dir = self.args.output
        self.threads = self.args.threads
        self.timeout = self.args.timeout
        self.verbose = self.args.verbose
        self.results = {}
        
        # إنشاء مجلد للنتائج إذا لم يكن موجودًا
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def banner(self):
        banner = f'''
{Fore.GREEN}  _    _                _     {Fore.YELLOW} _____                 
{Fore.GREEN} | |  | |              | |    {Fore.YELLOW}/  ___|                
{Fore.GREEN} | |__| | __ ___      _| | __ {Fore.YELLOW}\ `--.  ___ __ _ _ __  
{Fore.GREEN} |  __  |/ _` \ \ /\ / / |/ / {Fore.YELLOW} `--. \/ __/ _` | '_ \ 
{Fore.GREEN} | |  | | (_| |\ V  V /|   <  {Fore.YELLOW}/\__/ / (_| (_| | | | |
{Fore.GREEN} |_|  |_|\__,_| \_/\_/ |_|\_\ {Fore.YELLOW}\____/ \___\__,_|_| |_|
{Style.RESET_ALL}                                                  
        {Fore.CYAN}[ تم تطويره بواسطة: Saudi Linux ]{Style.RESET_ALL}
        {Fore.CYAN}[ الإصدار: 1.0.0 ]{Style.RESET_ALL}
        '''
        print(banner)
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='HawkScan - أداة فحص أمان المواقع')
        parser.add_argument('-t', '--target', required=True, help='الهدف المراد فحصه (مثال: example.com)')
        parser.add_argument('-o', '--output', help='مجلد حفظ النتائج')
        parser.add_argument('--threads', type=int, default=10, help='عدد العمليات المتزامنة (الافتراضي: 10)')
        parser.add_argument('--timeout', type=int, default=30, help='مهلة الاتصال بالثواني (الافتراضي: 30)')
        parser.add_argument('-v', '--verbose', action='store_true', help='عرض معلومات تفصيلية')
        parser.add_argument('--dns', action='store_true', help='فحص سجلات DNS')
        parser.add_argument('--whois', action='store_true', help='جمع معلومات Whois')
        parser.add_argument('--headers', action='store_true', help='فحص رؤوس HTTP')
        parser.add_argument('--ssl', action='store_true', help='فحص شهادة SSL')
        parser.add_argument('--ports', action='store_true', help='فحص المنافذ المفتوحة')
        parser.add_argument('--all', action='store_true', help='تنفيذ جميع الفحوصات')
        return parser.parse_args()
    
    def log(self, message, level='info'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if level == 'info':
            print(f"{Fore.BLUE}[{timestamp}] [INFO] {message}{Style.RESET_ALL}")
        elif level == 'success':
            print(f"{Fore.GREEN}[{timestamp}] [SUCCESS] {message}{Style.RESET_ALL}")
        elif level == 'warning':
            print(f"{Fore.YELLOW}[{timestamp}] [WARNING] {message}{Style.RESET_ALL}")
        elif level == 'error':
            print(f"{Fore.RED}[{timestamp}] [ERROR] {message}{Style.RESET_ALL}")
    
    def normalize_url(self, url):
        if not url.startswith('http'):
            return f"http://{url}"
        return url
    
    def check_dns_records(self):
        self.log(f"جاري فحص سجلات DNS لـ {self.target}...")
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(answer) for answer in answers]
                dns_records[record_type] = records
                self.log(f"تم العثور على {len(records)} سجل من نوع {record_type}", 'success')
            except Exception as e:
                if self.verbose:
                    self.log(f"لا يوجد سجلات {record_type}: {str(e)}", 'warning')
        
        self.results['dns_records'] = dns_records
        return dns_records
    
    def check_whois(self):
        self.log(f"جاري جمع معلومات Whois لـ {self.target}...")
        try:
            w = whois.whois(self.target)
            self.results['whois'] = w
            self.log("تم جمع معلومات Whois بنجاح", 'success')
            return w
        except Exception as e:
            self.log(f"فشل في جمع معلومات Whois: {str(e)}", 'error')
            return None
    
    def check_http_headers(self):
        url = self.normalize_url(self.target)
        self.log(f"جاري فحص رؤوس HTTP لـ {url}...")
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(response.headers)
            
            # تحليل رؤوس الأمان
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'غير موجود'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'غير موجود'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'غير موجود'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'غير موجود'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'غير موجود')
            }
            
            self.results['http_headers'] = headers
            self.results['security_headers'] = security_headers
            self.log("تم فحص رؤوس HTTP بنجاح", 'success')
            return headers, security_headers
        except Exception as e:
            self.log(f"فشل في فحص رؤوس HTTP: {str(e)}", 'error')
            return None, None
    
    def check_ssl_certificate(self):
        self.log(f"جاري فحص شهادة SSL لـ {self.target}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # استخراج معلومات الشهادة
                    issued_to = dict(cert['subject'][0])[('commonName',)]
                    issuer = dict(cert['issuer'][0])[('commonName',)]
                    valid_from = cert['notBefore']
                    valid_until = cert['notAfter']
                    
                    ssl_info = {
                        'issued_to': issued_to,
                        'issuer': issuer,
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                        'version': cert['version']
                    }
                    
                    self.results['ssl_certificate'] = ssl_info
                    self.log("تم فحص شهادة SSL بنجاح", 'success')
                    return ssl_info
        except Exception as e:
            self.log(f"فشل في فحص شهادة SSL: {str(e)}", 'error')
            return None
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout / 5)  # وقت أقل للمنافذ
            result = sock.connect_ex((self.target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, True, service
            return port, False, None
        except:
            return port, False, None
        finally:
            sock.close()
    
    def scan_common_ports(self):
        self.log(f"جاري فحص المنافذ الشائعة لـ {self.target}...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, service = future.result()
                if is_open:
                    open_ports[port] = service
                    self.log(f"المنفذ {port} ({service}) مفتوح", 'success')
        
        self.results['open_ports'] = open_ports
        return open_ports
    
    def save_results(self):
        if not self.output_dir:
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f"{self.target}_{timestamp}.json")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=4, default=str)
        
        self.log(f"تم حفظ النتائج في {filename}", 'success')
    
    def run(self):
        self.log(f"بدء فحص {self.target}...")
        start_time = time.time()
        
        # تنفيذ الفحوصات المطلوبة
        if self.args.all or self.args.dns:
            self.check_dns_records()
        
        if self.args.all or self.args.whois:
            self.check_whois()
        
        if self.args.all or self.args.headers:
            self.check_http_headers()
        
        if self.args.all or self.args.ssl:
            self.check_ssl_certificate()
        
        if self.args.all or self.args.ports:
            self.scan_common_ports()
        
        # حفظ النتائج
        self.save_results()
        
        end_time = time.time()
        duration = end_time - start_time
        self.log(f"اكتمل الفحص في {duration:.2f} ثانية", 'success')

if __name__ == "__main__":
    try:
        scanner = HawkScan()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}تم إيقاف الفحص بواسطة المستخدم{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}حدث خطأ: {str(e)}{Style.RESET_ALL}")