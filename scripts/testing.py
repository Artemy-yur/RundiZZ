import os
import requests
import ssl
import socket
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime
import json

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def log_result(self, vulnerability_type, severity, description, details=""):
        """Записывает результат проверки"""
        result = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'url': self.target_url,
            'vulnerability': vulnerability_type,
            'severity': severity,
            'description': description,
            'details': details
        }
        self.results.append(result)
        print(f"[{severity}] {vulnerability_type}: {description}")
    
    def check_sql_injection(self):
        """Проверка на SQL инъекции"""
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "' OR 'x'='x"
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                for payload in sql_payloads:
                    test_url = f"{self.target_url}?id={payload}"
                    test_response = self.session.get(test_url, timeout=5)
                    
                    # Простая проверка на ошибки SQL
                    sql_errors = [
                        "mysql_fetch_array",
                        "ORA-01756",
                        "Microsoft OLE DB Provider",
                        "SQLServer JDBC Driver",
                        "PostgreSQL query failed",
                        "Warning: mysql_",
                        "valid MySQL result",
                        "MySqlClient.",
                        "SQL syntax",
                        "mysql_num_rows()",
                        "mysql_query()",
                        "mysql_fetch_assoc()"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in test_response.text.lower():
                            self.log_result(
                                "SQL Injection",
                                "HIGH",
                                f"Возможная SQL инъекция обнаружена с payload: {payload}",
                                f"Ответ содержит: {error}"
                            )
                            return True
        except Exception as e:
            self.log_result("SQL Injection", "INFO", f"Ошибка при проверке SQL инъекций: {str(e)}")
        
        return False
    
    def check_xss(self):
        """Проверка на XSS уязвимости"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>"
        ]
        
        try:
            for payload in xss_payloads:
                test_url = f"{self.target_url}?q={payload}"
                test_response = self.session.get(test_url, timeout=5)
                
                if payload in test_response.text:
                    self.log_result(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        f"Возможная XSS уязвимость с payload: {payload}",
                        "Полезная нагрузка отражена в ответе без фильтрации"
                    )
                    return True
        except Exception as e:
            self.log_result("XSS", "INFO", f"Ошибка при проверке XSS: {str(e)}")
        
        return False
    
    def check_security_headers(self):
        """Проверка HTTP заголовков безопасности"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=',
                'Content-Security-Policy': None,
                'Referrer-Policy': None
            }
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif expected_value and isinstance(expected_value, list):
                    if headers[header] not in expected_value:
                        missing_headers.append(f"{header} (неправильное значение: {headers[header]})")
                elif expected_value and expected_value not in headers[header]:
                    missing_headers.append(f"{header} (неправильное значение: {headers[header]})")
            
            if missing_headers:
                self.log_result(
                    "Missing Security Headers",
                    "MEDIUM",
                    f"Отсутствуют важные заголовки безопасности: {', '.join(missing_headers)}",
                    "Рекомендуется добавить недостающие заголовки для повышения безопасности"
                )
            else:
                self.log_result(
                    "Security Headers",
                    "INFO",
                    "Все основные заголовки безопасности присутствуют",
                    "Сайт имеет хорошую конфигурацию заголовков безопасности"
                )
                
        except Exception as e:
            self.log_result("Security Headers", "INFO", f"Ошибка при проверке заголовков: {str(e)}")
    
    def check_ssl_certificate(self):
        """Проверка SSL сертификата"""
        try:
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme == 'https':
                hostname = parsed_url.hostname
                port = parsed_url.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Проверка срока действия сертификата
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            self.log_result(
                                "SSL Certificate",
                                "HIGH",
                                f"SSL сертификат истекает через {days_until_expiry} дней",
                                f"Срок действия: {cert['notAfter']}"
                            )
                        elif days_until_expiry < 90:
                            self.log_result(
                                "SSL Certificate",
                                "MEDIUM",
                                f"SSL сертификат истекает через {days_until_expiry} дней",
                                f"Срок действия: {cert['notAfter']}"
                            )
                        else:
                            self.log_result(
                                "SSL Certificate",
                                "INFO",
                                f"SSL сертификат действителен еще {days_until_expiry} дней",
                                f"Срок действия: {cert['notAfter']}"
                            )
                            
        except Exception as e:
            self.log_result("SSL Certificate", "MEDIUM", f"Ошибка при проверке SSL: {str(e)}")
    
    def check_directory_traversal(self):
        """Проверка на Directory Traversal"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        try:
            for payload in traversal_payloads:
                test_url = f"{self.target_url}?file={payload}"
                test_response = self.session.get(test_url, timeout=5)
                
                # Проверка на содержимое системных файлов
                if any(indicator in test_response.text.lower() for indicator in [
                    'root:', 'bin:', 'daemon:', 'system32', 'windows'
                ]):
                    self.log_result(
                        "Directory Traversal",
                        "HIGH",
                        f"Возможная Directory Traversal уязвимость с payload: {payload}",
                        "Обнаружено содержимое системных файлов"
                    )
                    return True
        except Exception as e:
            self.log_result("Directory Traversal", "INFO", f"Ошибка при проверке Directory Traversal: {str(e)}")
        
        return False
    
    def scan_site(self):
        """Основная функция сканирования"""
        print(f"Начинаем сканирование: {self.target_url}")
        print("=" * 50)
        
        # Выполняем все проверки
        self.check_sql_injection()
        self.check_xss()
        self.check_security_headers()
        self.check_ssl_certificate()
        self.check_directory_traversal()
        
        # Записываем результаты в файл
        self.save_results()
        
        print("=" * 50)
        print(f"Сканирование завершено. Найдено {len(self.results)} проблем.")
    
    def save_results(self):
        """Сохраняет результаты в файл testsite.txt"""
        try:
            with open('testsite.txt', 'w', encoding='utf-8') as f:
                f.write(f"ОТЧЕТ О СКАНИРОВАНИИ БЕЗОПАСНОСТИ\n")
                f.write(f"Целевой сайт: {self.target_url}\n")
                f.write(f"Дата сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                if not self.results:
                    f.write("Уязвимости не обнаружены.\n")
                else:
                    # Группируем по уровню серьезности
                    high_vulns = [r for r in self.results if r['severity'] == 'HIGH']
                    medium_vulns = [r for r in self.results if r['severity'] == 'MEDIUM']
                    info_vulns = [r for r in self.results if r['severity'] == 'INFO']
                    
                    if high_vulns:
                        f.write("КРИТИЧЕСКИЕ УЯЗВИМОСТИ (HIGH):\n")
                        f.write("-" * 30 + "\n")
                        for vuln in high_vulns:
                            f.write(f"• {vuln['vulnerability']}: {vuln['description']}\n")
                            if vuln['details']:
                                f.write(f"  Детали: {vuln['details']}\n")
                            f.write(f"  Время: {vuln['timestamp']}\n\n")
                    
                    if medium_vulns:
                        f.write("СРЕДНИЕ УЯЗВИМОСТИ (MEDIUM):\n")
                        f.write("-" * 30 + "\n")
                        for vuln in medium_vulns:
                            f.write(f"• {vuln['vulnerability']}: {vuln['description']}\n")
                            if vuln['details']:
                                f.write(f"  Детали: {vuln['details']}\n")
                            f.write(f"  Время: {vuln['timestamp']}\n\n")
                    
                    if info_vulns:
                        f.write("ИНФОРМАЦИОННЫЕ СООБЩЕНИЯ (INFO):\n")
                        f.write("-" * 30 + "\n")
                        for vuln in info_vulns:
                            f.write(f"• {vuln['vulnerability']}: {vuln['description']}\n")
                            if vuln['details']:
                                f.write(f"  Детали: {vuln['details']}\n")
                            f.write(f"  Время: {vuln['timestamp']}\n\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("Сканирование завершено.\n")
                
            print(f"Результаты сохранены в файл testsite.txt")
            
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {str(e)}")

def main():
    """Основная функция для запуска сканера"""
    print("Сканер уязвимостей веб-сайтов")
    print("=" * 40)
    
    # Можно изменить URL для тестирования
    target_urls = [
        "https://httpbin.org/get",  # Тестовый сайт
        
    ]
    
    for url in target_urls:
        scanner = VulnerabilityScanner(url)
        scanner.scan_site()
        print("\n" + "=" * 60 + "\n")
        time.sleep(2)  # Пауза между сканированиями

if __name__ == "__main__":
    main()