#!/usr/bin/env python3
"""Web3k 敏感信息扫描工具
一款专注于Web敏感信息泄露扫描的工具。"""
import argparse,concurrent.futures,logging,os,re,time
from dataclasses import dataclass
from typing import List, Set
from urllib.parse import urljoin, urlparse
import urllib3
from requests.adapters import HTTPAdapter
from tqdm import tqdm
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
from requests.exceptions import RequestException
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
BANNER = """
 __          __  _    ____  _  __
 \ \        / / | |  |___ \| |/ /
  \ \  /\  / /__| |__  __) | ' / 
   \ \/  \/ / _ \ '_ \|__ <|  <  
    \  /\  /  __/ |_) |__) | . \ 
     \/  \/ \___|_.__/____/|_|\_\\
                                  
    Web3k敏感信息扫描工具 v1.0
"""
@dataclass
class ScanConfig:
    target_url: str
    threads: int = 10
    proxy: str = None
    delay: float = 0.5
    status_filter: List[int] = None
    auto_optimize: bool = True
    custom_signatures: str = None
    filter_max_same_code: int = None  # 新增：同一状态码最大显示数量
class SensitiveScanner:
    def _load_signatures(self, filename: str) -> List[str]:
        try:
            with open(os.path.join('signatures', filename), 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.warning(f"Signature file {filename} not found")
            return []
    def _load_custom_signatures(self, filepath: str) -> List[str]:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"Custom signature file not found: {filepath}")
            return []
        except Exception as e:
            logger.error(f"Error loading custom signature file: {str(e)}")
            return []
    def __init__(self, config: ScanConfig):
        # 清空之前的日志文件
        with open('scan.log', 'w', encoding='utf-8') as f:
            f.write(f"扫描开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标: {config.target_url}\n")
            f.write("-" * 60 + "\n")
        self.config = config
        self.session = self._init_session()
        self.target_url = self._normalize_url(config.target_url)
        self.host_info = self._parse_host_info(self.target_url)
        self.scan_results: Set[str] = set()
        self.backup_signatures = self._load_signatures('backup_urls.txt')
        self.github_signatures = self._load_signatures('github_urls.txt')
        self.env_signatures = self._load_signatures('env_urls.txt')
        self.data_signatures = self._load_signatures('data_urls.txt')
        self.install_signatures = self._load_signatures('install_urls.txt')
        self.dev_signatures = self._load_signatures('dev_urls.txt')
        self.api_signatures = self._load_signatures('api_urls.txt')
        self.cms_signatures = self._load_signatures('cms_urls.txt')
        self.server_signatures = self._load_signatures('server_urls.txt')
        self.editor_signatures = self._load_signatures('editor_urls.txt')
        self.java_signatures = self._load_signatures('java_urls.txt')
        self.custom_signatures = []
        if config.custom_signatures:
            self.custom_signatures = self._load_custom_signatures(config.custom_signatures)
    def _init_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        adapter = HTTPAdapter(pool_connections=self.config.threads,pool_maxsize=self.config.threads,max_retries=3,pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        if self.config.proxy:
            session.proxies = {'http': self.config.proxy,'https': self.config.proxy}
        return session
    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        return url
    def _parse_host_info(self, url: str) -> dict:
        parsed = urlparse(url)
        host = parsed.netloc
        if ':' in host:
            domain = host.split(':')[0]
        else:
            domain = host
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))
        domain_parts = []
        if not is_ip:
            parts = domain.split('.')
            for i in range(len(parts)):
                domain_parts.append('.'.join(parts[i:]))
        return {'domain': domain,'is_ip': is_ip,'domain_parts': domain_parts}
    def _generate_backup_names(self) -> List[str]:
        suffixes = ['.zip', '.rar', '.tar.gz', '.tar', '.bak', '.backup', '.sql', '.old']
        base_names = ['backup', 'web', 'www', 'site', 'back', 'cms', '1', '123']
        if self.host_info['is_ip']:
            base_names.append(self.host_info['domain'])
        else:
            base_names.extend(self.host_info['domain_parts'])
            for domain_part in self.host_info['domain_parts']:
                base_names.append(domain_part.split('.')[0])
        names = []
        for base in base_names:
            for suffix in suffixes:
                names.append(f"{base}{suffix}")
        return list(set(names))
    def _update_progress(self, url: str):
        """Update scanning progress with rolling URL display"""
        sys.stdout.write('\033[K')  # 清除当前行
        sys.stdout.write(f"\r正在扫描: {url}")  # \r回到行首
        sys.stdout.flush()
    def scan_url(self, url: str) -> None:
        self._update_progress(url)
        try:
            if self.config.delay:
                time.sleep(self.config.delay)
            response = self.session.head(url, allow_redirects=False, timeout=10)
            # 记录所有请求到日志文件
            with open('scan.log', 'a', encoding='utf-8') as f:
                f.write(f"{url} [{response.status_code}]\n")
            if response.status_code != 404:
                result = f"{url} [{response.status_code}]"
                self.scan_results.add(result)
                if self.config.auto_optimize:
                    self._adjust_scan_parameters(response.elapsed.total_seconds())
        except RequestException as e:
            # 记录错误请求到日志文件
            with open('scan.log', 'a', encoding='utf-8') as f:
                f.write(f"{url} [ERROR: {str(e)}]\n")
            logger.debug(f"Error scanning {url}: {str(e)}")
    def _adjust_scan_parameters(self, response_time: float):
        if response_time < 0.5 and self.config.threads < 20:
            self.config.threads += 1
            self.config.delay = max(0.1, self.config.delay - 0.1)
        elif response_time > 2.0 and self.config.threads > 5:
            self.config.threads -= 1
            self.config.delay = min(1.0, self.config.delay + 0.1)
    def scan(self):
        urls_to_scan = []
        urls_to_scan.extend(self._generate_backup_urls())
        urls_to_scan.extend(self._generate_github_urls())
        urls_to_scan.extend(self._generate_env_urls())
        urls_to_scan.extend(self._generate_data_urls())
        urls_to_scan.extend(self._generate_install_urls())
        urls_to_scan.extend(self._generate_dev_urls())
        urls_to_scan.extend(self._generate_api_urls())
        urls_to_scan.extend(self._generate_cms_urls())
        urls_to_scan.extend(self._generate_server_urls())
        urls_to_scan.extend(self._generate_editor_urls())
        urls_to_scan.extend(self._generate_java_urls())
        if self.custom_signatures:
            urls_to_scan.extend(self._generate_custom_urls())
        print(f"\n总计待扫描URL数: {len(urls_to_scan)}")
        print("\n开始扫描...")
        start_time = time.time()
        with tqdm(total=len(urls_to_scan), desc="进度", unit="url") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = []
                for url in urls_to_scan:
                    future = executor.submit(self.scan_url, url)
                    future.add_done_callback(lambda p: pbar.update(1))
                    futures.append(future)
                concurrent.futures.wait(futures)
        # 记录扫描完成信息
        duration = time.time() - start_time
        with open('scan.log', 'a', encoding='utf-8') as f:
            f.write("\n" + "-" * 60 + "\n")
            f.write(f"扫描完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"耗时: {duration:.2f} 秒\n")
            f.write(f"扫描URL总数: {len(urls_to_scan)}\n")
            f.write(f"发现敏感文件数: {len(self.scan_results)}\n")
    def _generate_backup_urls(self) -> List[str]:
        return [urljoin(self.target_url, name) for name in self._generate_backup_names()]
    def _generate_github_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.github_signatures]
    def _generate_env_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.env_signatures]
    def _generate_data_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.data_signatures]
    def _generate_install_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.install_signatures]
    def _generate_dev_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.dev_signatures]
    def _generate_api_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.api_signatures]
    def _generate_cms_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.cms_signatures]
    def _generate_server_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.server_signatures]
    def _generate_editor_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.editor_signatures]
    def _generate_java_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.java_signatures]
    def _generate_custom_urls(self) -> List[str]:
        return [urljoin(self.target_url, path) for path in self.custom_signatures]
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description='Web Sensitive Information Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-p', '--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between requests')
    parser.add_argument('-s', '--status', type=int, nargs='+', help='Filter by HTTP status codes')
    parser.add_argument('--no-optimize', action='store_false', help='Disable auto-optimization')
    parser.add_argument('-f', '--file', help='Custom URL signature file')
    args = parser.parse_args()

    print(f"目标: {args.url}")
    print(f"线程数: {args.threads}")
    if args.proxy:
        print(f"代理: {args.proxy}")
    
    # 中文交互式引导
    print("\n扫描优化选项:")
    print("是否开启状态码过滤（当某个状态码结果超过30个时将被过滤）? (y/N)", end=' ')
    filter_enabled = input().lower() == 'y'
    print()  # 空行

    config = ScanConfig(
        target_url=args.url,
        threads=args.threads,
        proxy=args.proxy,
        delay=args.delay,
        status_filter=args.status,
        auto_optimize=not args.no_optimize,
        custom_signatures=args.file,
        filter_max_same_code=30 if filter_enabled else None
    )
    
    scanner = SensitiveScanner(config)
    scanner.scan()
    
    print("\n扫描结果:")
    print("-" * 60)
    if scanner.scan_results:
        if filter_enabled:
            # 统计每个状态码的数量
            status_code_count = {}
            for result in scanner.scan_results:
                status_code = result.split('[')[1].split(']')[0]
                status_code_count[status_code] = status_code_count.get(status_code, 0) + 1
            
            # 过滤并显示结果
            filtered_results = []
            skipped_codes = set()
            for result in sorted(scanner.scan_results):
                status_code = result.split('[')[1].split(']')[0]
                if status_code_count[status_code] <= 30:
                    filtered_results.append(result)
                else:
                    skipped_codes.add(status_code)
            
            # 显示过滤后的结果
            if filtered_results:
                for result in filtered_results:
                    print(result)
            else:
                print("过滤后没有可显示的结果")
            
            # 显示被过滤的状态码信息
            if skipped_codes:
                print("\n以下状态码因数量超过30个而被过滤:")
                for code in sorted(skipped_codes):
                    print(f"状态码 [{code}]: {status_code_count[code]} 个结果")
        else:
            # 不过滤，显示所有结果
            for result in sorted(scanner.scan_results):
                print(result)
    else:
        print("未发现敏感文件")
if __name__ == '__main__':
    main()