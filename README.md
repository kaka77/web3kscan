# Web3kscan敏感信息扫描工具

![image](https://raw.githubusercontent.com/kaka77/web3kscan/refs/heads/main/img/example.jpg)

🔍 Web3K - 敏感信息扫描工具 | Web Sensitive Information Scanner
<br>


📝 简介 | Introduction
<br>
<br>
一款专注于Web敏感信息泄露扫描的工具。它能够快速发现网站上可能存在的敏感文件和目录，包括但不限于：
A tool focused on scanning web sensitive information leakage. It can quickly discover sensitive files and directories that may exist on websites, including but not limited to:
<br>
<br>
📂 支持扫描类型 | Supported Scan Types
- 备份文件 | Backup files (.zip/.rar/.bak etc.)
- 版本控制信息 | Version control info (.git/.svn)
- 配置文件 | Configuration files (.env/config)
- 开发调试文件 | Development debug files
- CMS特征文件 | CMS feature files
- API接口文件 | API interface files
- 服务器配置文件 | Server configuration files
- 编辑器临时文件 | Editor temporary files
- Java相关配置文件 | Java related configuration files

✨ 特点 | Features
- 多线程扫描，支持自动优化线程数 | Multi-threaded scanning with auto-optimization
- 支持HTTP代理 | HTTP proxy support
- 自定义状态码过滤 | Custom status code filtering
- 详细的扫描日志 | Detailed scan logs
- 支持自定义URL特征库 | Custom URL signature support
- 智能域名变形组合 | Smart domain name mutation

🚀 主要特性 | Core Features
- 智能组合域名/子域名作为文件名进行扫描 | Smart domain/subdomain combination scanning
- 多线程扫描，自动优化线程数和请求延迟 | Multi-threaded scanning with auto-optimization
- 11类敏感信息特征库 | 11 categories of sensitive information signatures
- 支持自定义特征库 | Custom signature library support
- 支持HTTP代理 | HTTP proxy support
- 详细扫描日志 | Detailed scan logs
- 状态码智能过滤 | Smart status code filtering



### 环境要求
```
requests>=2.25.1
urllib3>=1.26.5
certifi>=2021.5.30
tqdm
```


### 命令行选项

- `url`：目标URL（必需）
- `-t, --threads`：并发线程数（默认：10）
- `-p, --proxy`：HTTP代理（例如：http://127.0.0.1:8080）
- `-d, --delay`：请求间隔时间（秒）（默认：0.5）
- `-s, --status`：HTTP状态码过滤（例如：-s 200 301 302）
- `--no-optimize`：禁用自动优化
- `-f, --file`：自定义URL特征库文件路径

### 特征库文件

工具使用位于 `signatures` 目录下的多个特征库文件：

- `backup_urls.txt`：常见备份文件模式
- `github_urls.txt`：GitHub和源代码相关文件
- `env_urls.txt`：环境和配置文件
- `data_urls.txt`：数据和上传目录

### 安装方法

1. 克隆仓库：

```
git clone https://github.com/kaka77/web3kscan.git
cd web3kscan
```

2. 安装依赖：

```
pip install -r requirements.txt
```

### 使用方法

基本用法：

```
python web3k.py example.com
```

高级选项：

```
python web3k.py example.com -t 20 -s 200 -p http://127.0.0.1:8080
```

### 使用示例

1. 基本扫描：
```
python web3k.py example.com
```

2. 自定义特征库扫描：
```
# 使用自定义特征库扫描
python web3k.py example.com -f my_urls.txt

# 组合使用
python web3k.py example.com -f my_urls.txt -t 20 -s 200

```

3. 使用代理和状态码过滤：
```
python web3k.py example.com -p http://127.0.0.1:8080 -s 200
```

4. 自定义线程数和延迟：
```
python web3k.py example.com -t 20 -d 1.0
```

### 扫描结果输出示例

```
http://example.com/.git/config [200] [Size: 1234]
http://example.com/backup.zip [200] [Size: 5678901]
http://example.com/.env [403]
```

### 参与贡献

1. Fork 本仓库
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

### 开源协议

本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。

### 免责声明

本工具仅用于教育目的。用户需要遵守相关法律法规，对使用该工具的行为负责。
