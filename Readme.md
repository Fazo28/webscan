# WEBSCAN - Modern Website Scanner

WEBSCAN is a powerful, feature-rich website scanning tool designed for both Termux and Linux users. It provides comprehensive website analysis with a modern, user-friendly interface.

![WEBSCAN Banner](https://i.imgur.com/examplebanner.png)

## Features

### 🛠️ Core Scanning Capabilities
- **CMS Detection**: Identify WordPress, Joomla, Drupal, Magento, and other CMS platforms
- **Database Detection**: Detect MySQL, PostgreSQL, SQLite, MongoDB, and Microsoft SQL Server
- **User Estimation**: Estimate number of registered users (especially effective for WordPress)

### 🔍 Information Gathering
- **IP Resolution**: Get website IP address and server location
- **WHOIS Lookup**: Retrieve domain registration details
- **DNS Records**: Fetch A, MX, NS, and TXT records
- **Server Headers**: Analyze server response headers
- **Port Scanning**: Scan common web ports (80, 443, 21, 22, 3306, etc.)

### 🛡️ Security Analysis
- **Vulnerability Checks**: Detect common security issues
- **Admin Panel Finder**: Discover hidden admin interfaces
- **Sensitive File Detection**: Identify exposed config files
- **XML-RPC Check**: WordPress-specific vulnerability detection

### 📊 Data Management
- **Scan History**: SQLite database stores all scan results
- **Interactive Mode**: User-friendly menu system
- **Colorized Output**: Easy-to-read terminal interface

## 📥 Installation

### Prerequisites
- Python 3.x
- pip package manager

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Old-Hacker01/webscan.git
   cd webscan
   pip install -r requirements.txt
   chmod +x webscan.py
2. USAGE
   ```bash
  ./webscan.py -u https://example.com
