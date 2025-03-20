# wpbscan
# WPBScan - WordPress Basic Scanner

WPBScan is a powerful Python-based tool designed to identify security vulnerabilities in WordPress websites. It offers comprehensive scanning capabilities similar to WPScan but with a simplified interface and lightweight implementation.

[image](image_2.png) 

## Features

- WordPress version detection
- Plugin and theme enumeration
- User enumeration
- Directory discovery
- Firewall detection
- Comprehensive security scans (Nikto-like)
- SSL certificate verification
- Security header checks
- Database backup detection
- Config file backup detection

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Installing on Kali Linux

1. Clone the repository:
```bash
git clone https://github.com/JOSHUACRAZES/wpbscan.git
cd wpbscan
```

2. Install the required dependencies:
```bash
pip3 install -r requirements.txt
```

3. Make the script executable:
```bash
chmod +x wpbscan.py
```

4. Create a symbolic link (optional, for system-wide access):
```bash
sudo ln -s $(pwd)/wpbscan.py /usr/local/bin/wpbscan
```

### Requirements

The tool requires the following Python packages:
- requests
- beautifulsoup4
- urllib3

These are included in the requirements.txt file.

## Usage

Basic usage:
```bash
python3 wpbscan.py [options] <target-url>
```

### Command Line Options

```
usage: wpbscan.py [-h] [-v] [-t] [-u] [-d] [-f] [-n] [-w WORDLIST] [-o OUTPUT]
                  [-e [ENUMERATE]]
                  url

WPBScan - WordPress Security Scanner

positional arguments:
  url                   The URL of the WordPress site to scan

options:
  -h, --help            show this help message and exit
  -v, --version         Find WordPress version
  -t, --themes-plugins  Find vulnerable themes and plugins
  -u, --users           Enumerate users
  -d, --directories     Find directories
  -f, --firewall        Check for firewall
  -n, --nikto           Perform Nikto-like scans
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist file for directory and user enumeration
  -o OUTPUT, --output OUTPUT
                        Output file (TXT or JSON)
  -e [ENUMERATE], --enumerate [ENUMERATE]
                        Enumeration Process
                             Available Choices:
                              vp   Vulnerable plugins
                              ap   All plugins
                              p    Popular plugins
                              vt   Vulnerable themes
                              at   All themes
                              t    Popular themes
                              tt   Timthumbs
                              cb   Config backups
                              dbe  Db exports
                              ALL  All enumeration options (default)
```

## Detailed Function Explanations

### WordPress Version Detection (-v, --version)
Attempts to identify the WordPress version by examining:
- HTML meta tags
- JavaScript files
- README files
- Other version fingerprints

This information is critical as older WordPress versions often contain known vulnerabilities.

### Themes and Plugins Scanning (-t, --themes-plugins)
Performs a basic scan for potentially vulnerable themes and plugins by analyzing their presence and version information.

### User Enumeration (-u, --users)
Attempts to discover WordPress usernames by:
- Checking author pages
- Using the WordPress JSON API
- Testing common username patterns

Can be enhanced with a wordlist via the `-w` option.

### Directory Discovery (-d, --directories)
Scans for important WordPress directories that might be accessible, including:
- wp-admin
- wp-content
- wp-includes
- Various upload and backup directories

Can be enhanced with a wordlist via the `-w` option.

### Firewall Detection (-f, --firewall)
Identifies if the site is protected by a Web Application Firewall (WAF) such as:
- Wordfence
- Sucuri
- ModSecurity
- CloudFlare

### Nikto-like Scans (-n, --nikto)
Performs comprehensive security checks similar to the Nikto scanner:
- Dangerous file detection
- Server software identification
- Insecure default files
- Vulnerable file discovery
- SSL certificate analysis
- HTTP security header verification

### Enumeration Options (-e, --enumerate)

Provides detailed enumeration of specific WordPress components:

#### Plugin Enumeration
- **vp (Vulnerable plugins)**: Focuses on detecting plugins with known vulnerabilities
- **ap (All plugins)**: Discovers all plugins installed on the WordPress site
- **p (Popular plugins)**: Checks for commonly used WordPress plugins

#### Theme Enumeration
- **vt (Vulnerable themes)**: Identifies themes with known security issues
- **at (All themes)**: Discovers all themes installed on the WordPress site
- **t (Popular themes)**: Checks for commonly used WordPress themes

#### Additional Enumeration
- **tt (Timthumbs)**: Finds instances of the TimThumb script, which has had serious vulnerabilities
- **cb (Config backups)**: Searches for WordPress configuration file backups that might contain sensitive information
- **dbe (Db exports)**: Looks for exposed database exports or backups

#### Usage Examples
Enumerate vulnerable plugins and themes:
```bash
python3 wpbscan.py https://example.com -e vp,vt
```

Run all enumeration scans:
```bash
python3 wpbscan.py https://example.com -e ALL
```

### Output Options (-o, --output)
Save scan results to a file in either TXT or JSON format:
```bash
python3 wpbscan.py https://example.com -v -t -o results.json
```

## Example Usage Scenarios

### Basic Scan
```bash
python3 wpbscan.py https://example.com -v
```
Performs a basic scan to identify the WordPress version.

### Full Security Audit
```bash
python3 wpbscan.py https://example.com -v -t -u -d -f -n -e ALL -o audit_report.json
```
Conducts a comprehensive security assessment and saves results to a JSON file.

### Quick Plugin Check
```bash
python3 wpbscan.py https://example.com -e vp,p
```
Quickly checks for vulnerable and popular plugins.

### User Discovery with Custom Wordlist
```bash
python3 wpbscan.py https://example.com -u -w /path/to/usernames.txt
```
Attempts to discover WordPress users using a custom wordlist.

## Security Considerations

- Always obtain proper authorization before scanning any website
- Be aware that aggressive scanning may trigger security mechanisms
- Some websites may ban your IP address if too many requests are made

## Troubleshooting

- If you encounter SSL certificate verification errors, ensure your CA certificates are up to date
- For connection timeout issues, try increasing the delay between requests
- If user enumeration fails, try using the `-w` option with a comprehensive wordlist

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- WordPress security community
- WPScan team for inspiration
- Kali Linux project

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Contact

GitHub: [JOSHUACRAZES](https://github.com/JOSHUACRAZES)
