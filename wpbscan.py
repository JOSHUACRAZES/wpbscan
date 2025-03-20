#!/usr/bin/env python3

import argparse
import json
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import re
import sys
import time
import random
import os
from urllib.parse import urljoin

def print_logo():
    logo = """
    _____________________________________________________________
         __          _______   _____ ___                ____
         \\ \\        / /  __ \\  |  __  |  / ____|
          \\ \\  /\\  / /| |__) | | |__|_|     (___   ___  __ _ _ __ ®
           \\ \\/  \\/ / |  ___/  | |____   \\___ \\ / __|/ _` | '_ \\
            \\  /\\  /  | |       | |__| |  ____) | (__| (_| | | | |
             \\/  \\/   |_|       |__ __ |  _____/ \\___|\\__,_|_| |_|

         WordPress Basic Scan by Joshuacraes
    _____________________________________________________________
"""
    print(logo)

def find_wordpress_version(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator and 'WordPress' in meta_generator['content']:
                return meta_generator['content']
            
            # Try to find version in the main page source
            match = re.search(r'wp-includes\/js\/wp-emoji-release\.min\.js\?ver=([0-9.]+)', response.text)
            if match:
                return f"WordPress {match.group(1)}"
                
            # Check readme.html
            readme_url = urljoin(url, 'readme.html')
            readme_response = requests.get(readme_url)
            if readme_response.status_code == 200:
                readme_soup = BeautifulSoup(readme_response.content, 'html.parser')
                version_h1 = readme_soup.find('h1', text=re.compile(r'WordPress.*'))
                if version_h1:
                    return version_h1.text.strip()
    except Exception as e:
        print(f"[!] Error finding WordPress version: {e}")
    return None

def find_vulnerable_themes_plugins(url):
    print("[*] Checking for vulnerable themes and plugins...")
    # Placeholder
    return []

def user_enumeration(url, wordlist=None):
    print("[*] Enumerating users...")
    users = []
    
    # Try to enumerate via author pages
    try:
        for i in range(1, 10):  # Try first 10 author IDs
            response = requests.get(f"{url}/?author={i}")
            if response.status_code == 200:
                # Look for redirects to author page
                if 'author/' in response.url:
                    author = response.url.split('author/')[1].rstrip('/')
                    if author and author not in users:
                        users.append(author)
                        print(f"  [+] Found user: {author}")
    except Exception as e:
        print(f"[!] Error during author enumeration: {e}")
    
    # Try to use WP-JSON API if available
    try:
        response = requests.get(f"{url}/wp-json/wp/v2/users")
        if response.status_code == 200:
            json_data = response.json()
            for user in json_data:
                if 'slug' in user and user['slug'] not in users:
                    users.append(user['slug'])
                    print(f"  [+] Found user via API: {user['slug']}")
    except Exception as e:
        # API might not be available or accessible
        pass
    
    # Try with wordlist if provided
    if wordlist:
        try:
            with open(wordlist, 'r') as f:
                for line in f:
                    user = line.strip()
                    response = requests.get(f"{url}/?author={user}")
                    if response.status_code == 200:
                        users.append(user)
                        print(f"  [+] Found user from wordlist: {user}")
        except Exception as e:
            print(f"[!] Error enumerating users from wordlist: {e}")
    
    return users

def directory_finding(url, wordlist=None):
    print("[*] Finding directories...")
    directories = []
    common_dirs = [
        'wp-admin', 'wp-content', 'wp-includes', 
        'wp-content/uploads', 'wp-content/plugins', 
        'wp-content/themes', 'wp-content/uploads/backups',
        'wp-content/backup-db'
    ]
    
    # Check common directories first
    for directory in common_dirs:
        try:
            response = requests.get(f"{url}/{directory}")
            if response.status_code == 200 or response.status_code == 403:
                directories.append(directory)
                print(f"  [+] Found directory: {directory} (Status: {response.status_code})")
        except Exception as e:
            pass
    
    # Use wordlist if provided
    if wordlist:
        try:
            with open(wordlist, 'r') as f:
                for line in f:
                    directory = line.strip()
                    try:
                        response = requests.get(f"{url}/{directory}")
                        if response.status_code == 200 or response.status_code == 403:
                            directories.append(directory)
                            print(f"  [+] Found directory: {directory} (Status: {response.status_code})")
                    except requests.exceptions.RequestException:
                        pass
        except Exception as e:
            print(f"[!] Error finding directories with wordlist: {e}")
    
    return directories

def check_firewall(url):
    print("[*] Checking for firewall...")
    firewall_signs = {
        'Wordfence': ['wordfence', 'generated by Wordfence'],
        'Sucuri': ['sucuri', 'cloudproxy'],
        'ModSecurity': ['mod_security', 'not acceptable'],
        'CloudFlare': ['cloudflare', 'cloudflare-nginx']
    }
    
    try:
        # Make a normal request
        response = requests.get(url)
        headers = response.headers
        content = response.text.lower()
        
        detected_firewalls = []
        
        # Check headers for firewall signatures
        server = headers.get('Server', '')
        for fw_name, signatures in firewall_signs.items():
            for sig in signatures:
                if sig.lower() in server.lower() or sig.lower() in content:
                    detected_firewalls.append(fw_name)
                    break
        
        # Make a suspicious request to trigger WAF
        suspicious_url = f"{url}/?author=1' OR 1=1 --"
        sus_response = requests.get(suspicious_url)
        
        if sus_response.status_code == 403 or sus_response.status_code == 406:
            if not detected_firewalls:
                detected_firewalls.append("Unknown WAF")
        
        if detected_firewalls:
            print(f"  [+] Firewall detected: {', '.join(detected_firewalls)}")
            return detected_firewalls
        else:
            print("  [-] No firewall detected")
            return False
    except Exception as e:
        print(f"[!] Error checking firewall: {e}")
        return None

def identify_dangerous_files(url):
    print("[*] Checking for dangerous files...")
    dangerous_files = ['/test.cgi', '/phpmyadmin/', '/admin/', '/login.php', '/setup.php', 
                      '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old', '/wp-config.php.save']
    found_files = []
    for file in dangerous_files:
        try:
            response = requests.get(url + file)
            if response.status_code == 200:
                found_files.append(file)
                print(f"  [+] Found dangerous file: {file}")
        except requests.exceptions.RequestException:
            pass
    return found_files

def detect_outdated_server_software(url):
    print("[*] Detecting server software...")
    try:
        response = requests.get(url)
        server = response.headers.get('Server', 'Unknown')
        print(f"  [+] Server software: {server}")
        return server
    except Exception as e:
        print(f"[!] Error detecting server software: {e}")
    return None

def find_insecure_default_files(url):
    print("[*] Checking for insecure default files...")
    insecure_files = ['/readme.html', '/license.txt', '/wp-config-sample.php',
                     '/xmlrpc.php', '/wp-links-opml.php', '/wp-trackback.php']
    found_files = []
    for file in insecure_files:
        try:
            response = requests.get(url + file)
            if response.status_code == 200:
                found_files.append(file)
                print(f"  [+] Found insecure default file: {file}")
        except requests.exceptions.RequestException:
            pass
    return found_files

def scan_vulnerable_files(url):
    print("[*] Scanning for vulnerable files...")
    vulnerable_files = ['/cgi-bin/test.cgi', '/phpmyadmin/', '/admin/', '/login.php']
    found_files = []
    for file in vulnerable_files:
        try:
            response = requests.get(url + file)
            if response.status_code == 200:
                found_files.append(file)
                print(f"  [+] Found potentially vulnerable file: {file}")
        except requests.exceptions.RequestException:
            pass
    return found_files

def check_ssl_certificate(url):
    print("[*] Checking SSL certificate...")
    if not url.startswith('https://'):
        print("  [-] Not an HTTPS site")
        return None
    
    try:
        host = url.replace("https://", "").split('/')[0]
        port = 443
        
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry_date = cert['notAfter']
                
                # Format the result
                result = (
                    f"Subject: {dict(x[0] for x in cert['subject'])}\n"
                    f"Issuer: {dict(x[0] for x in cert['issuer'])}\n"
                    f"Version: {cert['version']}\n"
                    f"Serial Number: {cert.get('serialNumber', 'Unknown')}\n"
                    f"Valid From: {cert['notBefore']}\n"
                    f"Valid Until: {cert['notAfter']}"
                )
                print("  [+] SSL certificate information retrieved")
                return result
    except Exception as e:
        print(f"[!] Error checking SSL certificate: {e}")
    return None

def check_http_headers(url):
    print("[*] Checking HTTP security headers...")
    try:
        response = requests.get(url)
        headers = response.headers
        missing = []
        required = [
            'Strict-Transport-Security', 
            'Content-Security-Policy', 
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        for header in required:
            if header not in headers:
                missing.append(header)
                print(f"  [-] Missing security header: {header}")
            else:
                print(f"  [+] Found security header: {header}")
        return missing
    except Exception as e:
        print(f"[!] Error checking HTTP headers: {e}")
    return []

def enumerate_vulnerable_plugins(url):
    print("[*] Enumerating vulnerable plugins...")
    # Common vulnerable plugins to check
    plugins = [
        'wp-file-manager', 'wp-imageio', 'wp-super-cache', 'wp-optimize',
        'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo',
        'wptouch', 'all-in-one-seo-pack', 'duplicator', 'jetpack',
        'akismet', 'wp-fastest-cache', 'wordfence', 'wordpress-seo',
        'really-simple-ssl', 'all-in-one-wp-migration', 'wordpress-importer'
    ]
    
    vulnerable_plugins = []
    
    # Check each plugin by requesting their readme.txt or main file
    for plugin in plugins:
        try:
            readme_url = f"{url}/wp-content/plugins/{plugin}/readme.txt"
            response = requests.get(readme_url)
            if response.status_code == 200:
                print(f"  [+] Found plugin: {plugin}")
                # Try to determine version
                version_match = re.search(r'Stable tag:\s*([0-9.]+)', response.text)
                if version_match:
                    version = version_match.group(1)
                    print(f"  [+] Plugin version: {version}")
                    vulnerable_plugins.append({'name': plugin, 'version': version})
                else:
                    vulnerable_plugins.append({'name': plugin, 'version': 'unknown'})
            else:
                # Try alternative location
                alt_url = f"{url}/wp-content/plugins/{plugin}/"
                alt_response = requests.get(alt_url)
                if alt_response.status_code == 200:
                    print(f"  [+] Found plugin: {plugin}")
                    vulnerable_plugins.append({'name': plugin, 'version': 'unknown'})
        except Exception as e:
            # Silently ignore connection issues
            pass
            
    return vulnerable_plugins

def enumerate_all_plugins(url):
    print("[*] Enumerating all plugins...")
    plugins = []
    
    # Check plugins directory for listing enabled
    try:
        plugins_url = f"{url}/wp-content/plugins/"
        response = requests.get(plugins_url)
        if response.status_code == 200 and 'Index of' in response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href != '../' and not href.startswith('?') and not href.startswith('/'):
                    plugin_name = href.rstrip('/')
                    if plugin_name:
                        plugins.append({'name': plugin_name, 'version': 'unknown'})
                        print(f"  [+] Found plugin: {plugin_name}")
    except Exception as e:
        print(f"  [!] Error checking directory listing: {e}")
    
    # Check via plugin stylesheets
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('link', {'rel': 'stylesheet'}):
                href = link.get('href', '')
                if 'wp-content/plugins/' in href:
                    plugin_path = href.split('wp-content/plugins/')[1].split('/')[0]
                    if plugin_path and {'name': plugin_path, 'version': 'unknown'} not in plugins:
                        plugins.append({'name': plugin_path, 'version': 'unknown'})
                        print(f"  [+] Found plugin from stylesheet: {plugin_path}")
    except Exception as e:
        print(f"  [!] Error checking stylesheets: {e}")
    
    # Common plugins to check individually
    common_plugins = [
        'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo', 'akismet',
        'jetpack', 'wordfence', 'really-simple-ssl', 'wp-super-cache', 
        'all-in-one-seo-pack', 'duplicator', 'wpforms-lite'
    ]
    
    for plugin in common_plugins:
        if not any(p['name'] == plugin for p in plugins):
            try:
                plugin_url = f"{url}/wp-content/plugins/{plugin}/"
                response = requests.get(plugin_url)
                if response.status_code == 200 or response.status_code == 403:
                    plugins.append({'name': plugin, 'version': 'unknown'})
                    print(f"  [+] Found plugin: {plugin}")
            except Exception:
                pass
    
    return plugins

def enumerate_popular_plugins(url):
    print("[*] Enumerating popular plugins...")
    popular_plugins = [
        'akismet', 'contact-form-7', 'elementor', 'woocommerce', 'yoast-seo',
        'wordfence', 'really-simple-ssl', 'wp-super-cache', 'jetpack',
        'wpforms-lite', 'all-in-one-seo-pack', 'duplicate-page', 'duplicate-post',
        'google-analytics-for-wordpress', 'updraftplus', 'mailchimp-for-wp',
        'classic-editor', 'wp-optimize', 'wordpress-seo', 'wp-mail-smtp'
    ]
    
    found_plugins = []
    
    for plugin in popular_plugins:
        try:
            plugin_url = f"{url}/wp-content/plugins/{plugin}/"
            response = requests.get(plugin_url)
            if response.status_code == 200 or response.status_code == 403:
                print(f"  [+] Found popular plugin: {plugin}")
                
                # Try to determine version from readme.txt
                readme_url = f"{url}/wp-content/plugins/{plugin}/readme.txt"
                readme_response = requests.get(readme_url)
                if readme_response.status_code == 200:
                    version_match = re.search(r'Stable tag:\s*([0-9.]+)', readme_response.text)
                    if version_match:
                        version = version_match.group(1)
                        print(f"  [+] Plugin version: {version}")
                        found_plugins.append({'name': plugin, 'version': version})
                    else:
                        found_plugins.append({'name': plugin, 'version': 'unknown'})
                else:
                    found_plugins.append({'name': plugin, 'version': 'unknown'})
        except Exception:
            # Silently ignore connection issues
            pass
    
    return found_plugins

def enumerate_vulnerable_themes(url):
    print("[*] Enumerating vulnerable themes...")
    known_vulnerable_themes = [
        'twentytwenty', 'twentynineteen', 'twentysixteen', 'avada',
        'divi', 'astra', 'flatsome', 'enfold', 'betheme', 'the7',
        'bridge', 'newspaper', 'sydney', 'jupiter', 'generatepress'
    ]
    
    vulnerable_themes = []
    
    # Check each theme by requesting their style.css
    for theme in known_vulnerable_themes:
        try:
            style_url = f"{url}/wp-content/themes/{theme}/style.css"
            response = requests.get(style_url)
            if response.status_code == 200:
                print(f"  [+] Found theme: {theme}")
                
                # Try to determine version
                version_match = re.search(r'Version:\s*([0-9.]+)', response.text)
                if version_match:
                    version = version_match.group(1)
                    print(f"  [+] Theme version: {version}")
                    vulnerable_themes.append({'name': theme, 'version': version})
                else:
                    vulnerable_themes.append({'name': theme, 'version': 'unknown'})
        except Exception:
            # Silently ignore connection issues
            pass
            
    return vulnerable_themes

def enumerate_all_themes(url):
    print("[*] Enumerating all themes...")
    themes = []
    
    # Check themes directory for listing enabled
    try:
        themes_url = f"{url}/wp-content/themes/"
        response = requests.get(themes_url)
        if response.status_code == 200 and 'Index of' in response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href != '../' and not href.startswith('?') and not href.startswith('/'):
                    theme_name = href.rstrip('/')
                    if theme_name:
                        themes.append({'name': theme_name, 'version': 'unknown'})
                        print(f"  [+] Found theme: {theme_name}")
    except Exception as e:
        print(f"  [!] Error checking directory listing: {e}")
    
    # Try to find current theme from HTML source
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Method 1: Check stylesheets
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('link', {'rel': 'stylesheet'}):
                href = link.get('href', '')
                if 'wp-content/themes/' in href:
                    theme_path = href.split('wp-content/themes/')[1].split('/')[0]
                    if theme_path and not any(t['name'] == theme_path for t in themes):
                        themes.append({'name': theme_path, 'version': 'unknown'})
                        print(f"  [+] Found active theme: {theme_path}")
    except Exception as e:
        print(f"  [!] Error checking theme from source: {e}")
    
    # Common themes to check individually
    common_themes = [
        'twentytwentythree', 'twentytwentytwo', 'twentytwentyone', 'twentytwenty', 
        'astra', 'divi', 'avada', 'flatsome', 'oceanwp', 'generatepress',
        'sydney', 'hello-elementor', 'neve'
    ]
    
    for theme in common_themes:
        if not any(t['name'] == theme for t in themes):
            try:
                theme_url = f"{url}/wp-content/themes/{theme}/style.css"
                response = requests.get(theme_url)
                if response.status_code == 200:
                    # Try to get version
                    version_match = re.search(r'Version:\s*([0-9.]+)', response.text)
                    if version_match:
                        version = version_match.group(1)
                        themes.append({'name': theme, 'version': version})
                        print(f"  [+] Found theme: {theme} (Version: {version})")
                    else:
                        themes.append({'name': theme, 'version': 'unknown'})
                        print(f"  [+] Found theme: {theme}")
            except Exception:
                pass
    
    return themes

def enumerate_popular_themes(url):
    print("[*] Enumerating popular themes...")
    popular_themes = [
        'astra', 'divi', 'avada', 'twentytwentytwo', 'twentytwentythree',
        'flatsome', 'oceanwp', 'generatepress', 'hello-elementor', 'neve',
        'sydney', 'twentytwentyone', 'twentytwenty', 'twentynineteen',
        'storefront', 'elementor', 'hestia', 'kadence', 'colibri-wp',
        'blocksy', 'customify', 'bricks'
    ]
    
    found_themes = []
    
    for theme in popular_themes:
        try:
            style_url = f"{url}/wp-content/themes/{theme}/style.css"
            response = requests.get(style_url)
            if response.status_code == 200:
                print(f"  [+] Found popular theme: {theme}")
                
                # Try to determine version
                version_match = re.search(r'Version:\s*([0-9.]+)', response.text)
                if version_match:
                    version = version_match.group(1)
                    print(f"  [+] Theme version: {version}")
                    found_themes.append({'name': theme, 'version': version})
                else:
                    found_themes.append({'name': theme, 'version': 'unknown'})
        except Exception:
            # Silently ignore connection issues
            pass
    
    return found_themes

def enumerate_timthumbs(url):
    print("[*] Enumerating TimThumb instances...")
    timthumb_paths = [
        '/timthumb.php', 
        '/wp-content/themes/*/timthumb.php',
        '/wp-content/plugins/*/timthumb.php',
        '/wp-content/uploads/*/thumb.php'
    ]
    
    found_timthumbs = []
    
    # Check common locations
    for path in timthumb_paths:
        if '*' not in path:
            try:
                full_url = urljoin(url, path)
                response = requests.get(full_url)
                if response.status_code == 200 and ('TimThumb' in response.text or 'timthumb' in response.text):
                    found_timthumbs.append(path)
                    print(f"  [+] Found TimThumb instance: {path}")
            except Exception:
                pass
    
    # Expand wildcards by checking for specific themes and plugins
    if found_timthumbs:
        # If we found timthumb, it's likely there are more instances in themes/plugins
        print("  [*] Found TimThumb instance(s). Checking themes and plugins for more...")
        
        # Check popular themes for timthumb
        themes = enumerate_popular_themes(url)
        for theme in themes:
            theme_name = theme['name']
            timthumb_url = f"{url}/wp-content/themes/{theme_name}/timthumb.php"
            try:
                response = requests.get(timthumb_url)
                if response.status_code == 200 and ('TimThumb' in response.text or 'timthumb' in response.text):
                    found_path = f"/wp-content/themes/{theme_name}/timthumb.php"
                    if found_path not in found_timthumbs:
                        found_timthumbs.append(found_path)
                        print(f"  [+] Found TimThumb in theme: {theme_name}")
            except Exception:
                pass
        
        # Check popular plugins for timthumb
        plugins = enumerate_popular_plugins(url)
        for plugin in plugins:
            plugin_name = plugin['name']
            timthumb_url = f"{url}/wp-content/plugins/{plugin_name}/timthumb.php"
            try:
                response = requests.get(timthumb_url)
                if response.status_code == 200 and ('TimThumb' in response.text or 'timthumb' in response.text):
                    found_path = f"/wp-content/plugins/{plugin_name}/timthumb.php"
                    if found_path not in found_timthumbs:
                        found_timthumbs.append(found_path)
                        print(f"  [+] Found TimThumb in plugin: {plugin_name}")
            except Exception:
                pass
    
    return found_timthumbs

def enumerate_config_backups(url):
    print("[*] Enumerating configuration backups...")
    backup_files = [
        '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.save',
        '/wp-config.php.swp', '/wp-config.php.old', '/wp-config.php.orig',
        '/wp-config.php.original', '/wp-config.txt', '/wp-config.php.txt',
        '/wp-config-backup.php', '/wp-config.php.zip', '/wp-config.php.gz',
        '/wp-config.php.tar.gz', '/.wp-config.php.swp', '/wp-config.php_bak'
    ]
    
    found_backups = []
    
    for file in backup_files:
        try:
            backup_url = urljoin(url, file)
            response = requests.get(backup_url)
            # We're looking for successful responses or redirects that might indicate file exists
            if response.status_code == 200:
                # Check if it's a PHP file being served as text (likely a backup)
                if 'DB_NAME' in response.text or 'MySQL settings' in response.text:
                    found_backups.append(file)
                    print(f"  [+] Found config backup: {file} [CRITICAL]")
                elif file.endswith(('.bak', '.txt', '.old', '.orig', '.save', '~')):
                    # For backup extensions, even empty files could be backups
                    found_backups.append(file)
                    print(f"  [+] Found possible config backup: {file}")
        except Exception:
            pass
    
    return found_backups

def enumerate_db_exports(url):
    print("[*] Enumerating database exports...")
    db_files = [
        '/wp-content/backup-db/', '/wp-content/backups/', 
        '/wp-content/mysql.sql', '/backup/', '/backups/',
        '/wp-content/uploads/db-backup/', '/db-backup/',
        '/wp-content/uploads/dump.sql', '/wp-content/dump.sql',
        '/wp-content/database.sql', '/database.sql', '/mysql.sql',
        '/backup.sql', '/wordpress.sql', '/wp.sql', '/site.sql',
        '/wp-content/mysql.sql.gz', '/wp-content/mysql.sql.bz2'
    ]
    
    found_exports = []
    
    for file in db_files:
        try:
            export_url = urljoin(url, file)
            response = requests.get(export_url)
            # Check for successful response
            if response.status_code == 200:
                # For SQL files, check if they contain SQL content
                if file.endswith('.sql'):
                    if 'CREATE TABLE' in response.text or 'INSERT INTO' in response.text:
                        found_exports.append(file)
                        print(f"  [+] Found database export: {file} [CRITICAL]")
                # For directories, check if they show directory listing
                elif file.endswith('/'):
                    if 'Index of' in response.text or 'sql' in response.text.lower():
                        found_exports.append(file)
                        print(f"  [+] Found database backup directory: {file}")
                # For compressed files, just note their existence
                elif file.endswith(('.gz', '.bz2', '.zip', '.tar')):
                    found_exports.append(file)
                    print(f"  [+] Found possible database export: {file}")
        except Exception:
            pass
    
    return found_exports

def save_output(data, filename):
    with open(filename, 'w') as f:
        if filename.endswith('.txt'):
            for key, value in data.items():
                f.write(f"{key}:\n")
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            f.write(f"  - {item}\n")
                        else:
                            f.write(f"  - {item}\n")
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        f.write(f"  {subkey}: {subvalue}\n")
                else:
                    f.write(f"  {value}\n")
                f.write("\n")
        else:
            json.dump(data, f, indent=4)

def parse_enumerate_options(options_str):
    """Parse the enumeration options string into a list of options"""
    valid_options = ['vp', 'ap', 'p', 'vt', 'at', 't', 'tt', 'cb', 'dbe']
    
    if not options_str or options_str.lower() == "all":
        return valid_options
    
    options = options_str.split(',')
    parsed_options = []
    
    for opt in options:
        opt = opt.strip().lower()
        if opt in valid_options:
            parsed_options.append(opt)
        else:
            print(f"[!] Warning: Invalid enumeration option '{opt}'. Ignoring.")
    
    return parsed_options

def main():
    print_logo()
    parser = argparse.ArgumentParser(description='WPBScan - WordPress Security Scanner')
    parser.add_argument('url', help='The URL of the WordPress site to scan')
    parser.add_argument('-v', '--version', action='store_true', help='Find WordPress version')
    parser.add_argument('-t', '--themes-plugins', action='store_true', help='Find vulnerable themes and plugins')
    parser.add_argument('-u', '--users', action='store_true', help='Enumerate users')
    parser.add_argument('-d', '--directories', action='store_true', help='Find directories')
    parser.add_argument('-f', '--firewall', action='store_true', help='Check for firewall')
    parser.add_argument('-n', '--nikto', action='store_true', help='Perform Nikto-like scans')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for directory and user enumeration')
    parser.add_argument('-o', '--output', help='Output file (TXT or JSON)')
    parser.add_argument('-e', '--enumerate', nargs='?', const='all', 
                       help='''Enumeration Process
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
                              ALL  All enumeration options (default)''')

    args = parser.parse_args()
    
    # Normalize URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    if args.url.endswith('/'):
        args.url = args.url[:-1]
    
    print(f"[+] Starting scan on {args.url}")
    results = {}

    # Add a small delay between requests to avoid overwhelming the server
    time.sleep(0.5)
    
    if args.version:
        results['wordpress_version'] = find_wordpress_version(args.url)

    if args.themes_plugins:
        results['vulnerable_themes_plugins'] = find_vulnerable_themes_plugins(args.url)

    if args.users:
        results['users'] = user_enumeration(args.url, args.wordlist)

    if args.directories:
        results['directories'] = directory_finding(args.url, args.wordlist)

    if args.firewall:
        results['firewall'] = check_firewall(args.url)

    if args.nikto:
        results['dangerous_files'] = identify_dangerous_files(args.url)
        results['server_software'] = detect_outdated_server_software(args.url)
        results['insecure_files'] = find_insecure_default_files(args.url)
        results['vulnerable_files'] = scan_vulnerable_files(args.url)
        
        # Skip SSL check for non-HTTPS sites
        if args.url.startswith('https://'):
            results['ssl_certificate'] = check_ssl_certificate(args.url)
            
        results['missing_http_headers'] = check_http_headers(args.url)

    # Handle enumeration options
    if args.enumerate:
        enum_options = parse_enumerate_options(args.enumerate)
        
        if 'vp' in enum_options:
            results['vulnerable_plugins'] = enumerate_vulnerable_plugins(args.url)
            
        if 'ap' in enum_options:
            results['all_plugins'] = enumerate_all_plugins(args.url)
            
        if 'p' in enum_options:
            results['popular_plugins'] = enumerate_popular_plugins(args.url)
            
        if 'vt' in enum_options:
            results['vulnerable_themes'] = enumerate_vulnerable_themes(args.url)
            
        if 'at' in enum_options:
            results['all_themes'] = enumerate_all_themes(args.url)
            
        if 't' in enum_options:
            results['popular_themes'] = enumerate_popular_themes(args.url)
            
        if 'tt' in enum_options:
            results['timthumbs'] = enumerate_timthumbs(args.url)
            
        if 'cb' in enum_options:
            results['config_backups'] = enumerate_config_backups(args.url)
            
        if 'dbe' in enum_options:
            results['db_exports'] = enumerate_db_exports(args.url)

    if args.output:
        save_output(results, args.output)
        print(f"[+] Results saved to {args.output}")
    elif results:
        print("\n[+] Scan Results:")
        for key, value in results.items():
            print(f"\n{key.replace('_', ' ').title()}:")
            if isinstance(value, list):
                if not value:
                    print("  No findings")
                else:
                    for item in value:
                        if isinstance(item, dict):
                            item_str = ", ".join([f"{k}: {v}" for k, v in item.items()])
                            print(f"  - {item_str}")
                        else:
                            print(f"  - {item}")
            elif isinstance(value, dict):
                for subkey, subvalue in value.items():
                    print(f"  {subkey}: {subvalue}")
            else:
                if value:
                    print(f"  {value}")
                else:
                    print("  No findings")
    else:
        print("[-] No scan options selected. Use -h for help.")
    
    print("\n[+] Scan completed!")

if __name__ == '__main__':
    main()
