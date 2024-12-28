import os
import re
import stat
import base64
import binascii
import json
from datetime import datetime

class SecurityScanner:
    def __init__(self):
        self.suspicious_patterns = {
            'php_patterns': [
                r'eval\s*\(',
                r'base64_decode\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec\s*\(',
                r'passthru\s*\(',
                r'preg_replace\s*\([^,]*\/[^,]*\/[^,]*e[^,]*,',  # PHP code execution in preg_replace
                r'\$\{.+?\}',  # PHP variable interpolation
                r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\(\s*\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\)',  # Variable functions
                r'create_function\s*\(',
                r'include\s*\(\s*[\'"]php:\/\/input[\'"]\s*\)',
                r'file_get_contents\s*\(\s*[\'"]php:\/\/input[\'"]\s*\)',
                r'assert\s*\(',
                r'str_rot13\s*\(',
                r'gzinflate\s*\(',
                r'gzuncompress\s*\(',
                r'\/e\'\s*,\s*\$_',  # Exploit in preg_replace
            ],
            'js_patterns': [
                r'eval\s*\(',
                r'document\.write\s*\(',
                r'unescape\s*\(',
                r'escape\s*\(',
                r'document\.cookie',
                r'localStorage\.',
                r'sessionStorage\.',
                r'new\s+Function\s*\(',
            ],
            'suspicious_files': [
                r'\.php\.',  # PHP files with multiple extensions
                r'(?<!wp-)config\.php',  # config.php files not wp-config.php
                r'(?<!index)\.php$',  # PHP files not named index.php
                r'shell\.php',
                r'backdoor\.php',
                r'(?:c99|r57|fx29)shell\.php',
                r'\.htaccess$',
            ],
            'base64_patterns': [
                rb'eval\s*\(',
                rb'base64_decode',
                rb'system\s*\(',
                rb'exec\s*\(',
                rb'shell_exec',
            ]
        }
        
    def is_binary_file(self, filepath):
        """Check if file is binary."""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except:
            return False

    def check_permissions(self, filepath):
        """Check file permissions."""
        try:
            st = os.stat(filepath)
            mode = st.st_mode
            issues = []
            
            # Check world-writable permissions
            if mode & stat.S_IWOTH:
                issues.append("File is world-writable")
            
            # Check executable permissions
            if mode & stat.S_IXUSR or mode & stat.S_IXGRP or mode & stat.S_IXOTH:
                if not filepath.endswith(('.sh', '.py')):
                    issues.append("File has executable permissions but doesn't appear to be a script")
            
            return issues
        except:
            return []

    def scan_file_content(self, filepath):
        """Scan file content for suspicious patterns."""
        try:
            if os.path.getsize(filepath) > 10_000_000:  # Skip files larger than 10MB
                return ["File too large to scan"]
                
            if self.is_binary_file(filepath) and not filepath.endswith(('.php', '.js', '.txt')):
                return []

            with open(filepath, 'rb') as f:
                content = f.read()
                issues = []
                
                # Try to decode base64 content
                try:
                    if len(content) > 100:
                        decoded = base64.b64decode(content)
                        for pattern in self.suspicious_patterns['base64_patterns']:
                            if re.search(pattern, decoded):
                                issues.append(f"Contains suspicious base64-encoded pattern")
                                break
                except:
                    pass

                # Convert to string for text-based scanning
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    # Check PHP patterns
                    if filepath.endswith('.php'):
                        for pattern in self.suspicious_patterns['php_patterns']:
                            if re.search(pattern, text_content):
                                issues.append(f"Contains suspicious PHP pattern: {pattern}")
                    
                    # Check JavaScript patterns
                    if filepath.endswith('.js'):
                        for pattern in self.suspicious_patterns['js_patterns']:
                            if re.search(pattern, text_content):
                                issues.append(f"Contains suspicious JavaScript pattern: {pattern}")
                    
                    # Check for encoded/obfuscated code
                    if re.search(r'\\x[0-9a-fA-F]{2}', text_content):
                        issues.append("Contains hex-encoded strings")
                    
                    if re.search(r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*.*){10,}', text_content):
                        issues.append("Contains multiple consecutive variable assignments (possible obfuscation)")
                        
                except:
                    pass
                
            return issues
        except Exception as e:
            return [f"Error scanning file: {str(e)}"]

    def scan_directory(self, directory):
        """Scan directory recursively."""
        print(f"\nScanning directory: {directory}")
        print("-" * 80)
        
        suspicious_files = []
        
        for root, dirs, files in os.walk(directory):
            # Skip WordPress core directories
            if any(core_dir in root for core_dir in ['wp-includes', 'wp-admin']):
                continue
                
            for filename in files:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, directory)
                issues = []
                
                # Check filename patterns
                for pattern in self.suspicious_patterns['suspicious_files']:
                    if re.search(pattern, filename, re.IGNORECASE):
                        issues.append(f"Suspicious filename pattern: {pattern}")
                
                # Check permissions
                perm_issues = self.check_permissions(filepath)
                issues.extend(perm_issues)
                
                # Scan content
                content_issues = self.scan_file_content(filepath)
                issues.extend(content_issues)
                
                if issues:
                    suspicious_files.append({
                        'file': relative_path,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                        'issues': issues
                    })
        
        if suspicious_files:
            print("\nFound suspicious files:")
            for item in suspicious_files:
                print(f"\nFile: {item['file']}")
                print(f"Size: {item['size']} bytes")
                print(f"Modified: {item['modified']}")
                print("Issues found:")
                for issue in item['issues']:
                    print(f"  - {issue}")
        else:
            print("\nNo suspicious files found.")
        
        print("\nScan complete.")
        return suspicious_files

if __name__ == "__main__":
    wp_root = "/Users/jessicajohnson/Downloads/wordpress 3"
    scanner = SecurityScanner()
    
    # Scan specific directories
    directories_to_scan = [
        os.path.join(wp_root, "wp-content/plugins"),
        os.path.join(wp_root, "wp-content/themes"),
        os.path.join(wp_root, "wp-content/uploads"),
        os.path.join(wp_root, "wp-content/mu-plugins") if os.path.exists(os.path.join(wp_root, "wp-content/mu-plugins")) else None
    ]
    
    print("Starting WordPress Security Scan")
    print("=" * 80)
    print("Note: WordPress core files will be skipped")
    
    for directory in directories_to_scan:
        if directory and os.path.exists(directory):
            scanner.scan_directory(directory)
