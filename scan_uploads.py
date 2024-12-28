import os
import re
import stat
import base64
import binascii
import mimetypes

def is_suspicious_filename(filename):
    """Check if filename has suspicious patterns."""
    suspicious_patterns = [
        r'\.php\d*$',  # PHP files
        r'\.(php|phtml|php3|php4|php5|phar|inc)\..*$',  # Double extensions with PHP
        r'^\.',  # Hidden files
        r'\.exe$|\.dll$|\.so$',  # Executable extensions
        r'[0-9a-fA-F]{32}',  # MD5-like names
        r'base64',  # Base64 in filename
        r'eval|exec|system|shell|hack',  # Suspicious terms
    ]
    return any(re.search(pattern, filename, re.IGNORECASE) for pattern in suspicious_patterns)

def is_binary_file(filepath):
    """Check if file is binary."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except:
        return False

def has_suspicious_content(filepath):
    """Check file content for suspicious patterns."""
    try:
        # Skip large files (>10MB) and binary files
        if os.path.getsize(filepath) > 10_000_000 or is_binary_file(filepath):
            return False, ""

        with open(filepath, 'rb') as f:
            content = f.read()
            
            # Check if content might be base64 encoded
            try:
                if len(content) > 100:  # Avoid small files
                    decoded = base64.b64decode(content)
                    if b'<?php' in decoded or b'eval(' in decoded:
                        return True, "Contains base64 encoded PHP code"
            except (binascii.Error, UnicodeDecodeError):
                pass
            
            # Convert to string if possible
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                return False, ""
            
            suspicious_patterns = [
                r'eval\s*\(',
                r'base64_decode\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec\s*\(',
                r'passthru\s*\(',
                r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*.*){10,}',  # Long variable assignments
                r'\\x[0-9a-fA-F]{2}',  # Hex encoded strings
                r'<\?php',  # PHP opening tags
                r'GIF89a.*<\?php',  # PHP code hidden in GIF
                r'\$GLOBALS\[.{0,30}\]\[\d+\]',  # Obfuscated global variables
                r'chr\(\d+\)\.chr\(\d+\)',  # Character concatenation
                r'str_rot13',  # ROT13 encoding
                r'gzinflate|gzuncompress|base64_decode',  # Common malware encoding
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, text_content):
                    return True, f"Contains suspicious pattern: {pattern}"
                    
    except (IOError, OSError) as e:
        return False, f"Error reading file: {str(e)}"
    
    return False, ""

def check_file_permissions(filepath):
    """Check for unusual file permissions."""
    try:
        st = os.stat(filepath)
        mode = st.st_mode
        
        # Check if file is executable or writable by others
        if mode & stat.S_IXUSR or mode & stat.S_IXGRP or mode & stat.S_IXOTH:
            return True, "File has executable permissions"
        if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
            return True, "File is writable by group/others"
            
    except OSError:
        return False, ""
    
    return False, ""

def get_mime_type(filepath):
    """Get MIME type of file."""
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type or "unknown"

def scan_directory(directory):
    """Scan directory for suspicious files."""
    print(f"Scanning directory: {directory}")
    print("-" * 80)
    
    suspicious_files = []
    
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            issues = []
            
            # Check filename
            if is_suspicious_filename(filename):
                issues.append("Suspicious filename pattern")
            
            # Check file type
            mime_type = get_mime_type(filepath)
            if mime_type in ['application/x-httpd-php', 'text/x-php']:
                issues.append(f"Suspicious MIME type: {mime_type}")
            
            # Check content
            is_suspicious, reason = has_suspicious_content(filepath)
            if is_suspicious:
                issues.append(reason)
            
            # Check permissions
            has_issues, perm_reason = check_file_permissions(filepath)
            if has_issues:
                issues.append(perm_reason)
            
            if issues:
                suspicious_files.append((filepath, issues))
    
    if suspicious_files:
        print("\nFound suspicious files:")
        for filepath, issues in suspicious_files:
            print(f"\nFile: {filepath}")
            print(f"Size: {os.path.getsize(filepath)} bytes")
            print(f"MIME type: {get_mime_type(filepath)}")
            print("Issues found:")
            for issue in issues:
                print(f"  - {issue}")
    else:
        print("\nNo suspicious files found.")
    
    print("\nScan complete.")

if __name__ == "__main__":
    uploads_dir = "/Users/jessicajohnson/Downloads/wordpress 3/wp-content/uploads"
    scan_directory(uploads_dir)
