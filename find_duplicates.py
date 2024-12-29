import os
import hashlib
from collections import defaultdict

def get_file_hash(filepath):
    """Calculate SHA-256 hash of file contents."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)  # Read in 64kb chunks
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def find_duplicates(directory):
    """Find duplicate files in directory and its subdirectories."""
    hash_map = defaultdict(list)
    
    # Walk through directory
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                file_hash = get_file_hash(filepath)
                hash_map[file_hash].append(filepath)
            except (IOError, OSError):
                continue

    # Print duplicates
    has_duplicates = False
    for file_hash, file_list in hash_map.items():
        if len(file_list) > 1:
            has_duplicates = True
            print("\nDuplicate files (identical content):")
            for filepath in file_list:
                print(f"  {filepath}")
            print("-" * 80)
    
    if not has_duplicates:
        print("No duplicate files found.")

if __name__ == "__main__":
    wp_content_dir = "/Users/jessicajohnson/Downloads/wordpress 3/wp-content"
    print(f"Scanning for duplicates in: {wp_content_dir}")
    print("This may take a few moments...")
    find_duplicates(wp_content_dir)
