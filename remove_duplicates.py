import os
import hashlib
from collections import defaultdict
import re

def get_file_hash(filepath):
    """Calculate SHA-256 hash of file contents."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def is_sized_image(filename):
    """Check if the file is a sized version of an image."""
    return bool(re.search(r'-\d+x\d+\.[a-zA-Z]+$', filename))

def remove_duplicates(directory):
    """Remove .bak files and duplicates while preserving sized images."""
    # First, remove all .bak files
    bak_files_removed = 0
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.bak'):
                filepath = os.path.join(root, filename)
                try:
                    os.remove(filepath)
                    print(f"Removed .bak file: {filepath}")
                    bak_files_removed += 1
                except OSError as e:
                    print(f"Error removing {filepath}: {e}")

    # Then handle other duplicates
    hash_map = defaultdict(list)
    
    # First pass: collect all files and their hashes
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            if not is_sized_image(filename):  # Only hash non-sized images
                try:
                    file_hash = get_file_hash(filepath)
                    hash_map[file_hash].append(filepath)
                except (IOError, OSError):
                    continue

    # Second pass: remove duplicates
    duplicates_removed = 0
    for file_hash, file_list in hash_map.items():
        if len(file_list) > 1:
            # Keep the first file, remove the rest
            for filepath in file_list[1:]:
                try:
                    os.remove(filepath)
                    print(f"Removed duplicate file: {filepath}")
                    duplicates_removed += 1
                except OSError as e:
                    print(f"Error removing {filepath}: {e}")

    print(f"\nSummary:")
    print(f"- Removed {bak_files_removed} .bak files")
    print(f"- Removed {duplicates_removed} duplicate files")
    print("- Preserved all sized image variants")

if __name__ == "__main__":
    wp_content_dir = "/Users/jessicajohnson/Downloads/wordpress 3/wp-content"
    print(f"Cleaning up duplicates in: {wp_content_dir}")
    print("This may take a few moments...")
    remove_duplicates(wp_content_dir)
