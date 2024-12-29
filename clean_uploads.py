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
    print(f"Analyzing files in: {directory}")
    
    # First, find and remove .bak files
    bak_files = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.bak'):
                filepath = os.path.join(root, filename)
                bak_files.append(filepath)
    
    if bak_files:
        print("\nFound .bak files:")
        for filepath in bak_files:
            print(f"  {filepath}")
        
        response = input("\nDo you want to remove these .bak files? (y/n): ")
        if response.lower() == 'y':
            for filepath in bak_files:
                try:
                    os.remove(filepath)
                    print(f"Removed: {filepath}")
                except OSError as e:
                    print(f"Error removing {filepath}: {e}")

    # Then handle other duplicates
    hash_map = defaultdict(list)
    
    # First pass: collect all files and their hashes
    print("\nAnalyzing for duplicates (excluding sized images)...")
    for root, _, files in os.walk(directory):
        for filename in files:
            if not is_sized_image(filename):  # Skip sized images
                filepath = os.path.join(root, filename)
                try:
                    file_hash = get_file_hash(filepath)
                    hash_map[file_hash].append(filepath)
                except (IOError, OSError):
                    continue

    # Show duplicates and ask for confirmation
    duplicates_found = False
    for file_hash, file_list in hash_map.items():
        if len(file_list) > 1:
            if not duplicates_found:
                print("\nFound duplicate files:")
                duplicates_found = True
            
            print("\nDuplicate set:")
            for idx, filepath in enumerate(file_list, 1):
                print(f"  {idx}. {filepath}")

    if duplicates_found:
        response = input("\nDo you want to keep the first file in each set and remove the others? (y/n): ")
        if response.lower() == 'y':
            duplicates_removed = 0
            for file_hash, file_list in hash_map.items():
                if len(file_list) > 1:
                    # Keep the first file, remove the rest
                    for filepath in file_list[1:]:
                        try:
                            os.remove(filepath)
                            print(f"Removed: {filepath}")
                            duplicates_removed += 1
                        except OSError as e:
                            print(f"Error removing {filepath}: {e}")
            print(f"\nRemoved {duplicates_removed} duplicate files")
    else:
        print("\nNo duplicates found (excluding sized images)")

if __name__ == "__main__":
    uploads_dir = "/Users/jessicajohnson/Downloads/wordpress 3/wp-content/uploads"
    remove_duplicates(uploads_dir)
