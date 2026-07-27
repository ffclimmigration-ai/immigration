import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

def main():
    # Get the directory of this script (should be the project root)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Find all .htm files
    html_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".htm"):
                html_files.append(os.path.join(dirpath, filename))
    
    broken_links = []
    
    for file_path in html_files:
        # Read the file
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                soup = BeautifulSoup(f.read(), "html.parser")
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")
                continue
        
        # Find all links
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            # Skip external links
            if href.startswith("http://") or href.startswith("https://"):
                continue
            # Skip mailto links
            if href.startswith("mailto:"):
                continue
            # Skip anchor links
            if href.startswith("#"):
                continue
            
            # Parse the URL
            parsed = urlparse(href)
            path = unquote(parsed.path)
            
            # Resolve relative path
            if path.startswith("/"):
                # Absolute path from root
                abs_path = os.path.join(root_dir, path.lstrip("/"))
            else:
                # Relative path from current file
                file_dir = os.path.dirname(file_path)
                abs_path = os.path.normpath(os.path.join(file_dir, path))
            
            # Check if file exists
            if os.path.isfile(abs_path):
                continue
            # Check if it's a directory with index.htm
            if os.path.isdir(abs_path) and os.path.isfile(os.path.join(abs_path, "index.htm")):
                continue
            
            # If we get here, it's a broken link
            broken_links.append({
                "file": file_path,
                "href": href,
                "resolved_path": abs_path
            })
    
    # Print results
    if broken_links:
        print(f"Found {len(broken_links)} broken links:")
        for link in broken_links:
            print(f"File: {link['file']}")
            print(f"  Href: {link['href']}")
            print(f"  Resolved path: {link['resolved_path']}")
            print()
    else:
        print("No broken links found!")

if __name__ == "__main__":
    main()