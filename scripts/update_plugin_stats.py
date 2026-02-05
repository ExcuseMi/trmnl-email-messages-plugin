#!/usr/bin/env python3
import hashlib
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


def load_plugin_config():
    """Load plugin IDs from plugins.env file"""
    config = {
        'plugin_ids': [],
        'section_title': '🚀 Plugin Statistics',
        'images_dir': 'assets/plugin-images'
    }

    try:
        with open('plugins.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if key == 'PLUGIN_IDS':
                            config['plugin_ids'] = [pid.strip() for pid in value.split(',') if pid.strip()]
                        elif key == 'SECTION_TITLE':
                            config['section_title'] = value
                        elif key == 'IMAGES_DIR':
                            config['images_dir'] = value
    except FileNotFoundError:
        print("⚠️  plugins.env file not found. Using default configuration.")

    return config


def get_image_extension(url: str, content_type: str = None):
    """
    Extract file extension from URL or Content-Type header

    Args:
        url: Image URL
        content_type: Content-Type header from response

    Returns:
        File extension with dot (e.g., '.png', '.svg')
    """
    # First try Content-Type header (most reliable)
    if content_type:
        content_type = content_type.lower().split(';')[0].strip()

        mime_to_ext = {
            'image/svg+xml': '.svg',
            'image/png': '.png',
            'image/jpeg': '.jpg',
            'image/jpg': '.jpg',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/bmp': '.bmp',
            'image/x-icon': '.ico',
        }

        if content_type in mime_to_ext:
            return mime_to_ext[content_type]

    # Fall back to URL parsing (remove query parameters)
    parsed = urlparse(url)
    path = parsed.path.split('?')[0]  # Remove query params
    _, ext = os.path.splitext(path)

    # Normalize extension
    if ext:
        ext = ext.lower()
        # Handle common variations
        if ext in ['.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico']:
            return ext

    # Default to .png if we can't determine
    return '.png'


def fetch_and_save_image(url: str, plugin_id: str, image_type: str, images_dir: str, max_retries=3):
    """
    Fetch image with proper extension detection and save locally

    Args:
        url: Image URL
        plugin_id: Plugin ID for filename
        image_type: 'icon' or 'screenshot'
        images_dir: Directory to save images
        max_retries: Number of retry attempts

    Returns:
        Local file path if successful, None otherwise
    """
    for attempt in range(max_retries):
        try:
            headers = {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'User-Agent': 'Mozilla/5.0 (compatible; PluginStatsBot/1.0)'
            }
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            # Get extension from Content-Type header
            content_type = response.headers.get('Content-Type', '')
            ext = get_image_extension(url, content_type)

            # Build filename and path
            filename = f"{plugin_id}_{image_type}{ext}"
            save_path = os.path.join(images_dir, filename)

            # Get content
            new_content = response.content
            new_hash = hashlib.md5(new_content).hexdigest()

            # Check if file exists and compare hash
            if os.path.exists(save_path):
                with open(save_path, 'rb') as f:
                    old_hash = hashlib.md5(f.read()).hexdigest()

                if old_hash == new_hash:
                    print(f"  ↪ Unchanged: {filename}")
                    return save_path

            # Create directory if needed
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Save the file
            with open(save_path, 'wb') as f:
                f.write(new_content)

            print(f"  ✓ Updated: {filename} ({content_type or 'unknown type'})")
            return save_path

        except requests.RequestException as e:
            if attempt < max_retries - 1:
                print(f"  ⚠️  Retry {attempt + 1}/{max_retries - 1} for {image_type}")
            else:
                print(f"  ✗ Failed to download {image_type} after {max_retries} attempts: {e}")
                return None

    return None


def fetch_plugin_data(plugin_id: str, max_retries=3):
    """Fetch plugin data from TRMNL API with retry logic"""
    url = f"https://trmnl.com/recipes/{plugin_id}.json"

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                print(f"  ⚠️  Retry {attempt + 1}/{max_retries - 1} for plugin data")
            else:
                print(f"  ✗ HTTP Error fetching plugin data after {max_retries} attempts: {e}")
                return None
        except ValueError as e:
            print(f"  ✗ JSON parsing error for plugin {plugin_id}: {e}")
            print(f"  Response content: {response.text[:200]}...")
            return None

    return None


def process_plugin_images(plugin_id: str, plugin_data: dict, images_dir: str):
    """Download plugin images and return local paths"""
    if not plugin_data:
        return None

    plugin = plugin_data.get('data', {})

    # Get image URLs
    icon_url = plugin.get('icon_url', '')
    screenshot_url = plugin.get('screenshot_url', '')

    local_paths = {
        'icon': None,
        'screenshot': None
    }

    download_success = True

    # Download icon
    if icon_url:
        icon_path = fetch_and_save_image(icon_url, plugin_id, 'icon', images_dir)
        if icon_path:
            local_paths['icon'] = icon_path
        else:
            download_success = False

    # Download screenshot
    if screenshot_url:
        screenshot_path = fetch_and_save_image(screenshot_url, plugin_id, 'screenshot', images_dir)
        if screenshot_path:
            local_paths['screenshot'] = screenshot_path
        else:
            download_success = False

    return local_paths if download_success else None


def generate_plugin_section(data, plugin_id: str, image_paths: dict):
    """Generate markdown section for a plugin"""
    if not data:
        markdown = f"""
## 🔒 Plugin ID: {plugin_id}

**Status**: ⏳ Not yet published on TRMNL or API unavailable

This plugin is configured but either hasn't been published to the TRMNL marketplace yet or the API is temporarily unavailable.

**Plugin URL**: https://trmnl.com/recipes/{plugin_id}

---
"""
        return markdown

    plugin = data.get('data', {})

    if not plugin:
        markdown = f"""
## 🔒 Plugin ID: {plugin_id}

**Status**: ⏳ Plugin data incomplete

The plugin exists but data is not available yet. This usually means it's very new or still being processed.

**Plugin URL**: https://trmnl.com/recipes/{plugin_id}

---
"""
        return markdown

    stats = plugin.get('stats', {})

    # Use local image paths or fallback to original URLs
    icon_path = image_paths.get('icon') if image_paths else plugin.get('icon_url', '')
    screenshot_path = image_paths.get('screenshot') if image_paths else plugin.get('screenshot_url', '')

    name = plugin.get('name', 'Unknown Plugin')
    description = plugin.get('author_bio', {}).get('description', 'No description available')
    installs = stats.get('installs', 0)
    forks = stats.get('forks', 0)

    markdown = f"""
## <img src="{icon_path}" alt="{name} icon" width="32"/> [{name}](https://trmnl.com/recipes/{plugin_id})

![{name} screenshot]({screenshot_path})

### Description
{description}

### 📊 Statistics

| Metric | Value |
|--------|-------|
| Installs | {installs:,} |
| Forks | {forks:,} |

---
"""
    return markdown


def update_readme(plugin_sections: str, section_title: str):
    """Update README.md with plugin statistics"""
    try:
        with open('README.md', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        content = "# Project README\n\n"

    start_marker = "<!-- PLUGIN_STATS_START -->"
    end_marker = "<!-- PLUGIN_STATS_END -->"

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    new_content = f"{start_marker}\n## {section_title}\n\n*Last updated: {timestamp}*\n\n{plugin_sections}\n{end_marker}"

    if start_marker in content and end_marker in content:
        pattern = f"{re.escape(start_marker)}.*?{re.escape(end_marker)}"
        updated_content = re.sub(pattern, new_content, content, flags=re.DOTALL)
    else:
        updated_content = content + "\n\n" + new_content + "\n"

    with open('README.md', 'w') as f:
        f.write(updated_content)


def main():
    """Main execution function"""
    config = load_plugin_config()
    plugin_ids = config['plugin_ids']
    section_title = config['section_title']
    images_dir = config['images_dir']

    if not plugin_ids:
        print("❌ No plugin IDs found in plugins.env")
        return

    print(f"📋 Tracking {len(plugin_ids)} plugins: {', '.join(plugin_ids)}")
    print(f"📁 Images will be saved to: {images_dir}\n")

    plugin_sections = []
    total = len(plugin_ids)

    published_plugins = 0
    unpublished_plugins = 0
    failed_downloads = []

    for idx, plugin_id in enumerate(plugin_ids, 1):
        print(f"🔍 [{idx}/{total}] Processing plugin: {plugin_id}")

        data = fetch_plugin_data(plugin_id)

        image_paths = None
        if data and data.get('data'):
            image_paths = process_plugin_images(plugin_id, data, images_dir)
            if image_paths:
                published_plugins += 1
                print(f"  ✓ Plugin processed successfully")
            else:
                published_plugins += 1
                failed_downloads.append(plugin_id)
                print(f"  ⚠️  Plugin found but image downloads failed")
        else:
            unpublished_plugins += 1
            if data and not data.get('data'):
                print(f"  ⚠️  Plugin exists but data is incomplete")
            else:
                print(f"  ⏳ Plugin not published yet or API error")

        section = generate_plugin_section(data, plugin_id, image_paths)
        plugin_sections.append(section)
        print()

    all_sections = "\n".join(plugin_sections)
    update_readme(all_sections, section_title)

    print("✅ README.md updated successfully with plugin statistics!")
    print(f"📊 Summary:")
    print(f"   Published plugins: {published_plugins}")
    print(f"   Unpublished/Error plugins: {unpublished_plugins}")
    if failed_downloads:
        print(f"   ⚠️  Failed image downloads for: {', '.join(failed_downloads)}")
    print(f"📸 Images saved to: {images_dir}/")


if __name__ == "__main__":
    main()