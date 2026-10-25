#!/usr/bin/env python3
import hashlib
import os
import re
import sys
from pathlib import Path

import requests
import yaml

IMAGES_DIR = "assets/plugin-images"
SETTINGS_PATH = "plugin/src/settings.yml"
API_BASE = "https://trmnl.com/recipes"
BADGE_BASE = "https://trmnl-badges.gohk.xyz/badge"

CONTENT_TYPE_EXT = {
    "image/svg+xml": ".svg",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}


def load_plugin_id():
    with open(SETTINGS_PATH) as f:
        settings = yaml.safe_load(f)
    plugin_id = settings.get("id")
    if not plugin_id:
        sys.exit(f"No 'id' field found in {SETTINGS_PATH}")
    return str(plugin_id)


def ext_from_response(response, url):
    ct = response.headers.get("Content-Type", "").split(";")[0].strip()
    if ct in CONTENT_TYPE_EXT:
        return CONTENT_TYPE_EXT[ct]
    _, url_ext = os.path.splitext(url.split("?")[0])
    return url_ext or ".png"


def download_image(url, save_path):
    response = requests.get(url, timeout=15)
    response.raise_for_status()
    new_content = response.content
    if os.path.exists(save_path):
        with open(save_path, "rb") as f:
            if hashlib.md5(f.read()).hexdigest() == hashlib.md5(new_content).hexdigest():
                print(f"  unchanged: {os.path.basename(save_path)}")
                return
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(new_content)
    print(f"  updated: {os.path.basename(save_path)}")
    return response


def fetch_plugin(plugin_id):
    response = requests.get(f"{API_BASE}/{plugin_id}.json", timeout=10)
    response.raise_for_status()
    return response.json().get("data", {})


def build_section(plugin, plugin_id, icon_path, screenshot_path):
    name = plugin.get("name", "Unknown Plugin")
    description = plugin.get("author_bio", {}).get("description", "")
    return f"""## <img src="{icon_path}" alt="{name} icon" width="32"/> [{name}](https://trmnl.com/recipes/{plugin_id})

![Installs]({BADGE_BASE}/installs?recipe={plugin_id}) ![Forks]({BADGE_BASE}/forks?recipe={plugin_id})

![{name} screenshot]({screenshot_path})

### Description
{description}

---
"""


def update_readme(section):
    start = "<!-- PLUGIN_STATS_START -->"
    end = "<!-- PLUGIN_STATS_END -->"
    try:
        content = Path("README.md").read_text()
    except FileNotFoundError:
        content = "# Plugin\n\n"
    block = f"{start}\n{section}\n{end}"
    if start in content and end in content:
        updated = re.sub(
            f"{re.escape(start)}.*?{re.escape(end)}", block, content, flags=re.DOTALL
        )
    else:
        updated = content.rstrip() + "\n\n" + block + "\n"
    Path("README.md").write_text(updated)


def main():
    plugin_id = load_plugin_id()
    print(f"Plugin ID: {plugin_id}")

    plugin = fetch_plugin(plugin_id)
    if not plugin:
        print("Plugin not yet published — no data returned")
        update_readme(f"*Plugin {plugin_id} not yet published.*\n")
        return

    icon_url = plugin.get("icon_url", "")
    screenshot_url = plugin.get("screenshot_url", "")

    # Download icon
    icon_resp = requests.get(icon_url, timeout=15)
    icon_resp.raise_for_status()
    icon_ext = ext_from_response(icon_resp, icon_url)
    icon_path = f"{IMAGES_DIR}/{plugin_id}_icon{icon_ext}"
    os.makedirs(IMAGES_DIR, exist_ok=True)
    if not (os.path.exists(icon_path) and
            hashlib.md5(open(icon_path, "rb").read()).hexdigest() ==
            hashlib.md5(icon_resp.content).hexdigest()):
        open(icon_path, "wb").write(icon_resp.content)
        print(f"  updated: {os.path.basename(icon_path)}")
    else:
        print(f"  unchanged: {os.path.basename(icon_path)}")

    # Download screenshot
    shot_resp = requests.get(screenshot_url, timeout=15)
    shot_resp.raise_for_status()
    shot_ext = ext_from_response(shot_resp, screenshot_url)
    shot_path = f"{IMAGES_DIR}/{plugin_id}_screenshot{shot_ext}"
    if not (os.path.exists(shot_path) and
            hashlib.md5(open(shot_path, "rb").read()).hexdigest() ==
            hashlib.md5(shot_resp.content).hexdigest()):
        open(shot_path, "wb").write(shot_resp.content)
        print(f"  updated: {os.path.basename(shot_path)}")
    else:
        print(f"  unchanged: {os.path.basename(shot_path)}")

    section = build_section(plugin, plugin_id, icon_path, shot_path)
    update_readme(section)
    print("README.md updated")


if __name__ == "__main__":
    main()
