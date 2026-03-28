#!/usr/bin/env python3
"""
generate.py - Creates embed pages for Discord.

1. Drop files into raw/
2. python generate.py
3. git add -A && git commit -m "add" && git push

Links will be: yourdomain.com/coolpic
"""

import os, mimetypes

# ============================================================
# SET YOUR GITHUB PAGES URL
# ============================================================
BASE_URL = "https://YOURUSERNAME.github.io/YOURREPO"
# ============================================================

RAW_DIR = "raw"
VIDEO_EXTS = {".mp4", ".webm", ".mov"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}
ALLOWED = VIDEO_EXTS | IMAGE_EXTS

def main():
    os.makedirs(RAW_DIR, exist_ok=True)
    files = [f for f in os.listdir(RAW_DIR) if os.path.splitext(f)[1].lower() in ALLOWED]

    if not files:
        print("No media files in raw/")
        return

    for filename in files:
        name, ext = os.path.splitext(filename)
        ext = ext.lower()
        is_video = ext in VIDEO_EXTS
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        raw_url = f"{BASE_URL}/raw/{filename}"

        if is_video:
            og = f'''    <meta property="og:type" content="video.other"/>
    <meta property="og:video" content="{raw_url}"/>
    <meta property="og:video:url" content="{raw_url}"/>
    <meta property="og:video:secure_url" content="{raw_url}"/>
    <meta property="og:video:type" content="{mime}"/>
    <meta property="og:video:width" content="1280"/>
    <meta property="og:video:height" content="720"/>
    <meta name="twitter:card" content="player"/>
    <meta name="twitter:player" content="{raw_url}"/>'''
        else:
            og = f'''    <meta property="og:type" content="website"/>
    <meta property="og:image" content="{raw_url}"/>
    <meta property="og:image:url" content="{raw_url}"/>
    <meta property="og:image:secure_url" content="{raw_url}"/>
    <meta property="og:image:type" content="{mime}"/>
    <meta property="og:image:width" content="1280"/>
    <meta property="og:image:height" content="720"/>
    <meta name="twitter:card" content="summary_large_image"/>
    <meta name="twitter:image" content="{raw_url}"/>'''

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <meta property="og:title" content=" "/>
    <meta property="og:description" content=" "/>
    <meta property="og:site_name" content="media"/>
    <meta name="theme-color" content="#000000"/>
{og}
    <meta http-equiv="refresh" content="0;url={raw_url}"/>
    <style>body{{background:#000;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}}</style>
</head>
<body></body>
</html>'''

        # Create folder with index.html so GitHub Pages serves it at /name
        folder = os.path.join(".", name)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "index.html"), "w") as f:
            f.write(html)

        print(f"  ✓ {filename}")
        print(f"    link: {BASE_URL}/{name}")
        print()

    print(f"Done. git add -A && git commit -m 'add' && git push")

if __name__ == "__main__":
    main()
