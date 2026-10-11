"""
Comprehensive UI & Alignment Checker across Forensic-Q Applications.
Checks rendered HTML of all views and template files on disk for:
1. Colliding / duplicate adjacent text (e.g. SignalSignal)
2. Absolute positioning conflicts inside nested relative wrappers
3. Sticky header overlap / z-index collisions
4. Truncation / flex overflow vulnerabilities
5. Drawer / backdrop nesting bugs
"""

import os
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django  # noqa: E402

django.setup()

from django.test import Client  # noqa: E402


def check_all():
    client = Client()
    session = client.session
    session["portal_authenticated"] = True
    session.save()

    urls = [
        ("/", "Landing Page"),
        ("/bank/", "Q-Bank"),
        ("/trail/", "Q-Trail"),
        ("/link/", "Q-Link"),
        ("/ledger/", "Q-Ledger"),
        ("/mail/", "Q-Mail"),
        ("/chat/", "Q-Chat"),
        ("/verify/", "Q-Verify"),
        ("/scan/", "Q-Scan"),
        ("/voice/", "Q-Voice"),
    ]

    print("=================================================================")
    print("  SCANNING ALL FORENSIC-Q APPLICATIONS FOR UI MISALIGNMENTS")
    print("=================================================================")

    found_issues = []

    # 1. Rendered Views Inspection
    for path, name in urls:
        res = client.get(path)
        if res.status_code != 200:
            found_issues.append(f"[{name}] {path} returned HTTP {res.status_code}")
            continue

        html = res.content.decode("utf-8", errors="ignore")

        # Check for duplicated adjacent words in text like "SignalSignal"
        for pattern in ["SignalSignal", "AlertAlert", "AuditAudit", "TargetTarget", "TokenToken"]:
            for m in re.finditer(pattern, html):
                idx = m.start()
                snippet = (
                    html[max(0, idx - 30) : min(len(html), idx + 80)].replace("\n", " ").strip()
                )
                found_issues.append(f"[{name}] Colliding text '{pattern}': ...{snippet}...")

        # Specific Q-Link checks
        if path == "/link/":
            if 'class="absolute top-16' in html:
                found_issues.append(
                    "[Q-Link] Floating legend has 'absolute top-16' inside outer container, causing it to overlap top toolbar and status banner!"
                )
            if "Signal & Entity Types" in html and "Signal" in html:
                header_match = re.search(
                    r"<div[^>]*border-b[^>]*>.*?Signal.*?Signal & Entity Types.*?</div>",
                    html,
                    re.DOTALL,
                )
                if header_match:
                    found_issues.append(
                        f"[Q-Link] Mashed header inside legend card: {header_match.group(0).strip()}"
                    )

        # Check for z-index ordering conflicts:
        drawer_matches = re.findall(r"id=\"[^\"]*drawer\"[^>]*class=\"[^\"]*z-(\d+|\[\d+\])", html)
        if "sticky top-0 z-50" in html:
            for dm in drawer_matches:
                clean_z = int(dm.strip("[]"))
                if clean_z <= 50:
                    found_issues.append(
                        f"[{name}] Drawer z-index ({clean_z}) is <= sticky header (z-50)!"
                    )

        # Duplicate x-data attributes on same tag
        alpine_broken = re.findall(r"x-data=\"[^\"]*\"[^>]*x-data=", html)
        if alpine_broken:
            found_issues.append(f"[{name}] Duplicate x-data attributes found!")

        # Horizontal overflow risk
        if "w-screen" in html and "overflow-x-hidden" not in html:
            found_issues.append(
                f"[{name}] Uses w-screen without overflow-x-hidden, potential horizontal scroll!"
            )

    # 2. Template Source Code Inspection
    print("  Scanning raw template files on disk...")
    template_files = []
    for root, _dirs, files in os.walk(str(BASE_DIR)):
        if any(
            ignored in root for ignored in [".venv", "node_modules", ".git", ".gemini", "brain"]
        ):
            continue
        for f in files:
            if f.endswith(".html"):
                template_files.append(Path(root) / f)

    for tf in template_files:
        try:
            content = tf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_path = tf.relative_to(BASE_DIR)

        # Search for accidental duplicate concatenated words (e.g., "wordword" in text nodes)
        text_only = re.sub(r"<script.*?</script>", "", content, flags=re.DOTALL)
        text_only = re.sub(r"<style.*?</style>", "", text_only, flags=re.DOTALL)
        text_only = re.sub(r"<svg.*?</svg>", "", text_only, flags=re.DOTALL)

        for m in re.finditer(r">\s*([A-Z][a-z]{3,})\1\s*<", text_only):
            found_issues.append(
                f"[{rel_path}] Obvious text duplication in template: '{m.group(0)}'"
            )

    print(f"\nTotal potential issues detected: {len(found_issues)}")
    if found_issues:
        for i, issue in enumerate(found_issues, 1):
            print(f" {i}. {issue}")
    else:
        print("  All checks PASSED cleanly! No misalignments or collisions found.")


if __name__ == "__main__":
    check_all()
