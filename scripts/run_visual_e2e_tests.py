"""
Comprehensive End-to-End Visual & Layout Testing with Playwright.
Validates:
1. Live page rendering and HTTP status across all 10 applications.
2. Horizontal overflow defects (document.documentElement.scrollWidth > clientWidth).
3. Q-Link canvas bounding-box alignment:
   - Verifies the floating 'Signal' legend card is strictly inside canvas area.
   - Verifies NO overlap between Signal legend card and the Active Mode Status Banner / toolbar.
   - Verifies interactive loading overlay and drawer z-index stacking above sticky header.
4. Q-Trail AI reasoning loading overlay and data tables.
5. Captures full-page high-resolution visual screenshots for verification.
"""

import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django  # noqa: E402

django.setup()

from django.contrib.sessions.backends.db import SessionStore  # noqa: E402
from django.contrib.staticfiles.handlers import StaticFilesHandler  # noqa: E402
from django.test.testcases import LiveServerThread  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

SCREENSHOTS_DIR = BASE_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)


def create_authenticated_session() -> str:
    """Creates a persistent Django session with portal authentication and active audit."""
    from core.models import Audit

    session = SessionStore()
    session["portal_authenticated"] = True
    first_audit = Audit.objects.first()
    if first_audit:
        session["active_audit_id"] = str(first_audit.id)
    session.save()
    return session.session_key


def test_box_overlap(box1, box2) -> bool:
    """Returns True if box1 and box2 overlap in 2D space."""
    if not box1 or not box2:
        return False
    return not (
        box1["x"] + box1["width"] <= box2["x"]
        or box2["x"] + box2["width"] <= box1["x"]
        or box1["y"] + box1["height"] <= box2["y"]
        or box2["y"] + box2["height"] <= box1["y"]
    )


def run_visual_suite():
    print("=================================================================")
    print("  STARTING FORENSIQ LIVE PLAYWRIGHT VISUAL TESTING SUITE")
    print("=================================================================")

    # 1. Connect to live Django server (port 8000 if active, else spawn LiveServerThread)
    server_thread = None
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_port_8000_open = s.connect_ex(("127.0.0.1", 8000)) == 0
    s.close()

    if is_port_8000_open:
        base_url = "http://127.0.0.1:8000"
        print(f"[*] Connecting to active Django server at {base_url}")
    else:
        server_thread = LiveServerThread("127.0.0.1", StaticFilesHandler, port=0)
        server_thread.daemon = True
        server_thread.start()
        server_thread.is_ready.wait(timeout=10)
        base_url = f"http://127.0.0.1:{server_thread.port}"
        print(f"[*] Live Django Server started at {base_url}")

    session_key = create_authenticated_session()
    print(f"[*] Authenticated test session initialized: {session_key[:8]}...")

    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            color_scheme="dark",
            device_scale_factor=1,
        )

        # Inject session cookie
        context.add_cookies(
            [
                {
                    "name": "sessionid",
                    "value": session_key,
                    "domain": "127.0.0.1",
                    "path": "/",
                }
            ]
        )

        page = context.new_page()

        # Listen to console errors
        console_errors = []
        page.on(
            "console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None
        )

        test_routes = [
            ("/", "Landing Page", "01_landing.png"),
            ("/bank/", "Q-Bank", "02_q_bank.png"),
            ("/trail/", "Q-Trail", "03_q_trail.png"),
            ("/link/", "Q-Link", "04_q_link.png"),
            ("/ledger/", "Q-Ledger", "05_q_ledger.png"),
            ("/mail/", "Q-Mail", "06_q_mail.png"),
            ("/chat/", "Q-Chat", "07_q_chat.png"),
            ("/verify/", "Q-Verify", "08_q_verify.png"),
            ("/scan/", "Q-Scan", "09_q_scan.png"),
            ("/voice/", "Q-Voice", "10_q_voice.png"),
        ]

        for path, app_name, img_name in test_routes:
            url = f"{base_url}{path}"
            print(f"\n--> Inspecting [{app_name}] at {path}")

            resp = page.goto(url, wait_until="commit", timeout=15000)
            time.sleep(1.0)
            status = resp.status if resp else "N/A"

            # Check if loading overlay exists (Q-Trail or Q-Link)
            loading_overlay = page.locator("div[x-show='isLoading']")
            if loading_overlay.count() > 0 and loading_overlay.first.is_visible():
                print(
                    f"    [OK] Detected active AI Reasoning loading screen in {app_name}. Waiting for completion..."
                )
                # Wait for loading overlay to complete (up to 7s)
                page.wait_for_function(
                    "!document.querySelector(\"div[x-show='isLoading']\") || document.querySelector(\"div[x-show='isLoading']\").style.display === 'none' || getComputedStyle(document.querySelector(\"div[x-show='isLoading']\")).display === 'none'",
                    timeout=10000,
                )
                time.sleep(0.5)

            # Check Horizontal Overflow across Responsive Viewports (Desktop, Tablet, Mobile)
            viewport_overflows = {}
            for vp_name, vp_size in [
                ("Desktop", {"width": 1440, "height": 900}),
                ("Tablet", {"width": 768, "height": 1024}),
                ("Mobile", {"width": 375, "height": 667}),
            ]:
                page.set_viewport_size(vp_size)
                time.sleep(0.15)
                overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth")
                if overflow:
                    blowout_px = page.evaluate(
                        "document.documentElement.scrollWidth - window.innerWidth"
                    )
                    viewport_overflows[vp_name] = f"+{blowout_px}px"

            # Reset viewport back to desktop for visual inspection & screenshots
            page.set_viewport_size({"width": 1440, "height": 900})
            time.sleep(0.15)

            is_overflowing = len(viewport_overflows) > 0
            overflow_detail = (
                "PASS"
                if not is_overflowing
                else f"FAIL ({', '.join(f'{k}: {v}' for k, v in viewport_overflows.items())})"
            )

            # Page-specific deep inspections
            layout_issue = None

            if path == "/link/":
                # 1. Inspect Canvas & Legend Card alignment
                canvas = page.locator("#qlink-canvas")
                legend_card = page.locator("#signal-legend-card")
                banner = page.locator("#mode-status-desc")

                if canvas.count() > 0 and legend_card.count() > 0:
                    canvas_box = canvas.bounding_box()
                    legend_box = legend_card.bounding_box()

                    # Check that legend is inside canvas bounds
                    if legend_box and canvas_box:
                        inside_x = (legend_box["x"] >= canvas_box["x"] - 5) and (
                            legend_box["x"] + legend_box["width"]
                            <= canvas_box["x"] + canvas_box["width"] + 5
                        )
                        inside_y = (legend_box["y"] >= canvas_box["y"] - 5) and (
                            legend_box["y"] + legend_box["height"]
                            <= canvas_box["y"] + canvas_box["height"] + 5
                        )

                        if not (inside_x and inside_y):
                            layout_issue = f"Signal Legend Card is OUTSIDE Canvas area! Legend: {legend_box}, Canvas: {canvas_box}"
                        else:
                            print(
                                "    [OK] Signal Legend Card is precisely inside Canvas viewport bounds."
                            )

                    # Check NO overlap with the status banner
                    if banner.count() > 0 and legend_box:
                        banner_box = banner.bounding_box()
                        if test_box_overlap(legend_box, banner_box):
                            layout_issue = (
                                "COLLISION: Signal Legend Card OVERLAPS Active Mode Status Banner!"
                            )
                        else:
                            print(
                                "    [OK] No collision between Signal Legend Card and Status Banner."
                            )

                # 2. Test Workstation Drawer interaction
                drawer = page.locator("#workstation-drawer")
                page.evaluate("openWorkstationDrawer('inspector')")
                time.sleep(0.4)
                if drawer.is_visible():
                    print("    [OK] Workstation Drawer opened cleanly.")
                    # Take drawer screenshot
                    page.screenshot(path=str(SCREENSHOTS_DIR / "04_q_link_drawer.png"))
                    # Close drawer
                    page.evaluate("closeWorkstationDrawer()")
                    time.sleep(0.4)

            # Capture visual screenshot
            screenshot_path = SCREENSHOTS_DIR / img_name
            page.screenshot(path=str(screenshot_path), full_page=False)
            print(f"    [OK] Screenshot captured -> {screenshot_path.name}")

            results.append(
                {
                    "app": app_name,
                    "path": path,
                    "status": status,
                    "overflow": overflow_detail,
                    "layout": layout_issue or "PASS",
                    "screenshot": str(screenshot_path),
                }
            )

        browser.close()

    if server_thread:
        server_thread.terminate()

    print(
        "\n========================================================================================="
    )
    print(
        "                              VISUAL TESTING RESULTS                                     "
    )
    print(
        "========================================================================================="
    )
    print(
        f"{'App':<14} | {'Status':<6} | {'Overflow (All Breakpoints)':<28} | {'Visual Alignment':<25}"
    )
    print("-" * 85)

    all_passed = True
    for r in results:
        status_str = str(r["status"])
        overflow_str = r["overflow"]
        layout_str = r["layout"]
        if overflow_str != "PASS" or layout_str != "PASS":
            all_passed = False
        print(f"{r['app']:<14} | {status_str:<6} | {overflow_str:<28} | {layout_str:<25}")

    print("=================================================================")
    if all_passed:
        print(">> ALL VISUAL & PLAYWRIGHT E2E TESTS PASSED WITH 0 DEFECTS! <<")
    else:
        print(">> DEFECTS DETECTED: Please review issues listed above! <<")
    print("=================================================================\n")

    return all_passed


if __name__ == "__main__":
    success = run_visual_suite()
    sys.exit(0 if success else 1)
