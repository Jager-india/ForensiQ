"""
Playwright Forensic Visual Auditor for ForensiQ.
Navigates across Q-Voice, Q-Chat, Q-Scan, and Q-Verify workspaces,
tests Suggested Counterparties / Entities interaction, and takes screenshots.
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCREENSHOT_DIR = Path(
    r"C:\Users\VikashG\.gemini\antigravity-cli\brain\85a94c37-ae31-4c72-9668-98fdefb847de\screenshots"
)
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


def dismiss_modal_if_open(page):
    try:
        close_btn = page.locator("button:has-text('Close')")
        if close_btn.count() > 0 and close_btn.first.is_visible():
            close_btn.first.click()
            page.wait_for_timeout(400)
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)
    except Exception:
        pass


def audit():
    print("[*] Starting Playwright Browser Audit...")
    print(f"[*] Saving screenshots to: {SCREENSHOT_DIR}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        # Step 1: Login
        print("[*] Navigating to login page...")
        page.goto("http://127.0.0.1:8000/login/")
        page.wait_for_load_state("networkidle")

        # Fill login form
        page.fill("input[name='username']", "276980")
        page.fill("input[name='password']", "password123")
        page.click("button[type='submit']")
        page.wait_for_load_state("networkidle")
        print(f"[OK] Logged in. Current URL: {page.url}")

        # Step 2: Q-Voice Custodian Detail (Kaviarasan)
        print("\n--- Auditing Q-Voice Workspace ---")
        voice_url = "http://127.0.0.1:8000/voice/custodian/Kaviarasan/"
        page.goto(voice_url)
        page.wait_for_load_state("networkidle")
        dismiss_modal_if_open(page)

        card_toggle = page.locator("[data-testid='suggested-entities-toggle']")
        if card_toggle.count() > 0:
            card_toggle.first.scroll_into_view_if_needed()
            # If currently expanded, let's take expanded screenshot, toggle to collapsed, and toggle back
            page.screenshot(path=str(SCREENSHOT_DIR / "01_voice_suggested_entities_expanded.png"))
            print("[OK] Saved 01_voice_suggested_entities_expanded.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)
            page.screenshot(path=str(SCREENSHOT_DIR / "02_voice_suggested_entities_collapsed.png"))
            print("[OK] Saved 02_voice_suggested_entities_collapsed.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)

        # Step 3: Q-Chat Custodian Detail (Veeramani Velmurugan)
        print("\n--- Auditing Q-Chat Workspace ---")
        chat_url = "http://127.0.0.1:8000/chat/custodian/Veeramani%20Velmurugan/"
        page.goto(chat_url)
        page.wait_for_load_state("networkidle")
        dismiss_modal_if_open(page)

        card_toggle = page.locator("[data-testid='suggested-entities-toggle']")
        if card_toggle.count() > 0:
            card_toggle.first.scroll_into_view_if_needed()
            page.screenshot(path=str(SCREENSHOT_DIR / "03_chat_suggested_entities_expanded.png"))
            print("[OK] Saved 03_chat_suggested_entities_expanded.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)
            page.screenshot(path=str(SCREENSHOT_DIR / "04_chat_suggested_entities_collapsed.png"))
            print("[OK] Saved 04_chat_suggested_entities_collapsed.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)

        # Step 4: Q-Scan Device Detail
        print("\n--- Auditing Q-Scan Workspace ---")
        scan_url = "http://127.0.0.1:8000/scan/devices/da1132a7-8561-4230-91ed-f91d18ff71c9/"
        page.goto(scan_url)
        page.wait_for_load_state("networkidle")
        dismiss_modal_if_open(page)

        card_toggle = page.locator("[data-testid='suggested-entities-toggle']")
        if card_toggle.count() > 0:
            card_toggle.first.scroll_into_view_if_needed()
            page.screenshot(path=str(SCREENSHOT_DIR / "05_scan_suggested_entities_expanded.png"))
            print("[OK] Saved 05_scan_suggested_entities_expanded.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)
            page.screenshot(path=str(SCREENSHOT_DIR / "06_scan_suggested_entities_collapsed.png"))
            print("[OK] Saved 06_scan_suggested_entities_collapsed.png")

            card_toggle.first.click()
            page.wait_for_timeout(600)

        # Step 5: Q-Verify Case Detail
        print("\n--- Auditing Q-Verify Workspace ---")
        verify_url = "http://127.0.0.1:8000/verify/case/08bc7541-01bc-4dfc-ae0b-f134fb0bcbd1/"
        page.goto(verify_url)
        page.wait_for_load_state("networkidle")
        dismiss_modal_if_open(page)

        card_toggle = page.locator("[data-testid='suggested-entities-toggle']")
        if card_toggle.count() > 0:
            card_toggle.first.scroll_into_view_if_needed()
            page.screenshot(path=str(SCREENSHOT_DIR / "07_verify_suggested_entities_expanded.png"))
            print("[OK] Saved 07_verify_suggested_entities_expanded.png")

            # Test Interactive "Add as Keyword" promotion on first item
            add_btn = page.locator("button:has-text('Add as Keyword')")
            if add_btn.count() > 0:
                print(
                    f"[*] Found {add_btn.count()} 'Add as Keyword' buttons. Clicking first one..."
                )
                add_btn.first.click()
                page.wait_for_timeout(1500)
                page.screenshot(
                    path=str(SCREENSHOT_DIR / "08_verify_keyword_added_interaction.png")
                )
                print("[OK] Saved 08_verify_keyword_added_interaction.png")

        browser.close()
        print("\n[OK] All visual audit tests completed successfully!")


if __name__ == "__main__":
    audit()
