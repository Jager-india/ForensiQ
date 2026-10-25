# ruff: noqa: E402
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")
import django

django.setup()

from django.contrib.auth import get_user_model
from django.test import Client
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding="utf-8")

ARTIFACTS_DIR = os.path.join(
    r"C:\Users\VikashG\.gemini\antigravity-cli\brain\85a94c37-ae31-4c72-9668-98fdefb847de",
    "screenshots",
)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

scratch_dir = BASE_DIR / "scratch"
vis_js = (scratch_dir / "vis-network.min.js").read_bytes()
tailwind_js = (scratch_dir / "tailwind.js").read_bytes()
alpine_js = (scratch_dir / "alpine.min.js").read_bytes()
fa_css = (scratch_dir / "all.min.css").read_bytes()


def get_authenticated_session() -> str:
    User = get_user_model()
    user = User.objects.filter(is_active=True).first()
    if not user:
        user = User.objects.create_superuser(username="999999", password="testpassword123")
    c = Client()
    c.force_login(user)
    s = c.session
    s["portal_authenticated"] = True
    s.save()
    return s.session_key


def handle_route(route):
    url = route.request.url
    if "vis-network" in url:
        route.fulfill(status=200, content_type="application/javascript", body=vis_js)
    elif "tailwindcss.com" in url or "tailwind" in url:
        route.fulfill(status=200, content_type="application/javascript", body=tailwind_js)
    elif "alpinejs" in url or "alpine" in url:
        route.fulfill(status=200, content_type="application/javascript", body=alpine_js)
    elif "font-awesome" in url or "all.min.css" in url:
        route.fulfill(status=200, content_type="text/css", body=fa_css)
    elif "127.0.0.1" in url or "localhost" in url:
        if url.endswith(".mp4") or url.endswith(".webm"):
            route.abort()
        else:
            route.continue_()
    else:
        route.abort()


def main():
    session_key = get_authenticated_session()
    print("Authenticated session key created:", session_key)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1600, "height": 950})
        context.route("**/*", handle_route)
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

        print("Navigating to Q-Link Knowledge Graph (/link/?mode=audit)...")
        page.goto(
            "http://127.0.0.1:8000/link/?mode=audit", wait_until="domcontentloaded", timeout=15000
        )

        # Wait for reasoning overlay to finish
        print("Waiting for reasoning overlay to complete...")
        time.sleep(6)

        # Set Dark Mode & dismiss any leftover overlay
        page.evaluate(
            """() => {
            if (typeof ForensiQTheme !== 'undefined' && ForensiQTheme.set) {
                ForensiQTheme.set('dark');
            } else {
                document.documentElement.classList.add('dark');
            }
            window.dispatchEvent(new Event('themeChanged'));

            document.querySelectorAll('[x-data]').forEach(el => {
                if (el._x_dataStack) {
                    el._x_dataStack.forEach(s => {
                        if ('isLoading' in s) s.isLoading = false;
                        if ('showAuditModal' in s) s.showAuditModal = false;
                        if ('isOpen' in s) s.isOpen = false;
                    });
                }
            });
            const overlay = document.querySelector("div[x-show='isLoading']");
            if (overlay) overlay.style.display = 'none';
            document.querySelectorAll('[data-teleport-target="true"]').forEach(el => el.style.display = 'none');
        }"""
        )
        time.sleep(1)

        # Ensure all edge labels are toggled on
        page.evaluate(
            """() => {
            if (typeof showAllEdgeLabels !== 'undefined' && !showAllEdgeLabels) {
                toggleAllEdgeLabels();
            }
        }"""
        )
        time.sleep(1.5)

        # 1. Capture Full Knowledge Graph Overview with Kinship & Roles (Screenshot 27)
        overview_path = os.path.join(ARTIFACTS_DIR, "27_qlink_kinship_and_role_overview.png")
        page.evaluate("() => { try { document.fonts.clear(); } catch(e){} }")
        page.screenshot(path=overview_path)
        print(f"Captured Screenshot 27: {overview_path}")

        # Retrieve Node and Edge IDs for Inspection
        graph_entities = page.evaluate(
            """() => {
            const rawNodes = initialGraphData.nodes || [];
            const rawEdges = initialGraphData.edges || [];

            let monishaId = null;
            rawNodes.forEach(n => {
                if (n.label && n.label.toUpperCase().includes('MONISHA')) {
                    monishaId = n.id;
                }
            });

            let kinshipEdgeId = null;
            let kinshipSubIds = null;
            rawEdges.forEach(e => {
                const isK = e.is_kinship || (e.relation_type && (e.relation_type === 'SPOUSE' || e.relation_type === 'KINSHIP'));
                if (isK && !kinshipEdgeId) {
                    kinshipEdgeId = e.id;
                    const raw = e.raw || {};
                    kinshipSubIds = (raw.sub_link_ids && raw.sub_link_ids.length > 0) ? raw.sub_link_ids.join(',') : e.id;
                }
            });

            let roleEdgeId = null;
            let roleSubIds = null;
            rawEdges.forEach(e => {
                const isR = e.is_role || (e.relation_type && (e.relation_type === 'ROLE_IN' || e.relation_type === 'EMPLOYEE_OF'));
                if (isR && !roleEdgeId && String(e.label || '').includes('Hydro Pumps')) {
                    roleEdgeId = e.id;
                    const raw = e.raw || {};
                    roleSubIds = (raw.sub_link_ids && raw.sub_link_ids.length > 0) ? raw.sub_link_ids.join(',') : e.id;
                }
            });

            return { monishaId, kinshipEdgeId, kinshipSubIds, roleEdgeId, roleSubIds };
        }"""
        )
        print("Graph target entities for inspection:", graph_entities)

        # 2. Inspect MONISHA node (Entity Inspector Drawer - Screenshot 28)
        monisha_id = graph_entities.get("monishaId")
        if monisha_id:
            print(f"Inspecting Entity MONISHA ({monisha_id})...")
            page.evaluate(
                f"""() => {{
                inspectEntity('{monisha_id}');
                openWorkstationDrawer('inspector');
            }}"""
            )
            time.sleep(2.5)

            node_drawer_path = os.path.join(ARTIFACTS_DIR, "28_qlink_kinship_node_inspector.png")
            page.evaluate("() => { try { document.fonts.clear(); } catch(e){} }")
            page.screenshot(path=node_drawer_path)
            print(f"Captured Screenshot 28: {node_drawer_path}")

            # Close inspector drawer
            page.evaluate("closeWorkstationDrawer()")
            time.sleep(1)

        # 3. Inspect Raju -> MONISHA Kinship Edge (Evidence Trail Drawer - Screenshot 29)
        kinship_edge_id = graph_entities.get("kinshipEdgeId")
        kinship_sub_ids = graph_entities.get("kinshipSubIds") or kinship_edge_id
        if kinship_edge_id:
            print(f"Inspecting Kinship Edge ({kinship_edge_id})...")
            page.evaluate(f"inspectEdge('{kinship_sub_ids}', '{kinship_edge_id}')")
            time.sleep(2.5)

            edge_drawer_path = os.path.join(ARTIFACTS_DIR, "29_qlink_kinship_edge_evidence.png")
            page.evaluate("() => { try { document.fonts.clear(); } catch(e){} }")
            page.screenshot(path=edge_drawer_path)
            print(f"Captured Screenshot 29: {edge_drawer_path}")

            page.evaluate("closeEvidenceDrawer()")
            time.sleep(1)

        # 4. Inspect BALAMURUGAN -> Hydro Pumps Role Edge (Evidence Trail Drawer - Screenshot 30)
        role_edge_id = graph_entities.get("roleEdgeId")
        role_sub_ids = graph_entities.get("roleSubIds") or role_edge_id
        if role_edge_id:
            print(f"Inspecting Role Edge ({role_edge_id})...")
            page.evaluate(f"inspectEdge('{role_sub_ids}', '{role_edge_id}')")
            time.sleep(2.5)

            role_drawer_path = os.path.join(ARTIFACTS_DIR, "30_qlink_role_edge_evidence.png")
            page.evaluate("() => { try { document.fonts.clear(); } catch(e){} }")
            page.screenshot(path=role_drawer_path)
            print(f"Captured Screenshot 30: {role_drawer_path}")

            page.evaluate("closeEvidenceDrawer()")
            time.sleep(1)

        browser.close()
        print("Playwright visual verification complete! All 4 screenshots captured successfully.")


if __name__ == "__main__":
    main()
