# ruff: noqa: E402
import os
import sys
from pathlib import Path

import django

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")
django.setup()

import pypdf

from core.entity_extractor import extract_entities_from_text

TESTING_ROOT = Path(r"C:\Users\VikashG\Downloads\Testing")

print("=" * 75)
print("  REAL-WORLD EXTRACTION TEST SUITE ON REAL FORENSIC CASE EVIDENCE")
print("=" * 75)

# Case 2: Real Partnership Deed
print("\n--- 1. REAL CASE 2: Partnership_Deed.pdf ---")
deed_path = TESTING_ROOT / "case 2" / "Partnership_Deed.pdf"
reader = pypdf.PdfReader(deed_path)
deed_text = "\n".join(p.extract_text() for p in reader.pages)
ents_deed = extract_entities_from_text(
    deed_text, source_context="Partnership Deed", custodian_name="Maharajan"
)
print(f"[✓] Discovered {len(ents_deed)} entities from actual deed:")
for e in ents_deed:
    print(
        f"    * {e['name']:<25} | Category: {e['category']:<12} | Role: {e['role']:<25} | Count: {e['count']}"
    )

# Case 1.b: Real WhatsApp Chat Export
print("\n--- 2. REAL CASE 1.b: WhatsApp_Chat_Export.txt ---")
chat_path = TESTING_ROOT / "case 1.b" / "WhatsApp_Chat_Export.txt"
with open(chat_path, encoding="utf-8") as f:
    chat_text = f.read()
ents_chat = extract_entities_from_text(
    chat_text, source_context="WhatsApp Chat", custodian_name="Veeramani Velmurugan"
)
print(f"[✓] Discovered {len(ents_chat)} entities from actual WhatsApp chat export:")
for e in ents_chat:
    print(
        f"    * {e['name']:<25} | Category: {e['category']:<12} | Role: {e['role']:<25} | Count: {e['count']}"
    )

# Case 1: Real Nominee Schedule
print("\n--- 3. REAL CASE 1: Sanitized_Employee_and_Nominee_Schedule.pdf ---")
sched_path = TESTING_ROOT / "case 1" / "Sanitized_Employee_and_Nominee_Schedule.pdf"
sched_reader = pypdf.PdfReader(sched_path)
sched_text = "\n".join(p.extract_text() for p in sched_reader.pages)
ents_sched = extract_entities_from_text(
    sched_text, source_context="Nominee Schedule", custodian_name="Veeramani Velmurugan"
)
print(f"[✓] Discovered {len(ents_sched)} entities from actual Nominee Schedule:")
for e in ents_sched:
    print(
        f"    * {e['name']:<25} | Category: {e['category']:<12} | Role: {e['role']:<25} | Count: {e['count']}"
    )

print("\n" + "=" * 75)
print("  REAL-WORLD EXTRACTION COMPLETED SUCCESSFULLY!")
print("=" * 75)
