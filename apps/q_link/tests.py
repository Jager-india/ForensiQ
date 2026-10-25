"""
Q-Link Comprehensive Test Suite
Validates entity resolution, RapidFuzz fuzzy alias matching,
event ingestion, graph pathfinding, risk alerts, LLM tool execution, and REST APIs.
"""

import json
import uuid

from django.test import Client, TestCase
from django.utils import timezone

from .backend.dispatcher import emit_forensic_finding
from .backend.llm_agent import ForensicCopilotAgent, ForensicToolRegistry
from .models import (
    EntityAlias,
    EvidencePointer,
    ForensicEntity,
    ForensicTimelineEvent,
    RelationshipAlert,
)
from .selectors import (
    find_paths_between,
)
from .services import (
    clean_entity_name,
    create_or_update_relationship,
    evaluate_relationship_risks,
    normalize_identifier,
    record_timeline_event,
    resolve_or_create_entity,
)


class QLinkEntityResolutionTests(TestCase):
    """Tests normalization and fuzzy alias resolution."""

    def test_clean_entity_name(self):
        self.assertEqual(clean_entity_name("ABC Enterprises Pvt Ltd"), "ABC")
        self.assertEqual(clean_entity_name("Global Logistics Solutions LLP"), "GLOBAL LOGISTICS")

    def test_normalize_identifier(self):
        self.assertEqual(
            normalize_identifier("user@example.com", "EMAIL_ID"), "EMAIL:user@example.com"
        )
        self.assertEqual(normalize_identifier("HDFC-123-456", "BANK_ACCOUNT"), "ACC:HDFC123456")

    def test_fuzzy_alias_matching(self):
        # 1. Create canonical vendor
        v1, created1 = resolve_or_create_entity(
            "ABC Enterprises Pvt Ltd", ForensicEntity.EntityType.VENDOR
        )
        self.assertTrue(created1)

        # 2. Ingest variant spelling
        v2, created2 = resolve_or_create_entity(
            "A.B.C. Enterprises", ForensicEntity.EntityType.VENDOR
        )
        self.assertFalse(created2)
        self.assertEqual(v1.id, v2.id)

        # Check alias recorded
        self.assertTrue(
            EntityAlias.objects.filter(entity=v1, alias_name="A.B.C. Enterprises").exists()
        )


class QLinkGraphAndEventDispatcherTests(TestCase):
    """Tests decoupled event ingestion and graph traversal."""

    def setUp(self):
        self.emp, _ = resolve_or_create_entity(
            "Target Custodian A",
            ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
        )
        self.vendor, _ = resolve_or_create_entity(
            "Apex Global Supplies",
            ForensicEntity.EntityType.VENDOR,
        )

    def test_emit_forensic_finding(self):
        primary, rels = emit_forensic_finding(
            source_module="q_bank",
            event_type="BANK_TRANSFER",
            primary_entity_data={
                "name": "Target Custodian A",
                "type": ForensicEntity.EntityType.EMPLOYEE,
            },
            secondary_entities_data=[
                {
                    "name": "Apex Global Supplies",
                    "type": ForensicEntity.EntityType.VENDOR,
                    "relation_type": "TRANSFERRED_FUNDS",
                    "weight": 500000.0,
                }
            ],
            evidence_data={
                "source_module": "q_bank",
                "source_model": "BankTransaction",
                "source_record_id": "TXN-999",
                "evidence_url": "/bank/account/1/",
                "summary_snippet": "Transfer ₹5,00,000",
            },
            timeline_title="Bank Transfer ₹5,00,000",
            severity="WARNING",
        )

        self.assertEqual(primary.id, self.emp.id)
        self.assertEqual(len(rels), 1)
        self.assertTrue(EvidencePointer.objects.filter(source_record_id="TXN-999").exists())
        self.assertTrue(ForensicTimelineEvent.objects.filter(entity=self.emp).exists())

    def test_multi_hop_pathfinding(self):
        # Create chain: Emp -> Vendor -> Conduit Co -> Target Z
        conduit, _ = resolve_or_create_entity(
            "Conduit Shell Ltd", ForensicEntity.EntityType.COMPANY
        )
        final_dest, _ = resolve_or_create_entity(
            "Offshore Corp Z", ForensicEntity.EntityType.COMPANY
        )

        create_or_update_relationship(self.emp, self.vendor, "ISSUED_PO", source_module="q_ledger")
        create_or_update_relationship(
            self.vendor, conduit, "TRANSFERRED_FUNDS", source_module="q_bank"
        )
        create_or_update_relationship(conduit, final_dest, "CONDUIT_TO", source_module="q_trail")

        paths = find_paths_between(str(self.emp.id), str(final_dest.id), max_hops=4)
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0]), 3)

    def test_automated_risk_alert(self):
        # Linking across 3 modules triggers Multi-Tool Correlation Alert
        e2, _ = resolve_or_create_entity("Partner B", ForensicEntity.EntityType.COMPANY)
        e3, _ = resolve_or_create_entity("Partner C", ForensicEntity.EntityType.COMPANY)
        e4, _ = resolve_or_create_entity("Partner D", ForensicEntity.EntityType.COMPANY)

        create_or_update_relationship(self.emp, e2, "EMAILED", source_module="q_mail")
        create_or_update_relationship(self.emp, e3, "ISSUED_PO", source_module="q_ledger")
        create_or_update_relationship(self.emp, e4, "TRANSFERRED_FUNDS", source_module="q_bank")

        evaluate_relationship_risks(self.emp)
        self.assertTrue(RelationshipAlert.objects.filter(primary_entity=self.emp).exists())


class QLinkAgentToolCallingTests(TestCase):
    """Tests the LLM tool calling registry and execution."""

    def setUp(self):
        self.emp, _ = resolve_or_create_entity(
            "Arun Kumar", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.vendor, _ = resolve_or_create_entity("Alpha Traders", ForensicEntity.EntityType.VENDOR)
        create_or_update_relationship(
            self.emp, self.vendor, "TRANSFERRED_FUNDS", weight=100000.0, source_module="q_bank"
        )
        record_timeline_event(
            self.emp, "Fund Transfer", "Transferred ₹1,00,000", timezone.now(), "q_bank"
        )

    def test_tool_definitions(self):
        defs = ForensicToolRegistry.get_tool_definitions()
        self.assertGreaterEqual(len(defs), 4)

    def test_tool_execution(self):
        res = ForensicToolRegistry.execute_tool(
            "get_entity_network", {"entity_name": "Arun Kumar", "max_hops": 2}
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target_entity"], "Arun Kumar")
        self.assertEqual(res["connected_nodes_count"], 2)

        # Test find_paths_between
        res_paths = ForensicToolRegistry.execute_tool(
            "find_paths_between",
            {"source_name": "Arun Kumar", "target_name": "Alpha Traders", "max_hops": 3},
        )
        self.assertEqual(res_paths["status"], "success")

        # Test get_entity_timeline
        res_time = ForensicToolRegistry.execute_tool(
            "get_entity_timeline", {"entity_name": "Arun Kumar"}
        )
        self.assertEqual(res_time["status"], "success")

        # Test get_evidence_details
        res_ev = ForensicToolRegistry.execute_tool(
            "get_evidence_details", {"entity_name": "Arun Kumar"}
        )
        self.assertEqual(res_ev["status"], "success")

        # Test error paths
        err_res = ForensicToolRegistry.execute_tool("unknown_tool", {})
        self.assertEqual(err_res["status"], "error")

    def test_copilot_agent_fallback(self):
        agent = ForensicCopilotAgent()
        out = agent.analyze_investigative_query("Investigate Arun Kumar")
        self.assertIn(out.get("mode"), ("agentic_tool_calling", "llm_offline"))
        self.assertTrue(len(out["response"]) > 0)

    def test_copilot_agent_offline_fallback(self):
        agent = ForensicCopilotAgent()
        agent.endpoint = "http://127.0.0.1:9999/unreachable"
        agent.timeout = 0.5
        out = agent.analyze_investigative_query("Investigate Arun Kumar")
        self.assertEqual("llm_offline", out.get("mode"))
        self.assertIn("offline", out["response"].lower())

    def test_copilot_agent_no_entities(self):
        # When querying in an empty state with no matches
        agent = ForensicCopilotAgent()
        from q_link.models import ForensicEntity

        original_entities = list(ForensicEntity.objects.all())
        ForensicEntity.objects.all().delete()
        try:
            out = agent.analyze_investigative_query("Nonexistent Query")
            self.assertEqual("entity_not_found", out.get("mode"))
            self.assertIn("No matching forensic entity found", out["response"])
        finally:
            ForensicEntity.objects.bulk_create(original_entities)


class QLinkAPITests(TestCase):
    """Tests Q-Link view endpoints."""

    def setUp(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        self.user = User.objects.create_user(username="testuser_api", password="password123")
        self.client = Client()
        self.client.force_login(self.user)
        # Set session master portal auth
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.emp, _ = resolve_or_create_entity(
            "Investigative Subject", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )

    def test_dashboard_view(self):
        resp = self.client.get("/link/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Q-Link")

    def test_api_network(self):
        resp = self.client.get("/link/api/network/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("nodes", data)

        # Query specific entity network
        resp2 = self.client.get(f"/link/api/network/?entity_id={self.emp.id}&max_hops=1")
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["status"], "success")

    def test_api_entity_detail(self):
        resp = self.client.get(f"/link/api/entity/{self.emp.id}/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["entity"]["name"], "Investigative Subject")

        # Entity not found
        resp_404 = self.client.get(f"/link/api/entity/{uuid.uuid4()}/")
        self.assertEqual(resp_404.status_code, 404)

    def test_api_copilot_chat(self):
        resp = self.client.post(
            "/link/api/copilot/",
            data=json.dumps({"query": "Investigate Subject"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("response", data)

    def test_api_sync_and_alert_ack(self):
        # Test manual sync API
        sync_resp = self.client.post("/link/api/sync/")
        self.assertEqual(sync_resp.status_code, 200)
        sync_data = sync_resp.json()
        self.assertEqual(sync_data["status"], "success")
        self.assertIn("stats", sync_data)

        # Create alert and test acknowledgement
        alert = RelationshipAlert.objects.create(
            primary_entity=self.emp,
            title="Suspicious Loop Detected",
            alert_level=RelationshipAlert.AlertLevel.HIGH,
            risk_score=85,
            trigger_reason="Circular flow between Subject and Vendor",
        )
        ack_resp = self.client.post(f"/link/api/alert/{alert.id}/ack/")
        self.assertEqual(ack_resp.status_code, 200)
        self.assertEqual(ack_resp.json()["status"], "success")
        alert.refresh_from_db()
        self.assertTrue(alert.is_acknowledged)

        # Acknowledge non-existent alert
        ack_404 = self.client.post(f"/link/api/alert/{uuid.uuid4()}/ack/")
        self.assertEqual(ack_404.status_code, 404)

    def test_api_copilot_chat_errors(self):
        # Empty query
        res_empty = self.client.post(
            "/link/api/copilot/",
            data=json.dumps({"query": "  "}),
            content_type="application/json",
        )
        self.assertEqual(res_empty.status_code, 400)
        self.assertIn("Query cannot be empty", res_empty.json()["message"])

        # Invalid JSON
        res_bad = self.client.post(
            "/link/api/copilot/",
            data=b"not-a-valid-json{",
            content_type="application/json",
        )
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn("Invalid JSON format", res_bad.json()["message"])

        # 500 Exception path in copilot chat
        from unittest.mock import patch

        with patch.object(
            ForensicCopilotAgent,
            "analyze_investigative_query",
            side_effect=RuntimeError("AI Crash"),
        ):
            res_500 = self.client.post(
                "/link/api/copilot/",
                data=json.dumps({"query": "Crash Test"}),
                content_type="application/json",
            )
            self.assertEqual(res_500.status_code, 500)

        # 500 Exception path in sync modules
        with patch("q_link.views.sync_all_modules", side_effect=RuntimeError("Sync Crash")):
            res_sync_500 = self.client.post("/link/api/sync/")
            self.assertEqual(res_sync_500.status_code, 500)


class QLinkSyncAllTests(TestCase):
    """Tests the sync_all_modules ingestion engine across models."""

    def test_sync_all_execution(self):
        from decimal import Decimal

        from django.apps import apps

        from .backend.sync_all import sync_all_modules

        # Create Q-Ledger PO
        VendorMaster = apps.get_model("q_ledger", "VendorMaster")
        PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")
        vendor = VendorMaster.objects.create(vendor_code="V-TEST-99", vendor_name="Alpha Tech Corp")
        PurchaseOrder.objects.create(
            vendor=vendor,
            po_number="PO-TEST-100",
            total_amount=Decimal("150000.00"),
            approved_by="Jane Doe",
            po_date=timezone.now(),
        )

        # Create Q-Trail path
        FundTrailPath = apps.get_model("q_trail", "FundTrailPath")
        FundTrailPath.objects.create(
            source_entity="Source Company A",
            destination_entity="Dest Vendor B",
            hop_count=2,
            total_amount=Decimal("500000.00"),
            intermediate_hops=[{"entity": "Conduit Intermediary X", "amount": 500000.0}],
            is_circular=False,
        )

        # Create Q-Bank transaction
        AuditedPerson = apps.get_model("q_bank", "AuditedPerson")
        BankAccount = apps.get_model("q_bank", "BankAccount")
        BankTransaction = apps.get_model("q_bank", "BankTransaction")
        person = AuditedPerson.objects.create(full_name="Target Custodian A")
        account = BankAccount.objects.create(
            person=person,
            account_number="1122334455",
            bank_name="Global Trust",
        )
        BankTransaction.objects.create(
            account=account,
            txn_date="2026-03-01T10:00:00Z",
            narration="TRANSFER TO Apex Logistics",
            direction=BankTransaction.Direction.DEBIT,
            debit_amount=Decimal("50000.00"),
        )

        # Create Q-Mail message
        MailboxInvestigation = apps.get_model("q_mail", "MailboxInvestigation")
        EmailMessage = apps.get_model("q_mail", "EmailMessage")
        inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-SYNC-01",
            audit_name="Audit Sync Case",
            auditee_name="Jane Doe",
            auditee_email="jane@company.com",
            pst_file_name="sync.pst",
        )
        EmailMessage.objects.create(
            mailbox=inv,
            subject="Invoice approval discussion",
            sender_name="Jane Doe",
            sender_email="jane@company.com",
            recipients_to=["vendor@apex.com"],
            body_plain="Approved the $50000 payout to Apex Logistics",
        )

        # Create Q-Verify case & document
        VerificationCase = apps.get_model("q_verify", "VerificationCase")
        VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")
        case = VerificationCase.objects.create(
            case_ref="VER-SYNC-01",
            case_title="Vendor Verification Check",
            custodian_name="Jane Doe",
            custodian_department="Procurement",
        )
        VerifiedDocument.objects.create(
            case=case,
            filename="tampered_po.pdf",
            authenticity_score=40,
            risk_level="HIGH",
        )

        counts = sync_all_modules()
        self.assertIsInstance(counts, dict)
        self.assertGreaterEqual(counts["q_ledger"], 1)
        self.assertGreaterEqual(counts["q_trail"], 1)
        self.assertGreaterEqual(counts["q_bank"], 1)
        self.assertGreaterEqual(counts["q_mail"], 1)
        self.assertGreaterEqual(counts["q_verify"], 1)


class QLinkDeepCoverageTests(TestCase):
    """Deep edge-case coverage for selectors and services to guarantee >=90% CI threshold."""

    def test_selectors_and_services_branches(self):
        from .selectors import (
            find_paths_between,
            get_entity_by_id,
            get_entity_network,
            get_recent_alerts,
        )
        from .services import acknowledge_alert, normalize_identifier, resolve_or_create_entity

        # Normalization edge cases
        self.assertEqual(
            normalize_identifier("+91-98765-43210", ForensicEntity.EntityType.PHONE),
            "PHONE:919876543210",
        )
        self.assertEqual(
            normalize_identifier("PO 12345", ForensicEntity.EntityType.PO), "PO:PO12345"
        )
        self.assertEqual(
            normalize_identifier("INV 9988", ForensicEntity.EntityType.INVOICE), "INV:INV9988"
        )

        # Entity target promotion
        e, _ = resolve_or_create_entity(
            "Promote Target", ForensicEntity.EntityType.EMPLOYEE, is_target=False
        )
        self.assertFalse(e.is_target)
        e2, _ = resolve_or_create_entity(
            "Promote Target", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.assertTrue(e2.is_target)

        # Non-existent lookups
        self.assertIsNone(get_entity_by_id("non-existent-uuid"))
        net = get_entity_network("non-existent-uuid")
        self.assertEqual(net["nodes"], [])
        self.assertFalse(acknowledge_alert("non-existent-uuid"))

        # Model querying
        entities = ForensicEntity.objects.filter(
            display_name__icontains="Promote",
            entity_type=ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
        )
        self.assertGreaterEqual(entities.count(), 1)

        # Same entity pathfinding
        paths = find_paths_between(str(e.id), str(e.id))
        self.assertEqual(paths, [])

        # Recent alerts unacknowledged
        alerts = get_recent_alerts(unacknowledged_only=True)
        self.assertIsNotNone(alerts)


class QLinkAuditScopingTests(TestCase):
    """Tests for Q-Link audit scoping and scope toggle between audit and all profiles."""

    def setUp(self):
        from django.contrib.auth import get_user_model

        from core.audits import create_audit
        from core.models import InvestigationProfile

        User = get_user_model()
        self.user = User.objects.create_user(username="testuser_scope", password="password123")
        self.client.force_login(self.user)

        self.prof1 = InvestigationProfile.objects.create(
            full_name="Vikash Subject Alpha",
            employee_id="EMP-LK1",
            department="Procurement",
        )
        self.prof2 = InvestigationProfile.objects.create(
            full_name="Raja Subject Beta",
            employee_id="EMP-LK2",
            department="Finance",
        )

        self.e1, _ = resolve_or_create_entity(
            "Vikash Subject Alpha", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.e2, _ = resolve_or_create_entity(
            "Raja Subject Beta", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.e3, _ = resolve_or_create_entity(
            "Unrelated Vendor Omega", ForensicEntity.EntityType.VENDOR, is_target=False
        )

        self.audit = create_audit(
            title="Q-Link Target Audit",
            profile_ids=[str(self.prof1.id), str(self.prof2.id)],
        )

    def test_get_graph_overview_scoped_by_filter_names(self):
        from .selectors import get_graph_overview

        # Scoped overview
        graph = get_graph_overview(filter_names=["Vikash Subject Alpha"])
        node_labels = [n["label"] for n in graph["nodes"]]
        self.assertIn("Vikash Subject Alpha", node_labels)
        self.assertNotIn("Unrelated Vendor Omega", node_labels)

        # Global overview
        all_graph = get_graph_overview()
        all_labels = [n["label"] for n in all_graph["nodes"]]
        self.assertIn("Vikash Subject Alpha", all_labels)
        self.assertIn("Unrelated Vendor Omega", all_labels)

    def test_dashboard_view_audit_scope_and_toggle(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session["active_audit_id"] = str(self.audit.id)
        session["active_audit_name"] = self.audit.name
        session.save()

        # 1. Scope audit
        res_audit = self.client.get(reverse("q_link:dashboard") + "?scope=audit")
        self.assertEqual(res_audit.status_code, 200)
        self.assertEqual(res_audit.context["scope"], "audit")
        target_names = [p.full_name for p in self.audit.profiles.all()]
        self.assertIn("Vikash Subject Alpha", target_names)

        # 2. Scope all
        res_all = self.client.get(reverse("q_link:dashboard") + "?scope=all")
        self.assertEqual(res_all.status_code, 200)
        self.assertEqual(res_all.context["scope"], "all")


class QLinkThreeOperationalModesTests(TestCase):
    """
    Tests for the 3 Operational Modes:
    - Mode 1: Keyword Network
    - Mode 2: Full Audit Topology
    - Mode 3: Global Vault Match
    """

    def setUp(self):
        from core.audits import create_audit
        from core.models import InvestigationProfile

        self.prof_a = InvestigationProfile.objects.create(
            full_name="Maharajan",
            keywords=["Partnership", "Contract", "Chennai"],
            is_substantiated=False,
        )
        self.prof_b = InvestigationProfile.objects.create(
            full_name="Dhanasekaran",
            keywords=["Associate", "Substantiated"],
            is_substantiated=True,
        )
        self.audit = create_audit(
            title="Forensic Audit Beta",
            profile_ids=[str(self.prof_a.id), str(self.prof_b.id)],
        )

        self.ent_a, _ = resolve_or_create_entity(
            "Maharajan", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.ent_b, _ = resolve_or_create_entity(
            "Dhanasekaran",
            ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
            metadata={"is_substantiated": True},
        )
        self.ent_ext, _ = resolve_or_create_entity(
            "Metec Global Outside Audit",
            ForensicEntity.EntityType.COMPANY,
            is_target=False,
        )

        # Connect internal entities
        self.rel, _ = create_or_update_relationship(
            self.ent_a,
            self.ent_b,
            relation_type="PARTNER",
            weight=100000.0,
            source_module="core",
        )
        record_timeline_event(
            self.ent_a,
            "Partnership Deed Signatory",
            "Dhanasekaran identified as Partner in deed",
            timezone.now(),
            "q_scan",
            relationship=self.rel,
        )

    def test_mode1_keyword_graph(self):
        from .selectors import get_mode1_keyword_graph

        res = get_mode1_keyword_graph(audit_id=str(self.audit.id), keyword="Partnership")
        self.assertEqual(res["mode"], "keyword")
        self.assertEqual(res["keyword"], "Partnership")
        self.assertGreaterEqual(len(res["nodes"]), 1)
        node_labels = [n["label"] for n in res["nodes"]]
        self.assertIn("Maharajan", node_labels)
        # Verify external entity from outside the audit is excluded
        self.assertNotIn("Metec Global Outside Audit", node_labels)

    def test_mode1_keyword_graph_audit_scoping_and_star_topology(self):
        from .selectors import get_mode1_keyword_graph

        # Add counterparties to active audit target
        cp1, _ = resolve_or_create_entity("EPALANI", ForensicEntity.EntityType.VENDOR)
        cp2, _ = resolve_or_create_entity("SILVIYAJ", ForensicEntity.EntityType.VENDOR)
        rel_bank, _ = create_or_update_relationship(
            self.ent_a, cp1, relation_type="TRANSFERRED_FUNDS", source_module="q_bank"
        )
        EvidencePointer.objects.create(
            relationship=rel_bank,
            source_module="q_bank",
            source_model="BankTransaction",
            source_record_id="TX-101",
            summary_snippet="NEFT payment to EPALANI",
        )
        rel_trail, _ = create_or_update_relationship(
            self.ent_a, cp2, relation_type="RAPID_LAYERING", source_module="q_trail"
        )
        EvidencePointer.objects.create(
            relationship=rel_trail,
            source_module="q_trail",
            source_model="MoneyTrailHop",
            source_record_id="TR-202",
            summary_snippet="Rapid turnaround layering with SILVIYAJ",
        )

        res = get_mode1_keyword_graph(audit_id=str(self.audit.id), keyword="")
        self.assertEqual(res["mode"], "keyword")
        node_labels = {n["label"] for n in res["nodes"]}

        # 1. Scope: Active audit auditees and verified counterparties included, external excluded
        self.assertIn("Maharajan", node_labels)
        self.assertIn("EPALANI", node_labels)
        self.assertIn("SILVIYAJ", node_labels)
        self.assertNotIn("Metec Global Outside Audit", node_labels)

        # 2. Star Topology: every edge must connect to an auditee (ent_a or ent_b)
        target_ids = {str(self.ent_a.id), str(self.ent_b.id)}
        for edge in res["edges"]:
            self.assertTrue(
                edge["source"] in target_ids or edge["target"] in target_ids,
                f"Edge {edge} violates star topology (connects two non-target counterparties)",
            )

        # 3. Tool prefix on edge labels: instead of 'Keyword: name', shows originating tool 'Bank: name' / 'Trail: name'
        labels = [e["label"] for e in res["edges"]]
        self.assertTrue(
            any(lbl.startswith("Bank:") for lbl in labels), f"No Bank: label in {labels}"
        )
        self.assertTrue(
            any(lbl.startswith("Trail:") for lbl in labels), f"No Trail: label in {labels}"
        )
        self.assertFalse(
            any(lbl.startswith("Keyword:") for lbl in labels),
            f"Unexpected generic Keyword: label in {labels}",
        )

    def test_mode2_audit_graph(self):
        from .selectors import get_mode2_audit_graph

        res = get_mode2_audit_graph(audit_id=str(self.audit.id))
        self.assertEqual(res["mode"], "audit")
        node_labels = [n["label"] for n in res["nodes"]]
        self.assertIn("Maharajan", node_labels)
        self.assertIn("Dhanasekaran", node_labels)

        # Verify Dhanasekaran has Substantiated tag
        dhan_node = next(n for n in res["nodes"] if n["label"] == "Dhanasekaran")
        self.assertIn("Substantiated", dhan_node["tags"])

        # Check edge
        self.assertGreaterEqual(len(res["edges"]), 1)
        first_edge = res["edges"][0]
        self.assertIn("from", first_edge)
        self.assertIn("to", first_edge)
        self.assertIn("source", first_edge)
        self.assertIn("target", first_edge)

    def test_2_hop_document_nexus_mode1_and_mode2(self):
        from .selectors import get_mode1_keyword_graph, get_mode2_audit_graph

        # 1. Setup Document intermediary node
        doc_ent, _ = resolve_or_create_entity(
            "Partnership_Deed.pdf", ForensicEntity.EntityType.DOCUMENT
        )
        cp_partner, _ = resolve_or_create_entity("Venkatesan C", ForensicEntity.EntityType.EMPLOYEE)

        # Hop 1: Auditee (Maharajan) -> Document
        rel_hop1, _ = create_or_update_relationship(
            self.ent_a,
            doc_ent,
            relation_type="DOCUMENT_ATTACHED",
            source_module="q_verify",
        )
        EvidencePointer.objects.create(
            relationship=rel_hop1,
            source_module="q_verify",
            source_model="VerifiedDocument",
            source_record_id="DOC-99",
            summary_snippet="Partnership_Deed.pdf attached to Maharajan",
        )

        # Hop 2: Document -> Partner (Venkatesan C)
        rel_hop2, _ = create_or_update_relationship(
            doc_ent,
            cp_partner,
            relation_type="PARTNER",
            source_module="q_verify",
        )
        EvidencePointer.objects.create(
            relationship=rel_hop2,
            source_module="q_verify",
            source_model="VerifiedDocument",
            source_record_id="DOC-99",
            summary_snippet="Partnership_Deed.pdf establishes partnership for Venkatesan C",
        )

        # Test Mode 1 without keyword: star topology with document bridge
        g1_star = get_mode1_keyword_graph(audit_id=str(self.audit.id), keyword="")
        labels1 = {n["label"] for n in g1_star["nodes"]}
        self.assertIn("Maharajan", labels1)
        self.assertIn("Partnership_Deed.pdf", labels1)
        self.assertIn("Venkatesan C", labels1)

        edges1 = [(e["source"], e["target"]) for e in g1_star["edges"]]
        self.assertIn((str(self.ent_a.id), str(doc_ent.id)), edges1)
        self.assertIn((str(doc_ent.id), str(cp_partner.id)), edges1)

        # Test Mode 1 with keyword search for counterparty name
        g1_kw = get_mode1_keyword_graph(audit_id=str(self.audit.id), keyword="Venkatesan C")
        labels_kw = {n["label"] for n in g1_kw["nodes"]}
        self.assertIn("Maharajan", labels_kw)
        self.assertIn("Partnership_Deed.pdf", labels_kw)
        self.assertIn("Venkatesan C", labels_kw)
        edges_kw = [(e["source"], e["target"]) for e in g1_kw["edges"]]
        self.assertIn((str(self.ent_a.id), str(doc_ent.id)), edges_kw)
        self.assertIn((str(doc_ent.id), str(cp_partner.id)), edges_kw)

        # Test Mode 2: Full Audit Topology includes 2-hop document nexus
        g2 = get_mode2_audit_graph(audit_id=str(self.audit.id))
        labels2 = {n["label"] for n in g2["nodes"]}
        self.assertIn("Maharajan", labels2)
        self.assertIn("Partnership_Deed.pdf", labels2)
        self.assertIn("Venkatesan C", labels2)
        edges2 = [(e["source"], e["target"]) for e in g2["edges"]]
        self.assertTrue(
            any(
                (e[0] == str(self.ent_a.id) and e[1] == str(doc_ent.id))
                or (e[1] == str(self.ent_a.id) and e[0] == str(doc_ent.id))
                for e in edges2
            )
        )
        self.assertTrue(
            any(
                (e[0] == str(doc_ent.id) and e[1] == str(cp_partner.id))
                or (e[1] == str(doc_ent.id) and e[0] == str(cp_partner.id))
                for e in edges2
            )
        )

    def test_mode3_global_graph(self):
        from .selectors import get_mode3_global_graph

        res = get_mode3_global_graph(audit_id=str(self.audit.id), query="Metec")
        self.assertEqual(res["mode"], "global")
        # Check that external entity exists and is marked is_external
        ext_nodes = [n for n in res["nodes"] if n["is_external"]]
        self.assertGreaterEqual(len(ext_nodes), 1)
        self.assertTrue(ext_nodes[0]["is_external"])
        self.assertIn("External Vault", ext_nodes[0]["tags"])


class QLinkEdgeEvidenceAndDrawerTests(TestCase):
    """
    Tests for granular edge evidence retrieval and interactive drawer API.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        self.user = User.objects.create_user(username="testuser_drawer", password="password123")
        self.client.force_login(self.user)

        self.e1, _ = resolve_or_create_entity("Mr. V", ForensicEntity.EntityType.EMPLOYEE)
        self.e2, _ = resolve_or_create_entity("Palani", ForensicEntity.EntityType.VENDOR)
        self.rel, _ = create_or_update_relationship(
            self.e1,
            self.e2,
            relation_type="RAPID_LAYERING",
            weight=250000.0,
            source_module="q_trail",
        )
        self.rel.metadata = {
            "is_rapid_layering": True,
            "turnaround": "3h 45m (< 24h)",
            "inflow_ref": "IMPS/9812",
            "outflow_ref": "NEFT/1102",
        }
        self.rel.save()

        self.ev_ptr = EvidencePointer.objects.create(
            relationship=self.rel,
            source_module="q_trail",
            source_model="MoneyTrailHop",
            source_record_id="HOP-001",
            summary_snippet="Rapid turnaround layering transfer from Mr. V to Palani",
            metadata={
                "amount": 250000.0,
                "narration": "IMPS Palani Turnaround",
                "ref_no": "IMPS/9812",
                "turnaround": "3h 45m (< 24h)",
                "is_rapid_layering": True,
            },
        )

    def test_get_edge_evidence_selector(self):
        from .selectors import get_edge_evidence

        ev = get_edge_evidence(str(self.rel.id))
        self.assertEqual(ev["status"], "success")
        self.assertEqual(ev["edge"]["source_name"], "Mr. V")
        self.assertEqual(ev["edge"]["target_name"], "Palani")
        self.assertTrue(ev["edge"]["is_rapid_layering"])
        self.assertEqual(len(ev["evidence_items"]), 1)
        item = ev["evidence_items"][0]
        self.assertEqual(item["amount"], 250000.0)
        self.assertEqual(item["turnaround"], "3h 45m (< 24h)")
        self.assertEqual(item["ref_no"], "IMPS/9812")

    def test_api_edge_detail_endpoint(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        url = reverse("q_link:api_edge_detail", kwargs={"edge_id": str(self.rel.id)})
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["edge"]["source_name"], "Mr. V")
        self.assertEqual(data["edge"]["target_name"], "Palani")
        self.assertTrue(data["edge"]["is_rapid_layering"])

    def test_api_entity_detail_evidence_metadata(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        url = reverse("q_link:api_entity_detail", kwargs={"entity_id": str(self.e1.id)})
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["entity"]["name"], "Mr. V")
        self.assertGreaterEqual(len(data["evidence"]), 1)
        ev_item = data["evidence"][0]
        self.assertIn("metadata", ev_item)
        self.assertEqual(ev_item["metadata"].get("turnaround"), "3h 45m (< 24h)")
        self.assertTrue(ev_item["metadata"].get("is_rapid_layering"))

    def test_dashboard_ui_revamp_elements(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        url = reverse("q_link:dashboard")
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        content = res.content.decode("utf-8")
        # Check modern card-node canvas & dot grid matrix
        self.assertIn('id="qlink-canvas"', content)
        self.assertIn("radial-gradient", content)
        # Check no split-screen layout (no 12-col screen split)
        self.assertNotIn("lg:grid-cols-12", content)
        # Check off-canvas workstation slide-over drawer
        self.assertIn('id="workstation-drawer"', content)
        self.assertIn("openWorkstationDrawer", content)
        # Check top bar header pills & badges
        self.assertIn("LIVE SYNC", content)
        self.assertIn("PRIORITY FLAGS", content)
        self.assertIn("High Risk Flow", content)
        self.assertIn("Full Audit Topology", content)
        # Check Archivus-style evidence reader drawer
        self.assertIn('id="evidence-reader-drawer"', content)
        self.assertIn('id="reader-spotlight-box"', content)
        self.assertIn("Flagged Evidence Excerpt", content)
        self.assertIn("openEvidenceReaderDrawer", content)
        # Check LLM-Style Interactive AI Loading Screen (Matching Q-Trail)
        self.assertIn("isLoading", content)
        self.assertIn("loadingSteps", content)
        self.assertIn("AI Reasoning Engine", content)
        self.assertIn("Synthesizing Intelligence Graph...", content)
        self.assertIn("Scanning Entities", content)
        self.assertIn("Correlating Edges", content)
        self.assertIn("Resolving Clusters", content)
        self.assertIn("Compiling Graph", content)
        self.assertIn("getRandomDuration", content)
        self.assertIn("runSequentialLoading", content)

    def test_q_link_sync_vendor_master_keyword_nexus(self):
        from django.apps import apps

        from .backend.sync_all import sync_all_modules
        from .models import EntityRelationship, ForensicEntity

        VendorMaster = apps.get_model("q_ledger", "VendorMaster")
        InvestigationProfile = apps.get_model("core", "InvestigationProfile")

        # 1. Create Investigation Profile with target keywords
        InvestigationProfile.objects.create(
            full_name="Maharajan",
            keywords=["Sri Mirra", "Kickback", "98765432100"],
        )

        # 2. Create Vendor Master matching one of the keywords
        vendor = VendorMaster.objects.create(
            vendor_code="V-NEXUS-01",
            vendor_name="Sri Mirra Engineers",
            bank_account_no="98765432100",
            is_flagged=False,
        )

        # 3. Run sync_all_modules
        counts = sync_all_modules()
        self.assertGreaterEqual(counts.get("q_ledger", 0), 1)

        # 4. Verify vendor record is flagged in database
        vendor.refresh_from_db()
        self.assertTrue(vendor.is_flagged)
        self.assertTrue(len(vendor.matched_keywords) > 0)

        # 5. Verify relationship created in Q-Link knowledge graph
        emp_entity = ForensicEntity.objects.filter(display_name="Maharajan").first()
        self.assertIsNotNone(emp_entity)
        vendor_entity = ForensicEntity.objects.filter(display_name="Sri Mirra Engineers").first()
        self.assertIsNotNone(vendor_entity)

        rel = EntityRelationship.objects.filter(
            source_entity=emp_entity,
            target_entity=vendor_entity,
            relation_type="EMPLOYEE_VENDOR_NEXUS",
        ).first()
        self.assertIsNotNone(rel)

    def test_vendor_bank_cross_reference_dual_financial_flows(self):
        """
        Verifies Vendor Master cross-referencing against BankTransaction records:
        1. Inflow credit creates VENDOR_KICKBACK_RECEIVED (Vendor -> Auditee).
        2. Outflow debit creates VENDOR_PAYOUT_DETECTED (Auditee -> Vendor).
        3. BankTransaction risk_level is elevated to High with risk_score >= 90.
        4. Graph edge formatting and get_edge_evidence return vendor metadata.
        """
        from django.apps import apps

        from .backend.sync_all import sync_all_modules
        from .models import EntityRelationship, ForensicEntity
        from .selectors import get_edge_evidence

        VendorMaster = apps.get_model("q_ledger", "VendorMaster")
        BankAccount = apps.get_model("q_bank", "BankAccount")
        BankTransaction = apps.get_model("q_bank", "BankTransaction")
        InvestigationProfile = apps.get_model("core", "InvestigationProfile")

        # Create Profile
        InvestigationProfile.objects.create(full_name="Pasupathy Target")

        # Create Vendor Master
        VendorMaster.objects.create(
            vendor_code="VM-8800",
            vendor_name="Apex Power Turbines",
            owner_name="Pasupathy",
            bank_account_no="1234567890",
            phone="9876543210",
        )

        # Create Bank Account and Transactions
        acc = BankAccount.objects.create(
            account_holder="Pasupathy Target",
            account_number="ACC-1111",
            bank_name="HDFC Bank",
        )

        # Credit: Vendor -> Auditee
        t_credit = BankTransaction.objects.create(
            account=acc,
            direction="IN",
            credit_amount=500000.0,
            debit_amount=0.0,
            narration="RTGS FROM APEX POWER TURBINES KICKBACK",
            party_name="Apex Power Turbines",
            risk_level="Low",
            risk_score=10,
        )

        # Debit: Auditee -> Vendor
        t_debit = BankTransaction.objects.create(
            account=acc,
            direction="OUT",
            debit_amount=200000.0,
            credit_amount=0.0,
            narration="NEFT TO PASUPATHY CONSULTING EXPENSES",
            party_name="Pasupathy",
            risk_level="Low",
            risk_score=10,
        )

        # Run sync
        sync_all_modules()

        # Verify transaction risk elevated
        t_credit.refresh_from_db()
        self.assertEqual(t_credit.risk_level, "High")
        self.assertEqual(t_credit.risk_score, 95)
        self.assertIn("Suspected Vendor Kickback", t_credit.flag_reason)

        t_debit.refresh_from_db()
        self.assertEqual(t_debit.risk_level, "High")
        self.assertEqual(t_debit.risk_score, 90)
        self.assertIn("Undisclosed Vendor Payment", t_debit.flag_reason)

        # Verify Q-Link relationships
        v_entity = ForensicEntity.objects.get(display_name="Apex Power Turbines")
        a_entity = ForensicEntity.objects.get(display_name="Pasupathy Target")

        kb_rel = EntityRelationship.objects.filter(
            source_entity=v_entity,
            target_entity=a_entity,
            relation_type="VENDOR_KICKBACK_RECEIVED",
        ).first()
        self.assertIsNotNone(kb_rel)
        self.assertEqual(kb_rel.weight, 500000.0)
        self.assertIn("[Kickback]", kb_rel.metadata.get("formatted_label", ""))

        po_rel = EntityRelationship.objects.filter(
            source_entity=a_entity,
            target_entity=v_entity,
            relation_type="VENDOR_PAYOUT_DETECTED",
        ).first()
        self.assertIsNotNone(po_rel)
        self.assertEqual(po_rel.weight, 200000.0)
        self.assertIn("[Payout]", po_rel.metadata.get("formatted_label", ""))

        # Verify get_edge_evidence
        ev_data = get_edge_evidence(str(kb_rel.id))
        self.assertEqual(ev_data["status"], "success")
        self.assertEqual(ev_data["edge"]["relation_type"], "VENDOR_KICKBACK_RECEIVED")
        self.assertEqual(ev_data["edge"]["metadata"]["vendor_code"], "VM-8800")


class QLinkKinshipAndRoleTests(TestCase):
    """
    Tests forensic Kinship relationships (Spouse, Nominee) and Organizational Roles
    in Q-Link graph serialization, APIs, and drawer dossiers.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        self.user = User.objects.create_user(username="kinship_analyst", password="password123")
        self.client = Client()
        self.client.force_login(self.user)
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.emp, _ = resolve_or_create_entity(
            "Raj Target",
            ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
        )
        self.nominee, _ = resolve_or_create_entity(
            "Monisha Spouse",
            ForensicEntity.EntityType.EMPLOYEE,
            metadata={
                "tags": ["Nominee", "Spouse / Wife"],
                "kinship": "Monisha is Spouse / Wife of Raj",
            },
        )
        self.vendor, _ = resolve_or_create_entity(
            "Hydro Pumps Ltd",
            ForensicEntity.EntityType.VENDOR,
        )
        self.contact, _ = resolve_or_create_entity(
            "Balamurugan Contact",
            ForensicEntity.EntityType.EMPLOYEE,
            metadata={
                "role": "Manager of Hydro Pumps Ltd",
                "tags": ["Manager", "Hydro Pumps Ltd"],
            },
        )

    def test_kinship_edge_and_node_formatting(self):
        from .selectors import _format_edge, _format_node, get_edge_evidence

        # Create Kinship relationship
        rel, ev_ptr = create_or_update_relationship(
            source_entity=self.emp,
            target_entity=self.nominee,
            relation_type="SPOUSE",
            metadata={
                "formatted_label": "Spouse / Wife",
                "relationship": "Monisha is Spouse / Wife of Raj",
                "inference": "Monisha is Spouse / Wife of Raj",
                "tags": ["Nominee", "Spouse / Wife"],
            },
            evidence_data={
                "source_module": "q_scan",
                "source_model": "FileEvidenceHit",
                "source_record_id": str(uuid.uuid4()),
                "summary_snippet": "Employee: Raj | Relationship: Spouse / Wife | Nominee: Monisha",
                "metadata": {
                    "file_name": "Insurance_Schedule.xlsx",
                    "inference": "Monisha is Spouse / Wife of Raj",
                },
            },
        )

        edge_data = _format_edge(rel)
        self.assertTrue(edge_data["is_kinship"])
        self.assertEqual(edge_data["label"], "Spouse / Wife")
        self.assertEqual(edge_data["inference"], "Monisha is Spouse / Wife of Raj")

        node_data = _format_node(self.nominee)
        self.assertIn("Spouse / Wife", node_data["tags"])
        self.assertEqual(node_data["kinship"], "Monisha is Spouse / Wife of Raj")

        ev_data = get_edge_evidence(str(rel.id))
        self.assertEqual(ev_data["status"], "success")
        self.assertTrue(ev_data["edge"]["is_kinship"])
        self.assertEqual(ev_data["evidence_items"][0]["file_name"], "Insurance_Schedule.xlsx")
        self.assertEqual(
            ev_data["evidence_items"][0]["inference"], "Monisha is Spouse / Wife of Raj"
        )

    def test_role_edge_and_node_formatting(self):
        from .selectors import _format_edge, _format_node

        rel, _ = create_or_update_relationship(
            source_entity=self.contact,
            target_entity=self.vendor,
            relation_type="ROLE_IN",
            metadata={
                "role": "Manager of Hydro Pumps Ltd",
                "formatted_label": "Manager of Hydro Pumps Ltd",
                "relationship": "Balamurugan is Manager of Hydro Pumps Ltd",
            },
        )

        edge_data = _format_edge(rel)
        self.assertTrue(edge_data["is_role"])
        self.assertEqual(edge_data["label"], "Manager of Hydro Pumps Ltd")

        node_data = _format_node(self.contact)
        self.assertIn("Manager of Hydro Pumps Ltd", node_data["tags"])
        self.assertEqual(node_data["role"], "Manager of Hydro Pumps Ltd")

    def test_api_entity_and_edge_detail(self):
        rel, _ = create_or_update_relationship(
            source_entity=self.emp,
            target_entity=self.nominee,
            relation_type="SPOUSE",
            metadata={
                "formatted_label": "Spouse / Wife",
                "relationship": "Monisha is Spouse / Wife of Raj",
            },
        )

        resp = self.client.get(f"/link/api/entity/{self.nominee.id}/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["entity"]["kinship"], "Monisha is Spouse / Wife of Raj")
        self.assertIn("Spouse / Wife", data["entity"]["tags"])
        self.assertTrue(len(data["incoming_relationships"]) > 0)
        self.assertEqual(data["incoming_relationships"][0]["type"], "SPOUSE")
        self.assertEqual(data["incoming_relationships"][0]["label"], "Spouse / Wife")

        resp_edge = self.client.get(f"/link/api/edge/{rel.id}/")
        self.assertEqual(resp_edge.status_code, 200)
        edge_data = resp_edge.json()
        self.assertTrue(edge_data["edge"]["is_kinship"])
        self.assertIn("Spouse / Wife", edge_data["edge"]["label"])
