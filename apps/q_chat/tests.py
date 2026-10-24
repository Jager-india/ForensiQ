import json
import uuid

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .backend.chat_parser import (
    parse_csv_export,
    parse_json_export,
    parse_whatsapp_export,
)
from .selectors import (
    get_all_custodian_profiles,
    get_chat_channel_by_id,
    get_chat_dashboard_metrics,
    get_chat_participants_summary,
    get_custodian_profile_detail,
    get_paginated_chat_messages,
)
from .services import ingest_chat_export_file


class QChatForensicTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        self.user = User.objects.create_user(username="chat_test_user", password="password")
        self.client.force_login(self.user)
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.raw_whatsapp = (
            "24/04/2024, 10:15 - Arun Kumar: Good morning team, please check the quote for tender L1.\n"
            "24/04/2024, 10:16 - Rajesh M: Received. Can we discuss the commission cut off the record?\n"
            "24/04/2024, 10:17 - Arun Kumar: <Media omitted>\n"
            "24/04/2024, 10:18 - Rajesh M: You deleted this message\n"
            "24/04/2024, 10:20 - Arun Kumar: Send cash payment details on personal account please.\n"
        )
        self.channel = ingest_chat_export_file(
            file_obj_or_content=self.raw_whatsapp,
            filename="whatsapp_export.txt",
            platform="WHATSAPP",
            channel_name="Procurement Tender Chat",
            custodian_name="Arun Kumar",
        )

    def test_whatsapp_ingestion(self):
        self.assertEqual(self.channel.total_messages, 5)
        self.assertEqual(self.channel.participant_count, 2)
        self.assertTrue(self.channel.flagged_messages_count >= 2)

        # Check deleted message flag
        deleted_msg = self.channel.messages.filter(is_deleted=True).first()
        self.assertIsNotNone(deleted_msg)
        self.assertEqual(deleted_msg.sender_name, "Rajesh M")

        # Check media attachment flag
        media_msg = self.channel.messages.filter(has_media=True).first()
        self.assertIsNotNone(media_msg)
        self.assertEqual(media_msg.media_type, "IMAGE")

    def test_json_ingestion(self):
        json_content = (
            '{"messages": ['
            '{"sender_name": "Supplier Lead", "sent_at": "2024-05-01T12:00:00Z", "message_text": "Here is the revised tender proposal"},'
            '{"sender_name": "Buyer", "sent_at": "2024-05-01T12:05:00Z", "message_text": "Ensure we get 10% cash discount off the record"}'
            "]}"
        )
        ch2 = ingest_chat_export_file(
            file_obj_or_content=json_content,
            filename="teams_export.json",
            platform="TEAMS",
            channel_name="Supplier Teams Thread",
        )
        self.assertEqual(ch2.total_messages, 2)
        self.assertTrue(ch2.flagged_messages_count >= 1)

    def test_selectors(self):
        metrics = get_chat_dashboard_metrics()
        self.assertGreaterEqual(metrics["total_channels"], 1)
        self.assertGreaterEqual(metrics["total_messages"], 5)

        participants = get_chat_participants_summary(self.channel.id)
        self.assertEqual(len(participants), 2)

        paginated = get_paginated_chat_messages(self.channel.id, page=1, page_size=10)
        self.assertEqual(paginated["total_count"], 5)

    def test_views_and_endpoints(self):
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        # Dashboard View
        r_dash = self.client.get(reverse("q_chat:dashboard"))
        self.assertEqual(r_dash.status_code, 200)

        # Channel Detail View
        r_detail = self.client.get(reverse("q_chat:channel_detail", args=[self.channel.id]))
        self.assertEqual(r_detail.status_code, 200)

        # Messages API View
        r_api = self.client.get(reverse("q_chat:messages_api", args=[self.channel.id]))
        self.assertEqual(r_api.status_code, 200)
        self.assertEqual(r_api.json()["total_count"], 5)

        # Delete Channel
        r_del = self.client.post(reverse("q_chat:delete_channel", args=[self.channel.id]))
        self.assertEqual(r_del.status_code, 302)
        self.assertIsNone(get_chat_channel_by_id(self.channel.id))

    def test_upload_chat_view_and_errors(self):
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        # 1. POST without file
        res_empty = self.client.post(reverse("q_chat:upload"), data={})
        self.assertEqual(res_empty.status_code, 302)

        # 2. POST with valid chat file
        chat_content = (
            b"25/04/2024, 11:00 - Manager: Please review the PO.\n"
            b"25/04/2024, 11:05 - Supplier: Approved, sending revised invoice.\n"
        )
        upload_file = SimpleUploadedFile("chat.txt", chat_content, content_type="text/plain")
        res_ok = self.client.post(
            reverse("q_chat:upload"),
            data={
                "chat_file": upload_file,
                "platform": "WHATSAPP",
                "channel_name": "PO Review",
                "custodian_name": "Manager",
            },
        )
        self.assertEqual(res_ok.status_code, 302)

        # 3. Channel Detail 404
        res_404 = self.client.get(reverse("q_chat:channel_detail", args=[uuid.uuid4()]))
        self.assertEqual(res_404.status_code, 404)

        # 4. Delete non-existent channel
        res_del_err = self.client.post(reverse("q_chat:delete_channel", args=[uuid.uuid4()]))
        self.assertEqual(res_del_err.status_code, 302)

    def test_chat_parser_extended_formats(self):
        # 1. parse_csv_export
        csv_sample = (
            "sender,message,date,has_media,media_type,filename,is_deleted,is_edited\n"
            "Alice,Here is the confidential invoice,2026-03-01T10:00:00,true,DOCUMENT,invoice.pdf,false,false\n"
            "Bob,Deleting my response now,invalid_date,false,NONE,,true,true\n"
        )
        csv_msgs = parse_csv_export(csv_sample)
        self.assertEqual(len(csv_msgs), 2)
        self.assertEqual(csv_msgs[0]["sender_name"], "Alice")
        self.assertTrue(csv_msgs[0]["has_media"])
        self.assertEqual(csv_msgs[0]["media_type"], "DOCUMENT")
        self.assertEqual(csv_msgs[0]["media_filename"], "invoice.pdf")
        self.assertTrue(csv_msgs[1]["is_deleted"])
        self.assertTrue(csv_msgs[1]["is_edited"])

        # 2. parse_whatsapp_txt with document, audio, and multi-line continuation
        wa_sample = (
            "20/05/2024, 09:00 - Sunil: Contract draft (file attached) settlement_v1.docx\n"
            "20/05/2024, 09:05 - David: audio omitted\n"
            "20/05/2024, 09:10 - Sunil: First line of proposal.\n"
            "Second line continuation of the proposal with kickback details.\n"
        )
        wa_msgs = parse_whatsapp_export(wa_sample)
        self.assertEqual(len(wa_msgs), 3)
        self.assertEqual(wa_msgs[0]["media_type"], "DOCUMENT")
        self.assertEqual(wa_msgs[0]["media_filename"], "settlement_v1.docx")
        self.assertEqual(wa_msgs[1]["media_type"], "AUDIO")
        self.assertIn("Second line continuation", wa_msgs[2]["message_text"])

        # 3. parse_json_export with unix timestamp, telegram rich text blocks, and invalid date
        json_sample = json.dumps(
            {
                "messages": [
                    {
                        "from": "UserA",
                        "ts": 1714560000,
                        "text": [{"text": "Telegram"}, " rich block"],
                    },
                    {"author": "UserB", "sent_at": "invalid-iso", "body": "Standard message"},
                ]
            }
        )
        json_msgs = parse_json_export(json_sample)
        self.assertEqual(len(json_msgs), 2)
        self.assertEqual(json_msgs[0]["sender_name"], "UserA")
        self.assertIn("Telegram", json_msgs[0]["message_text"])
        self.assertEqual(json_msgs[1]["sender_name"], "UserB")

    def test_system_disclaimer_and_chat_order(self):
        """
        Tests that WhatsApp disclaimers are recognized as system messages and that
        senders maintain consistent left vs right side alignment across multiple messages.
        """
        chat_content = (
            "[03/02/2026, 11:22:22] Arshita Intern HMIL: Good morning, Sir.\n"
            "[03/02/2026, 11:37:19] Messages and calls are end-to-end encrypted. Only people in this chat can read, listen to, or share them.\n"
            "[03/02/2026, 11:37:19] Arshita Intern HMIL is a contact.\n"
            "[03/02/2026, 13:25:31] Vikash G: Will let you know\n"
            "[03/02/2026, 13:53:14] Arshita Intern HMIL: Sure, Thank you!\n"
            "[03/02/2026, 13:53:20] Arshita Intern HMIL: Please keep me updated.\n"
            "[06/02/2026, 17:54:32] Vikash G: Hi can you send me your resume\n"
            "[06/02/2026, 17:54:40] Vikash G: Also send your portfolio.\n"
        )
        ch = ingest_chat_export_file(
            file_obj_or_content=chat_content,
            filename="_chat.txt",
            platform="WHATSAPP",
            channel_name="Interview Followup",
        )

        # System messages must NOT count as human participants
        self.assertEqual(ch.participant_count, 2)
        self.assertIn("Arshita Intern HMIL", ch.participants)
        self.assertIn("Vikash G", ch.participants)
        self.assertNotIn("System", ch.participants)

        # Retrieve messages
        paginated = get_paginated_chat_messages(ch.id, page=1, page_size=20)
        messages = paginated["data"]
        self.assertEqual(len(messages), 8)

        # Verify system messages
        sys_msgs = [m for m in messages if m["is_system"]]
        self.assertEqual(len(sys_msgs), 2)
        self.assertEqual(sys_msgs[0]["sender_name"], "System")
        self.assertIn("end-to-end encrypted", sys_msgs[0]["message_text"])
        self.assertEqual(sys_msgs[1]["sender_name"], "System")
        self.assertIn("is a contact", sys_msgs[1]["message_text"])

        # Verify sender side consistency
        # Person 1 (Arshita) must ALWAYS be on the left (is_right_side == False)
        # Person 2 (Vikash) must ALWAYS be on the right (is_right_side == True)
        arshita_msgs = [m for m in messages if m["sender_name"] == "Arshita Intern HMIL"]
        self.assertEqual(len(arshita_msgs), 3)
        for m in arshita_msgs:
            self.assertFalse(
                m["is_right_side"],
                f"Expected Arshita's message '{m['message_text']}' to be on the left",
            )

        vikash_msgs = [m for m in messages if m["sender_name"] == "Vikash G"]
        self.assertEqual(len(vikash_msgs), 3)
        for m in vikash_msgs:
            self.assertTrue(
                m["is_right_side"],
                f"Expected Vikash's message '{m['message_text']}' to be on the right",
            )

    def test_human_messages_with_system_phrases_not_hijacked(self):
        """
        Tests that human messages containing words like 'is a contact' or 'left the group'
        are retained as human messages and NOT converted into system messages.
        """
        chat_content = (
            "[03/02/2026, 10:10:00] Alice: Mr. Sharma is a contact person for the vendor.\n"
            "[03/02/2026, 10:11:00] Bob: Why have they left the group?\n"
            "[03/02/2026, 10:12:00] Messages and calls are end-to-end encrypted. Only people in this chat can read, listen to, or share them.\n"
            "[03/02/2026, 10:13:00] Arshita Intern HMIL is a contact.\n"
        )
        ch = ingest_chat_export_file(
            file_obj_or_content=chat_content,
            filename="false_positives_test.txt",
            platform="WHATSAPP",
            channel_name="Contact Discussion",
        )

        paginated = get_paginated_chat_messages(ch.id, page=1, page_size=10)
        msgs = paginated["data"]
        self.assertEqual(len(msgs), 4)

        # Message 1 from Alice
        self.assertEqual(msgs[0]["sender_name"], "Alice")
        self.assertFalse(msgs[0]["is_system"])
        self.assertEqual(msgs[0]["message_text"], "Mr. Sharma is a contact person for the vendor.")

        # Message 2 from Bob
        self.assertEqual(msgs[1]["sender_name"], "Bob")
        self.assertFalse(msgs[1]["is_system"])
        self.assertEqual(msgs[1]["message_text"], "Why have they left the group?")

        # Message 3: real encryption notice
        self.assertEqual(msgs[2]["sender_name"], "System")
        self.assertTrue(msgs[2]["is_system"])

        # Message 4: real contact notice
        self.assertEqual(msgs[3]["sender_name"], "System")
        self.assertTrue(msgs[3]["is_system"])

    def test_filtered_chat_messages(self):
        pag_search = get_paginated_chat_messages(self.channel.id, search="quote")
        self.assertEqual(pag_search["total_count"], 1)

        pag_sender = get_paginated_chat_messages(self.channel.id, sender="Rajesh M")
        self.assertEqual(pag_sender["total_count"], 2)

        pag_flagged = get_paginated_chat_messages(self.channel.id, flagged_only=True)
        self.assertGreaterEqual(pag_flagged["total_count"], 1)

        pag_media = get_paginated_chat_messages(self.channel.id, media_only=True)
        self.assertEqual(pag_media["total_count"], 1)

        pag_deleted = get_paginated_chat_messages(self.channel.id, deleted_only=True)
        self.assertEqual(pag_deleted["total_count"], 1)

    def test_custodian_profile_analysis_and_directory(self):
        # Ingest another chat under Arun Kumar
        extra_chat = (
            "25/04/2024, 14:00 - Arun Kumar: Following up on tender delivery.\n"
            "25/04/2024, 14:05 - Vendor Lead: Delivery scheduled for Friday.\n"
        )
        ingest_chat_export_file(
            file_obj_or_content=extra_chat,
            filename="tender_delivery.txt",
            platform="TEAMS",
            channel_name="Tender Delivery Followup",
            custodian_name="Arun Kumar",
        )

        # 1. Test get_all_custodian_profiles
        profiles = get_all_custodian_profiles()
        self.assertGreaterEqual(len(profiles), 1)
        arun_profile = next((p for p in profiles if p["custodian_name"] == "Arun Kumar"), None)
        self.assertIsNotNone(arun_profile)
        self.assertEqual(arun_profile["channels_count"], 2)
        self.assertEqual(arun_profile["total_messages"], 7)

        # 2. Test get_custodian_profile_detail
        arun_detail = get_custodian_profile_detail("Arun Kumar")
        self.assertEqual(arun_detail["channels_count"], 2)
        self.assertEqual(arun_detail["total_messages"], 7)

        # 3. Test combined messages
        combined_msgs = get_paginated_chat_messages(custodian_name="Arun Kumar")
        self.assertEqual(combined_msgs["total_count"], 7)

        # 4. Test custodian views
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        # Combined view
        res_view = self.client.get(reverse("q_chat:custodian_detail", args=["Arun Kumar"]))
        self.assertEqual(res_view.status_code, 200)

        # Scoped view
        res_scoped = self.client.get(
            reverse("q_chat:custodian_detail", args=["Arun Kumar"])
            + f"?channel_id={self.channel.id}"
        )
        self.assertEqual(res_scoped.status_code, 200)

        # Delete custodian
        res_del = self.client.post(reverse("q_chat:delete_custodian", args=["Arun Kumar"]))
        self.assertEqual(res_del.status_code, 302)
        self.assertEqual(len(get_all_custodian_profiles()), 0)

    def test_keywords_linked_with_flagged_words_and_clickable_hits(self):
        from core.models import InvestigationProfile

        # 1. Setup profile with custom keywords
        InvestigationProfile.objects.create(
            full_name="Arun Kumar",
            keywords=["tender L1", "consultant"],
        )

        # 2. Test searching for a flagged term (e.g. 'off the record')
        hits = get_paginated_chat_messages(self.channel.id, search="off the record")
        self.assertGreaterEqual(hits["total_count"], 1)
        found_texts = [m["message_text"] for m in hits["data"]]
        self.assertTrue(any("off the record" in t for t in found_texts))

        # 3. Test flagged_only filter includes all flagged words & profile keywords
        flagged_res = get_paginated_chat_messages(
            self.channel.id, custodian_name="Arun Kumar", flagged_only=True
        )
        self.assertGreaterEqual(flagged_res["total_count"], 3)
        for m in flagged_res["data"]:
            self.assertTrue(m["risk_score"] >= 50)
            self.assertTrue(len(m["flagged_terms"]) > 0)

        # 4. Test view renders clickable flagword badge links
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        res = self.client.get(reverse("q_chat:custodian_detail", args=["Arun Kumar"]))
        self.assertEqual(res.status_code, 200)
        content = res.content.decode("utf-8")

        # Flagged terms should be clickable links with ?q=
        self.assertIn("?q=commission", content)
        self.assertIn("?q=cash", content)
        self.assertIn("Hit:", content)
        self.assertIn("Profile Keyword Registry", content)

    def test_custodian_detail_suggested_entities_in_context(self):
        res = self.client.get(
            reverse("q_chat:custodian_detail", kwargs={"custodian_name": "Arun Kumar"})
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("suggested_entities", res.context)
        self.assertIn("analyzed_profiles", res.context)

    def test_chat_suggested_entity_keyword_services(self):
        from q_chat.services import (
            add_suggested_chat_entity_keyword_service,
            bulk_add_chat_entities_as_keywords_service,
        )

        from core.models import InvestigationProfile

        prof = InvestigationProfile.objects.create(
            full_name="Emor Palani",
            keywords=["vendor"],
        )

        res = add_suggested_chat_entity_keyword_service(prof.id, "Apex Enterprises")
        self.assertEqual(res["status"], "success")
        self.assertIn("Apex Enterprises", res["keywords"])

        batch_res = bulk_add_chat_entities_as_keywords_service(
            [
                {"profile_id": str(prof.id), "keyword": "Gopal"},
                {"profile_id": str(prof.id), "keyword": "9840998877"},
            ]
        )
        self.assertEqual(batch_res["status"], "success")
        prof.refresh_from_db()
        self.assertIn("Gopal", prof.keywords)
        self.assertIn("9840998877", prof.keywords)
