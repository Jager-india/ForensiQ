"""
Unit tests for Core Forensic Named Entity Recognition (NER) & Heuristic Entity Extractor.
Tests Indian proper names, honorifics, kinship, legal deeds, and corporate entities.
"""

from django.test import TestCase

from core.entity_extractor import (
    extract_entities_from_case_documents,
    extract_entities_from_chat_messages,
    extract_entities_from_scan_hits,
    extract_entities_from_text,
    extract_entities_from_transcript_segments,
)
from core.models import InvestigationProfile


class EntityExtractorTests(TestCase):
    def setUp(self):
        self.prof_venkat = InvestigationProfile.objects.create(
            full_name="Venkatesan C",
            department="Procurement",
            keywords=["raw_keyword"],
        )
        self.prof_raj = InvestigationProfile.objects.create(
            full_name="Raj",
            department="Finance",
            keywords=["secret_term"],
        )

    def test_indian_honorifics_and_initials(self):
        text = "Meeting with Shri Venkatesan C and Mr. S Maharajan regarding project delivery."
        entities = extract_entities_from_text(text, source_context="audio call")
        names = {e["name"] for e in entities}
        self.assertIn("Venkatesan C", names)
        self.assertIn("Maharajan", names)

    def test_kinship_and_nominee_patterns(self):
        text = "Nominee is J. Silviya Spouse of A. Joseph Remigius, son of Mr. Dhasarathan."
        entities = extract_entities_from_text(text, source_context="deed agreement")
        names = {e["name"] for e in entities}
        self.assertIn("J. Silviya", names)
        self.assertIn("A. Joseph Remigius", names)
        self.assertIn("Dhasarathan", names)

    def test_corporate_entities_and_suffixes(self):
        text = "Sub-contract awarded to Sri Mirra Engineers and ARR Enterprises Pvt Ltd."
        entities = extract_entities_from_text(text)
        names = {e["name"] for e in entities}
        self.assertIn("Sri Mirra Engineers", names)
        self.assertIn("ARR Enterprises Pvt Ltd", names)

    def test_conversational_verbs_and_mentions(self):
        text = "I spoke to Balamurugan yesterday and will transfer to brokerx@okaxis or call 9840123456."
        entities = extract_entities_from_text(text)
        names = {e["name"] for e in entities}
        self.assertIn("Balamurugan", names)
        self.assertIn("brokerx@okaxis", names)
        self.assertIn("9840123456", names)

    def test_subsumption_of_single_word_names(self):
        # When both 'Venkatesan C' and 'Venkatesan' appear, 'Venkatesan C' subsumes 'Venkatesan'
        text = "Venkatesan C spoke at the event. Venkatesan was satisfied with the terms."
        entities = extract_entities_from_text(text)
        names = [e["name"] for e in entities]
        self.assertIn("Venkatesan C", names)
        self.assertNotIn("Venkatesan", names)

    def test_voice_transcript_segments_extraction(self):
        segments = [
            {
                "speaker": "Raj",
                "transcript": "Did you speak to Balamurugan about the ARR Enterprises payment?",
            },
            {"speaker": "Venkat", "transcript": "Yes, I will transfer to brokerx@okaxis today."},
        ]
        entities = extract_entities_from_transcript_segments(
            segments=segments,
            custodian_name="Venkat",
            default_profile_id=str(self.prof_venkat.id),
            default_profile_name=self.prof_venkat.full_name,
        )
        names = {e["name"] for e in entities}
        self.assertIn("Balamurugan", names)
        self.assertIn("ARR Enterprises", names)
        self.assertIn("brokerx@okaxis", names)
        # Senders as call participants
        self.assertIn("Raj", names)

    def test_chat_messages_extraction(self):
        messages = [
            {"sender": "Raj", "message_text": "Please transfer 250000 to Pasupathy for supplies."},
            {
                "sender": "Venkat",
                "message_text": "Transferred to Senthamilkannan account directly.",
            },
        ]
        participants = [
            {"sender_name": "Supplier Suresh", "message_count": 5},
        ]
        entities = extract_entities_from_chat_messages(
            messages=messages,
            participants=participants,
            custodian_name="Venkat",
            default_profile_id=str(self.prof_venkat.id),
        )
        names = {e["name"] for e in entities}
        self.assertIn("Pasupathy", names)
        self.assertIn("Senthamilkannan", names)
        self.assertIn("Supplier Suresh", names)

    def test_scan_hits_extraction(self):
        hits = [
            {
                "file_name": "Dhanasekaran_Partnership_Deed.pdf",
                "content_snippet": "Capital invested by Sri Mirra Engineers.",
                "meta_author": "Balamurugan",
            }
        ]
        entities = extract_entities_from_scan_hits(
            hits=hits,
            custodian_name="Venkat",
            default_profile_id=str(self.prof_venkat.id),
        )
        names = {e["name"] for e in entities}
        self.assertIn("Dhanasekaran", names)
        self.assertIn("Sri Mirra Engineers", names)
        self.assertIn("Balamurugan", names)

    def test_verify_case_documents_extraction(self):
        documents = [
            {
                "filename": "Partnership_Deed.pdf",
                "raw_metadata": {
                    "ner_entities": [
                        {
                            "name": "Dhanasekaran",
                            "entity_type": "PARTNER",
                            "role": "Deed Partner",
                            "count": 2,
                            "confidence": 0.95,
                        },
                        {
                            "name": "Sri Mirra Engineers",
                            "entity_type": "ORGANIZATION",
                            "role": "Partnership Firm",
                            "count": 4,
                            "confidence": 0.95,
                        },
                    ]
                },
            }
        ]
        entities = extract_entities_from_case_documents(
            documents=documents,
            custodian_name="Venkat",
            default_profile_id=str(self.prof_venkat.id),
        )
        names = {e["name"] for e in entities}
        self.assertIn("Dhanasekaran", names)
        self.assertIn("Sri Mirra Engineers", names)
