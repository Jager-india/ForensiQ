from unittest.mock import MagicMock, patch

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from core.models import InvestigationProfile

from .backend.voice_parser import (
    extract_speaker_and_text,
    ingest_transcript_content,
    parse_transcript_text_to_timeline,
    screen_text_for_intent,
    tag_transcript_detections,
)
from .models import AudioRecording, TranscriptSegment, VoiceWatchlistRule
from .selectors import (
    get_all_custodian_profiles,
    get_all_recordings,
    get_combined_timeline_for_custodian,
    get_combined_timeline_for_recording,
    get_custodian_profile_detail,
    get_global_voice_metrics,
    get_metrics_for_custodian,
    get_metrics_for_recording,
    get_recording_by_id,
)
from .services import (
    delete_audio_recording,
    get_voice_api_endpoint,
    ingest_audio_recording,
    request_remote_transcription,
)


class QVoiceModelAndBackendTests(TestCase):
    def setUp(self):
        self.recording = AudioRecording.objects.create(
            call_ref="CALL-TEST-001",
            call_title="Vendor Pricing Call",
            custodian_name="Procurement Officer",
            caller_number="+91-9876543210",
            callee_number="+91-9876543211",
            call_timestamp=timezone.now(),
            duration_seconds=125,
            transcription_status=AudioRecording.TranscriptionStatus.COMPLETED,
            risk_score=75,
        )

    def test_audio_recording_str_and_duration_formatted(self):
        self.assertIn("CALL-TEST-001", str(self.recording))
        self.assertEqual(self.recording.duration_formatted, "02:05")

        # Test hours formatting
        self.recording.duration_seconds = 3665
        self.assertEqual(self.recording.duration_formatted, "01:01:05")

    def test_transcript_segment_str_and_timestamp(self):
        segment = TranscriptSegment.objects.create(
            recording=self.recording,
            speaker_tag="Speaker 1",
            start_time_seconds=65.5,
            end_time_seconds=75.0,
            text_content="We can discuss the kickback off the record.",
            detected_intent=TranscriptSegment.IntentCategory.COLLUSION,
            risk_score=95,
        )
        self.assertEqual(segment.timestamp_formatted, "01:05")
        self.assertIn("Speaker 1", str(segment))

    def test_voice_watchlist_rule_str(self):
        rule = VoiceWatchlistRule.objects.create(
            rule_name="Kickback Marker",
            keyword="kickback",
            risk_weight=95,
            category="Collusion",
        )
        self.assertIn("Collusion", str(rule))
        self.assertIn("kickback", str(rule))

    def test_extract_speaker_and_text(self):
        speaker, text = extract_speaker_and_text("Speaker 2: Let us finalize the rates.")
        self.assertEqual(speaker, "Speaker 2")
        self.assertEqual(text, "Let us finalize the rates.")

        speaker2, text2 = extract_speaker_and_text(
            "Plain conversational speech without speaker prefix.", default_speaker="Speaker 1"
        )
        self.assertEqual(speaker2, "Speaker 1")
        self.assertEqual(text2, "Plain conversational speech without speaker prefix.")

        # Empty string
        spk_empty, txt_empty = extract_speaker_and_text("", default_speaker="DefaultAgent")
        self.assertEqual(spk_empty, "DefaultAgent")
        self.assertEqual(txt_empty, "")

        # <v Speaker> tag format
        spk_v, txt_v = extract_speaker_and_text("<v Audit Manager>Review the ledger</v>")
        self.assertEqual(spk_v, "Audit Manager")
        self.assertEqual(txt_v, "Review the ledger")

        # [Speaker] bracket format
        spk_b, txt_b = extract_speaker_and_text("[Procurement Lead]: Submit the quote")
        self.assertEqual(spk_b, "Procurement Lead")
        self.assertEqual(txt_b, "Submit the quote")

    def test_screen_text_for_intent(self):
        intent, kw, risk = screen_text_for_intent("I want my 10% commission and kickback cash.")
        self.assertEqual(intent, "Collusion")
        self.assertIn("KICKBACK", [k.upper() for k in kw])
        self.assertGreaterEqual(risk, 85)

        clean_intent, _, clean_risk = screen_text_for_intent(
            "Good morning team, let us review the presentation."
        )
        self.assertEqual(clean_intent, "General")
        self.assertEqual(clean_risk, 0)

        # Empty text
        empty_intent, empty_kw, empty_risk = screen_text_for_intent("")
        self.assertEqual(empty_intent, "General")
        self.assertEqual(empty_risk, 0)

    def test_tag_transcript_detections(self):
        detections = tag_transcript_detections(
            "Transfer ten lakh rupees to HDFC account for Rajesh."
        )
        terms = [d["term"].lower() for d in detections]
        self.assertTrue(any("hdfc" in t for t in terms))

        # Empty text
        self.assertEqual(tag_transcript_detections(""), [])

    def test_parse_transcript_text_and_ingest_content(self):
        # 1. Interval with single colon mm:ss.000 --> mm:ss.000
        raw_vtt = "WEBVTT\n\n01:10.000 --> 01:15.000\nSpeaker 1: Verify the invoice details."
        timeline = parse_transcript_text_to_timeline(raw_vtt)
        self.assertEqual(len(timeline), 1)
        self.assertIn("00:01:10", timeline[0]["timestamp"])

        # 2. Inline format [mm:ss] text
        raw_inline = "[02:30] Discussing payment clearance"
        timeline_inline = parse_transcript_text_to_timeline(raw_inline)
        self.assertEqual(len(timeline_inline), 1)
        self.assertIn("00:02:30", timeline_inline[0]["timestamp"])

        # 3. JSON ingest list
        json_list = '[{"timestamp": "[00:00:00 --> 00:00:05]", "transcript": "Hello"}]'
        ingested_list = ingest_transcript_content(json_list, "transcript.json")
        self.assertEqual(len(ingested_list), 1)

        # 4. JSON ingest dict with timeline_transcript
        json_dict = '{"timeline_transcript": [{"timestamp": "00:01", "transcript": "Report"}]}'
        ingested_dict = ingest_transcript_content(json_dict, "transcript.json")
        self.assertEqual(len(ingested_dict), 1)

        # 5. Broken JSON fallback
        broken_json = "{invalid_json_content"
        fallback_timeline = ingest_transcript_content(broken_json, "transcript.json")
        self.assertIsInstance(fallback_timeline, list)


class QVoiceServicesAndSelectorsTests(TestCase):
    def setUp(self):
        self.client = Client()
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

    def test_endpoint_resolution(self):
        endpoint = get_voice_api_endpoint()
        self.assertTrue(endpoint.endswith("/v1/audio/transcriptions"))

    @patch("q_voice.services.request_remote_transcription")
    def test_ingest_audio_recording_successful(self, mock_remote_call):
        mock_remote_call.return_value = (
            True,
            {
                "timeline_transcript": [
                    {
                        "timestamp": "[00:00:00 --> 00:00:15]",
                        "transcript": "Speaker 1: Please keep this off the record.",
                    },
                    {
                        "timestamp": "[00:00:15 --> 00:00:30]",
                        "transcript": "Speaker 2: We will transfer via SBI account.",
                    },
                ],
                "suspicious_detections": [],
            },
            "",
        )

        audio_content = b"RIFF....WAVEfmt ...."
        fake_audio = SimpleUploadedFile("wiretap_test.wav", audio_content, content_type="audio/wav")

        rec, err = ingest_audio_recording(
            audio_file=fake_audio,
            call_ref="CALL-AUTO-001",
            call_title="Audit Wiretap 1",
            custodian_name="VP Sourcing",
        )

        self.assertEqual(err, "")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.call_ref, "CALL-AUTO-001")
        self.assertEqual(rec.total_segments, 2)
        self.assertEqual(rec.duration_seconds, 30)
        self.assertEqual(rec.transcription_status, AudioRecording.TranscriptionStatus.COMPLETED)
        self.assertEqual(rec.segments.count(), 2)

    @patch("q_voice.services.request_remote_transcription")
    def test_ingest_audio_recording_api_failure_handled(self, mock_remote_call):
        mock_remote_call.return_value = (
            False,
            None,
            "Connection refused to Whisper transcription daemon at 127.0.0.1:8434",
        )

        fake_audio = SimpleUploadedFile("offline_test.wav", b"AUDIOBYTES", content_type="audio/wav")

        rec, err = ingest_audio_recording(
            audio_file=fake_audio,
            call_ref="CALL-FAIL-001",
            call_title="Failed Call",
        )

        self.assertIn("Connection refused", err)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.transcription_status, AudioRecording.TranscriptionStatus.FAILED)
        self.assertIn("Connection refused", rec.error_message)

    @patch("requests.post")
    def test_request_remote_transcription_branches(self, mock_post):
        # 1. Successful 200 with text
        mock_resp_ok = MagicMock()
        mock_resp_ok.status_code = 200
        mock_resp_ok.json.return_value = {"text": "Transcribed audio text successfully"}
        mock_post.return_value = mock_resp_ok

        success, data, err = request_remote_transcription(filename="test.wav", file_bytes=b"RIFF")
        self.assertTrue(success)
        self.assertEqual(data["text"], "Transcribed audio text successfully")

        # 2. 200 with error payload
        mock_resp_err = MagicMock()
        mock_resp_err.status_code = 200
        mock_resp_err.json.return_value = {"status": "error", "message": "Corrupt audio stream"}
        mock_post.return_value = mock_resp_err

        success, data, err = request_remote_transcription(filename="test.wav", file_bytes=b"RIFF")
        self.assertFalse(success)
        self.assertIn("Corrupt audio stream", err)

        # 3. HTTP 500
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_post.return_value = mock_resp_500

        success, data, err = request_remote_transcription(filename="test.wav", file_bytes=b"RIFF")
        self.assertFalse(success)
        self.assertIn("500", err)

        # 4. Timeout exception
        mock_post.side_effect = requests.exceptions.Timeout("Read timed out")
        success, data, err = request_remote_transcription(filename="test.wav", file_bytes=b"RIFF")
        self.assertFalse(success)
        self.assertIn("timed out", err)

        # 5. Generic RequestException
        mock_post.side_effect = requests.exceptions.RequestException("Host unreachable")
        success, data, err = request_remote_transcription(filename="test.wav", file_bytes=b"RIFF")
        self.assertFalse(success)
        self.assertIn("Failed to reach", err)

    @patch("q_voice.services.request_remote_transcription")
    def test_ingest_audio_recording_with_segments_and_text(self, mock_remote):
        # Ingestion using 'segments' format
        mock_remote.return_value = (
            True,
            {
                "segments": [
                    {"start": 1.0, "end": 6.5, "text": "Transfer the funds to HDFC account now."},
                    {"start": 7.0, "end": 12.0, "text": "Confirmed, initiating money transfer."},
                ]
            },
            "",
        )
        fake_audio1 = SimpleUploadedFile("segments.wav", b"RIFFDATA", content_type="audio/wav")
        rec1, err1 = ingest_audio_recording(
            audio_file=fake_audio1,
            call_ref="CALL-SEG-001",
        )
        self.assertEqual(err1, "")
        self.assertEqual(rec1.segments.count(), 2)
        self.assertEqual(rec1.total_segments, 2)
        self.assertGreaterEqual(rec1.risk_score, 0)

        # Ingestion using raw 'text' format with multiple sentences
        mock_remote.return_value = (
            True,
            {
                "text": "Hello, this is confidential. Let us discuss the secret kickback percentage. We agree."
            },
            "",
        )
        fake_audio2 = SimpleUploadedFile("rawtext.wav", b"RIFFDATA", content_type="audio/wav")
        rec2, err2 = ingest_audio_recording(
            audio_file=fake_audio2,
            call_ref="CALL-TXT-001",
        )
        self.assertEqual(err2, "")
        self.assertEqual(rec2.segments.count(), 3)

    def test_delete_audio_recording(self):
        rec = AudioRecording.objects.create(
            call_ref="CALL-DEL-001",
            call_title="To Delete",
            call_timestamp=timezone.now(),
            duration_seconds=10,
        )
        self.assertTrue(delete_audio_recording(rec.id))
        self.assertFalse(AudioRecording.objects.filter(id=rec.id).exists())
        self.assertFalse(delete_audio_recording("invalid-uuid"))

    def test_selectors_and_metrics(self):
        rec = AudioRecording.objects.create(
            call_ref="CALL-SEL-001",
            call_title="Selector Test",
            call_timestamp=timezone.now(),
            duration_seconds=180,
            risk_score=90,
            total_segments=1,
        )
        TranscriptSegment.objects.create(
            recording=rec,
            speaker_tag="Officer",
            start_time_seconds=0.0,
            end_time_seconds=15.0,
            text_content="Take the secret kickback cut.",
            detected_intent=TranscriptSegment.IntentCategory.COLLUSION,
            risk_score=90,
        )

        recordings = get_all_recordings()
        self.assertIn(rec, recordings)

        fetched = get_recording_by_id(rec.id)
        self.assertEqual(fetched, rec)

        metrics = get_global_voice_metrics()
        self.assertGreaterEqual(metrics["total_recordings"], 1)
        self.assertGreaterEqual(metrics["collusion_calls"], 1)

        rec_metrics = get_metrics_for_recording(rec)
        self.assertEqual(rec_metrics["total_segments"], 1)

        timeline = get_combined_timeline_for_recording(rec)
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["speaker"], "Officer")


class QVoiceViewsTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        self.user = User.objects.create_user(username="voice_views_user", password="password")
        self.client = Client()
        self.client.force_login(self.user)
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.recording = AudioRecording.objects.create(
            call_ref="CALL-VIEW-001",
            call_title="Executive Meeting",
            call_timestamp=timezone.now(),
            duration_seconds=100,
        )

    def test_dashboard_view_unauthenticated(self):
        anon_client = Client()
        res = anon_client.get(reverse("q_voice:dashboard"))
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login/", res.url)

    def test_dashboard_view_authenticated(self):
        res = self.client.get(reverse("q_voice:dashboard"))
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Q-Voice", res.content)
        self.assertIn(b"CALL-VIEW-001", res.content)

    def test_recording_detail_view(self):
        res = self.client.get(
            reverse("q_voice:recording_detail", kwargs={"recording_id": self.recording.id})
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Executive Meeting", res.content)

        # 404 for missing recording
        import uuid

        missing_res = self.client.get(
            reverse("q_voice:recording_detail", kwargs={"recording_id": uuid.uuid4()})
        )
        self.assertEqual(missing_res.status_code, 404)

    def test_delete_recording_view(self):
        res = self.client.post(
            reverse("q_voice:delete_recording", kwargs={"recording_id": self.recording.id}),
            follow=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(AudioRecording.objects.filter(id=self.recording.id).exists())

    def test_timeline_parser_and_ingestion(self):
        from .backend.voice_parser import (
            ingest_transcript_content,
            parse_transcript_text_to_timeline,
        )

        vtt_sample = """WEBVTT

1
00:00:01.000 --> 00:00:05.000
Speaker 1: Please transfer cash payment kickback into the off the record account

2
00:00:06.000 --> 00:00:10.000
Speaker 2: Understood, concealing the invoice margin now
"""
        timeline = parse_transcript_text_to_timeline(vtt_sample)
        self.assertEqual(len(timeline), 2)
        self.assertIn("Speaker 1", timeline[0]["speaker"])
        self.assertGreater(timeline[0]["risk_score"], 0)

        # Inline format
        inline_sample = "[00:02:15] Vendor: Sending kickback commission now"
        inline_timeline = parse_transcript_text_to_timeline(inline_sample)
        self.assertEqual(len(inline_timeline), 1)

        # Ingest JSON
        json_sample = '{"timeline_transcript": [{"timestamp": "[00:01 --> 00:05]", "speaker": "CEO", "transcript": "Verified", "risk_score": 10}]}'
        json_res = ingest_transcript_content(json_sample, "call.json")
        self.assertEqual(len(json_res), 1)
        self.assertEqual(json_res[0]["speaker"], "CEO")

    @patch("q_voice.views.ingest_audio_recording")
    def test_dashboard_view_post_handling(self, mock_ingest):
        url = reverse("q_voice:dashboard")

        # 1. POST without audio file
        res_empty = self.client.post(url, data={})
        self.assertEqual(res_empty.status_code, 200)
        self.assertIn("No audio file provided", res_empty.context["error_message"])

        # 2. POST with audio file and successful ingestion
        mock_rec = MagicMock()
        mock_rec.id = self.recording.id
        mock_rec.call_ref = "CALL-POST-001"
        mock_rec.custodian_name = "Auditee"
        mock_rec.transcription_status = AudioRecording.TranscriptionStatus.COMPLETED
        mock_ingest.return_value = (mock_rec, "")

        dummy_audio = SimpleUploadedFile("audio.wav", b"RIFFDATA", content_type="audio/wav")
        res_ok = self.client.post(
            url,
            data={
                "audio_file": dummy_audio,
                "call_ref": "CALL-POST-001",
                "call_title": "Call Title",
                "custodian_name": "Auditee",
            },
        )
        self.assertEqual(res_ok.status_code, 302)
        self.assertIn("Auditee", res_ok.url)
        self.assertIn(f"recording_id={self.recording.id}", res_ok.url)

        # 3. POST with audio file and ingestion failure
        mock_rec_fail = MagicMock()
        mock_rec_fail.transcription_status = AudioRecording.TranscriptionStatus.FAILED
        mock_ingest.return_value = (mock_rec_fail, "Server error")

        dummy_audio_fail = SimpleUploadedFile("fail.wav", b"RIFFDATA", content_type="audio/wav")
        res_fail = self.client.post(url, data={"audio_file": dummy_audio_fail})
        self.assertEqual(res_fail.status_code, 200)
        self.assertEqual(res_fail.context["status"], "error")


class QVoiceCustodianProfileTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        self.user = User.objects.create_user(username="voice_cust_user", password="password")
        self.client = Client()
        self.client.force_login(self.user)
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.profile = InvestigationProfile.objects.create(
            full_name="Rajesh Sharma",
            employee_id="EMP-7701",
            department="Procurement",
            designation="Chief Buyer",
        )

        self.rec1 = AudioRecording.objects.create(
            call_ref="CALL-RAJ-001",
            call_title="Supplier Call 1",
            custodian_name="Rajesh Sharma",
            call_timestamp=timezone.now(),
            duration_seconds=120,
            risk_score=80,
            detected_intent_summary="Collusion",
            total_segments=2,
            flagged_segments_count=1,
            transcription_status=AudioRecording.TranscriptionStatus.COMPLETED,
        )
        TranscriptSegment.objects.create(
            recording=self.rec1,
            speaker_tag="Rajesh Sharma",
            start_time_seconds=0.0,
            end_time_seconds=30.0,
            text_content="Let us discuss the secret kickback for the contract.",
            detected_intent=TranscriptSegment.IntentCategory.COLLUSION,
            risk_score=80,
        )
        TranscriptSegment.objects.create(
            recording=self.rec1,
            speaker_tag="Vendor",
            start_time_seconds=30.0,
            end_time_seconds=60.0,
            text_content="We can transfer the cash via HDFC account.",
            detected_intent=TranscriptSegment.IntentCategory.PRICE_NEGOTIATION,
            risk_score=50,
        )

        self.rec2 = AudioRecording.objects.create(
            call_ref="CALL-RAJ-002",
            call_title="Supplier Call 2",
            custodian_name="Rajesh Sharma",
            call_timestamp=timezone.now(),
            duration_seconds=180,
            risk_score=60,
            detected_intent_summary="Price Negotiation",
            total_segments=1,
            flagged_segments_count=0,
            transcription_status=AudioRecording.TranscriptionStatus.COMPLETED,
        )
        TranscriptSegment.objects.create(
            recording=self.rec2,
            speaker_tag="Rajesh Sharma",
            start_time_seconds=0.0,
            end_time_seconds=45.0,
            text_content="Verify the updated quote with procurement team.",
            detected_intent=TranscriptSegment.IntentCategory.GENERAL,
            risk_score=10,
        )

        # Also create a general custodian recording
        self.rec_gen = AudioRecording.objects.create(
            call_ref="CALL-GEN-001",
            call_title="General Call",
            custodian_name="",
            call_timestamp=timezone.now(),
            duration_seconds=60,
            risk_score=20,
            total_segments=1,
        )

    def test_get_all_custodian_profiles(self):
        profiles = get_all_custodian_profiles()
        self.assertGreaterEqual(len(profiles), 2)

        rajesh = next((p for p in profiles if p["custodian_name"] == "Rajesh Sharma"), None)
        self.assertIsNotNone(rajesh)
        self.assertEqual(rajesh["recordings_count"], 2)
        self.assertEqual(rajesh["total_duration_seconds"], 300)
        self.assertEqual(rajesh["total_duration_formatted"], "05:00")
        self.assertEqual(rajesh["total_segments"], 3)
        self.assertEqual(rajesh["max_risk_score"], 80)
        self.assertEqual(rajesh["department"], "Procurement")
        self.assertEqual(rajesh["employee_id"], "EMP-7701")

        general = next((p for p in profiles if p["custodian_name"] == "General Custodian"), None)
        self.assertIsNotNone(general)
        self.assertEqual(general["recordings_count"], 1)

    def test_get_custodian_profile_detail(self):
        detail = get_custodian_profile_detail("Rajesh Sharma")
        self.assertEqual(detail["custodian_name"], "Rajesh Sharma")
        self.assertEqual(detail["recordings_count"], 2)
        self.assertEqual(detail["total_duration_seconds"], 300)
        self.assertEqual(detail["department"], "Procurement")

        gen_detail = get_custodian_profile_detail("General Custodian")
        self.assertEqual(gen_detail["custodian_name"], "General Custodian")
        self.assertEqual(gen_detail["recordings_count"], 1)

    def test_get_combined_timeline_for_custodian(self):
        # Combined view (all recordings)
        combined = get_combined_timeline_for_custodian("Rajesh Sharma")
        self.assertEqual(len(combined), 3)
        self.assertTrue(any(item["call_ref"] == "CALL-RAJ-001" for item in combined))
        self.assertTrue(any(item["call_ref"] == "CALL-RAJ-002" for item in combined))

        # Scoped view (only rec1)
        scoped = get_combined_timeline_for_custodian("Rajesh Sharma", recording_id=self.rec1.id)
        self.assertEqual(len(scoped), 2)
        self.assertTrue(all(item["call_ref"] == "CALL-RAJ-001" for item in scoped))

    def test_get_metrics_for_custodian(self):
        metrics = get_metrics_for_custodian("Rajesh Sharma")
        self.assertEqual(metrics["total_segments"], 3)
        self.assertGreaterEqual(metrics["risk_score"], 80)
        self.assertGreaterEqual(metrics["suspicious_count"], 1)

        # Scoped metrics
        scoped_metrics = get_metrics_for_custodian("Rajesh Sharma", recording_id=self.rec2.id)
        self.assertEqual(scoped_metrics["total_segments"], 1)

    def test_custodian_detail_suggested_entities_in_context(self):
        res = self.client.get(
            reverse("q_voice:custodian_detail", kwargs={"custodian_name": "Rajesh Sharma"})
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("suggested_entities", res.context)
        self.assertIn("analyzed_profiles", res.context)

    def test_custodian_detail_view(self):
        # Combined view
        res = self.client.get(
            reverse("q_voice:custodian_detail", kwargs={"custodian_name": "Rajesh Sharma"})
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Rajesh Sharma", res.content)
        self.assertIn(b"All Recordings Combined", res.content)
        self.assertIn(b"CALL-RAJ-001", res.content)
        self.assertIn(b"CALL-RAJ-002", res.content)

        # Scoped view with recording_id parameter
        res_scoped = self.client.get(
            reverse("q_voice:custodian_detail", kwargs={"custodian_name": "Rajesh Sharma"})
            + f"?recording_id={self.rec1.id}"
        )
        self.assertEqual(res_scoped.status_code, 200)
        self.assertEqual(res_scoped.context["selected_recording"], self.rec1)

        # 404 for non-existent custodian
        res_404 = self.client.get(
            reverse("q_voice:custodian_detail", kwargs={"custodian_name": "NonExistentPerson"})
        )
        self.assertEqual(res_404.status_code, 404)

    def test_delete_custodian_view(self):
        res = self.client.post(
            reverse("q_voice:delete_custodian", kwargs={"custodian_name": "Rajesh Sharma"}),
            follow=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(AudioRecording.objects.filter(custodian_name="Rajesh Sharma").exists())
        self.assertFalse(TranscriptSegment.objects.filter(recording=self.rec1).exists())
