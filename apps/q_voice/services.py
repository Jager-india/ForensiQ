"""
Q-Voice Forensic Services
Business logic orchestrating remote transcription API calls, audio ingestion, diarization, and database persistence.
"""

import hashlib
import os
import re
import uuid
from typing import Any

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from loguru import logger

from .backend.voice_parser import (
    extract_speaker_and_text,
    screen_text_for_intent,
    tag_transcript_detections,
)
from .models import AudioRecording, TranscriptSegment


def get_voice_api_endpoint() -> str:
    """
    Resolves the active Voice Model transcription endpoint from Django settings or environment.
    Defaults to http://127.0.0.1:8434/v1/audio/transcriptions.
    """
    configured_url = (
        getattr(settings, "VOICE_MODEL_ENDPOINT", None)
        or os.getenv("VOICE_MODEL_ENDPOINT")
        or os.getenv("VOICE_API_URL")
        or os.getenv("API_URL")
        or "http://127.0.0.1:8434/v1/audio/transcriptions"
    )

    if "/v1/audio/transcriptions" in configured_url or "/transcribe" in configured_url:
        return configured_url
    return f"{configured_url.rstrip('/')}/v1/audio/transcriptions"


def request_remote_transcription(
    *, filename: str, file_bytes: bytes, content_type: str = "audio/wav"
) -> tuple[bool, dict[str, Any] | None, str]:
    """
    Calls the remote Q-Voice ASR & Diarization API at VOICE_MODEL_ENDPOINT.
    Returns (success, api_data_dict, error_message).
    """
    api_url = get_voice_api_endpoint()
    voice_timeout_setting = getattr(settings, "VOICE_API_TIMEOUT", None)
    voice_timeout_env = os.getenv("VOICE_API_TIMEOUT")
    timeout_sec = float(voice_timeout_setting or voice_timeout_env or 60.0)

    try:
        files = {"file": (filename, file_bytes, content_type)}
        response = requests.post(api_url, files=files, timeout=timeout_sec)

        if response.status_code == 200:
            api_data = response.json()
            if isinstance(api_data, dict) and (
                "text" in api_data
                or "timeline_transcript" in api_data
                or "segments" in api_data
                or api_data.get("status") == "success"
            ):
                return True, api_data, ""
            return (
                False,
                None,
                api_data.get("message", "API reported internal transcription failure."),
            )

        return (
            False,
            None,
            f"Remote API responded with HTTP status {response.status_code} at {api_url}",
        )

    except requests.exceptions.Timeout:
        return (
            False,
            None,
            f"Connection timed out ({timeout_sec}s) attempting to connect to transcription server at {api_url}. Verify server is running and accessible.",
        )
    except requests.exceptions.RequestException as exc:
        return (
            False,
            None,
            f"Failed to reach transcription server at {api_url}: {exc}",
        )


def ingest_audio_recording(
    *,
    audio_file,
    call_ref: str = "",
    call_title: str = "",
    custodian_name: str = "",
) -> tuple[AudioRecording | None, str]:
    """
    Processes an uploaded audio recording via remote API and persists recording & segments in database.
    """
    filename = getattr(audio_file, "name", "recording.wav")
    content_type = getattr(audio_file, "content_type", "audio/wav")

    file_bytes = audio_file.read()
    if hasattr(audio_file, "seek"):
        audio_file.seek(0)
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    from pathlib import Path

    from django.core.files.base import ContentFile

    wrapped_audio = ContentFile(file_bytes, name=Path(filename).name)

    # Call Live Transcription API
    success, api_data, error_msg = request_remote_transcription(
        filename=filename, file_bytes=file_bytes, content_type=content_type
    )

    auto_ref = call_ref.strip() or f"CALL-{uuid.uuid4().hex[:8].upper()}"
    auto_title = call_title.strip() or f"Audio - {filename}"

    if not success or not api_data:
        # Create a FAILED audit log in AudioRecording so investigators know an attempt occurred
        with transaction.atomic():
            rec = AudioRecording.objects.create(
                call_ref=auto_ref,
                call_title=auto_title,
                custodian_name=custodian_name.strip(),
                call_timestamp=timezone.now(),
                source_filename=filename,
                sha256_hash=sha256,
                audio_file=wrapped_audio,
                transcription_status=AudioRecording.TranscriptionStatus.FAILED,
                error_message=error_msg,
            )
        return rec, error_msg

    # Extract timeline and detections from API payload
    timeline_raw = api_data.get("timeline_transcript", [])
    detections_raw = api_data.get("suspicious_detections", [])

    # If timeline_transcript was not returned, check for OpenAI-compatible segments or raw text
    if not timeline_raw and "segments" in api_data and isinstance(api_data["segments"], list):
        for s in api_data["segments"]:
            s_sec = float(s.get("start", 0.0))
            e_sec = float(s.get("end", s_sec + 5.0))
            s_fmt = (
                f"{int(s_sec) // 3600:02d}:{(int(s_sec) % 3600) // 60:02d}:{int(s_sec) % 60:02d}"
            )
            e_fmt = (
                f"{int(e_sec) // 3600:02d}:{(int(e_sec) % 3600) // 60:02d}:{int(e_sec) % 60:02d}"
            )
            timeline_raw.append(
                {
                    "timestamp": f"[{s_fmt} --> {e_fmt}]",
                    "transcript": s.get("text", "").strip(),
                    "start_seconds": s_sec,
                    "end_seconds": e_sec,
                }
            )
    elif not timeline_raw and "text" in api_data:
        raw_text = str(api_data.get("text", "")).strip()
        if raw_text:
            sentences = [s.strip() for s in re.split(r"(?<=[.?!])\s+", raw_text) if s.strip()]
        else:
            sentences = ["Acoustic audio file processed. No vocal speech patterns detected."]

        cur_sec = 0.0
        for s_idx, sentence in enumerate(sentences):
            w_cnt = len(sentence.split())
            dur = max(4.0, w_cnt * 0.45)
            s_sec = cur_sec
            e_sec = cur_sec + dur
            cur_sec = e_sec

            s_fmt = (
                f"{int(s_sec) // 3600:02d}:{(int(s_sec) % 3600) // 60:02d}:{int(s_sec) % 60:02d}"
            )
            e_fmt = (
                f"{int(e_sec) // 3600:02d}:{(int(e_sec) % 3600) // 60:02d}:{int(e_sec) % 60:02d}"
            )

            timeline_raw.append(
                {
                    "timestamp": f"[{s_fmt} --> {e_fmt}]",
                    "transcript": sentence,
                    "start_seconds": s_sec,
                    "end_seconds": e_sec,
                    "speaker": f"Speaker {(s_idx % 2) + 1}",
                }
            )

    with transaction.atomic():
        recording = AudioRecording.objects.create(
            call_ref=auto_ref,
            call_title=auto_title,
            custodian_name=custodian_name.strip(),
            call_timestamp=timezone.now(),
            source_filename=filename,
            sha256_hash=sha256,
            audio_file=wrapped_audio,
            transcription_status=AudioRecording.TranscriptionStatus.COMPLETED,
        )

        segment_objs: list[TranscriptSegment] = []
        identities_cnt = 0
        financial_cnt = 0
        suspicious_cnt = 0
        max_risk = 0
        max_end_time = 0.0

        for idx, item in enumerate(timeline_raw):
            ts_label = item.get("timestamp", f"[{idx * 15:02d} --> {(idx + 1) * 15:02d}]")
            raw_text = item.get("transcript", "")
            speaker, clean_text = extract_speaker_and_text(raw_text, f"Speaker {(idx % 2) + 1}")

            # Parse start and end seconds from timestamp string like [00:00:15 --> 00:00:30]
            start_sec = 0.0
            end_sec = 0.0
            clean_ts = ts_label.replace("[", "").replace("]", "")
            if "-->" in clean_ts:
                s_part, e_part = clean_ts.split("-->", 1)
                s_tokens = s_part.strip().split(":")
                e_tokens = e_part.strip().split(":")
                try:
                    if len(s_tokens) == 3:
                        start_sec = (
                            int(s_tokens[0]) * 3600 + int(s_tokens[1]) * 60 + float(s_tokens[2])
                        )
                    elif len(s_tokens) == 2:
                        start_sec = int(s_tokens[0]) * 60 + float(s_tokens[1])
                    if len(e_tokens) == 3:
                        end_sec = (
                            int(e_tokens[0]) * 3600 + int(e_tokens[1]) * 60 + float(e_tokens[2])
                        )
                    elif len(e_tokens) == 2:
                        end_sec = int(e_tokens[0]) * 60 + float(e_tokens[1])
                except (ValueError, IndexError):
                    pass

            if end_sec > max_end_time:
                max_end_time = end_sec

            # Gather detections for this segment
            seg_detections = []
            for d in detections_raw:
                if d.get("timestamp") == ts_label:
                    seg_detections = d.get("detections", [])
                    break

            from core.profiles import get_profile_keywords

            profile_keywords = get_profile_keywords(custodian_name=custodian_name.strip())

            if not seg_detections:
                # Run internal hotword tagger if API detections were empty
                seg_detections = tag_transcript_detections(
                    clean_text, extra_keywords=profile_keywords
                )
            elif profile_keywords:
                # Append profile investigation detections
                p_dets = tag_transcript_detections(clean_text, extra_keywords=profile_keywords)
                for pd in p_dets:
                    if pd.get("type") == "profile" and pd not in seg_detections:
                        seg_detections.append(pd)

            # Classify detections counts
            for det in seg_detections:
                t = det.get("type", "").lower() or det.get("category", "").lower()
                if "id" in t or "person" in t:
                    identities_cnt += 1
                elif "fin" in t or "money" in t:
                    financial_cnt += 1
                else:
                    suspicious_cnt += 1

            intent, flagged_kw, risk = screen_text_for_intent(
                clean_text, extra_keywords=profile_keywords
            )
            if risk > max_risk:
                max_risk = risk

            segment_objs.append(
                TranscriptSegment(
                    recording=recording,
                    speaker_tag=speaker,
                    start_time_seconds=start_sec,
                    end_time_seconds=end_sec,
                    text_content=clean_text,
                    detected_intent=intent,
                    flagged_keywords=[d.get("term", "") for d in seg_detections if d.get("term")],
                    risk_score=risk,
                )
            )

        TranscriptSegment.objects.bulk_create(segment_objs, batch_size=1000)

        recording.total_segments = len(segment_objs)
        recording.duration_seconds = int(max_end_time)
        recording.risk_score = max_risk
        recording.save()

    # Emit forensic findings to Q-Link knowledge graph dynamically from detected entities
    try:
        from q_link.backend.dispatcher import emit_forensic_finding
        from q_link.models import ForensicEntity

        custodian = custodian_name.strip()
        if custodian and segment_objs:
            secondaries = []
            seen_terms = set()
            for seg in segment_objs:
                for term in seg.flagged_keywords or []:
                    term = (term or "").strip()
                    if not term or term.lower() == custodian.lower() or term.lower() in seen_terms:
                        continue
                    seen_terms.add(term.lower())
                    secondaries.append(
                        {
                            "name": term,
                            "type": ForensicEntity.EntityType.UNKNOWN,
                            "relation_type": "INTERCEPT_MENTION",
                            "direction": "out",
                        }
                    )
            if secondaries:
                emit_forensic_finding(
                    source_module="q_voice",
                    event_type="VOICE_SURVEILLANCE_DISPATCH",
                    primary_entity_data={
                        "name": custodian,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=secondaries,
                    evidence_data={
                        "source_module": "q_voice",
                        "source_model": "AudioRecording",
                        "source_record_id": str(recording.id),
                        "evidence_url": f"/voice/recording/{recording.id}/",
                        "summary_snippet": f"Surveillance audio '{filename}' established communication nexus.",
                    },
                    timeline_title=f"Voice Nexus: {custodian}",
                    timeline_description=f"Audio intercept established nexus with {', '.join([s['name'] for s in secondaries])}",
                    severity="WARNING",
                )
    except Exception as err:
        logger.warning(f"Error dispatching Q-Voice findings to Q-Link: {err}")

    logger.info(
        f"Persisted audio recording {recording.call_ref} ({recording.total_segments} segments, {recording.duration_seconds}s)"
    )

    # Propagate extracted entities from transcript to InvestigationProfile keywords
    if custodian_name.strip():
        try:
            from core.entity_extractor import extract_entities_from_text
            from core.models import InvestigationProfile
            from core.profiles import add_keywords_to_profile

            full_transcript = " ".join(seg.text_content for seg in segment_objs if seg.text_content)
            if full_transcript:
                discovered = extract_entities_from_text(
                    full_transcript,
                    source_context="Voice Surveillance",
                    custodian_name=custodian_name.strip(),
                )
                kws_to_add = [
                    e["name"] for e in discovered if e.get("name") and len(e["name"]) >= 3
                ]
                if kws_to_add:
                    prof = InvestigationProfile.objects.filter(
                        full_name__iexact=custodian_name.strip()
                    ).first()
                    if prof:
                        add_keywords_to_profile(prof.id, kws_to_add)
        except Exception as ex_prof:
            logger.debug(f"Auto-keyword propagation in Q-Voice skipped: {ex_prof}")

    return recording, ""


def delete_audio_recording(recording_id: str | uuid.UUID) -> bool:
    """
    Deletes an audio recording and associated transcript segments.
    """
    try:
        recording = AudioRecording.objects.get(id=recording_id)
        recording.delete()
        return True
    except (AudioRecording.DoesNotExist, ValueError, ValidationError):
        return False


@transaction.atomic
def delete_custodian_recordings(custodian_name: str) -> int:
    """
    Deletes all audio recordings and associated segments for a custodian profile.
    """
    clean_name = custodian_name.strip()
    is_general = clean_name.lower() in ("general custodian", "unassigned", "")

    if is_general:
        qs = AudioRecording.objects.filter(
            Q(custodian_name="")
            | Q(custodian_name__iexact="General Custodian")
            | Q(custodian_name__isnull=True)
        )
    else:
        qs = AudioRecording.objects.filter(custodian_name__iexact=clean_name)

    count = qs.count()
    if count > 0:
        qs.delete()
        logger.info(f"Deleted {count} audio recording(s) for custodian '{custodian_name}'")
    return count


def extract_suggested_entities_for_voice(
    timeline: list[dict[str, Any]],
    custodian_name: str = "",
    analyzed_profiles: list[dict[str, Any]] | None = None,
    existing_keywords: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts suggested counterparties and entities from Q-Voice transcript timeline segments,
    defaulting to the auditee profile matching the audio recording's custodian.
    """
    from core.entity_extractor import extract_entities_from_transcript_segments

    default_pid = ""
    default_pname = custodian_name
    if analyzed_profiles:
        matched = next(
            (
                p
                for p in analyzed_profiles
                if p["name"].strip().lower() == custodian_name.strip().lower()
            ),
            None,
        )
        if matched:
            default_pid = str(matched["id"])
            default_pname = matched["name"]
        elif analyzed_profiles:
            default_pid = str(analyzed_profiles[0]["id"])
            default_pname = analyzed_profiles[0]["name"]

    return extract_entities_from_transcript_segments(
        segments=timeline,
        custodian_name=custodian_name,
        default_profile_id=default_pid,
        default_profile_name=default_pname,
        existing_keywords=existing_keywords,
    )


def add_suggested_voice_entity_keyword_service(
    profile_id: str | uuid.UUID,
    keyword: str,
) -> dict[str, Any]:
    """
    Promotes a suggested entity discovered from voice intercepts into
    an investigation profile's search/flag keywords.
    """
    from core.models import InvestigationProfile
    from core.profiles import add_keywords_to_profile, get_profile_by_id

    clean_kw = str(keyword or "").strip()
    if not clean_kw:
        raise ValueError("Entity keyword cannot be empty.")

    clean_id = str(profile_id or "").strip()
    profile = get_profile_by_id(clean_id)
    if not profile:
        profile = InvestigationProfile.objects.filter(full_name__iexact=clean_id).first()

    if not profile:
        raise ValueError(f"Investigation profile not found for '{clean_id}'.")

    with transaction.atomic():
        updated_prof = add_keywords_to_profile(profile.id, [clean_kw])

    logger.info(
        "Promoted suggested voice entity '{}' to profile '{}' (Total keywords: {})",
        clean_kw,
        updated_prof.full_name,
        len(updated_prof.keywords or []),
    )

    return {
        "status": "success",
        "keyword": clean_kw,
        "profile_id": str(updated_prof.id),
        "profile_name": updated_prof.full_name,
        "keywords_count": len(updated_prof.keywords or []),
        "keywords": updated_prof.keywords or [],
    }


def bulk_add_voice_entities_as_keywords_service(
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Batch promotes multiple suggested voice entities into profile keywords.
    Items format: [{'profile_id': '...', 'keyword': '...'}, ...]
    """
    from core.models import InvestigationProfile
    from core.profiles import add_keywords_to_profile, get_profile_by_id

    if not items:
        return {"status": "success", "added_count": 0, "results": []}

    grouped_by_pid: dict[str, list[str]] = {}
    for item in items:
        pid = str(item.get("profile_id", "")).strip()
        kw = str(item.get("keyword", "")).strip()
        if pid and kw:
            grouped_by_pid.setdefault(pid, []).append(kw)

    results = []
    total_added = 0
    with transaction.atomic():
        for raw_pid, kws in grouped_by_pid.items():
            profile = get_profile_by_id(raw_pid)
            if not profile:
                profile = InvestigationProfile.objects.filter(full_name__iexact=raw_pid).first()
            if not profile:
                continue

            prev_len = len(profile.keywords or [])
            updated_prof = add_keywords_to_profile(profile.id, kws)
            new_len = len(updated_prof.keywords or [])
            added_for_p = new_len - prev_len
            total_added += added_for_p
            results.append(
                {
                    "profile_id": str(updated_prof.id),
                    "profile_name": updated_prof.full_name,
                    "added_count": added_for_p,
                    "keywords_count": new_len,
                }
            )

    return {
        "status": "success",
        "added_count": total_added,
        "results": results,
    }
