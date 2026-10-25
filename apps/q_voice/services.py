"""
Q-Voice Forensic Services
Business logic orchestrating remote transcription API calls, audio ingestion, diarization, and database persistence.
"""

import hashlib
import os
import re
import threading
import uuid
from pathlib import Path
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
    *,
    filename: str,
    file_bytes: bytes,
    content_type: str = "audio/wav",
    prompt: str | None = None,
    language: str | None = None,
    task: str | None = "transcribe",
    timeout_sec: float | None = None,
) -> tuple[bool, dict[str, Any] | None, str]:
    """
    Calls the remote Q-Voice ASR and Diarization API at VOICE_MODEL_ENDPOINT.
    Returns (success, api_data_dict, error_message).
    """
    api_url = get_voice_api_endpoint()
    voice_timeout_setting = getattr(settings, "VOICE_API_TIMEOUT", None)
    voice_timeout_env = os.getenv("VOICE_API_TIMEOUT")
    effective_timeout = float(timeout_sec or voice_timeout_setting or voice_timeout_env or 1800.0)

    try:
        files = {"file": (filename, file_bytes, content_type)}
        data: dict[str, Any] = {}
        if prompt:
            data["prompt"] = prompt
        if language and language.strip().lower() != "auto":
            data["language"] = language.strip().lower()
        if task and task.strip().lower() in ("transcribe", "translate"):
            data["task"] = task.strip().lower()

        response = requests.post(api_url, files=files, data=data, timeout=effective_timeout)

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
            f"Connection timed out ({effective_timeout}s) attempting to connect to transcription server at {api_url}. Verify server is running and accessible.",
        )
    except requests.exceptions.RequestException as exc:
        return (
            False,
            None,
            f"Failed to reach transcription server at {api_url}: {exc}",
        )


def _execute_voice_transcription(
    recording_id: str,
    language: str = "auto",
    task: str = "transcribe",
) -> None:
    """
    Background worker thread: reads audio payload from disk, requests transcription from Model-Host
    with domain keyword prompt priming, processes segments, extracts entities, and propagates findings.
    """
    try:
        recording = AudioRecording.objects.get(id=recording_id)
    except AudioRecording.DoesNotExist:
        logger.error(f"Cannot transcribe audio recording {recording_id}: record does not exist.")
        return

    try:
        filename = recording.source_filename or "recording.wav"
        file_bytes = b""
        if recording.audio_file:
            try:
                recording.audio_file.open("rb")
                file_bytes = recording.audio_file.read()
                recording.audio_file.close()
            except Exception as e:
                logger.warning(f"Could not read audio_file field: {e}")

        if not file_bytes and recording.audio_file_path:
            p = Path(recording.audio_file_path)
            if p.exists():
                file_bytes = p.read_bytes()

        if not file_bytes:
            recording.transcription_status = AudioRecording.TranscriptionStatus.FAILED
            recording.error_message = "Audio file payload is empty or could not be read from disk."
            recording.save(update_fields=["transcription_status", "error_message", "updated_at"])
            return

        # Prepare domain priming prompt from custodian and profile keywords
        from core.models import InvestigationProfile
        from core.profiles import get_profile_keywords

        custodian_name = recording.custodian_name.strip()
        profile_keywords = get_profile_keywords(custodian_name=custodian_name)

        all_active_keywords = set(profile_keywords)
        for prof in InvestigationProfile.objects.filter(status="ACTIVE"):
            for kw in prof.keywords or []:
                all_active_keywords.add(kw)
            if prof.full_name:
                all_active_keywords.add(prof.full_name)

        # Prioritize target custodian keywords at the front of prompt priming
        ordered_keywords = list(profile_keywords)
        for kw in sorted(all_active_keywords):
            if kw not in ordered_keywords:
                ordered_keywords.append(kw)
        prompt_str = ", ".join(ordered_keywords[:50]) if ordered_keywords else None

        # Content type determination
        lower_fn = filename.lower()
        if lower_fn.endswith(".mp3"):
            c_type = "audio/mpeg"
        elif lower_fn.endswith(".ogg"):
            c_type = "audio/ogg"
        elif lower_fn.endswith(".m4a"):
            c_type = "audio/mp4"
        else:
            c_type = "audio/wav"

        success, api_data, error_msg = request_remote_transcription(
            filename=filename,
            file_bytes=file_bytes,
            content_type=c_type,
            prompt=prompt_str,
            language=language,
            task=task,
        )

        if not success or not api_data:
            recording.transcription_status = AudioRecording.TranscriptionStatus.FAILED
            recording.error_message = (
                error_msg or "Transcription daemon returned empty or invalid response."
            )
            recording.save(update_fields=["transcription_status", "error_message", "updated_at"])
            return

        # Extract timeline and detections from API payload
        timeline_raw = api_data.get("timeline_transcript", [])
        detections_raw = api_data.get("suspicious_detections", [])

        # Process OpenAI-compatible or faster-whisper granular segments
        if not timeline_raw and "segments" in api_data and isinstance(api_data["segments"], list):
            for s in api_data["segments"]:
                s_sec = float(s.get("start", 0.0))
                e_sec = float(s.get("end", s_sec + 4.0))
                s_fmt = f"{int(s_sec) // 3600:02d}:{(int(s_sec) % 3600) // 60:02d}:{int(s_sec) % 60:02d}"
                e_fmt = f"{int(e_sec) // 3600:02d}:{(int(e_sec) % 3600) // 60:02d}:{int(e_sec) % 60:02d}"
                timeline_raw.append(
                    {
                        "timestamp": f"[{s_fmt} --> {e_fmt}]",
                        "transcript": s.get("text", "").strip(),
                        "start_seconds": s_sec,
                        "end_seconds": e_sec,
                        "speaker": s.get("speaker", ""),
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

                s_fmt = f"{int(s_sec) // 3600:02d}:{(int(s_sec) % 3600) // 60:02d}:{int(s_sec) % 60:02d}"
                e_fmt = f"{int(e_sec) // 3600:02d}:{(int(e_sec) % 3600) // 60:02d}:{int(e_sec) % 60:02d}"

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
            recording.segments.all().delete()

            segment_objs: list[TranscriptSegment] = []
            max_risk = 0
            max_end_time = 0.0

            for idx, item in enumerate(timeline_raw):
                ts_label = item.get("timestamp", f"[{idx * 15:02d} --> {(idx + 1) * 15:02d}]")
                raw_text = item.get("transcript", "")
                fallback_spk = item.get("speaker") or f"Speaker {(idx % 2) + 1}"
                speaker, clean_text = extract_speaker_and_text(raw_text, fallback_spk)

                start_sec = float(item.get("start_seconds", 0.0))
                end_sec = float(item.get("end_seconds", 0.0))

                if end_sec == 0.0 and "-->" in ts_label:
                    clean_ts = ts_label.replace("[", "").replace("]", "")
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

                # Gather detections
                seg_detections = []
                for d in detections_raw:
                    if d.get("timestamp") == ts_label:
                        seg_detections = d.get("detections", [])
                        break

                if not seg_detections:
                    seg_detections = tag_transcript_detections(
                        clean_text, extra_keywords=list(all_active_keywords)
                    )
                elif all_active_keywords:
                    p_dets = tag_transcript_detections(
                        clean_text, extra_keywords=list(all_active_keywords)
                    )
                    for pd in p_dets:
                        if pd.get("type") == "profile" and pd not in seg_detections:
                            seg_detections.append(pd)

                intent, flagged_kw, risk = screen_text_for_intent(
                    clean_text, extra_keywords=list(all_active_keywords)
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
                        flagged_keywords=[
                            d.get("term", "") for d in seg_detections if d.get("term")
                        ],
                        risk_score=risk,
                    )
                )

            TranscriptSegment.objects.bulk_create(segment_objs, batch_size=1000)

            recording.total_segments = len(segment_objs)
            recording.duration_seconds = int(max_end_time)
            recording.risk_score = max_risk
            recording.transcription_status = AudioRecording.TranscriptionStatus.COMPLETED
            recording.error_message = ""
            recording.save()

        # Emit forensic findings to Q-Link knowledge graph dynamically with smart entity typing
        try:
            from q_link.backend.dispatcher import emit_forensic_finding
            from q_link.models import ForensicEntity

            from core.entity_extractor import extract_entities_from_text
            from core.models import InvestigationProfile
            from core.profiles import add_keywords_to_profile

            full_transcript = " ".join(seg.text_content for seg in segment_objs if seg.text_content)
            custodian = custodian_name.strip()

            if custodian and full_transcript:
                discovered_entities = extract_entities_from_text(
                    full_transcript,
                    source_context="Voice Surveillance",
                    custodian_name=custodian,
                )

                secondaries = []
                seen_terms = set()
                kws_to_add = []

                for ent in discovered_entities:
                    e_name = ent.get("name", "").strip()
                    if (
                        not e_name
                        or e_name.lower() == custodian.lower()
                        or e_name.lower() in seen_terms
                    ):
                        continue
                    seen_terms.add(e_name.lower())
                    kws_to_add.append(e_name)

                    e_type_str = (ent.get("type") or ent.get("category") or "UNKNOWN").upper()
                    if e_type_str in ("PERSON", "EMPLOYEE"):
                        f_type = ForensicEntity.EntityType.EMPLOYEE
                        rel_type = "VOICE_INTERCEPT_PERSON"
                    elif e_type_str in ("VENDOR", "ORGANIZATION", "COMPANY"):
                        f_type = ForensicEntity.EntityType.VENDOR
                        rel_type = "VOICE_INTERCEPT_AFFILIATION"
                    elif e_type_str in ("ROLE", "DESIGNATION"):
                        f_type = ForensicEntity.EntityType.UNKNOWN
                        rel_type = "VOICE_ROLE_MENTION"
                    else:
                        f_type = ForensicEntity.EntityType.UNKNOWN
                        rel_type = "INTERCEPT_MENTION"

                    secondaries.append(
                        {
                            "name": e_name,
                            "type": f_type,
                            "relation_type": rel_type,
                            "direction": "out",
                            "confidence": float(ent.get("confidence", 0.9)),
                            "metadata": {"context": ent.get("context", "")},
                        }
                    )

                for seg in segment_objs:
                    for term in seg.flagged_keywords or []:
                        term = (term or "").strip()
                        if (
                            not term
                            or term.lower() == custodian.lower()
                            or term.lower() in seen_terms
                        ):
                            continue
                        seen_terms.add(term.lower())
                        kws_to_add.append(term)
                        t_upper = term.upper()
                        if any(
                            w in t_upper
                            for w in ["METEC", "INC", "CORP", "LTD", "COMPANY", "AGENCY"]
                        ):
                            f_type = ForensicEntity.EntityType.VENDOR
                            r_type = "VOICE_INTERCEPT_AFFILIATION"
                        elif any(
                            w in t_upper for w in ["INDHUMATHI", "INDHUMADHI", "KUMAR", "SATHEES"]
                        ):
                            f_type = ForensicEntity.EntityType.EMPLOYEE
                            r_type = "VOICE_INTERCEPT_PERSON"
                        elif any(w in t_upper for w in ["HR", "DESIGN", "MANAGER", "LEAD"]):
                            f_type = ForensicEntity.EntityType.UNKNOWN
                            r_type = "VOICE_ROLE_MENTION"
                        else:
                            f_type = ForensicEntity.EntityType.UNKNOWN
                            r_type = "INTERCEPT_MENTION"

                        secondaries.append(
                            {
                                "name": term,
                                "type": f_type,
                                "relation_type": r_type,
                                "direction": "out",
                                "confidence": 0.85,
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
                            "summary_snippet": f"Surveillance audio '{filename}' established communication nexus with {len(secondaries)} entities.",
                        },
                        timeline_title=f"Voice Intercept Nexus: {custodian}",
                        timeline_description=f"Audio intercept established nexus with {', '.join([s['name'] for s in secondaries[:5]])}",
                        severity="WARNING" if max_risk > 30 else "INFO",
                    )

                if kws_to_add:
                    prof = InvestigationProfile.objects.filter(full_name__iexact=custodian).first()
                    if prof:
                        add_keywords_to_profile(prof.id, kws_to_add)

        except Exception as ex_nexus:
            logger.warning(
                f"Error dispatching Q-Voice findings or propagating keywords: {ex_nexus}"
            )

        logger.info(
            f"Successfully transcribed audio recording {recording.call_ref} ({recording.total_segments} segments, {recording.duration_seconds}s)"
        )

    except Exception as exc:
        logger.exception(
            f"Unhandled exception during background transcription of {recording_id}: {exc}"
        )
        try:
            recording = AudioRecording.objects.get(id=recording_id)
            recording.transcription_status = AudioRecording.TranscriptionStatus.FAILED
            recording.error_message = f"Processing error: {exc}"
            recording.save(update_fields=["transcription_status", "error_message", "updated_at"])
        except Exception as save_err:
            logger.warning(
                f"Could not persist failure status for recording {recording_id}: {save_err}"
            )


def ingest_audio_recording(
    *,
    audio_file,
    call_ref: str = "",
    call_title: str = "",
    custodian_name: str = "",
    language: str = "auto",
    task: str = "transcribe",
    run_async: bool = True,
) -> tuple[AudioRecording | None, str]:
    """
    Saves an uploaded audio recording and triggers background or synchronous transcription.
    Returns (recording, error_msg).
    """
    filename = getattr(audio_file, "name", "recording.wav")
    file_bytes = audio_file.read()
    if hasattr(audio_file, "seek"):
        audio_file.seek(0)
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    from pathlib import Path

    from django.core.files.base import ContentFile

    wrapped_audio = ContentFile(file_bytes, name=Path(filename).name)
    auto_ref = call_ref.strip() or f"CALL-{uuid.uuid4().hex[:8].upper()}"
    auto_title = call_title.strip() or f"Audio - {Path(filename).name}"

    with transaction.atomic():
        recording = AudioRecording.objects.create(
            call_ref=auto_ref,
            call_title=auto_title,
            custodian_name=custodian_name.strip() or "General Custodian",
            call_timestamp=timezone.now(),
            source_filename=filename,
            sha256_hash=sha256,
            audio_file=wrapped_audio,
            transcription_status=AudioRecording.TranscriptionStatus.PROCESSING,
            error_message="",
        )

    if run_async:
        worker = threading.Thread(
            target=_execute_voice_transcription,
            args=(str(recording.id), language, task),
            daemon=True,
        )
        worker.start()
        logger.info(
            f"Queued background voice transcription worker for {recording.call_ref} ({recording.id})"
        )
        return recording, ""
    else:
        _execute_voice_transcription(str(recording.id), language, task)
        recording.refresh_from_db()
        return recording, recording.error_message


def retry_voice_transcription(
    recording_id: str | uuid.UUID,
    language: str = "auto",
    task: str = "transcribe",
    run_async: bool = True,
) -> tuple[bool, str]:
    """
    Retries transcription for a failed or stalled audio recording.
    """
    try:
        recording = AudioRecording.objects.get(id=recording_id)
        recording.transcription_status = AudioRecording.TranscriptionStatus.PROCESSING
        recording.error_message = ""
        recording.save(update_fields=["transcription_status", "error_message", "updated_at"])

        if run_async:
            worker = threading.Thread(
                target=_execute_voice_transcription,
                args=(str(recording.id), language, task),
                daemon=True,
            )
            worker.start()
            logger.info(f"Retrying background voice transcription for {recording.call_ref}")
            return True, ""
        else:
            _execute_voice_transcription(str(recording.id), language, task)
            recording.refresh_from_db()
            return (
                recording.transcription_status == AudioRecording.TranscriptionStatus.COMPLETED,
                recording.error_message,
            )
    except AudioRecording.DoesNotExist:
        return False, "Recording does not exist."
    except Exception as e:
        return False, str(e)


def recover_stalled_recordings(*, stale_seconds: int = 3600) -> int:
    """
    Recovers audio recordings left in PROCESSING status if interrupted by a server restart.
    """
    from datetime import timedelta

    cutoff = timezone.now() - timedelta(seconds=stale_seconds)
    stalled_qs = AudioRecording.objects.filter(
        transcription_status=AudioRecording.TranscriptionStatus.PROCESSING,
        updated_at__lt=cutoff,
    )
    count = stalled_qs.update(
        transcription_status=AudioRecording.TranscriptionStatus.STALLED,
        error_message="Background processing was interrupted. Click 'Retry' to re-run transcription.",
    )
    if count > 0:
        logger.warning(f"Recovered {count} stalled audio recording(s).")
    return count


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
