"""
Q-Voice Forensic Selectors
Queries, aggregates, and computes statistics for voice call recordings, speaker talk-time, and timeline segments.
"""

import uuid
from typing import Any

from django.db.models import Count, Q, QuerySet, Sum

from core.models import InvestigationProfile

from .backend.voice_parser import tag_transcript_detections
from .models import AudioRecording, TranscriptSegment


def get_all_custodian_profiles() -> list[dict[str, Any]]:
    """
    Groups all voice recordings by custodian name and returns aggregate
    forensic metrics per custodian profile for the directory card grid.
    """
    recordings = AudioRecording.objects.all().order_by("-call_timestamp", "-created_at")
    profiles_map = {
        p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all() if p.full_name
    }

    custodians_dict: dict[str, dict[str, Any]] = {}
    for rec in recordings:
        raw_name = rec.custodian_name.strip() if rec.custodian_name else ""
        c_name = raw_name if raw_name else "General Custodian"
        if c_name not in custodians_dict:
            inv_prof = profiles_map.get(c_name.lower())
            custodians_dict[c_name] = {
                "custodian_name": c_name,
                "department": (
                    inv_prof.department
                    if inv_prof and inv_prof.department
                    else (
                        "Procurement & Sourcing"
                        if c_name != "General Custodian"
                        else "General Auditee"
                    )
                ),
                "employee_id": inv_prof.employee_id if inv_prof else "",
                "designation": inv_prof.designation if inv_prof else "",
                "recordings": [],
                "recordings_count": 0,
                "total_duration_seconds": 0,
                "total_segments": 0,
                "flagged_segments_count": 0,
                "max_risk_score": 0,
                "intents_set": set(),
            }
        entry = custodians_dict[c_name]
        entry["recordings"].append(rec)
        entry["total_duration_seconds"] += rec.duration_seconds
        entry["total_segments"] += rec.total_segments
        entry["flagged_segments_count"] += rec.flagged_segments_count
        if rec.risk_score > entry["max_risk_score"]:
            entry["max_risk_score"] = rec.risk_score
        if rec.detected_intent_summary:
            entry["intents_set"].add(rec.detected_intent_summary)

    results = []
    for entry in custodians_dict.values():
        entry["recordings_count"] = len(entry["recordings"])
        mins, secs = divmod(entry["total_duration_seconds"], 60)
        hrs, mins = divmod(mins, 60)
        if hrs > 0:
            entry["total_duration_formatted"] = f"{hrs:02d}:{mins:02d}:{secs:02d}"
        else:
            entry["total_duration_formatted"] = f"{mins:02d}:{secs:02d}"
        entry["intents_list"] = sorted(entry["intents_set"])
        results.append(entry)

    results.sort(
        key=lambda x: (
            0 if x["custodian_name"] != "General Custodian" else 1,
            -x["max_risk_score"],
            -x["total_duration_seconds"],
            -x["recordings_count"],
        )
    )
    return results


def get_custodian_profile_detail(custodian_name: str) -> dict[str, Any]:
    """
    Retrieves full custodian metadata, linked audio recordings, and aggregate stats.
    """
    clean_name = custodian_name.strip()
    is_general = clean_name.lower() in ("general custodian", "unassigned", "")

    if is_general:
        recordings_qs = AudioRecording.objects.filter(
            Q(custodian_name="")
            | Q(custodian_name__iexact="General Custodian")
            | Q(custodian_name__isnull=True)
        )
    else:
        recordings_qs = AudioRecording.objects.filter(custodian_name__iexact=clean_name)

    recordings = list(recordings_qs.order_by("-call_timestamp", "-created_at"))

    inv_prof = (
        InvestigationProfile.objects.filter(full_name__iexact=clean_name).first()
        if not is_general
        else None
    )

    total_duration = sum(r.duration_seconds for r in recordings)
    mins, secs = divmod(total_duration, 60)
    hrs, mins = divmod(mins, 60)
    if hrs > 0:
        duration_fmt = f"{hrs:02d}h {mins:02d}m {secs:02d}s"
    else:
        duration_fmt = f"{mins:02d}m {secs:02d}s"

    total_segments = sum(r.total_segments for r in recordings)
    flagged_segments = sum(r.flagged_segments_count for r in recordings)
    max_risk = max((r.risk_score for r in recordings), default=0)

    return {
        "custodian_name": clean_name if not is_general else "General Custodian",
        "department": (
            inv_prof.department
            if inv_prof and inv_prof.department
            else ("Procurement & Sourcing" if not is_general else "General Auditee")
        ),
        "employee_id": inv_prof.employee_id if inv_prof else "",
        "designation": inv_prof.designation if inv_prof else "",
        "recordings": recordings,
        "recordings_count": len(recordings),
        "total_duration_seconds": total_duration,
        "total_duration_formatted": duration_fmt,
        "total_segments": total_segments,
        "flagged_segments_count": flagged_segments,
        "max_risk_score": max_risk,
    }


def get_combined_timeline_for_custodian(
    custodian_name: str,
    *,
    recording_id: str | uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    """
    Builds the standardized combined acoustic timeline for a custodian profile,
    optionally scoped to a specific recording.
    """
    clean_name = custodian_name.strip()
    is_general = clean_name.lower() in ("general custodian", "unassigned", "")

    if recording_id:
        segments_qs = TranscriptSegment.objects.filter(recording_id=recording_id).select_related(
            "recording"
        )
    elif is_general:
        segments_qs = TranscriptSegment.objects.filter(
            Q(recording__custodian_name="")
            | Q(recording__custodian_name__iexact="General Custodian")
            | Q(recording__custodian_name__isnull=True)
        ).select_related("recording")
    else:
        segments_qs = TranscriptSegment.objects.filter(
            recording__custodian_name__iexact=clean_name
        ).select_related("recording")

    segments = segments_qs.order_by("recording__call_timestamp", "start_time_seconds", "created_at")
    timeline: list[dict[str, Any]] = []

    for seg in segments:
        s_sec = int(seg.start_time_seconds)
        e_sec = int(seg.end_time_seconds)
        s_fmt = f"{s_sec // 3600:02d}:{(s_sec % 3600) // 60:02d}:{s_sec % 60:02d}"
        e_fmt = f"{e_sec // 3600:02d}:{(e_sec % 3600) // 60:02d}:{e_sec % 60:02d}"
        ts_label = f"[{s_fmt} --> {e_fmt}]"

        detections_detail = tag_transcript_detections(seg.text_content)

        timeline.append(
            {
                "recording_id": str(seg.recording_id),
                "call_ref": seg.recording.call_ref,
                "call_title": seg.recording.call_title,
                "timestamp": ts_label,
                "start_seconds": seg.start_time_seconds,
                "end_seconds": seg.end_time_seconds,
                "speaker": seg.speaker_tag or "Speaker",
                "transcript": seg.text_content,
                "detected_intent": seg.detected_intent or "General",
                "risk_score": seg.risk_score,
                "detections": seg.flagged_keywords or [d["term"] for d in detections_detail],
                "detections_detail": detections_detail,
            }
        )

    return timeline


def get_metrics_for_custodian(
    custodian_name: str,
    *,
    recording_id: str | uuid.UUID | None = None,
) -> dict[str, Any]:
    """
    Calculates HUD metrics (identities, financial terms, suspicious parameters)
    for a custodian profile or a specific recording.
    """
    timeline = get_combined_timeline_for_custodian(custodian_name, recording_id=recording_id)
    identities_cnt = 0
    financial_cnt = 0
    suspicious_cnt = 0
    max_risk = 0

    for item in timeline:
        if item["risk_score"] > max_risk:
            max_risk = item["risk_score"]
        for det in item["detections_detail"]:
            t = det.get("type", "")
            if t == "identity":
                identities_cnt += 1
            elif t == "financial":
                financial_cnt += 1
            elif t == "suspicious":
                suspicious_cnt += 1

    if recording_id:
        rec = AudioRecording.objects.filter(id=recording_id).first()
        duration_sec = rec.duration_seconds if rec else 0
        risk_score = rec.risk_score if rec else max_risk
    else:
        cust_info = get_custodian_profile_detail(custodian_name)
        duration_sec = cust_info["total_duration_seconds"]
        risk_score = cust_info["max_risk_score"]

    mins, secs = divmod(duration_sec, 60)
    hrs, mins = divmod(mins, 60)
    if hrs > 0:
        duration_fmt = f"{hrs:02d}h {mins:02d}m {secs:02d}s"
    else:
        duration_fmt = f"{mins:02d}m {secs:02d}s"

    return {
        "identities_count": identities_cnt,
        "financial_count": financial_cnt,
        "suspicious_count": suspicious_cnt,
        "total_segments": len(timeline),
        "duration_formatted": duration_fmt,
        "risk_score": risk_score,
    }


def get_all_recordings() -> QuerySet[AudioRecording]:
    """
    Retrieves all audio recordings ordered by timestamp.
    """
    return AudioRecording.objects.all().order_by("-call_timestamp", "-created_at")


def get_recording_by_id(recording_id: str | uuid.UUID) -> AudioRecording | None:
    """
    Retrieves a single audio recording with prefetched segments.
    """
    try:
        return AudioRecording.objects.prefetch_related("segments").get(id=recording_id)
    except (AudioRecording.DoesNotExist, ValueError):
        return None


def get_combined_timeline_for_recording(recording: AudioRecording) -> list[dict[str, Any]]:
    """
    Builds the standardized combined timeline format for the active recording.
    """
    segments = recording.segments.all().order_by("start_time_seconds", "created_at")
    timeline: list[dict[str, Any]] = []

    for seg in segments:
        s_sec = int(seg.start_time_seconds)
        e_sec = int(seg.end_time_seconds)
        s_fmt = f"{s_sec // 3600:02d}:{(s_sec % 3600) // 60:02d}:{s_sec % 60:02d}"
        e_fmt = f"{e_sec // 3600:02d}:{(e_sec % 3600) // 60:02d}:{e_sec % 60:02d}"
        ts_label = f"[{s_fmt} --> {e_fmt}]"

        # Detections detail with tag classifications
        detections_detail = tag_transcript_detections(seg.text_content)

        timeline.append(
            {
                "timestamp": ts_label,
                "start_seconds": seg.start_time_seconds,
                "end_seconds": seg.end_time_seconds,
                "speaker": seg.speaker_tag or "Speaker",
                "transcript": seg.text_content,
                "detected_intent": seg.detected_intent or "General",
                "risk_score": seg.risk_score,
                "detections": seg.flagged_keywords or [d["term"] for d in detections_detail],
                "detections_detail": detections_detail,
            }
        )

    return timeline


def get_global_voice_metrics() -> dict[str, Any]:
    """
    Computes global metrics across all ingested audio recordings in the system.
    """
    total_recordings = AudioRecording.objects.count()
    duration_sum = (
        AudioRecording.objects.aggregate(total_sec=Sum("duration_seconds"))["total_sec"] or 0
    )
    total_segments = TranscriptSegment.objects.count()
    flagged_segments = TranscriptSegment.objects.filter(risk_score__gte=50).count()
    collusion_calls = (
        AudioRecording.objects.filter(segments__detected_intent="Collusion").distinct().count()
    )

    hrs, remainder = divmod(duration_sum, 3600)
    mins, secs = divmod(remainder, 60)
    duration_fmt = f"{hrs}h {mins}m {secs}s" if hrs > 0 else f"{mins}m {secs}s"

    intent_breakdown = list(
        TranscriptSegment.objects.values("detected_intent")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    return {
        "total_recordings": total_recordings,
        "total_duration_seconds": duration_sum,
        "total_duration_formatted": duration_fmt,
        "total_segments": total_segments,
        "flagged_segments": flagged_segments,
        "collusion_calls": collusion_calls,
        "intent_breakdown": intent_breakdown,
    }
