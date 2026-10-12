"""
Q-Trail Presentation & View Controllers
=============================================================================
Coordinates user profile selection, multi-bank network reconciliation,
interactive Plotly Dark Sankey fund-flow charts, and Tabulator match tables.
Conforms strictly to agentic-django guidelines: thin views, delegating to
services and selectors.
=============================================================================
"""

import json
from decimal import Decimal

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from loguru import logger

from core.audits import get_active_audit, set_active_audit

from .selectors import (
    generate_trail_sankey_chart,
    get_all_trail_cases,
    get_available_profiles_for_trail,
)
from .services import analyze_profiles_money_trail


def _format_inr(value: float | Decimal | None) -> str:
    """Formats float/decimal into Indian Rupee comma grouping format."""
    if value is None:
        return "0.00"
    try:
        val = float(value)
        return f"{val:,.2f}"
    except (ValueError, TypeError):
        return "0.00"


@csrf_protect
@require_http_methods(["GET", "POST"])
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Trail Multi-Bank Money Trail & Network Matching Dashboard.
    Enables investigators to select multiple auditee profiles and trace
    direct transfers, 1-hop conduit intermediaries, and circular fund loops.
    """
    audit_id_param = request.GET.get("audit_id")
    if audit_id_param is not None:
        active_audit = set_active_audit(request, audit_id_param if audit_id_param.strip() else None)
    else:
        active_audit = get_active_audit(request)

    all_profiles = get_available_profiles_for_trail(audit_id=None)
    audit_profiles = (
        get_available_profiles_for_trail(audit_id=active_audit.id) if active_audit else []
    )

    scope = request.GET.get("scope") or request.POST.get("scope")
    if not scope:
        if active_audit:
            scope = "audit"
        else:
            scope = "all"

    if scope == "audit" and active_audit:
        available_profiles = audit_profiles
    else:
        available_profiles = all_profiles
        scope = "all"

    compare_all = (
        request.GET.get("compare_all") == "1" or request.POST.get("action") == "compare_all"
    )

    # Parse profile IDs and parameters from POST or GET
    if compare_all:
        profiles_with_data = [p["id"] for p in available_profiles if p.get("has_data")]
        profile_ids = (
            profiles_with_data if profiles_with_data else [p["id"] for p in available_profiles]
        )
        time_window_str = request.POST.get(
            "time_window_days", request.GET.get("time_window_days", "0")
        )
        min_amount_str = request.POST.get("min_amount", request.GET.get("min_amount", "1000"))
        save_dossier = request.method == "POST"
        case_title = ""
        if save_dossier and active_audit:
            case_title = f"Audit {active_audit.name} - Money Trail Reconciliation"
            try:
                from .models import CaseDossier

                CaseDossier.objects.filter(title=case_title).delete()
            except Exception as exc:
                logger.debug(f"[Q-Trail] Could not refresh automated dossier: {exc}")
    elif request.method == "POST":
        profile_ids = request.POST.getlist("profile_ids")
        time_window_str = request.POST.get("time_window_days", "0")
        min_amount_str = request.POST.get("min_amount", "1000")
        save_dossier = True
        case_title = request.POST.get("case_title", "").strip()
        if not case_title and active_audit:
            case_title = f"Audit {active_audit.name} - Money Trail Reconciliation"
            try:
                from .models import CaseDossier

                CaseDossier.objects.filter(title=case_title).delete()
            except Exception as exc:
                logger.debug(f"[Q-Trail] Could not refresh automated dossier: {exc}")
    else:
        profile_ids = request.GET.getlist("profile_ids")
        time_window_str = request.GET.get("time_window_days", "0")
        min_amount_str = request.GET.get("min_amount", "1000")
        save_dossier = False
        case_title = ""

    flat_ids = []
    for item in profile_ids:
        if "," in item:
            flat_ids.extend([x.strip() for x in item.split(",") if x.strip()])
        elif item.strip():
            flat_ids.append(item.strip())
    profile_ids = flat_ids

    try:
        time_window_days = max(0, min(365, int(time_window_str)))
    except (ValueError, TypeError):
        time_window_days = 0

    try:
        min_amount = max(1000.0, float(min_amount_str))
    except (ValueError, TypeError):
        min_amount = 1000.0

    # Default auto-selection heuristic: select profiles with available data within the current scope
    if not profile_ids:
        profiles_with_data = [p["id"] for p in available_profiles if p.get("has_data")]
        if len(profiles_with_data) >= 2:
            profile_ids = profiles_with_data
        elif len(available_profiles) >= 2:
            profile_ids = [available_profiles[0]["id"], available_profiles[1]["id"]]
        elif available_profiles:
            profile_ids = [available_profiles[0]["id"]]
        else:
            profile_ids = []

    # Execute money trail reconciliation
    analysis = analyze_profiles_money_trail(
        profile_ids=profile_ids,
        time_window_days=time_window_days,
        min_amount=min_amount,
        case_title=case_title,
        save_dossier=save_dossier,
    )

    direct_df = analysis["direct_transfers"]
    intermediate_df = analysis["intermediate_transfers"]
    metrics = analysis["metrics"]
    circular_trails = analysis["circular_trails"]
    analyzed_profiles = analysis["analyzed_profiles"]

    # Generate interactive Plotly Dark Sankey chart
    sankey_html = generate_trail_sankey_chart(direct_df, intermediate_df, height=480)

    # Format DataFrames for Tabulator tables
    direct_records = direct_df.to_dict(orient="records") if not direct_df.empty else []
    for r in direct_records:
        r["Amount_Formatted"] = f"₹{_format_inr(r.get('Amount'))}"

    intermediate_records = (
        intermediate_df.to_dict(orient="records") if not intermediate_df.empty else []
    )
    for r in intermediate_records:
        r["Outflow_Formatted"] = f"₹{_format_inr(r.get('Outflow_Amount'))}"
        r["Inflow_Formatted"] = f"₹{_format_inr(r.get('Inflow_Amount'))}"
        r["Retention_Formatted"] = f"₹{_format_inr(r.get('Retention_Amount'))}"
        r["Retention_Pct_Str"] = f"{float(r.get('Retention_Pct', 0.0)):.1f}%"

    # Format matrix structure for template rendering
    pairwise_matrix = analysis.get("pairwise_matrix", {})
    pairwise_summaries = analysis.get("pairwise_summaries", [])
    profile_names = [p["name"] for p in analyzed_profiles]

    formatted_matrix = []
    if len(profile_names) >= 2:
        for name_a in profile_names:
            row_targets = []
            for name_b in profile_names:
                cell = pairwise_matrix.get(name_a, {}).get(name_b, {})
                tot = cell.get("total_volume", 0.0)
                row_targets.append(
                    {
                        "target_name": name_b,
                        "is_self": cell.get("is_self", False),
                        "has_flow": cell.get("has_flow", False),
                        "direct_count": cell.get("direct_count", 0),
                        "direct_volume": cell.get("direct_volume", 0.0),
                        "direct_formatted": _format_inr(cell.get("direct_volume", 0.0)),
                        "intermediate_count": cell.get("intermediate_count", 0),
                        "intermediate_volume": cell.get("intermediate_volume", 0.0),
                        "intermediate_formatted": _format_inr(cell.get("intermediate_volume", 0.0)),
                        "total_volume": tot,
                        "total_formatted": _format_inr(tot),
                        "intermediaries": cell.get("intermediaries", []),
                    }
                )
            formatted_matrix.append({"source_name": name_a, "targets": row_targets})

    # Format metrics for presentation
    formatted_metrics = {
        **metrics,
        "total_direct_volume_formatted": _format_inr(metrics["total_direct_volume_inr"]),
        "total_outflow_formatted": _format_inr(metrics["total_outflow_to_intermediaries_inr"]),
        "total_inflow_formatted": _format_inr(metrics["total_inflow_from_intermediaries_inr"]),
        "total_retained_formatted": _format_inr(metrics["total_retained_by_intermediaries_inr"]),
    }

    # Saved case dossiers for reference
    saved_cases = get_all_trail_cases()[:5]

    # Executive Forensic Summary Intelligence
    executive_findings = []
    if formatted_metrics.get("total_intermediate_hops_count", 0) > 0:
        hops_cnt = formatted_metrics["total_intermediate_hops_count"]
        leakage = formatted_metrics.get("total_retained_formatted", "₹0.00")
        executive_findings.append(
            {
                "severity": "CRITICAL" if circular_trails else "WARNING",
                "icon": "fa-solid fa-layer-group",
                "title": f"Rapid Layering & Conduit Velocity: {hops_cnt} Hop(s) Detected",
                "detail": f"Funds routed through unverified third-party conduits with total conduit leakage of {leakage}.",
            }
        )

    if circular_trails:
        loop_cnt = len(circular_trails)
        executive_findings.append(
            {
                "severity": "CRITICAL",
                "icon": "fa-solid fa-arrows-spin",
                "title": f"Circular Flow / Round-Trip Kickbacks: {loop_cnt} Closed Loop(s)",
                "detail": "Capital routed outwards and returned to originator within forensic temporal windows, characteristic of rebate kickback mechanisms.",
            }
        )

    if formatted_metrics.get("total_direct_transfers_count", 0) > 0:
        d_cnt = formatted_metrics["total_direct_transfers_count"]
        d_vol = formatted_metrics.get("total_direct_volume_formatted", "₹0.00")
        executive_findings.append(
            {
                "severity": "INFO",
                "icon": "fa-solid fa-hand-holding-dollar",
                "title": f"Direct Counterparty Volume: {d_cnt} Direct Transfer(s) ({d_vol})",
                "detail": "Direct bank transactions reconciled between auditees and primary targets without intermediary shielding.",
            }
        )

    if analysis.get("metrics", {}).get("keyword_hits_count", 0) > 0:
        kw_cnt = analysis["metrics"]["keyword_hits_count"]
        executive_findings.append(
            {
                "severity": "WARNING",
                "icon": "fa-solid fa-bullseye",
                "title": f"Keyword Interlink Corroboration: {kw_cnt} Match(es)",
                "detail": "Transaction narrations match monitored audit keywords and cross-module investigative targets.",
            }
        )

    chronological_beats = analysis.get("chronological_beats", [])
    conduit_deck = analysis.get("conduit_deck", [])
    topology_graph = analysis.get("topology_graph", {})

    context = {
        "executive_findings": executive_findings,
        "available_profiles": available_profiles,
        "selected_profile_ids": profile_ids,
        "time_window_days": time_window_days,
        "min_amount": min_amount,
        "active_audit": active_audit,
        "scope": scope,
        "audit_profiles_count": len(audit_profiles),
        "all_profiles_count": len(all_profiles),
        "metrics": formatted_metrics,
        "sankey_figure_html": sankey_html,
        "direct_records": direct_records,
        "direct_records_json": json.dumps(direct_records),
        "intermediate_records": intermediate_records,
        "intermediate_records_json": json.dumps(intermediate_records),
        "circular_trails": circular_trails,
        "chronological_beats": chronological_beats,
        "beats_json": json.dumps(chronological_beats),
        "conduit_deck": conduit_deck,
        "conduit_deck_json": json.dumps(conduit_deck),
        "topology_graph": topology_graph,
        "topology_graph_json": json.dumps(topology_graph),
        "analyzed_profiles": analyzed_profiles,
        "profile_names": profile_names,
        "pairwise_matrix": formatted_matrix,
        "pairwise_summaries": pairwise_summaries,
        "saved_cases": saved_cases,
        "trail_keywords": analysis.get("trail_keywords", []),
    }

    return render(request, "q_trail/dashboard.html", context)


@csrf_protect
@require_POST
def analyze_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API endpoint for real-time asynchronous money trail analysis.
    Accepts JSON body or POST form data containing 'profile_ids', 'time_window_days', and 'min_amount'.
    """
    try:
        if request.content_type == "application/json":
            payload = json.loads(request.body.decode("utf-8"))
            profile_ids = payload.get("profile_ids", [])
            time_window_days = int(payload.get("time_window_days", 0))
            min_amount = max(1000.0, float(payload.get("min_amount", 1000.0)))
        else:
            profile_ids = request.POST.getlist("profile_ids")
            time_window_days = int(request.POST.get("time_window_days", 0))
            min_amount = max(1000.0, float(request.POST.get("min_amount", 1000.0)))
    except Exception as e:
        logger.warning(f"Invalid API request payload to Q-Trail analyze: {e}")
        return JsonResponse({"status": "error", "message": "Invalid request payload."}, status=400)

    analysis = analyze_profiles_money_trail(
        profile_ids=profile_ids,
        time_window_days=time_window_days,
        min_amount=min_amount,
    )

    direct_df = analysis["direct_transfers"]
    intermediate_df = analysis["intermediate_transfers"]

    sankey_html = generate_trail_sankey_chart(direct_df, intermediate_df, height=450)

    direct_records = direct_df.to_dict(orient="records") if not direct_df.empty else []
    intermediate_records = (
        intermediate_df.to_dict(orient="records") if not intermediate_df.empty else []
    )

    return JsonResponse(
        {
            "status": "success",
            "metrics": analysis["metrics"],
            "direct_transfers": direct_records,
            "intermediate_transfers": intermediate_records,
            "circular_trails": analysis["circular_trails"],
            "chronological_beats": analysis.get("chronological_beats", []),
            "conduit_deck": analysis.get("conduit_deck", []),
            "topology_graph": analysis.get("topology_graph", {}),
            "pairwise_matrix": analysis.get("pairwise_matrix", {}),
            "pairwise_summaries": analysis.get("pairwise_summaries", []),
            "sankey_html": sankey_html,
        }
    )
