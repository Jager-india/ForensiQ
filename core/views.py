import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from config import ALLOWED_KEYWORDS_EXTENSIONS, MAX_KEYWORDS_FILE_SIZE

from .audits import (
    create_audit,
    generate_next_audit_name,
    get_active_audit,
    get_all_audits,
    map_profiles_to_audit,
    set_active_audit,
)
from .manuals import get_manual_by_key, get_user_manuals
from .modules import get_discovered_modules
from .profiles import (
    add_keywords_to_profile,
    attach_document_to_profile,
    create_investigation_profile,
    extract_keywords_from_file,
    get_all_profiles,
    set_active_profile,
    update_investigation_profile,
)
from .selectors import get_active_audit_module_stats


@csrf_protect
@require_http_methods(["GET", "POST"])
def portal_login_view(request):
    """
    Master Portal Password Login View.
    Authenticates investigative access using only a portal password key.
    """
    next_url = request.GET.get("next") or request.POST.get("next") or "/"

    # Sanitize next_url against open redirect
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    # If already logged in, redirect straight away
    if request.session.get("portal_authenticated", False):
        return redirect(next_url)

    error = None

    if request.method == "POST":
        password = request.POST.get("password", "").strip()
        expected_password = getattr(settings, "PORTAL_ACCESS_PASSWORD", "")

        if password and expected_password and password == expected_password:
            request.session["portal_authenticated"] = True
            request.session.modified = True
            return redirect(next_url)
        else:
            error = "Invalid portal access key. Please verify your credentials."

    return render(
        request,
        "core/login.html",
        {
            "error": error,
            "next": next_url,
        },
    )


@require_http_methods(["GET", "POST"])
def portal_logout_view(request):
    """
    Logout View to lock the workstation and clear session credentials.
    """
    request.session.flush()
    return redirect("/login/")


@require_GET
def landing_view(request: HttpRequest) -> HttpResponse:
    """
    ForensiQ Landing Page dynamically loading all modules from apps/ directory,
    registered investigation profiles with their investigation keywords,
    forensic audits with mapped profiles, and active audit usage statistics.
    """
    modules = get_discovered_modules()
    active_audit = get_active_audit(request)
    module_stats = get_active_audit_module_stats(active_audit)

    used_satellite_count = 0
    for m in modules:
        m_name = m.get("name", "").lower()
        stat_item = module_stats.get(m_name) or module_stats.get(m.get("app_name", "")) or {}
        m["is_used"] = stat_item.get("is_used", False)
        m["status_badge"] = stat_item.get("status_badge", m.get("tag", "LIVE"))
        m["stats_line1"] = stat_item.get("stats_line1", "")
        m["stats_line2"] = stat_item.get("stats_line2", "")
        if m_name != "link" and m["is_used"]:
            used_satellite_count += 1

    profiles = [p.to_dict() for p in get_all_profiles()]
    audits = [a.to_dict() for a in get_all_audits()]
    next_audit_name = generate_next_audit_name()
    return render(
        request,
        "core/landing.html",
        {
            "modules": modules,
            "total_modules": len(modules),
            "used_satellite_count": used_satellite_count,
            "profiles": profiles,
            "profiles_json": json.dumps(profiles),
            "audits": audits,
            "audits_json": json.dumps(audits),
            "next_audit_name": next_audit_name,
        },
    )


@require_POST
def create_profile_view(request: HttpRequest) -> HttpResponse:
    """
    Creates a new investigation profile with optional investigation keywords
    from modal submission or AJAX fetch.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    full_name = str(payload.get("full_name") or "").strip()
    if not full_name:
        if is_json:
            return JsonResponse(
                {"status": "error", "message": "Target name is required."}, status=400
            )
        messages.error(request, "Target profile full name is required.")
        return redirect(payload.get("next", "/"))

    keywords_input = payload.get("keywords")
    if not keywords_input and not is_json:
        # Also check comma-separated keywords string from form post
        keywords_input = request.POST.get("keywords_input", "")

    is_substantiated_raw = payload.get("is_substantiated", False)
    is_substantiated = is_substantiated_raw in (True, "true", "True", "1", 1, "on")

    profile = create_investigation_profile(
        full_name=full_name,
        category=str(payload.get("category") or "EMPLOYEE").strip(),
        related_employee=str(payload.get("related_employee") or "").strip(),
        employee_id=str(payload.get("employee_id") or "").strip(),
        department=str(payload.get("department") or "").strip(),
        designation=str(payload.get("designation") or "").strip(),
        email=str(payload.get("email") or "").strip(),
        phone=str(payload.get("phone") or "").strip(),
        is_substantiated=is_substantiated,
        notes=str(payload.get("notes") or "").strip(),
        avatar_color=str(payload.get("avatar_color") or "").strip(),
        keywords=keywords_input,
    )

    # Check for attached evidentiary / legal document file
    if "document_file" in request.FILES:
        try:
            attach_document_to_profile(
                profile_id=profile.id,
                file_obj=request.FILES["document_file"],
                filename=request.FILES["document_file"].name,
            )
        except Exception as exc:
            messages.warning(
                request, f"Profile created, but document processing had an issue: {exc}"
            )

    # Automatically set newly created profile as active in session
    set_active_profile(request, profile.id)

    if is_json:
        return JsonResponse({"status": "success", "profile": profile.to_dict()})

    messages.success(
        request, f"Investigation Profile '{profile.full_name}' successfully registered."
    )
    next_url = payload.get("next") or "/"
    return redirect(next_url)


@require_POST
def edit_profile_view(request: HttpRequest, profile_id: str) -> HttpResponse:
    """
    Updates an existing investigation profile.
    Supports JSON AJAX requests or standard HTML form submissions.
    (Note: Profile deletion is strictly prohibited).
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    full_name = str(payload.get("full_name") or "").strip()
    if not full_name:
        if is_json:
            return JsonResponse(
                {"status": "error", "message": "Target name is required."}, status=400
            )
        messages.error(request, "Target profile full name is required.")
        return redirect(payload.get("next", "/"))

    keywords_input = payload.get("keywords")
    if not keywords_input and not is_json:
        keywords_input = request.POST.get("keywords_input", "")

    is_substantiated_raw = payload.get("is_substantiated", False)
    is_substantiated = is_substantiated_raw in (True, "true", "True", "1", 1, "on")

    try:
        profile = update_investigation_profile(
            profile_id=profile_id,
            full_name=full_name,
            category=str(payload["category"]).strip() if "category" in payload else None,
            related_employee=str(payload["related_employee"]).strip()
            if "related_employee" in payload
            else None,
            employee_id=str(payload.get("employee_id") or "").strip(),
            department=str(payload.get("department") or "").strip(),
            designation=str(payload.get("designation") or "").strip(),
            email=str(payload.get("email") or "").strip(),
            phone=str(payload.get("phone") or "").strip(),
            is_substantiated=is_substantiated,
            status=str(payload.get("status") or "ACTIVE").strip() or "ACTIVE",
            notes=str(payload.get("notes") or "").strip(),
            avatar_color=str(payload.get("avatar_color") or "").strip(),
            keywords=keywords_input if keywords_input is not None else None,
        )

        if "document_file" in request.FILES:
            try:
                attach_document_to_profile(
                    profile_id=profile.id,
                    file_obj=request.FILES["document_file"],
                    filename=request.FILES["document_file"].name,
                )
            except Exception as exc:
                messages.warning(
                    request, f"Profile updated, but document processing had an issue: {exc}"
                )
    except ValueError as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=404)
        messages.error(request, str(err))
        return redirect(payload.get("next", "/"))
    except Exception as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=500)
        messages.error(request, f"Failed updating profile: {err}")
        return redirect(payload.get("next", "/"))

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "message": f"Investigation Profile '{profile.full_name}' successfully updated.",
                "profile": profile.to_dict(),
            }
        )

    messages.success(request, f"Investigation Profile '{profile.full_name}' successfully updated.")
    next_url = payload.get("next") or "/"
    return redirect(next_url)


@require_POST
def upload_profile_document_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Attaches an evidentiary or legal document to an Investigation Profile.
    Extracts counterparties and synchronizes with Q-Link.
    """
    uploaded_file = request.FILES.get("file") or request.FILES.get("document_file")
    if not uploaded_file:
        return JsonResponse({"status": "error", "message": "No file uploaded."}, status=400)

    description = request.POST.get("description", "").strip()

    try:
        doc = attach_document_to_profile(
            profile_id=profile_id,
            file_obj=uploaded_file,
            filename=uploaded_file.name,
            description=description,
        )
        return JsonResponse(
            {
                "status": "success",
                "message": f"Successfully attached '{doc.filename}' to profile.",
                "document": doc.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed attaching document: {err}"}, status=500
        )


@require_POST
def add_profile_keywords_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Appends search and investigation keywords to an existing investigation profile.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    keywords = payload.get("keywords")
    if not keywords:
        return JsonResponse(
            {"status": "error", "message": "At least one keyword is required."},
            status=400,
        )

    try:
        profile = add_keywords_to_profile(profile_id, keywords)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Keywords appended to {profile.full_name}",
                "profile": profile.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_POST
def parse_keywords_file_view(request: HttpRequest) -> JsonResponse:
    """
    Parses and extracts keywords from an uploaded .txt file.
    Returns the extracted list of keywords for client-side tag insertion.
    """
    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse(
            {
                "status": "error",
                "message": "No file uploaded. Please select a .txt file.",
            },
            status=400,
        )

    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_KEYWORDS_EXTENSIONS:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Unsupported file type '{ext}'. Only .txt files are supported for keyword upload.",
            },
            status=400,
        )

    if uploaded_file.size > MAX_KEYWORDS_FILE_SIZE:
        return JsonResponse(
            {"status": "error", "message": "File exceeds 10MB size limit."},
            status=400,
        )

    try:
        keywords = extract_keywords_from_file(uploaded_file, uploaded_file.name)
        return JsonResponse(
            {
                "status": "success",
                "filename": uploaded_file.name,
                "count": len(keywords),
                "keywords": keywords,
            }
        )
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed parsing keywords file: {err}"},
            status=500,
        )


@require_POST
def upload_profile_keywords_file_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Uploads a .txt keywords file and directly attaches
    extracted investigation keywords to an existing profile.
    """
    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse(
            {
                "status": "error",
                "message": "No file uploaded. Please select a .txt file.",
            },
            status=400,
        )

    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_KEYWORDS_EXTENSIONS:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Unsupported file type '{ext}'. Only .txt files are supported for keyword upload.",
            },
            status=400,
        )

    if uploaded_file.size > MAX_KEYWORDS_FILE_SIZE:
        return JsonResponse(
            {"status": "error", "message": "File exceeds 10MB size limit."},
            status=400,
        )

    try:
        keywords = extract_keywords_from_file(uploaded_file, uploaded_file.name)
        if not keywords:
            return JsonResponse(
                {"status": "error", "message": "No valid keywords found in the uploaded file."},
                status=400,
            )

        profile = add_keywords_to_profile(profile_id, keywords)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Appended {len(keywords)} keywords from '{uploaded_file.name}' to {profile.full_name}.",
                "filename": uploaded_file.name,
                "added_count": len(keywords),
                "profile": profile.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed uploading keywords: {err}"},
            status=500,
        )


@require_POST
def set_active_profile_view(request: HttpRequest) -> HttpResponse:
    """
    Switches or clears the active investigation profile for the current investigator session.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    profile_id = str(payload.get("profile_id") or "").strip()
    profile = set_active_profile(request, profile_id if profile_id else None)

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "active_profile": profile.to_dict() if profile else None,
            }
        )

    next_url = payload.get("next") or request.META.get("HTTP_REFERER") or "/"
    return redirect(next_url)


@require_POST
def set_active_audit_view(request: HttpRequest) -> HttpResponse:
    """
    Switches or clears the active audit for the current investigator session.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    audit_id = str(payload.get("audit_id") or "").strip()
    audit = set_active_audit(request, audit_id if audit_id else None)

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "active_audit": audit.to_dict() if audit else None,
            }
        )

    next_url = payload.get("next") or request.META.get("HTTP_REFERER") or "/"
    return redirect(next_url)


@require_GET
def profile_list_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning all registered investigation profiles for client-side dropdowns and selectors.
    """
    profiles = get_all_profiles()
    return JsonResponse(
        {
            "status": "success",
            "profiles": [p.to_dict() for p in profiles],
        }
    )


@require_POST
def create_audit_view(request: HttpRequest) -> HttpResponse:
    """
    Creates a new Forensic Audit with an auto-generated unique name (YYYY-WB-XX)
    and maps initial investigation profiles under it.
    Supports both JSON AJAX submission and standard form POST.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    title = str(payload.get("title") or "").strip()
    description = str(payload.get("description") or "").strip()
    status = str(payload.get("status") or "ACTIVE").strip() or "ACTIVE"
    raw_name = payload.get("name")
    name = str(raw_name).strip() if raw_name and str(raw_name).strip() else None

    # Handle profile IDs from JSON list or form getlist
    profile_ids = []
    if is_json:
        raw_pids = payload.get("profile_ids")
        if isinstance(raw_pids, list):
            profile_ids = [str(x).strip() for x in raw_pids if str(x).strip()]
    else:
        raw_list = request.POST.getlist("profile_ids")
        for item in raw_list:
            if not item:
                continue
            item_str = str(item).strip()
            if item_str.startswith("["):
                try:
                    profile_ids.extend(
                        [str(x).strip() for x in json.loads(item_str) if str(x).strip()]
                    )
                except Exception:
                    profile_ids.extend(
                        [x.strip() for x in item_str.strip("[]").split(",") if x.strip()]
                    )
            elif "," in item_str:
                profile_ids.extend([x.strip() for x in item_str.split(",") if x.strip()])
            else:
                profile_ids.append(item_str)

    try:
        audit = create_audit(
            name=name,
            title=title,
            description=description,
            status=status,
            profile_ids=profile_ids,
        )
    except Exception as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=400)
        messages.error(request, f"Failed to create audit: {err}")
        return redirect(payload.get("next", "/"))

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "audit": audit.to_dict(),
                "next_audit_name": generate_next_audit_name(),
            }
        )

    messages.success(request, f"Audit '{audit.name}' successfully created.")
    return redirect(payload.get("next", "/"))


@require_POST
def map_audit_profiles_view(request: HttpRequest, audit_id: str) -> JsonResponse:
    """
    Updates or replaces mapped investigation profiles under a specific audit.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    replace = bool(payload.get("replace", True))
    raw_pids = payload.get("profile_ids", [])
    if isinstance(raw_pids, str):
        try:
            raw_pids = json.loads(raw_pids)
        except Exception:
            raw_pids = [x.strip() for x in raw_pids.split(",") if x.strip()]

    try:
        audit = map_profiles_to_audit(audit_id, raw_pids, replace=replace)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Updated profile mappings for Audit '{audit.name}'",
                "audit": audit.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_GET
def audit_list_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning all registered audits and their mapped profiles.
    """
    audits = get_all_audits()
    return JsonResponse(
        {
            "status": "success",
            "audits": [a.to_dict() for a in audits],
            "next_audit_name": generate_next_audit_name(),
        }
    )


@require_GET
def get_next_audit_name_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning the next sequential auto-generated audit name (YYYY-WB-XX).
    """
    year_param = request.GET.get("year")
    year = int(year_param) if year_param and year_param.isdigit() else None
    return JsonResponse(
        {
            "status": "success",
            "next_name": generate_next_audit_name(year=year),
        }
    )


@require_GET
def manuals_view(request: HttpRequest) -> HttpResponse:
    """
    ForensiQ User Manuals & Documentation Hub view.
    Displays interactive manuals for core platform and forensic analytical modules.
    """
    all_manuals = get_user_manuals()
    selected_key = request.GET.get("app", "core").strip().lower()

    active_manual = get_manual_by_key(selected_key) or (all_manuals[0] if all_manuals else None)
    if active_manual:
        selected_key = active_manual["key"]

    context = {
        "manuals": all_manuals,
        "manuals_json": json.dumps(all_manuals),
        "active_key": selected_key,
        "active_manual": active_manual,
    }
    return render(request, "core/manuals.html", context)


@require_GET
def privacy_policy_view(request: HttpRequest) -> HttpResponse:
    """
    ForensiQ Forensic Investigation Privacy Policy & Evidentiary Governance view.
    """
    return render(request, "core/privacy.html")


@require_GET
def terms_of_use_view(request: HttpRequest) -> HttpResponse:
    """
    ForensiQ Forensic Workstation Terms of Use & Evidentiary Integrity view.
    """
    return render(request, "core/terms.html")
