import urllib.parse

from django.shortcuts import redirect


class PortalAuthMiddleware:
    """
    Middleware that enforces master portal password authentication across
    all ForensiQ analytical modules and views (except exempt routes).
    """

    EXEMPT_PREFIXES = (
        "/login/",
        "/logout/",
        "/static/",
        "/media/",
        "/admin/",
        "/favicon.ico",
        "/manuals/",
        "/privacy/",
        "/terms/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info

        # Check if requested path is exempt
        is_exempt = any(path.startswith(prefix) for prefix in self.EXEMPT_PREFIXES)

        if not is_exempt:
            is_authenticated = request.session.get("portal_authenticated", False)
            if not is_authenticated:
                next_param = urllib.parse.quote(request.get_full_path())
                return redirect(f"/login/?next={next_param}")

        response = self.get_response(request)
        return response
