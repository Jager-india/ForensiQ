"""
Q-Trail URL Configuration
"""

from django.urls import path

from .views import add_counterparty_keyword_view, analyze_api_view, dashboard_view

app_name = "q_trail"

urlpatterns = [
    path("", dashboard_view, name="dashboard"),
    path("api/analyze/", analyze_api_view, name="analyze_api"),
    path(
        "api/add-counterparty-keyword/",
        add_counterparty_keyword_view,
        name="add_counterparty_keyword",
    ),
]
