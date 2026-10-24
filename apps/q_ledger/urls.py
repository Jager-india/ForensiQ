from django.urls import path

from . import views

app_name = "q_ledger"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("api/vendors/", views.vendor_directory_api_view, name="vendor_directory_api"),
    path("export-current-view/", views.export_current_view, name="export_current_view"),
    path("reset/", views.reset_data_view, name="reset_data"),
]
