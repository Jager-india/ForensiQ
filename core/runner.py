"""
ForensiQ Enterprise Test Suite Discoverer & Runner
Directs test discovery to the installed forensic application modules to avoid
dual-import namespace collisions when discovering from root BASE_DIR.
"""

from django.conf import settings
from django.test.runner import DiscoverRunner


class ForensicTestRunner(DiscoverRunner):
    """
    Standard test runner for ForensiQ.
    When no test labels are explicitly provided to 'python manage.py test',
    it automatically discovers and tests all registered forensic apps and core.
    """

    def build_suite(self, test_labels=None, extra_tests=None, **kwargs):
        if not test_labels:
            test_labels = [
                app_label
                for app_label in settings.INSTALLED_APPS
                if not app_label.startswith("django.") and app_label not in ("django_cotton", "ui")
            ]
        return super().build_suite(test_labels=test_labels, extra_tests=extra_tests, **kwargs)
