#!/usr/bin/env python
"""
ForensiQ Pre-Commit Quality, Security & Architecture Validator
Enforces:
1. Mandatory documentation (INSTRUCTION.md, SCHEMA.md, USER_GUIDE.md) & dbdiagram.io schemas
2. Cotton template tag safety (<c-slot name="..."> standard)
3. Ruff code formatting & linting standards
4. Bandit automated security scanning
5. Django system & ORM sanity checks (manage.py check)
"""

import re
import subprocess  # nosec B404
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def print_step(title: str) -> None:
    print(f"\n[ForensiQ Hook] >> {title}...")


def check_app_documentation() -> bool:
    print_step("Checking Mandatory App Documentation (INSTRUCTION.md, SCHEMA.md, USER_GUIDE.md)")

    app_dirs = [BASE_DIR / "core", BASE_DIR / "ui"]
    apps_folder = BASE_DIR / "apps"
    if apps_folder.exists():
        app_dirs.extend(
            [d for d in apps_folder.iterdir() if d.is_dir() and (d / "__init__.py").exists()]
        )

    required_files = ["INSTRUCTION.md", "SCHEMA.md", "USER_GUIDE.md"]
    errors = []

    for app in app_dirs:
        rel_app = app.relative_to(BASE_DIR)
        for req in required_files:
            target = app / req
            if not target.exists():
                errors.append(f"Missing required documentation: '{rel_app}/{req}'")
            elif target.stat().st_size < 50:
                errors.append(
                    f"Documentation file '{rel_app}/{req}' is too short (empty/placeholder)."
                )

        # Check for DBML syntax in SCHEMA.md
        schema_file = app / "SCHEMA.md"
        if schema_file.exists():
            content = schema_file.read_text(encoding="utf-8", errors="ignore")
            if "Table " not in content and "dbdiagram.io" not in content:
                errors.append(
                    f"'{rel_app}/SCHEMA.md' is missing DBML / dbdiagram.io compatible schema definition."
                )

    if errors:
        print("\n[FAIL] Documentation Check Failed:")
        for err in errors:
            print(f"   * {err}")
        return False

    print(
        f"   [OK] All {len(app_dirs)} applications have valid INSTRUCTION.md, SCHEMA.md (dbdiagram.io), and USER_GUIDE.md."
    )
    return True


def check_cotton_templates() -> bool:
    print_step("Checking Cotton Template Rules & Windows Compatibility")

    html_files = list(BASE_DIR.rglob("*.html"))
    errors = []
    colon_slot_regex = re.compile(r"<c-slot:[a-zA-Z0-9_-]+", re.IGNORECASE)

    for html_file in html_files:
        # Ignore virtualenv or cache
        if ".venv" in html_file.parts or ".git" in html_file.parts:
            continue

        rel_path = html_file.relative_to(BASE_DIR)
        content = html_file.read_text(encoding="utf-8", errors="ignore")

        # Check for Windows colon syntax bug
        if colon_slot_regex.search(content):
            errors.append(
                f"'{rel_path}' contains illegal '<c-slot:name>' tag. Use '<c-slot name=\"...\">' instead to prevent Windows WinError 123."
            )

    if errors:
        print("\n[FAIL] Cotton Template Syntax Check Failed:")
        for err in errors:
            print(f"   * {err}")
        return False

    print("   [OK] All Django Cotton templates conform to standard tag & slot rules.")
    return True


def check_ruff() -> bool:
    print_step("Running Ruff Linter & Formatter Validation")
    try:
        # Check linting
        subprocess.run(
            ["uv", "run", "ruff", "check", "."],  # nosec B603, B607
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        # Check formatting
        subprocess.run(
            ["uv", "run", "ruff", "format", "--check", "."],  # nosec B603, B607
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        print("   [OK] Ruff linting and formatting passed (0 issues).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] Ruff check failed:\n{e.stdout}\n{e.stderr}")
        print("   [TIP] Run 'uv run ruff check --fix .' and 'uv run ruff format .' to auto-fix.")
        return False


def check_bandit() -> bool:
    print_step("Running Bandit Security Static Analysis")
    try:
        subprocess.run(
            [  # nosec B603, B607
                "uv",
                "run",
                "bandit",
                "-r",
                ".",
                "-x",
                "./.venv,./staticfiles,./tests,./scripts",
                "-c",
                "pyproject.toml",
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        print("   [OK] Bandit security checks passed (0 vulnerabilities detected).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] Bandit security check failed:\n{e.stdout}\n{e.stderr}")
        return False


def check_django_system() -> bool:
    print_step("Running Django System Sanity Checks (manage.py check)")
    try:
        subprocess.run(  # nosec B603, B607
            ["uv", "run", "python", str(BASE_DIR / "manage.py"), "check"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        print("   [OK] Django system checks passed (0 issues).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] Django system check failed:\n{e.stderr or e.stdout}")
        return False


def check_django_migrations() -> bool:
    print_step("Checking Missing Django Model Migrations (makemigrations --check)")
    try:
        subprocess.run(  # nosec B603, B607
            [
                "uv",
                "run",
                "python",
                str(BASE_DIR / "manage.py"),
                "makemigrations",
                "--check",
                "--dry-run",
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        print("   [OK] Django model migrations are fully up to date (0 pending migrations).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] Pending Django migrations detected:\n{e.stderr or e.stdout}")
        print("   [TIP] Run 'uv run python manage.py makemigrations' to create migration files.")
        return False


def main():
    print("=" * 60)
    print("  ForensiQ Pre-Commit Quality & Architecture Validator")
    print("=" * 60)

    checks = [
        check_app_documentation,
        check_cotton_templates,
        check_ruff,
        check_bandit,
        check_django_system,
        check_django_migrations,
    ]

    all_passed = True
    for check_fn in checks:
        if not check_fn():
            all_passed = False

    if not all_passed:
        print("\n" + "=" * 60)
        print("[REJECTED] PRE-COMMIT CHECK FAILED: Fix the errors above before committing.")
        print("=" * 60 + "\n")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[PASSED] PRE-COMMIT CHECK PASSED: Codebase meets all architecture standards.")
    print("=" * 60 + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
