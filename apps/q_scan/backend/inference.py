"""
Q-Scan Forensic Snippet Inference Engine
Extracts forensic kinship relationships, employment roles, departments, and vendor affiliations
from raw context snippets identified during endpoint filesystem scans.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class InferenceResult:
    """
    Structured outcome of context snippet inference.
    """

    inference_text: str
    category: str  # KINSHIP, EMPLOYMENT, VENDOR, GENERAL, or empty
    primary_entity: str = ""
    secondary_entity: str = ""
    relation_type: str = ""


class SnippetInferenceEngine:
    """
    Forensic inference extractor analyzing surrounding snippet context against matched keywords.
    """

    KINSHIP_TERMS: ClassVar[set[str]] = {
        "spouse",
        "wife",
        "husband",
        "nominee",
        "son",
        "daughter",
        "child",
        "children",
        "father",
        "mother",
        "brother",
        "sister",
        "parent",
        "relative",
        "dependent",
        "family",
    }

    ROLE_TERMS: ClassVar[set[str]] = {
        "employee",
        "manager",
        "director",
        "head",
        "lead",
        "officer",
        "consultant",
        "proprietor",
        "partner",
        "executive",
        "specialist",
        "auditor",
        "signatory",
    }

    @classmethod
    def _parse_pipe_key_values(cls, snippet: str) -> dict[str, str]:
        """
        Parses structured pipe-delimited key: value snippets like:
        'Employee: Raj | Relationship: Spouse / Wife | Nominee: Monisha | Policy: ...'
        """
        kv_pairs: dict[str, str] = {}
        # Split on pipe or newline
        segments = re.split(r"[|\n]", snippet)
        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue
            if ":" in seg:
                key, val = seg.split(":", 1)
                kv_pairs[key.strip().lower()] = val.strip()
        return kv_pairs

    @classmethod
    def extract_inference(cls, matched_keyword: str, snippet: str) -> InferenceResult:
        """
        Analyzes a matched keyword within its context snippet to produce a high-confidence forensic inference.
        """
        if not snippet or snippet.strip() in {"-", "", "None"}:
            return InferenceResult(inference_text="", category="")

        snip_clean = snippet.strip()
        kw_clean = (matched_keyword or "").strip()
        kw_lower = kw_clean.lower()

        # ------------------------------------------------------------------
        # 1. Pipe-Delimited Structured Format (HR, Family Insurance, Policies)
        # ------------------------------------------------------------------
        kv = cls._parse_pipe_key_values(snip_clean)
        if kv:
            employee = (
                kv.get("employee")
                or kv.get("emp_name")
                or kv.get("name")
                or kv.get("insured")
                or ""
            )
            nominee = kv.get("nominee") or kv.get("beneficiary") or ""
            relationship = (
                kv.get("relationship") or kv.get("relation") or kv.get("relation_type") or ""
            )
            department = (
                kv.get("department") or kv.get("dept") or kv.get("division") or kv.get("unit") or ""
            )
            designation = (
                kv.get("designation")
                or kv.get("role")
                or kv.get("title")
                or kv.get("job_title")
                or ""
            )

            # Clean prefixes (e.g. ID numbers or parenthesis)
            clean_emp = re.sub(r"\s*\([^)]*\)", "", employee).strip() if employee else ""
            clean_nom = re.sub(r"\s*\([^)]*\)", "", nominee).strip() if nominee else ""

            # Check Kinship / Nominee match
            if relationship or nominee:
                rel_display = relationship.strip() or "Nominee / Relative"
                # Normalize common slashes e.g. "Spouse / Wife"
                rel_display_clean = re.sub(r"\s*/\s*", " / ", rel_display)

                # Case A: Keyword is Nominee
                if (
                    kw_lower
                    and clean_nom
                    and (
                        kw_lower in clean_nom.lower()
                        or clean_nom.lower() in kw_lower
                        or kw_lower in nominee.lower()
                    )
                ):
                    emp_display = clean_emp or employee or "Employee"
                    nom_display = clean_nom or kw_clean
                    return InferenceResult(
                        inference_text=f"{nom_display} is {rel_display_clean} of {emp_display}",
                        category="KINSHIP",
                        primary_entity=emp_display,
                        secondary_entity=nom_display,
                        relation_type=rel_display_clean.upper()
                        .replace(" / ", "_")
                        .replace(" ", "_"),
                    )

                # Case B: Keyword is Employee and has a Nominee
                if (
                    kw_lower
                    and clean_emp
                    and (
                        kw_lower in clean_emp.lower()
                        or clean_emp.lower() in kw_lower
                        or kw_lower in employee.lower()
                    )
                    and clean_nom
                ):
                    emp_display = clean_emp or kw_clean
                    return InferenceResult(
                        inference_text=f"{emp_display} has {rel_display_clean}: {clean_nom}",
                        category="KINSHIP",
                        primary_entity=emp_display,
                        secondary_entity=clean_nom,
                        relation_type=rel_display_clean.upper()
                        .replace(" / ", "_")
                        .replace(" ", "_"),
                    )

            # Check Employment / Department / Role match
            if department or designation or (employee and "employee" in kv):
                emp_display = clean_emp or employee or kw_clean
                parts = []
                if department:
                    parts.append(f"at {department}")
                if designation:
                    parts.append(f"as {designation}")

                role_desc = " ".join(parts) if parts else "at Organization"
                return InferenceResult(
                    inference_text=f"{emp_display} is an Employee {role_desc}",
                    category="EMPLOYMENT",
                    primary_entity=emp_display,
                    secondary_entity=department or "Organization",
                    relation_type="EMPLOYEE_DEPARTMENT",
                )

        # ------------------------------------------------------------------
        # 2. Point of Contact / Vendor Reviews / Notes Pattern
        # Example: 'Point of Contact: Balamurugan, Manager of Hydro Pumps (Director: ...)'
        # ------------------------------------------------------------------
        poc_match = re.search(
            r"(?:point of contact|contact person|poc|contact)\s*:\s*([^,;]+?)\s*,\s*(.*?)(?:\(|$|\.\.\.)",
            snip_clean,
            re.IGNORECASE,
        )
        if poc_match:
            person = poc_match.group(1).strip()
            role_and_co = poc_match.group(2).strip()
            sub_m = re.search(
                r"^(Manager|Director|Proprietor|Partner|Authorized Signatory|Lead|Officer|Executive)\s+of\s+(.+)$",
                role_and_co,
                re.IGNORECASE,
            )
            if sub_m:
                role = sub_m.group(1).strip()
                comp = sub_m.group(2).strip()
                return InferenceResult(
                    inference_text=f"{person} is {role} of {comp}",
                    category="VENDOR",
                    primary_entity=person,
                    secondary_entity=comp,
                    relation_type=f"VENDOR_{role.upper()}",
                )
            return InferenceResult(
                inference_text=f"{person} is {role_and_co}",
                category="VENDOR",
                primary_entity=person,
                secondary_entity=role_and_co,
                relation_type="VENDOR_CONTACT",
            )

        # Pattern: 'Manager / Director of <Company>'
        vendor_role_match = re.search(
            r"([A-Za-z\.\s]+?)\s*,\s*(Manager|Director|Proprietor|Partner|Authorized Signatory)\s+of\s+([A-Za-z0-9\.\s]+?)(?:\(|$|\.\.\.|,)",
            snip_clean,
            re.IGNORECASE,
        )
        if vendor_role_match:
            person = vendor_role_match.group(1).strip()
            role = vendor_role_match.group(2).strip()
            comp = vendor_role_match.group(3).strip()
            return InferenceResult(
                inference_text=f"{person} is {role} of {comp}",
                category="VENDOR",
                primary_entity=person,
                secondary_entity=comp,
                relation_type=f"VENDOR_{role.upper()}",
            )

        # ------------------------------------------------------------------
        # 3. Unstructured Kinship Heuristics
        # Patterns like: 'Monisha (wife of Raj)', 'wife of Raj: Monisha', 'nominee Monisha (spouse of Raj)'
        # ------------------------------------------------------------------
        kin_match1 = re.search(
            r"([A-Za-z\.\s]+?)\s*\(\s*(spouse|wife|husband|son|daughter|mother|father|brother|sister)\s+of\s+([A-Za-z\.\s]+?)\s*\)",
            snip_clean,
            re.IGNORECASE,
        )
        if kin_match1:
            p1 = kin_match1.group(1).strip()
            rel = kin_match1.group(2).strip()
            p2 = kin_match1.group(3).strip()
            return InferenceResult(
                inference_text=f"{p1} is {rel.capitalize()} of {p2}",
                category="KINSHIP",
                primary_entity=p2,
                secondary_entity=p1,
                relation_type=rel.upper(),
            )

        kin_match2 = re.search(
            r"(spouse|wife|husband|son|daughter|nominee)\s*[:=]\s*([A-Za-z\.\s]+?)\s*(?:of|for|\(employee:)\s*([A-Za-z\.\s]+?)(?:[|,\.]|$)",
            snip_clean,
            re.IGNORECASE,
        )
        if kin_match2:
            rel = kin_match2.group(1).strip()
            p1 = kin_match2.group(2).strip()
            p2 = kin_match2.group(3).strip()
            return InferenceResult(
                inference_text=f"{p1} is {rel.capitalize()} of {p2}",
                category="KINSHIP",
                primary_entity=p2,
                secondary_entity=p1,
                relation_type=rel.upper(),
            )

        # ------------------------------------------------------------------
        # 4. Unstructured Employment Heuristics
        # Patterns like: 'Employee: X, Department: Y' or 'X (Head Office SCM Finance)'
        # ------------------------------------------------------------------
        emp_match = re.search(
            r"Employee\s*:\s*([A-Za-z\.\s]+?)\s*(?:Department|Dept)\s*:\s*([^|,\.\n]+)",
            snip_clean,
            re.IGNORECASE,
        )
        if emp_match:
            emp = emp_match.group(1).strip()
            dept = emp_match.group(2).strip()
            return InferenceResult(
                inference_text=f"{emp} is an Employee at {dept}",
                category="EMPLOYMENT",
                primary_entity=emp,
                secondary_entity=dept,
                relation_type="EMPLOYEE_DEPARTMENT",
            )

        return InferenceResult(inference_text="", category="")
