# `q_trail` — Investigator & Auditor User Guide

## 1. Investigative Workflow
1. **Automatic Data Ingestion from Q-Bank:** Q-Trail has no direct file upload mechanism. It automatically reads accounts, auditee profiles, and bank transactions directly from **Q-Bank** statements imported for the active audit or auditee list.
2. **Define Source & Target Entities:** Select two or more auditee profiles to compare transfers and search for intermediary pass-through nodes.
3. **Execute Flow Stitcher:** Q-Trail correlates multi-bank timestamps and identifies pass-through conduits where funds were moved within designated temporal windows (e.g., 24 hours, 7 days).
4. **Analyze Circular Flows:** Highlight closed loops where funds flowed through intermediary shell entities back to the target director/promoter.
5. **Export Sankey Diagram:** Export publication-ready interactive fund flow diagrams for inclusion in charge-sheets and forensic dossiers.

