# Q-Link — Data & Architecture Flow

> **Audience**: Anyone seeking a clear, layman-friendly explanation of how Q-Link acts as the master forensic "brain" of ForensiQ, connecting the dots across emails, bank transactions, chats, and SAP ledgers — grounded in the actual Python codebase.

---

## 1. The Big Picture: What is `q_link`?

In a complex fraud investigation, **evidence is scattered across different silos**:
- In **`q_bank`**, an employee receives money from an unknown person named "S. Sharma".
- In **`q_mail`**, the same employee receives an email with an invoice from `sharma.trading@gmail.com`.
- In **`q_scan`**, a seized laptop contains an Excel file listing "Sunil Sharma" as the nominee of a vendor.
- In **`q_ledger`**, SAP records show that purchase orders were approved for "Sharma Logistics" without tenders.
- In **`q_chat`**, a WhatsApp message says: *"Sharma ji, send it to the same account"*.

No single department or tool has the full picture. If you look at `q_bank` alone, it just looks like a normal bank transfer.

**Q-Link is the master intelligence graph and syndicate detector**. It:
1. **Aggregates Evidence from All 8 Modules**: Automatically harvests entities from bank statements, emails, audio wiretaps, chats, disk scans, and SAP ledgers.
2. **Performs Entity Resolution & De-duplication**: Realizes that "S. Sharma", "Sunil Sharma", "sharma.trading@gmail.com", and "Sharma Logistics" are all the **same person or group** using fuzzy string matching and canonical identifiers.
3. **Builds a Master Knowledge Graph**: Maps out who is connected to whom, how much money moved between them, and what emails or chats connect them.
4. **Fires Automated Fraud Syndicate Alerts**: Automatically flags high-level fraud patterns (e.g., *Vendor Kickback Detected*, *Shared Phone/Address*, *Hidden Family Member Beneficiary*).
5. **AI Syndicate Dossier Writer (`llm_agent.py`)**: Uses specialized AI prompts to summarize an entire fraud syndicate's network in clear executive English.

---

## 2. Architecture & File Breakdown

The `q_link` codebase acts as the central convergence point for the whole platform:

```
apps/q_link/
├── models.py                 # Schemas: ForensicEntity, EntityAlias, EntityRelationship, EvidencePointer, TimelineEvent, IntelligenceAlert
├── selectors.py              # Read queries: Network graph topology, entity profiles, alert feeds, chronological timelines
├── services.py               # Orchestration: Triggers full-system sync, creates manual links, resolves conflicts
├── views.py                  # Controllers: Master graph dashboard, entity dossier explorer, AI synthesis endpoints
├── urls.py                   # Route mapping: Endpoints for knowledge graph visualization and intelligence alerts
├── templates/q_link/         # UI templates: dashboard.html with interactive Vis.js graph canvas
├── prompts/                  # AI Prompts: syndicate_overview.txt, dual_entity_pathways.txt, single_entity_dossier.txt
└── backend/                  # Intelligence & Synchronization engines
    ├── sync_all.py           # Master harvester: Pulls and normalizes entities from all 8 forensic modules
    ├── dispatcher.py         # Real-time event broker: Updates graph when any individual app finishes ingesting files
    └── llm_agent.py          # AI Knowledge Graph Analyst: Explains hidden pathways between any two suspects
```

---

## 3. End-to-End Data Flow

Here is how isolated evidence points become an interconnected fraud graph:

```mermaid
flowchart TD
    subgraph Analytical Evidence Silos
        QBank["Q-Bank - (Bank Accounts and Narrations)"]
        QMail["Q-Mail - (Email Senders and Inboxes)"]
        QTrail["Q-Trail - (Conduits and Money Loops)"]
        QScan["Q-Scan - (Laptop Files and Nominee Hits)"]
        QVerify["Q-Verify - (Invoices and Tampered Docs)"]
        QVoice["Q-Voice - (Audio Diarization and Callers)"]
        QLedger["Q-Ledger - (SAP Vendors and Purchase Orders)"]
        QChat["Q-Chat - (WhatsApp and Teams Messages)"]
    end
    
    QBank & QMail & QTrail & QScan & QVerify & QVoice & QLedger & QChat -->|"1. Data Harvest Trigger"| SyncAll["Master Harvester - (q_link/backend/sync_all.py)"]
    
    subgraph Entity Resolution and Graph Synthesis
        SyncAll -->|"2. Normalizes IDs (EMAIL, ACC, PHONE, VENDOR)"| Canonical["Canonical Normalizer"]
        Canonical -->|"3. Matches Aliases via RapidFuzz"| AliasResolver["Entity Resolver - (EntityAlias)"]
        AliasResolver -->|"Creates or Updates Nodes"| EntityDB[("ForensicEntity Table")]
        
        SyncAll -->|"4. Synthesizes Edges (EMAILED, TRANSFERRED, KINSHIP, PO)"| RelDB[("EntityRelationship Table")]
        SyncAll -->|"5. Creates Master Timeline"| TimeDB[("TimelineEvent Table")]
    end
    
    EntityDB & RelDB -->|"6. Anomaly and Rule Check"| AlertEngine["Alert Generator"]
    AlertEngine -->|"Generates Kickback or Collusion Alerts"| AlertDB[("IntelligenceAlert Table")]
    
    EntityDB & RelDB -->|"7. Feeds Graph Data"| GraphUI["Interactive Knowledge Graph - (templates/q_link/dashboard.html)"]
    
    EntityDB & RelDB -->|"8. AI Synthesis"| LLMAgent["llm_agent.py"]
    LLMAgent -->|"Generates Syndicate Dossier"| GraphUI
```

### Detailed Flow Steps:

1. **Master Synchronization (`backend/sync_all.py`)**:
   - The investigator clicks "Sync Intelligence" on the Q-Link dashboard, or an individual app triggers a background sync via `dispatcher.py`.
   - `sync_all.py` queries every app database table across the system.

2. **Canonical Normalization & De-duplication**:
   - Entities are transformed into standard canonical keys:
     - Emails: `EMAIL:sharma@vendor.com`
     - Bank Accounts: `ACC:HDFC:1234567890`
     - Phone Numbers: `PHONE:+919876543210`
     - Vendors: `VENDOR:V10023`
     - Employees: `EMP:HYU-9021`
   - If an entity appears under slight spelling variations (e.g., "S. Sharma" vs "Sunil Sharma"), `EntityAlias` uses `core.fuzzy` (RapidFuzz) to link the alias to the master `ForensicEntity`.

3. **Relationship Edge Creation (`models.EntityRelationship`)**:
   - The engine generates directed connections between entities:
     - `TRANSFERRED_FUNDS` (sourced from `q_bank` and `q_trail`)
     - `EMAILED` (sourced from `q_mail`)
     - `ISSUED_PO` / `APPROVED_BY` (sourced from `q_ledger`)
     - `KINSHIP` / `SPOUSE` / `NOMINEE` (sourced from `q_scan` and `core.entity_extractor`)
     - `COMMUNICATED_ON_CHAT` (sourced from `q_chat`)

4. **Automated Intelligence Alerts (`models.IntelligenceAlert`)**:
   - Q-Link analyzes the assembled graph topology looking for fraud signatures:
     - **Vendor Kickback Alert**: If an employee approved an SAP Purchase Order for Vendor V, and that same vendor (or the vendor's spouse) sent money to the employee's bank account.
     - **Shared Digital Identifier**: If a vendor company and an employee share the same phone number, PAN, or physical address.
     - **Conduit Alert**: If an intermediary is detected moving funds between an employee and a supplier.

5. **AI Investigative Dossier Synthesis (`backend/llm_agent.py`)**:
   - Investigators can select any single entity (to generate a complete 360-degree background dossier) or select any two entities (to discover hidden pathways connecting them).
   - `llm_agent.py` loads prompts from `prompts/dual_entity_pathways.txt` and feeds the graph traversal into the LLM, producing an executive report.

---

## 4. Business Logic Flow & Decision Rules

Q-Link functions as the cognitive intelligence correlation engine, evaluating whether multi-source connections establish corporate fraud, bribery, or conflict of interest.

```mermaid
flowchart TD
    HarvestTrigger([Harvest All Active App Records]) --> CanonicalRule["1. Normalize Canonical Identifiers (EMAIL, ACC, PHONE, VENDOR, EMP)"]
    
    CanonicalRule --> FuzzyCheck{"2. Fuzzy Name Match against Existing Entities?"}
    FuzzyCheck -->|"Score >= 0.85"| MergeAlias["Attach EntityAlias (confidence >= 0.85) to Master Node"]
    FuzzyCheck -->|"Score < 0.85"| CreateNode["Create New ForensicEntity Node"]
    
    MergeAlias & CreateNode --> EdgeSynthesis["3. Synthesize Directed Evidence Edges (RelDB)"]
    
    subgraph Syndicate Pattern Rules
        EdgeSynthesis --> CheckKickback{"Kickback Check: PO Approved in q_ledger AND Funds Returned in q_bank?"}
        CheckKickback -->|"Yes"| AlertKickback["Fire CRITICAL Alert: Suspected Vendor Kickback"]
        CheckKickback -->|"No"| CheckShared{"Shared Identifier Check: Employee and Vendor share Phone, PAN, or Address?"}
        
        CheckShared -->|"Yes"| AlertShared["Fire CRITICAL Alert: Undisclosed Beneficial Ownership"]
        CheckShared -->|"No"| CheckKinshipFlow{"Kinship Conduit Check: Vendor paying Employee Nominee or Spouse?"}
        
        CheckKinshipFlow -->|"Yes"| AlertKinship["Fire CRITICAL Alert: Indirect Kickback via Relative"]
        CheckKinshipFlow -->|"No"| CheckSecretComms{"Secret Channel Check: Official PO followed by WhatsApp or Personal Mail?"}
        
        CheckSecretComms -->|"Yes"| AlertComms["Fire HIGH Alert: Off-the-Record Procurement Coordination"]
        CheckSecretComms -->|"No"| NormalAssociate["Standard Associate Relationship Edge"]
    end
    
    AlertKickback & AlertShared & AlertKinship & AlertComms --> FeedAlerts["Save IntelligenceAlert Records - Elevate Target Risk Rating"]
    FeedAlerts --> AIPathways["Trigger LLM Graph Reasoning (Dual Entity Pathways)"]
```

### Detailed Business Rules & Logic Specifications:

| Rule Name | Trigger Condition | Logic & Thresholds | Outcome / Business Action |
| :--- | :--- | :--- | :--- |
| **Canonical Identity Mapping** | Raw record contains email, account, vendor ID, or phone | Formats: `EMAIL:x@y.com`, `ACC:BANK:123`, `PHONE:+91..`, `VENDOR:V100`. Strip whitespace, lowercasing. | Creates unique deterministic primary key nodes that cross boundaries between apps. |
| **Fuzzy Alias Resolution** | New proper noun string encountered during harvest | Evaluates `rapidfuzz.fuzz.token_sort_ratio`. Threshold >= 85%. | Connects variants ("S. Sharma", "Sunil Sharma", "Sharmaji") into a single `ForensicEntity` via `EntityAlias`. |
| **Vendor Kickback Rule** | Employee approved SAP PO, and Vendor sent funds to Employee | Relational graph cycle: `(Emp)-[APPROVED_BY]->(PO)<-[ISSUED_PO]-(Vendor)` AND `(Vendor)-[TRANSFERRED_FUNDS]->(Emp)`. | Fires **CRITICAL Intelligence Alert**: Proves direct financial quid-pro-quo. |
| **Undisclosed Beneficial Ownership** | Employee and Vendor share attributes | Matching metadata fields: `phone_number`, `pan_number`, `bank_account_no`, or office address. | Fires **CRITICAL Intelligence Alert**: Proves the employee owns or controls the vendor company. |
| **Indirect Kinship Conduit Rule** | Vendor transfers funds to employee's spouse/nominee | Relational graph: `(Emp)-[SPOUSE/NOMINEE]->(Relative)<-[TRANSFERRED_FUNDS]-(Vendor)`. | Fires **CRITICAL Intelligence Alert**: Exposes indirect bribes routed through family members. |
| **Off-the-Record Comms Rule** | Corporate procurement coupled with WhatsApp or personal mail | Vendor and employee communicate via `q_chat` (WhatsApp) or `q_mail` (Gmail) within +/- 3 days of a PO or tender date. | Fires **HIGH Intelligence Alert**: Flags improper commercial side-channel communications. |
| **Entity Risk Rating Calculation** | Alerts, transaction weights, and relationship edges | Accumulates risk points based on active alerts (+30 per Critical alert, +15 per High alert). Max 100. | Prioritizes target auditees in top investigative matrices. |

---

## 5. Key Database Entities in `q_link`

| Model Name | What it Stores | Why it Matters to the Investigator |
| :--- | :--- | :--- |
| `ForensicEntity` | Entity type, canonical identifier, display name, risk rating, target flag | The master profile node in the knowledge graph. |
| `EntityAlias` | Master entity, alias variant name, match source, confidence | Tracks all alternate spellings and nicknames of a person or company. |
| `EntityRelationship` | Source entity, target entity, relation type, weight, source app | The directed edge (transfer, email, marriage, approval) connecting two nodes. |
| `EvidencePointer` | Source app name, record UUID, file reference | Clickable link taking the auditor directly back to the original email, invoice, or bank row. |
| `TimelineEvent` | Timestamp, entity, description, source module | Universal chronological feed of everything that happened in the case. |
| `IntelligenceAlert` | Title, description, severity (`HIGH`, `CRITICAL`), related entities | Automated red flags uncovering fraud syndicates. |

---

## 6. How `q_link` Connects to Other Apps

- **To all apps (`q_bank`, `q_mail`, `q_trail`, `q_scan`, `q_verify`, `q_voice`, `q_ledger`, `q_chat`)**: Q-Link is the **unifying capstone** of ForensiQ. It consumes data from all 8 modules and maintains bi-directional `EvidencePointer` links back to the source records.
