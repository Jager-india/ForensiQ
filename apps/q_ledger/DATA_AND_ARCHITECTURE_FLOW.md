# Q-Ledger — Data & Architecture Flow

> **Audience**: Anyone seeking a clear, layman-friendly explanation of how Q-Ledger audits SAP ERP procurement data, detects phantom vendors, catches split Purchase Orders, and performs 3-way matching — grounded in the actual Python codebase.

---

## 1. The Big Picture: What is `q_ledger`?

In large corporations, procurement departments spend **hundreds of crores of rupees** buying parts, raw materials, and services through ERP systems like SAP.

Because the volume of procurement is so vast, dishonest employees exploit procedural loopholes to siphon corporate funds:
1. **The "Split Purchase Order" Trick**: If company policy requires Vice President approval for any Purchase Order (PO) above ₹5,00,000, a corrupt manager might issue **two separate POs for ₹4,80,000 on the same day** to bypass senior approval and favor a friendly vendor.
2. **Phantom Vendors**: Creating a fake company in the SAP Vendor Master that has no real warehouse, no real employees, and shares a bank account or phone number with a company employee.
3. **The 3-Way Matching Fraud**: Normally, payment is only made if three documents agree:
   - The **Purchase Order (PO)**: What was ordered.
   - The **Goods Receipt Note (GRN)**: What was physically delivered at the warehouse.
   - The **Vendor Invoice**: What the vendor billed.
   Corrupt actors bill the company for 1,000 parts when only 600 were physically delivered to the factory floor!

**Q-Ledger is an automated SAP procurement audit engine**. It ingests SAP PR/PO dumps, Material Masters (MARA), Storage Locations (SLoc), and General Ledgers (GL), checks them against forensic rules, and instantly flags procurement fraud.

---

## 2. Architecture & File Breakdown

The `q_ledger` codebase is organized around enterprise ERP data pipelines and forensic rule engines:

```
apps/q_ledger/
├── models.py                     # Schemas: LedgerMasterConfig, LedgerDataset, VendorMaster, PurchaseOrder, ERPThreeWayMatch
├── selectors.py                  # Read queries: Fast spend analytics, vendor risk ranking, anomaly summaries
├── services.py                   # Ingestion: Uploads SAP master tables, runs batch anomaly detectors
├── views.py                      # Controllers: ERP dashboard, procurement data grid, anomaly filters
├── urls.py                       # Route mapping: Endpoints for SAP datasets and anomaly views
├── templates/q_ledger/           # UI templates: dashboard.html, includes/table_view.html (Tabulator grids & Plotly charts)
└── backend/                      # Specialized SAP data processing engines
    ├── data_preprocessing.py     # Cleans SAP columns, handles dates, normalizes vendor IDs and material codes
    └── analysis_functions.py     # Computes 3-way match variances, split PO flags, and Plotly spend charts
```

---

## 3. End-to-End Data Flow

Here is how SAP ERP records are ingested and screened for procurement fraud:

```mermaid
flowchart TD
    User([Investigator]) -->|"1. Uploads SAP PR/PO and Master Files (Excel, CSV)"| Intake["Q-Ledger Ingestion View - (q_ledger/views.py)"]
    
    Intake -->|"2. Orchestrates Ingestion"| Service["q_ledger/services.py"]
    
    subgraph SAP Data Preprocessing
        Service -->|"3. Cleans headers and dates"| Preprocessor["data_preprocessing.py"]
        Preprocessor -->|"Normalizes Vendor codes, PO numbers"| CleanData["Normalized SAP Tables"]
    end
    
    subgraph Forensic Procurement Checks
        CleanData -->|"4. Checks PO vs GRN vs Invoice"| ThreeWay["3-Way Match Check - (ERPThreeWayMatch)"]
        CleanData -->|"5. Detects sequential sub-threshold POs"| SplitPO["Split PO Evasion Detector"]
        CleanData -->|"6. Cross-references vendor bank/phone"| VendorCheck["Phantom Vendor Detector"]
    end
    
    ThreeWay & SplitPO & VendorCheck -->|"7. Persists Records"| DB[("Database - (LedgerDataset, VendorMaster, PurchaseOrder)")]
    
    DB -->|"8. Queries Metrics via Selectors"| Selectors["q_ledger/selectors.py"]
    Selectors -->|"9. Interactive Analytics and Grids"| UI["ERP Dashboard - (Plotly Charts + Tabulator Grids)"]
```

### Detailed Flow Steps:

1. **Master Configuration & File Ingestion (`services.py` & `models.py`)**:
   - The investigator uploads standard SAP extraction sheets:
     - **PR/PO File**: Purchase Requisition and Purchase Order transactions.
     - **MARA File**: Material Master dataset.
     - **Vendor Master File**: Vendor names, GSTINs, bank accounts, and addresses.
     - **SLoc & GL Masters**: Storage locations and general ledger account codes.
   - The files are permanently stored in `LedgerDataset` and `LedgerMasterConfig`.

2. **Data Preprocessing & Normalization (`backend/data_preprocessing.py`)**:
   - Cleans SAP column names, handles date formats (`Pstng Date`, `PO Date`), and converts currency numbers into standardized Python decimals.
   - Generates Indian currency formats (formatting amounts in Lakhs and Crores, e.g., ₹ 4.50 Cr).

3. **Core Forensic Anomaly Checkpoints (`backend/analysis_functions.py`)**:
   - **3-Way Match Reconciliation (`ERPThreeWayMatch`)**:
     - Compares the `PO Amount`, `GRN Amount` (physical goods received), and `Invoice Amount`.
     - Calculates the `variance_amount`. If the invoice amount exceeds the goods received, the transaction is flagged with an anomaly type.
   - **Split PO Approval Threshold Evasion**:
     - Identifies vendors receiving multiple POs on the same day or within 48 hours that fall just below executive approval thresholds.
   - **Phantom Vendor Screening**:
     - Screens `VendorMaster` records against employee profiles to find matching phone numbers, PAN cards, or bank account numbers.

4. **Interactive Dashboard & Plotly Visualizations (`selectors.py` & Cotton UI)**:
   - High-level executive charts display **Total Procurement Spend**, **Top 10 High-Risk Vendors**, and **Variance Distribution**.
   - An interactive **Tabulator.js** grid enables auditors to filter down to individual PO numbers, view the approved approver's name, and inspect line-item discrepancies.

---

## 4. Business Logic Flow & Decision Rules

Q-Ledger applies automated internal audit rules to detect procurement leakages and management limit evasions across SAP tables.

```mermaid
flowchart TD
    SAPRow([Incoming SAP Procurement Row]) --> BaselineCheck{"1. Validate against Master Configs (GL, SLoc, Vendor)?"}
    
    BaselineCheck -->|"Unregistered Vendor Code"| FlagUnreg["Flag: UNREGISTERED_VENDOR - Risk Score = 90"]
    BaselineCheck -->|"Approved Vendor Master"| ThreeWayCheck{"2. Execute 3-Way Match (PO vs GRN vs Invoice)"}
    
    FlagUnreg --> ThreeWayCheck
    
    ThreeWayCheck -->|"Invoice Amount > GRN Amount"| FlagOverbill["Flag: OVERBILLING_VARIANCE - Calculate Variance Amount"]
    ThreeWayCheck -->|"GRN Amount < PO Amount and Invoice == PO"| FlagShort["Flag: SHORT_DELIVERY_OVERBILLING"]
    ThreeWayCheck -->|"GRN == 0 but Invoice > 0"| FlagGhost["Flag: PHANTOM_RECEIPT (100% Leakage)"]
    ThreeWayCheck -->|"PO == GRN == Invoice"| MatchClean["Clean 3-Way Match: variance = 0.00"]
    
    FlagOverbill & FlagShort & FlagGhost & MatchClean --> SplitCheck{"3. Split PO Approval Limit Evasion Check"}
    
    SplitCheck -->|"Multiple POs to same vendor within 48h just below threshold"| FlagSplit["Set is_split_po = True - Flag Limit Evasion"]
    SplitCheck -->|"Normal Spaced Procurement"| FlagNormalPO["Standard PO Flow"]
    
    FlagSplit & FlagNormalPO --> ConflictCheck{"4. Conflict of Interest Check (Vendor vs Employee)"}
    
    ConflictCheck -->|"Vendor bank, PAN, or phone matches Employee"| FlagPhantom["Set is_flagged = True on VendorMaster - Proves Shell Vendor"]
    ConflictCheck -->|"No Attribute Collision"| SaveLedger["5. Commit to ERPThreeWayMatch and PurchaseOrder Tables"]
    
    FlagPhantom --> SaveLedger
    SaveLedger --> SpendAgg["Recalculate total_spend and Indian Rupee Formatting (Cr / L)"]
```

### Detailed Business Rules & Logic Specifications:

| Rule Name | Trigger Condition | Logic & Thresholds | Outcome / Business Action |
| :--- | :--- | :--- | :--- |
| **3-Way Match Overbilling Variance** | Vendor invoice amount exceeds goods physically received | Formula: `variance_amount = invoice_amount - grn_amount`. Condition: `variance_amount > 0`. | Flags `OVERBILLING_VARIANCE` anomaly. Proves company paid for goods never received in the warehouse. |
| **Short Delivery Overbilling** | Warehouse received partial goods, but full invoice paid | Condition: `grn_amount < po_amount` AND `invoice_amount == po_amount`. | Flags `SHORT_DELIVERY` anomaly. Prevents inventory shrinkage fraud. |
| **Phantom Delivery (Zero GRN)** | Invoiced and paid with zero goods received | Condition: `grn_amount == 0` AND `invoice_amount > 0`. | Flags `PHANTOM_RECEIPT` (100% fraudulent payout). Escalates directly to legal inquiry. |
| **Split PO Limit Evasion Rule** | Sequential POs issued just below executive threshold | Criteria: 1) Same vendor + same approver, 2) Time delta `<= 48 hours`, 3) Individual PO values `[0.80 * Limit, 0.99 * Limit]`, 4) Combined sum `> Limit`. | Sets `is_split_po = True`. Uncovers intentional evasion of senior executive authorization matrices. |
| **Phantom Vendor Entity Matching** | Vendor bank account, phone, or PAN matches employee | Cross-references `VendorMaster` fields against `core.InvestigationProfile` records. | Sets `is_flagged = True`. Identifies internal employees siphoning funds into shell companies they secretly own. |
| **Indian Rupee Formatting** | Currency presentation in dashboards and charts | Formats: `>= 1,00,00,000` -> `₹ X.XX Cr`, `>= 1,00,000` -> `₹ X.XX L`, else standard digit commas. | Displays human-readable executive financial figures instantly recognizable by management. |

---

## 5. Key Database Entities in `q_ledger`

| Model Name | What it Stores | Why it Matters to the Investigator |
| :--- | :--- | :--- |
| `LedgerMasterConfig` | GL accounts, storage locations, vendor masters files, total counts | Maintains reference baseline files for the active ERP audit. |
| `LedgerDataset` | Uploaded PR/PO and MARA files, total record count, total spend | The active procurement investigation dataset. |
| `VendorMaster` | Vendor code, vendor name, owner name, email, phone, GSTIN, bank details | Dossier of suppliers screened for phantom status or employee collusion. |
| `PurchaseOrder` | PO number, vendor, PO date, total amount, approver, split PO flag | The legal procurement commitment document issued by the company. |
| `ERPThreeWayMatch` | PO number, GRN number, invoice number, amounts, variance, anomaly type | The forensic comparison record proving overbilling or phantom delivery. |

---

## 6. How `q_ledger` Connects to Other Apps

- **To `core`**: Vendors and approvers link to `core.InvestigationProfile`, and datasets belong to the active `core.Audit`.
- **To `q_link`**: Vendor codes, PO numbers, and approver names are fed to `q_link`. If an employee approved POs for a vendor who transferred money to that employee's spouse in `q_bank`, `q_link` triggers a **Vendor Kickback Alert**!
- **To `q_verify`**: Questioned vendor invoices can be passed to `q_verify` to check for Canva or Photoshop metadata alterations.
