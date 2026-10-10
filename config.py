"""
Forensic-Q Centralized Forensic System Configuration & Engine Registry
=============================================================================
Single Source of Truth (SSOT) for all forensic analytical thresholds,
risk weights, noise filters, regex engines, domain rules, and LLM endpoints.

Every analytical module imports its defaults from this file to ensure
predictability, centralized calibration, and audit defensibility.
=============================================================================
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# =============================================================================
# 01. Q-BANK: Financial & Bank Statement Forensic Engine Configuration
# =============================================================================

DEFAULT_BANK_INVESTIGATION_KEYWORDS: list[str] = ["trust", "sarla"]
"""
Default investigative keyword targets seeded across bank statement triage.
Transactions whose narration or party name matches these terms are immediately
prioritized and highlighted on the Q-Bank dashboard.
"""

CASH_DEPOSIT_HIGH_RISK_THRESHOLD: float = 50000.0
"""
Minimum monetary threshold (in INR) for Cash Deposit Machine (CDM) / cash deposits
to be classified as High-Risk. In forensic anti-money laundering (AML), cash deposits
at or above ₹50,000 frequently signify placement layering, smurfing, or evasion of
income tax reporting limits (Section 269ST).
"""

HIGH_VALUE_DEBIT_THRESHOLD: float = 500000.0
"""
Minimum monetary threshold (in INR) for debit transfers / wires to be flagged
as High-Value Outflows (> ₹5,00,000). High-value wire transfers demand immediate
justification via purchase orders, contracts, or substantiated invoices.
"""

BANK_RISK_SCORE_HIGH_THRESHOLD: int = 70
"""
Composite risk score cutoff (scale 0-100) above which a bank transaction is
formally marked with status 'Flagged' and assigned High Risk severity.
"""

BANK_RISK_SCORE_MEDIUM_THRESHOLD: int = 40
"""
Composite risk score cutoff (scale 0-100) for Medium Risk classification.
Transactions below this threshold are marked Low Risk / Cleared.
"""

HYUNDAI_ENTITY_KEYWORDS: tuple[str, ...] = ("hyundai", "hmil")
"""
Corporate entity markers used to automatically flag and tally internal vendor,
payroll, or employee conflicts of interest inside bank transactions.
"""

BANK_STATEMENT_BATCH_SIZE: int = 250
"""
Database batch size used for bulk insertion (bulk_create) of normalized bank
transactions to completely prevent Django N+1 query bottlenecks during ingestion.
"""

SUPPORTED_STATEMENT_EXTENSIONS: set[str] = {".xlsx", ".xls", ".csv", ".docx", ".txt"}
"""
Permitted file extensions accepted by the Q-Bank statement ingestion parser.
"""


# =============================================================================
# 02. Q-TRAIL: Multi-Bank Money Trail & Intermediary Hop Topology Configuration
# =============================================================================

DEFAULT_MIN_TRANSACTION_THRESHOLD: float = 1000.0
"""
Default minimum monetary threshold (INR) for money trail analysis and flagging.
Transactions below this value (e.g. routine micro-payments < ₹1,000) are excluded
from direct transfer matching, intermediate conduit hops, and rapid layering flags.
This eliminates low-value retail noise (tea/coffee, grocery, tolls) and focuses
investigative scrutiny on substantive fund transfers.
"""

BANKING_NOISE_TOKENS: set[str] = {
    "UNKNOWN",
    "NONE",
    "NAN",
    "NULL",
    "NA",
    "N/A",
    "",
    "IN",
    "OUT",
    "DR",
    "CR",
    "UPI",
    "IMPS",
    "NEFT",
    "RTGS",
    "P2A",
    "P2M",
    "TFR",
    "TRANSFER",
    "PAYMENT",
    "PAY",
    "BIL",
    "INF",
    "MMT",
    "SENT",
    "RECEIVED",
}
"""
Banking protocol tokens, transfer direction indicators, and banking clutter words.
These terms are strictly forbidden from being extracted, displayed, or cataloged
as counterparty or person names across Q-Trail, Q-Link, and topology graphs.
"""

DEFAULT_RAPID_LAYERING_TIME_WINDOW_DAYS: int = 1
"""
Maximum temporal window (in days) used to identify Rapid Layering pass-throughs.
When an inflow into an auditee's account is followed within this window by rapid
outflows to third-party recipients, the sequence is flagged as a temporal pass-through.
"""

PASS_THROUGH_HIGH_RISK_HOURS: float = 24.0
"""
Time delta threshold (in hours) between conduit inflow and outflow. If funds are
dispersed within 24 hours, the hop is marked 'High Risk' (Rapid Layering).
"""

PASS_THROUGH_MEDIUM_RISK_HOURS: float = 72.0
"""
Time delta threshold (in hours) for delayed pass-throughs. If funds are dispersed
between 24 and 72 hours, the hop is marked 'Medium Risk' (Delayed Pass-Through).
"""

TOPOLOGY_COLUMN_X_ORIGIN: float = 160.0
"""
X-axis canvas coordinate for Column 0 (Origin Auditees) in the SVG/HTML topology diagram.
"""

TOPOLOGY_COLUMN_X_CONDUIT: float = 530.0
"""
X-axis canvas coordinate for Column 1 (Intermediary Conduits) in the topology diagram.
"""

TOPOLOGY_COLUMN_X_BENEFICIARY: float = 900.0
"""
X-axis canvas coordinate for Column 2 (Beneficiary Sinks) in the topology diagram.
"""

TOPOLOGY_DEFAULT_CANVAS_HEIGHT: int = 580
"""
Minimum baseline pixel height for the dynamic multi-hop SVG topology graph.
"""


# =============================================================================
# 03. Q-MAIL: Email Intelligence, Domains, & Currency Checkpoints
# =============================================================================

CORPORATE_DOMAINS: set[str] = {
    "hmil.net",
    "hyundai.com",
    "hyundai-autoever.com",
    "mobis.co.kr",
    "hyundai.co.kr",
    "kia.com",
}
"""
Whitelisted corporate email domains for Hyundai Motor Group and affiliated entities.
Emails sent outside this domain list are categorized under 'Apart from HMIL' to
detect data exfiltration, shadow communications, and personal dealings.
"""

PERSONAL_WEBMAIL_DOMAINS: set[str] = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "rediffmail.com",
    "zoho.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "ymail.com",
    "live.com",
    "mail.com",
}
"""
Commercial webmail and encrypted email provider domains. Communications involving
these domains trigger the 'Personal Webmail IDs' forensic checkpoint for off-channel scrutiny.
"""

PRIMARY_BANK_DOMAINS: set[str] = {
    "hdfcbank.net",
    "hdfcbank.com",
    "icicibank.com",
    "sbi.co.in",
    "axisbank.com",
    "kotak.com",
    "indusind.com",
    "yesbank.in",
    "canarabank.com",
    "bankofbaroda.co.in",
    "pnb.co.in",
    "rblbank.com",
    "idfcfirstbank.com",
    "unionbankofindia.co.in",
    "federalbank.co.in",
}
"""
Official domain handles of major Indian commercial and public sector banking institutions.
Used by Q-Mail to isolate automated bank statements, credit card bills, and transaction alerts.
"""

PRIMARY_BANK_KEYWORDS: set[str] = {
    "hdfc",
    "sbi",
    "icici",
    "axis bank",
    "kotak",
    "state bank",
    "bank of baroda",
    "canara bank",
    "netbanking",
    "account statement",
    "neft cr",
    "rtgs cr",
    "imps cr",
}
"""
Subject and body keywords indicating official banking correspondence or account statements.
"""

UPI_DOMAINS: set[str] = {
    "phonepe.com",
    "google.com",
    "paytm.com",
    "cred.club",
    "razorpay.com",
    "npci.org.in",
    "bhimupi.org.in",
}
"""
Third-party UPI application providers and PSP domains. Emails from these domains
are categorized under 'UPI Payments & Receipts'.
"""

UPI_KEYWORDS: set[str] = {
    "phonepe",
    "gpay",
    "google pay",
    "googlepay",
    "paytm",
    "upi",
    "vpa",
    "bhim",
    "cred",
    "upi ref",
    "upi transaction",
    "upi payment",
    "okaxis",
    "okhdfcbank",
    "oksbi",
    "okicici",
    "yespay",
    "ybl",
    "ibl",
}
"""
Keywords and VPA handle suffixes indicating peer-to-peer or merchant UPI payments.
"""

DEFAULT_MAIL_INVESTIGATION_KEYWORDS: list[str] = [
    "PAYMENT",
    "GIFT",
    "SALARY",
    "TAX",
    "LOAN",
    "CIBIL",
]
"""
Default investigative keywords screened across email subjects, message bodies, and attachments.
"""

CURRENCY_PATTERN: re.Pattern[str] = re.compile(
    r"(?:[₹$€£]\s*[\d,]+(?:\.\d+)?)"
    r"|(?:\b(?:inr|rs\.?|usd|eur|gbp)\s*[\d,]+(?:\.\d+)?)"
    r"|(?:[\d,]+(?:\.\d+)?\s*(?:lakhs?|crores?|lacs?|cr\.?|inr|usd|eur|dollars?|rupees?))",
    re.IGNORECASE,
)
"""
Compiled regular expression identifying currency symbols, denominations (Lakhs, Crores, INR, USD),
and monetary figures in email threads.
"""


# =============================================================================
# 04. Q-SCAN: Computer Evidence Discovery & Risk Scoring Configuration
# =============================================================================

HIGH_RISK_KEYWORDS: set[str] = {
    "password",
    "credentials",
    "secret",
    "private_key",
    "id_rsa",
    "kickback",
    "bribe",
    "shadow",
    "offshore",
    "unauthorized",
    "exploit",
    "backdoor",
}
"""
Critical forensic keywords indicating credential compromise, unauthorized access,
or severe compliance breaches on audited computer workstations (Base Score: 85).
"""

MEDIUM_RISK_KEYWORDS: set[str] = {
    "salary",
    "payroll",
    "invoice",
    "ledger",
    "confidential",
    "nda",
    "audit",
    "wire_transfer",
    "p&l",
}
"""
Elevated keywords indicating confidential financial records, payroll sheets,
or sensitive business plans (Base Score: 65).
"""

HIGH_RISK_BASE_SCORE: int = 85
"""
Base forensic score assigned to evidence items containing High-Risk keywords.
"""

MEDIUM_RISK_BASE_SCORE: int = 65
"""
Base forensic score assigned to evidence items containing Medium-Risk keywords.
"""

DEFAULT_RISK_BASE_SCORE: int = 45
"""
Default score assigned to standard keyword hits that do not fall into high or medium categories.
"""


# =============================================================================
# 05. Q-VOICE: Audio Transcript & Intent Diarization Screener Configuration
# =============================================================================

DEFAULT_VOICE_INTENTS: list[tuple[str, list[tuple[str, int]]]] = [
    (
        "Collusion",
        [
            ("kickback", 95),
            ("commission", 65),
            ("cut", 50),
            ("bribe", 95),
            ("cash payment", 85),
            ("hawala", 90),
            ("off the record", 80),
            ("secret deal", 85),
            ("inside info", 90),
            ("win the tender", 75),
        ],
    ),
    (
        "Concealment",
        [
            ("dont email", 85),
            ("delete the message", 85),
            ("burn this", 90),
            ("dont tell anyone", 80),
            ("keep it quiet", 75),
            ("call on personal phone", 75),
            ("no paper trail", 90),
        ],
    ),
    (
        "Price Negotiation",
        [
            ("quote", 40),
            ("discount", 45),
            ("margin", 45),
            ("l1 price", 65),
            ("lower the bid", 60),
            ("rates", 35),
        ],
    ),
    (
        "Pressure",
        [
            ("cancel contract", 70),
            ("blacklist", 75),
            ("do as i say", 80),
            ("last chance", 65),
        ],
    ),
    (
        "Procurement",
        [
            ("rfq", 40),
            ("vendor", 30),
            ("supplier", 30),
            ("specification", 35),
            ("po number", 50),
            ("purchase order", 45),
        ],
    ),
]
"""
Weighted taxonomy of conversational intents and risk phrases evaluated against
diarized call transcripts and audio intercepts in Q-Voice.
"""

IDENTITIES_KEYWORDS: set[str] = {
    "saravan",
    "kumar",
    "indumadhi",
    "indhumadhi",
    "indhumathi",
    "design",
    "hr",
    "metec",
    "arun",
    "rajesh",
    "boss",
    "manager",
    "vendor",
    "client",
    "supervisor",
    "officer",
    "buyer",
    "supplier",
    "lead",
}
"""
Key entity names, roles, and custodian aliases monitored during audio transcript parsing.
"""

FINANCIAL_KEYWORDS: set[str] = {
    "sbi",
    "icici",
    "hdfc",
    "axis",
    "canara",
    "thousand",
    "lakh",
    "crore",
    "rupees",
    "upa",
    "upi",
    "gpay",
    "phonepe",
    "paytm",
    "transfer",
    "bank account",
    "cac",
    "transaction",
    "inquiry",
    "november",
    "25,000",
    "25000",
    "50,000",
    "commission",
    "cash",
    "cut",
    "discount",
    "margin",
    "quote",
    "rate",
    "remit",
    "payment",
    "tender",
    "rfq",
}
"""
Financial, banking, and monetary terminology flagged during speech-to-text processing.
"""

SUSPICIOUS_KEYWORDS: set[str] = {
    "bribe",
    "kickback",
    "hawala",
    "dont email",
    "do not email",
    "delete the message",
    "delete",
    "burn this",
    "burn",
    "dont tell anyone",
    "keep it quiet",
    "call on personal phone",
    "off the record",
    "no paper trail",
}
"""
Overt illicit collusion and concealment phrases flagged in call transcripts.
"""

DEFAULT_VOICE_MODEL_ENDPOINT: str = "http://127.0.0.1:8434/v1/audio/transcriptions"
"""
Default REST API endpoint for local Whisper speech-to-text transcription daemon.
"""

DEFAULT_VOICE_API_TIMEOUT: float = 300.0
"""
Maximum HTTP timeout (in seconds) for long audio transcription jobs.
"""


# =============================================================================
# 06. Q-CHAT: Chat Parser & Forensic Screener Configuration
# =============================================================================

DEFAULT_CHAT_WATCHLIST: list[tuple[str, int, str]] = [
    ("cash", 70, "Bribery & Kickbacks"),
    ("commission", 60, "Bribery & Kickbacks"),
    ("bribe", 95, "Bribery & Kickbacks"),
    ("cut", 50, "Bribery & Kickbacks"),
    ("kickback", 95, "Bribery & Kickbacks"),
    ("hawala", 90, "Illicit Finance"),
    ("personal account", 80, "Off-Channel Payment"),
    ("gpay", 50, "Off-Channel Payment"),
    ("phonepe", 50, "Off-Channel Payment"),
    ("delete", 65, "Concealment"),
    ("clear chat", 75, "Concealment"),
    ("off the record", 85, "Concealment"),
    ("dont email", 80, "Concealment"),
    ("call me", 40, "Off-Channel Comms"),
    ("whatsapp only", 75, "Off-Channel Comms"),
    ("quote", 40, "Bid Rigging"),
    ("discount", 45, "Commercial Terms"),
    ("margin", 45, "Commercial Terms"),
    ("tender", 50, "Procurement"),
    ("l1", 60, "Bid Rigging"),
    ("competitor", 55, "Bid Rigging"),
    ("inside info", 90, "Collusion"),
    ("gift", 60, "Bribery & Kickbacks"),
]
"""
Comprehensive watchlist of suspicious phrases, risk weights, and investigative categories
used to screen chat messages (WhatsApp, Teams, Slack, Telegram).
"""

DEFAULT_CHAT_EXTRA_KEYWORD_WEIGHT: int = 50
"""
Default risk score increment added when a user-provided or profile-linked keyword hits a chat message.
"""

WHATSAPP_SYSTEM_REGEXES: list[re.Pattern[str]] = [
    re.compile(r"^(?:messages and calls are )?end-to-end encrypted\b", re.IGNORECASE),
    re.compile(r"\bsecured with end-to-end encryption\b", re.IGNORECASE),
    re.compile(r"^this chat is with (?:an official )?business account\b", re.IGNORECASE),
    re.compile(
        r"^.+?\b(?:is a contact|is not in your contacts|was added to your contacts)\.?$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^(?:your security code with .+? changed|.+?'s security code changed)",
        re.IGNORECASE,
    ),
    re.compile(r'^.+? created group ".*?"$', re.IGNORECASE),
    re.compile(
        r"^.+? changed the (?:subject to \".*?\"|group description|group's icon)$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^.+? (?:added you(?:\s+to\s+(?:the|this)\s+group)?|removed you|added (?:members?|participants?)|added ~?[\w\+\-]{2,25}|removed ~?[\w\+\-]{2,25})\.?$",
        re.IGNORECASE,
    ),
    re.compile(r"^.+? left(?: the group)?\.?$", re.IGNORECASE),
    re.compile(r"^you're now an admin\.?$", re.IGNORECASE),
    re.compile(r"^disappearing messages were turned (?:on|off)\.?$", re.IGNORECASE),
    re.compile(r"^waiting for this message\. this may take a while\.?$", re.IGNORECASE),
]
"""
Compiled regular expressions identifying automated WhatsApp encryption, group management,
and security notice disclaimers so they are not misattributed as human dialogue.
"""

WHATSAPP_PATTERNS: list[re.Pattern[str]] = [
    # 24/04/2024, 14:32 - Sender: Message
    re.compile(
        r"^(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\s*[-–]\s*(.*?):\s*(.*)$"
    ),
    # [24/04/24, 14:32:10] Sender: Message
    re.compile(
        r"^\[(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\]\s*(.*?):\s*(.*)$"
    ),
    # 24.04.2024, 14:32 - Sender: Message
    re.compile(
        r"^(\d{1,2}\.\d{1,2}\.\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\s*[-–]\s*(.*?):\s*(.*)$"
    ),
]
"""
Timestamp and sender line patterns for exported WhatsApp chat text files.
"""

WHATSAPP_SYSTEM_PATTERNS: list[re.Pattern[str]] = [
    # 24/04/2024, 14:32 - System message
    re.compile(
        r"^(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\s*[-–]\s*(.*)$"
    ),
    # [24/04/24, 14:32:10] System message
    re.compile(
        r"^\[(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\]\s*(.*)$"
    ),
    # 24.04.2024, 14:32 - System message
    re.compile(
        r"^(\d{1,2}\.\d{1,2}\.\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[apAP][mM])?)\s*[-–]\s*(.*)$"
    ),
]
"""
Timestamp line patterns for automated WhatsApp system announcements that lack a sender.
"""


# =============================================================================
# 07. Q-LINK: Knowledge Graph & Agentic LLM Copilot Configuration
# =============================================================================

LEGAL_SUFFIXES: list[str] = [
    r"\bpvt\.?\s*ltd\.?\b",
    r"\bltd\.?\b",
    r"\bllp\b",
    r"\binc\.?\b",
    r"\bcorp\.?\b",
    r"\benterprises?\b",
    r"\bsolutions?\b",
    r"\bservices?\b",
    r"\btechnologies?\b",
    r"\bindia\b",
]
"""
Corporate stop-suffixes stripped during canonical entity name normalization in Q-Link.
Ensures 'ABC Solutions Pvt. Ltd.' and 'ABC' resolve to the identical knowledge graph entity.
"""

STOP_WORDS: set[str] = {
    "the",
    "in",
    "to",
    "for",
    "with",
    "from",
    "on",
    "at",
    "by",
    "this",
    "that",
    "entity",
    "company",
    "audit",
    "tell",
    "me",
    "what",
    "who",
    "where",
    "how",
    "why",
    "about",
    "is",
    "are",
    "was",
    "were",
    "show",
    "give",
    "risk",
    "risks",
    "and",
    "or",
    "path",
    "between",
    "link",
    "connect",
    "connection",
    "connections",
    "find",
    "check",
    "analyze",
    "associated",
    "all",
    "any",
    "please",
    "help",
}
"""
Conversational stop words stripped when resolving entities from natural language copilot prompts.
"""

DEFAULT_LLM_API_ENDPOINT: str = "http://127.0.0.1:8434/v1/chat/completions"
"""
Default OpenAI-compatible REST API endpoint for the Model-Host LLM daemon.
"""

DEFAULT_LLM_API_KEY: str = "model-host"
"""
API key token provided in the Authorization header to Model-Host.
"""

DEFAULT_LLM_MODEL_NAME: str = "./models/Llama-3.2-1B-Instruct-Q4_K_M.gguf"
"""
Default local quantized GGUF weights used by Model-Host for zero-hallucination forensic inference.
"""

DEFAULT_LLM_TIMEOUT: float = 30.0
"""
Maximum HTTP request timeout (in seconds) for copilot LLM tool execution and synthesis.
"""

DEFAULT_MAX_HOPS: int = 2
"""
Default maximum traversal depth for knowledge graph entity network lookups.
"""


# =============================================================================
# 08. Q-VERIFY: Document Discrepancy & Authenticity Scoring Configuration
# =============================================================================

SUSPICIOUS_SOFTWARE_SIGNATURES: dict[str, tuple[str, str, int, str]] = {
    # Image Manipulation Tools: (Display Name, Severity, Penalty Points, Forensic Explanation)
    "photoshop": (
        "Adobe Photoshop",
        "CRITICAL",
        35,
        "Document was edited or created using photo editing software (Adobe Photoshop).",
    ),
    "canva": (
        "Canva Online Editor",
        "HIGH",
        30,
        "Document was assembled using Canva design software instead of native financial billing or accounting systems.",
    ),
    "gimp": (
        "GIMP Image Editor",
        "CRITICAL",
        35,
        "Document was edited using open-source raster graphics editor GIMP.",
    ),
    "pixelmator": (
        "Pixelmator",
        "HIGH",
        30,
        "Document created with Pixelmator graphic manipulation suite.",
    ),
    "snapseed": (
        "Snapseed",
        "HIGH",
        30,
        "Image edited using mobile photo enhancer Snapseed.",
    ),
    # Online / Consumer PDF Modifiers
    "ilovepdf": (
        "iLovePDF",
        "HIGH",
        25,
        "Document processed through online consumer PDF converter iLovePDF.",
    ),
    "smallpdf": (
        "Smallpdf",
        "HIGH",
        25,
        "Document modified using Smallpdf online utility.",
    ),
    "sejda": (
        "Sejda PDF Editor",
        "HIGH",
        25,
        "Document manipulated using Sejda online PDF modifier.",
    ),
    "pdf24": (
        "PDF24 Creator",
        "MEDIUM",
        15,
        "Document assembled using PDF24 virtual printer.",
    ),
    "sodapdf": (
        "Soda PDF",
        "MEDIUM",
        15,
        "Document edited using Soda PDF modifier.",
    ),
    "pdf candy": (
        "PDF Candy",
        "HIGH",
        25,
        "Document converted or altered with PDF Candy.",
    ),
}
"""
Metadata signature catalog of unauthorized image editors and online PDF manipulation utilities.
If a vendor invoice or bank document's Creator/Producer metadata contains these signatures,
penalty points are deducted from the document's authenticity score.
"""

AUTHENTICITY_SCORE_MAX: int = 100
"""
Baseline authenticity score (100) awarded to pristine, unmanipulated documents.
"""

AUTHENTICITY_FLAG_THRESHOLD: int = 70
"""
Score cutoff below which a document is formally flagged as suspect or manipulated.
"""


# =============================================================================
# 09. Q-LEDGER: SAP PR/PO & Material Ledger Forensic Configuration
# =============================================================================

HIGH_VALUE_PO_THRESHOLD: float = 1000000.0
"""
Minimum Purchase Order amount (in INR, ₹10,00,000) classified as High-Value in Q-Ledger.
Demands verification against competitive quotation thresholds.
"""

ROUND_SUM_PO_MODULO: float = 10000.0
"""
Modulo value used to identify artificially rounded purchase orders (e.g., exactly ₹50,000,
₹1,00,000, ₹5,00,000) which frequently indicate arbitrary quotation padding or kickback amounts.
"""

SAP_MATERIAL_TYPE_MAP: dict[str, str] = {
    "ABF": "Waste",
    "CBAU": "Compatible Unit",
    "CH00": "CH Contract Handling",
    "CONT": "Kanban Container",
    "COUP": "Coupons",
    "DIEN": "Service",
    "EPA": "Equipment Package",
    "ERSA": "PM Material",
    "FCKD": "Irregular CKD (FSC)",
    "FERT": "Finished Product(FSC)",
    "FFFC": "Form-Fit-Function class",
    "FGTR": "Beverages",
    "FHMI": "Production Resource/Tool",
    "FOOD": "Foods (excl. perishables)",
    "FRIP": "Perishables",
    "GBRA": "ETM usable material",
    "HALB": "Semifinished Product",
    "HALF": "FSC(Body/Paint)",
    "HAWA": "Trading Goods",
    "HERB": "Interchangeable part",
    "HERS": "Manufacturer Part",
    "HIBE": "Consum. Mat.(Only Stock)",
    "IBAU": "Maintenance assemblies",
    "INTR": "Intra materials",
    "KMAT": "Configurable materials",
    "LEER": "Empties",
    "LEIH": "Returnable packaging",
    "LGUT": "Empties (retail)",
    "MCFE": "Mill Cable Finished Prdts",
    "MCHA": "Mill Cable Trading Goods",
    "MCHF": "MillCab.Semifinishd Prodt",
    "MCRO": "Mill Cable Raw Material",
    "MODE": "Apparel (seasonal)",
    "MPO": "Material Planning Object",
    "MRM1": "Mill Reel",
    "MRM3": "Mill Returnable Reel",
    "MRO1": "Mill Reel Without t. Data",
    "NLAG": "Consum.Material(NonStock)",
    "NOF1": "Nonfoods",
    "Not Applicable": "Not Applicable",
    "PART": "Part",
    "PHNT": "PHANTOM",
    "PIPE": "Pipeline materials",
    "PLAN": "Trading goods (planned)",
    "PMAT": "Plan Material for Vehicle",
    "PROC": "Process materials",
    "PROD": "Product groups",
    "ROH": "Raw materials",
    "ROH1": "Raw materials (Coil)",
    "ROH2": "Sub-material",
    "ROH3": "Casting Material",
    "ROH9": "Costing Sub-material",
    "SCRP": "Scrap",
    "SCRZ": "Other Scrap Material",
    "UNBW": "Nonvaluated materials",
    "UNPA": "sequenced trolley",
    "UPGV": "UPGVC",
    "VBRA": "ETM consumption material",
    "VEHI": "Vehicle config.",
    "VERP": "Packaging",
    "VKHM": "Additionals",
    "VOLL": "Full products",
    "VVGR": "Competitor Product",
    "WERB": "Product catalogs",
    "WERT": "Value-only materials",
    "WETT": "Competitor products",
}
"""
Standard SAP material type master mapping for PR/PO line item forensic enrichment.
"""


# =============================================================================
# 10. CORE: Platform, Audit Scoping & Universal Search Configuration
# =============================================================================

HEADER_STOPWORDS: set[str] = {
    "keyword",
    "keywords",
    "key identifier",
    "key identifiers",
    "identifier",
    "identifiers",
    "target",
    "targets",
    "term",
    "terms",
    "watchlist",
    "watchlists",
    "entity",
    "entities",
    "name",
    "names",
    "search query",
    "search terms",
}
"""
Header tokens stripped during keyword list ingestion from .txt, .csv, and .xlsx files.
Prevents the column header itself (e.g. 'Keywords') from being erroneously cataloged as a search target.
"""

ALLOWED_KEYWORDS_EXTENSIONS: set[str] = {".txt"}
"""
Permitted file extensions for uploaded investigation profile keyword triage files.
"""

MAX_KEYWORDS_FILE_SIZE: int = 10 * 1024 * 1024
"""
Maximum allowable file size (10 MB in bytes) for uploaded keyword triage files.
"""

DEFAULT_AUDIT_PREFIX: str = "2026-WB-"
"""
Auto-sequential naming prefix applied to freshly registered forensic audit engagements.
"""

PROMPTS_DIR: Path = Path(__file__).resolve().parent / "apps"
"""
Master apps filesystem directory storing localized natural language prompt templates
under each individual application directory (`apps/<q_app>/prompts/`).
"""

DEFAULT_MODULE_SPECS: dict[str, dict[str, Any]] = {
    "q_bank": {
        "num": "01",
        "category": "TRANSACTION",
        "name": "Bank",
        "tag": "LIVE",
        "accent": "orange",
        "tagline": "Multi-Bank Forensic Analyzer",
        "href": "/bank/",
        "order": 1,
    },
    "q_trail": {
        "num": "02",
        "category": "TRANSACTION",
        "name": "Trail",
        "tag": "LIVE",
        "accent": "gold",
        "tagline": "End-to-End Money Trail Mapper",
        "href": "/trail/",
        "order": 2,
    },
    "q_mail": {
        "num": "03",
        "category": "COMMUNICATIONS",
        "name": "Mail",
        "tag": "LIVE",
        "accent": "purple",
        "tagline": "Email Forensic Intelligence Analyzer",
        "href": "/mail/",
        "order": 3,
    },
    "q_scan": {
        "num": "04",
        "category": "DESKTOP",
        "name": "Scan",
        "tag": "LIVE",
        "accent": "teal",
        "tagline": "Computer Evidence Discovery Tool",
        "href": "/scan/",
        "order": 4,
    },
    "q_link": {
        "num": "05",
        "category": "CORRELATOR",
        "name": "Link",
        "tag": "LIVE",
        "accent": "orange",
        "tagline": "Cross-Source Evidence Correlation & Intelligence Engine",
        "href": "/link/",
        "order": 5,
    },
    "q_verify": {
        "num": "06",
        "category": "DOCUMENT",
        "name": "Verify",
        "tag": "LIVE",
        "accent": "gold",
        "tagline": "Tamper & Forgery Detection System",
        "href": "/verify/",
        "order": 6,
    },
    "q_voice": {
        "num": "07",
        "category": "AUDIO",
        "name": "Voice",
        "tag": "LIVE",
        "accent": "teal",
        "tagline": "Audio Intelligence & Call Intercept Analyzer",
        "href": "/voice/",
        "order": 7,
    },
    "q_ledger": {
        "num": "08",
        "category": "ERP",
        "name": "Ledger",
        "tag": "LIVE",
        "accent": "purple",
        "tagline": "SAP Purchase Order & Material Anomaly Detector",
        "href": "/ledger/",
        "order": 8,
    },
    "q_chat": {
        "num": "09",
        "category": "COMMUNICATIONS",
        "name": "Chat",
        "tag": "LIVE",
        "accent": "orange",
        "tagline": "WhatsApp, Teams & Slack Evidence Analyzer",
        "href": "/chat/",
        "order": 9,
    },
}
"""
Default catalog and navigation registry for all Forensic-Q analytical modules.
"""
