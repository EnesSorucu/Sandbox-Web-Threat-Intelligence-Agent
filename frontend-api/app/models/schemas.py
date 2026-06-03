"""
Pydantic schemas for API request/response models.
"""
from pydantic import BaseModel, HttpUrl
from typing import Optional


class AnalyzeRequest(BaseModel):
    """Request model for the /api/analyze endpoint."""
    url: str


class SSLInfo(BaseModel):
    """SSL/TLS certificate analysis result."""
    has_ssl: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    age_days: Optional[int] = None
    is_suspicious: bool = False
    error: Optional[str] = None


class DomainInfo(BaseModel):
    """WHOIS & Domain analysis result."""
    domain: str = ""
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    is_new_domain: bool = False
    typosquatting_target: Optional[str] = None
    is_typosquatting: bool = False
    error: Optional[str] = None


class ContentAnalysis(BaseModel):
    """Page content and structure analysis result."""
    hidden_element_count: int = 0
    hidden_forms: list[str] = []
    hidden_links: list[str] = []
    hidden_elements: list[dict] = []
    obfuscation_keywords_found: list[str] = []
    obfuscation_score: int = 0
    external_scripts: list[str] = []
    total_scripts: int = 0
    external_script_ratio: float = 0.0


class FormInfo(BaseModel):
    """Single form structure info."""
    action: str = ""
    method: str = ""
    input_types: list[str] = []
    has_password_field: bool = False
    has_email_field: bool = False
    redirects_external: bool = False
    external_domain: Optional[str] = None


class FormAnalysis(BaseModel):
    """All forms on the page."""
    forms: list[FormInfo] = []
    suspicious_forms: int = 0
    total_forms: int = 0


class AIPreprocessedData(BaseModel):
    """Preprocessed data ready for AI model inference (placeholder)."""
    page_text: str = ""
    page_text_length: int = 0
    form_features: dict = {}
    ai_service_available: bool = False
    phishing_text_score: Optional[float] = None
    form_anomaly_score: Optional[float] = None


class DownloadDetection(BaseModel):
    """Drive-by download detection result."""
    download_attempted: bool = False
    download_filename: Optional[str] = None
    blocked: bool = False


class LogEntry(BaseModel):
    """Single log entry for the terminal UI."""
    level: str = "INFO"  # INFO, WARN, ALERT, SUCCESS
    message: str = ""


class AnalyzeResponse(BaseModel):
    """Full analysis response returned to the frontend."""
    url: str
    overall_status: str = "unknown"  # safe, suspicious, malicious
    overall_label: str = ""
    overall_description: str = ""

    ssl: SSLInfo = SSLInfo()
    domain: DomainInfo = DomainInfo()
    content: ContentAnalysis = ContentAnalysis()
    forms: FormAnalysis = FormAnalysis()
    download: DownloadDetection = DownloadDetection()
    ai_data: AIPreprocessedData = AIPreprocessedData()

    # New analysis modules
    screenshot_b64: str = ""
    security_headers: dict = {}
    cookie_analysis: dict = {}
    link_analysis: dict = {}

    alerts: list[dict] = []
    logs: list[LogEntry] = []
    error: Optional[str] = None

