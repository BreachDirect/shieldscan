from datetime import datetime

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target_url: str = Field(..., min_length=8, max_length=2048)
    authorised: bool = Field(..., description="User confirms they own or have permission to scan this target")


class Finding(BaseModel):
    id: str
    name: str
    risk: str
    confidence: str
    url: str
    parameter: str = ""
    evidence: str = ""
    description: str = ""
    solution: str = ""
    cwe: str = ""
    owasp_category: str = ""
    source: str = "scanner"


class ScanSummary(BaseModel):
    id: int
    target_url: str
    status: str
    status_message: str
    scanner_used: str
    risk_grade: str | None
    finding_count: int
    critical_count: int
    high_count: int
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanDetail(ScanSummary):
    findings: list[Finding] = []
    executive_summary: str | None = None
    ai_report: str | None = None
    error_message: str | None = None


class ScanProgress(BaseModel):
    id: int
    status: str
    status_message: str
    progress_percent: int
    finding_count: int
