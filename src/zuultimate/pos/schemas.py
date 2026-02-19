"""POS Pydantic schemas."""

from pydantic import BaseModel


class TerminalCreate(BaseModel):
    name: str
    location: str = ""
    device_type: str = ""


class TerminalResponse(BaseModel):
    id: str
    name: str
    location: str
    is_active: bool
    device_type: str


class TransactionCreate(BaseModel):
    terminal_id: str
    amount: float
    currency: str = "USD"


class TransactionResponse(BaseModel):
    id: str
    terminal_id: str
    amount: float
    currency: str
    status: str
    reference: str


class FraudAlertResponse(BaseModel):
    id: str
    transaction_id: str
    alert_type: str
    severity: str
    detail: str = ""
    resolved: bool = False
