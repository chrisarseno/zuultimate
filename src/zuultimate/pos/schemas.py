"""POS Pydantic schemas."""

from pydantic import BaseModel


class TerminalCreate(BaseModel):
    name: str
    location: str = ""
    device_type: str = ""


class TransactionCreate(BaseModel):
    terminal_id: str
    amount: float
    currency: str = "USD"


class FraudAlertResponse(BaseModel):
    id: str
    transaction_id: str
    alert_type: str
    severity: str
