"""HTTP schema metadata; manual strict parsers retain authority over admission."""
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict
from audit.catalog import CatalogEntry
from request_history.models import ERROR_CODES

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: str
    password: str

class AdminSession(BaseModel):
    actor_id: str
    scope: str
    authenticated_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    csrf_token: str

class Revocation(BaseModel):
    revoked: bool

class DocumentRedaction(BaseModel):
    format: str
    output_format: Literal['markdown']
    redacted_text: str
    characters: int
    block_count: int
    entity_count: int
    replacement_count: int
    entity_types: dict[str, int]
    warnings: list[str]
    package_hash: str

class ErrorDetail(BaseModel):
    code: str
    message: str | None = None
    blocking_reasons: list[str] | None = None

class AdminError(BaseModel):
    error: ErrorDetail

class HistoryMetadata(BaseModel):
    request_id: str
    protocol: Literal['deepseek-chat-completions', 'claude-messages']
    model: str
    created_at: datetime
    expires_at: datetime
    status: Literal['processing', 'completed', 'blocked', 'failed', 'partial']
    error_code: str | None

class HistoryStage(BaseModel):
    stage: Literal['input', 'redacted', 'upstream', 'restored']
    state: Literal['complete', 'partial', 'not_produced']
    media_type: str | None
    body: str | None

class HistoryPage(BaseModel):
    items: list[HistoryMetadata]
    next_cursor: str | None

class HistoryDetail(HistoryMetadata):
    stages: list[HistoryStage]

class ObjectPage(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None

class ObjectDetail(BaseModel):
    item: dict[str, Any]

class GovernanceResult(BaseModel):
    governance_version_id: str

class WithdrawResult(BaseModel):
    source_version: str
    withdrawn: bool

class PublishResult(BaseModel):
    publication_id: str

class RejectResult(BaseModel):
    rejected: bool

class ReviseResult(BaseModel):
    candidate_id: str

class AuditPage(BaseModel):
    items: list[CatalogEntry]
    next_cursor: str | None
    catalog_backlog: int | None
    catalog_error_code: str | None

class AuditDetail(BaseModel):
    item: CatalogEntry
    plaintext: str

class GraphQueryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cypher: str
    params: dict[str, Any] = {}
    purpose: str | None = None

class GraphNodeDTO(BaseModel):
    id: str
    name: str
    type: str
    tenant_id: str
    domain: str
    properties: dict[str, Any] = {}

class GraphEdgeDTO(BaseModel):
    claim_id: str
    source_id: str
    target_id: str
    predicate: str
    polarity: str
    modality: str
    publication_id: str
    valid_until: str
    is_active: bool
    properties: dict[str, Any] = {}

class GraphQueryResponse(BaseModel):
    nodes: list[GraphNodeDTO]
    edges: list[GraphEdgeDTO]
    raw_records: list[dict[str, Any]]
    execution_time_ms: float

class GraphRebuildResponse(BaseModel):
    nodes_rebuilt: int
    edges_rebuilt: int
    status: str = 'completed'

ERROR_RESPONSES = {status: {'model': AdminError} for status in (401,403,404,409,422,429,503)}
LOGIN_BODY = {'requestBody': {'required': True, 'content': {'application/json': {'schema': LoginRequest.model_json_schema()}}}}
HISTORY_QUERY = {'parameters': [
    {'name': name, 'in': 'query', 'required': False, 'schema': schema}
    for name, schema in {
        'limit': {'type':'integer','minimum':1,'maximum':100,'default':50},
        'cursor': {'type':'string','maxLength':512},
        'model': {'type':'string','minLength':1,'maxLength':256},
        'protocol': {'type':'string','enum':['deepseek-chat-completions','claude-messages']},
        'status': {'type':'string','enum':['processing','completed','blocked','failed','partial']},
        'error_code': {'type':'string', 'enum': sorted(ERROR_CODES)},
        'created_after': {'type':'string','format':'date-time'},
        'created_before': {'type':'string','format':'date-time'},
    }.items()
]}

