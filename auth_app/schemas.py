from typing import Optional, Any
from pydantic import BaseModel

class StandardResponse(BaseModel):
    status: str
    message: str
    data: Optional[Any] = None