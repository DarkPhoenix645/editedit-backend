from pydantic import BaseModel, ConfigDict
from typing import Any

class OCSFNormalization(BaseModel):
    class_name: str
    category_name: str
    severity: str
    raw_data_map: dict 
    model_config = ConfigDict(from_attributes=True)