import uuid
from sqlmodel import SQLModel


def generate_uuid() -> str:
    return str(uuid.uuid4())


class BaseModel(SQLModel):
    pass
