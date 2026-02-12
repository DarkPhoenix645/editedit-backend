from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import SessionLocal, get_db
from app.db.models import HealthCheck

router = APIRouter()

@router.get("/")
def health():
    return {"status": "ok"}

@router.get("/db-test")
def db_test(db: Session = Depends(get_db)):
    record = HealthCheck(status="ok")
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "db": "connected",
        "inserted_id": record.id
    }
