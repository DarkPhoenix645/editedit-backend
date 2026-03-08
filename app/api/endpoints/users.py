from fastapi import APIRouter, Depends
from app.core.middleware import get_current_user
from app.schemas.user import UserOut

router = APIRouter()

@router.get("/me", response_model=UserOut)
def read_me(current_user=Depends(get_current_user)):
    return current_user
