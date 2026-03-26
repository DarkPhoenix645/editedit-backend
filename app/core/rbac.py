from enum import Enum

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"

def user_role_from_db(value: str | None) -> UserRole | None:
    if value is None:
        return None
    try:
        return UserRole(value)
    except ValueError:
        return None

def can_read_users(role: UserRole) -> bool:
    return role in {
        UserRole.ADMIN,
        UserRole.INVESTIGATOR,
        UserRole.ANALYST,
        UserRole.AUDITOR,
    }

def can_create_users(role: UserRole) -> bool:
    return role == UserRole.ADMIN

def can_update_users(role: UserRole) -> bool:
    return role == UserRole.ADMIN

def can_delete_users(role: UserRole) -> bool:
    return role == UserRole.ADMIN

def can_update_own_profile(role: UserRole) -> bool:
    return role == UserRole.INVESTIGATOR

def can_read_audit_logs(role: UserRole) -> bool:
    return role in {UserRole.ADMIN, UserRole.AUDITOR}