from enum import Enum

# Role matrix (org-wide; case-level assignment can be layered later):
# - ADMIN: full org + user management, audit logs, org settings, infra (log sources / ELK) when exposed.
# - IT_STAFF: same effective access as ADMIN (full access).
# - INVESTIGATOR: assigned investigation work — users list (collab), ML/RAG/counterfactual/graph read,
#   hypotheses read/write (non-viewer mutations), no org admin, no audit log API.
# - VIEWER: read-only cases + hypotheses (GET); no mutations, no ML interactive POST, no user list, no audit.


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    IT_STAFF = "IT_STAFF"
    VIEWER = "VIEWER"


_LEGACY_ROLE_MAP = {
    "ANALYST": UserRole.INVESTIGATOR,
    "AUDITOR": UserRole.IT_STAFF,
    "USER": UserRole.INVESTIGATOR,
}


def user_role_from_db(value: str | None) -> UserRole | None:
    if value is None:
        return None
    try:
        return UserRole(value)
    except ValueError:
        key = (value or "").strip().upper()
        return _LEGACY_ROLE_MAP.get(key)


def is_full_access(role: UserRole) -> bool:
    """Admin + IT staff — manage org, users, infra hooks, audit logs."""
    return role in {UserRole.ADMIN, UserRole.IT_STAFF}


def can_read_users(role: UserRole) -> bool:
    return role in {UserRole.ADMIN, UserRole.IT_STAFF, UserRole.INVESTIGATOR}


def can_create_users(role: UserRole) -> bool:
    return is_full_access(role)


def can_update_users(role: UserRole) -> bool:
    return is_full_access(role)


def can_delete_users(role: UserRole) -> bool:
    return is_full_access(role)


def can_update_own_profile(role: UserRole) -> bool:
    return role in {
        UserRole.ADMIN,
        UserRole.IT_STAFF,
        UserRole.INVESTIGATOR,
        UserRole.VIEWER,
    }


def can_read_audit_logs(role: UserRole) -> bool:
    return is_full_access(role)


def can_read_organizations(role: UserRole) -> bool:
    return role in {
        UserRole.ADMIN,
        UserRole.IT_STAFF,
        UserRole.INVESTIGATOR,
        UserRole.VIEWER,
    }


def can_manage_organizations(role: UserRole) -> bool:
    return is_full_access(role)


def can_configure_infra(role: UserRole) -> bool:
    """Log sources, ELK/Fleet config, operational integrations — admin + IT staff."""
    return is_full_access(role)


def can_view_hypotheses(role: UserRole) -> bool:
    """List/get hypothesis and case-linked read APIs."""
    return role in {
        UserRole.ADMIN,
        UserRole.IT_STAFF,
        UserRole.INVESTIGATOR,
        UserRole.VIEWER,
    }


def can_use_ml_interactive(role: UserRole) -> bool:
    """RAG query, counterfactual simulate, hypothesis counterfactual POST — not viewer read-only."""
    return role in {UserRole.ADMIN, UserRole.IT_STAFF, UserRole.INVESTIGATOR}


def can_mutate_hypothesis(role: UserRole) -> bool:
    """PATCH hypothesis status/case — not viewer."""
    return role in {UserRole.ADMIN, UserRole.IT_STAFF, UserRole.INVESTIGATOR}


def can_view_graph(role: UserRole) -> bool:
    return can_view_hypotheses(role)


def can_verify_sealed_block(role: UserRole) -> bool:
    """POST /cold/verify — integrity check; all authenticated roles may run."""
    return role in {
        UserRole.ADMIN,
        UserRole.IT_STAFF,
        UserRole.INVESTIGATOR,
        UserRole.VIEWER,
    }
