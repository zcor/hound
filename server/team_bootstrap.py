"""Team bootstrap helpers for the v1 tenant-team model.

The SQLAlchemy `after_insert` listener in database.models auto-creates a Team
row for every new Tenant. This module attaches admin membership where we have
a user (OAuth signup + first-user-wins login).

Kept as a leaf module (imports only from database.models + sqlalchemy) so
both auth_routes.py and api.py can use it without circular-import risk.
"""

from sqlalchemy.orm import Session

from database.models import TeamMember, Tenant


def attach_admin_if_empty(db: Session, tenant: Tenant, user_id: int) -> bool:
    """Attach user as admin if the tenant team has zero members.

    Idempotent. Returns True if a TeamMember row was added, False otherwise.
    Caller must commit.

    IMPORTANT: the `@event.listens_for(Tenant, "after_insert")` listener in
    database.models writes tenant.team_id via the raw connection, which does
    NOT hydrate the in-memory ORM attribute. For freshly-inserted tenants,
    `tenant.team_id` can be None here even though the DB row has it set.
    We re-load from the DB rather than requiring every caller to remember
    `db.refresh(tenant)`.
    """
    team_id = tenant.team_id
    if team_id is None:
        team_id = (
            db.query(Tenant.team_id).filter(Tenant.id == tenant.id).scalar()
        )
        if team_id is None:
            return False  # event listener didn't run — shouldn't happen post-v1
        tenant.team_id = team_id  # sync in-memory attribute for subsequent reads
    existing_count = (
        db.query(TeamMember).filter(TeamMember.team_id == team_id).count()
    )
    if existing_count > 0:
        return False
    db.add(TeamMember(team_id=team_id, user_id=user_id, role="admin"))
    return True
