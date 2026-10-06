"""Permission re-check against the live identity provider, not the index copy."""

from __future__ import annotations

from ..interface import Chunk, IdentityState, User


def check_permission(
    user: User,
    chunk: Chunk,
    idp_state: dict[str, IdentityState] | None,
    fail_closed: bool = True,
) -> str | None:
    """Return a reason to block, or None if the user may see this chunk."""
    live = (idp_state or {}).get(user.id)
    if live is None:
        if fail_closed:
            return "identity provider has no record for this user"
        roles = set(user.roles)
    elif not live.active:
        return "user account is deactivated in the identity provider"
    else:
        roles = set(live.roles)

    if chunk.acl and not roles & set(chunk.acl):
        stale = bool(set(user.roles) & set(chunk.acl))
        why = "index grants access but live roles do not (stale permission)" if stale else "user lacks the chunk's ACL roles"
        return why
    if user.clearance < chunk.min_clearance:
        return f"clearance {user.clearance} below chunk minimum {chunk.min_clearance}"
    return None
