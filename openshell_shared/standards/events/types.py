from enum import Enum


class EventType(str, Enum):

    ENTITY_REGISTERED = "entity.registered"

    ENTITY_REVOKED = "entity.revoked"

    DOMAIN_CREATED = "domain.created"

    DOMAIN_UPDATED = "domain.updated"

    DOMAIN_DELETED = "domain.deleted"
    
    MEMBERSHIP_CREATED = "membership.created"

    TRUST_ESTABLISHED = "trust.established"