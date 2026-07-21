from __future__ import annotations

from dataclasses import fields
from uuid import UUID

import json
import re

import pytest

from openshell_shared.standards.passports.models import Passport
from openshell_shared.standards.passports.types import (
    PASSPORT_TYPE,
    PASSPORT_STATUS,
)


# =========================================================
# Constants
# =========================================================

DOMAIN_UID = (
    "019f8256-1470-720c-9e8c-65f563ece149"
)

ENTITY_UID = (
    "019f82b0-6228-763c-82fc-18a196313855"
)

OTHER_ENTITY_UID = (
    "019f82b1-b35b-72bb-9384-43076971e481"
)

ENTITY_PIK = (
    "MCowBQYDK2VwAyEA"
    "u7VKjD4uGzRj3oY0a8xQ2mH8Vk9P5WsL7R0xYk3pG1M="
)

OTHER_ENTITY_PIK = (
    "MCowBQYDK2VwAyEA"
    "C3mW7pV5xQ9aD2kF8nL1sJ4yR6uB0eH9tZ7gK5vP2A="
)

ROLE_AGENT = "AGENT"
ROLE_CONSOLE = "CONSOLE"

CUSTOM_SECURITY_CODE = "A3C9M1"


# =========================================================
# Fixtures
# =========================================================

@pytest.fixture
def open_passport() -> Passport:

    return Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
        security_code=CUSTOM_SECURITY_CODE,
    )


@pytest.fixture
def closed_passport() -> Passport:

    return Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.CLOSED.value,
        predefined_role=ROLE_CONSOLE,
        entity_uid=ENTITY_UID,
        entity_pik=ENTITY_PIK,
        security_code=CUSTOM_SECURITY_CODE,
    )


# =========================================================
# Dataclass configuration
# =========================================================

def test_constants_are_not_dataclass_fields():

    field_names = {
        field.name
        for field in fields(Passport)
    }

    assert (
        "DEFAULT_SECURITY_CODE_LENGTH"
        not in field_names
    )

    assert (
        "SECURITY_CODE_ALPHABET"
        not in field_names
    )


def test_class_constants_have_correct_types():

    assert isinstance(
        Passport.DEFAULT_SECURITY_CODE_LENGTH,
        int,
    )

    assert isinstance(
        Passport.SECURITY_CODE_ALPHABET,
        str,
    )

    assert (
        Passport.DEFAULT_SECURITY_CODE_LENGTH
        == 6
    )

    assert len(
        Passport.SECURITY_CODE_ALPHABET
    ) > 0


# =========================================================
# Security code generation
# =========================================================

def test_generate_security_code_default_length():

    security_code = (
        Passport.generate_security_code()
    )

    assert isinstance(
        security_code,
        str,
    )

    assert len(security_code) == 6


def test_generate_security_code_custom_length():

    security_code = (
        Passport.generate_security_code(
            length=32
        )
    )

    assert len(security_code) == 32


def test_generated_security_code_uses_supported_alphabet():

    security_code = (
        Passport.generate_security_code(
            length=128
        )
    )

    assert all(
        character
        in Passport.SECURITY_CODE_ALPHABET
        for character in security_code
    )


def test_generated_security_codes_are_not_identical():

    codes = {
        Passport.generate_security_code(
            length=16
        )
        for _ in range(50)
    }

    assert len(codes) > 1


@pytest.mark.parametrize(
    "invalid_length",
    [
        0,
        1,
        2,
        3,
        -1,
        -100,
    ]
)
def test_generate_security_code_rejects_short_length(
    invalid_length
):

    with pytest.raises(
        ValueError,
        match="at least 4"
    ):

        Passport.generate_security_code(
            invalid_length
        )


@pytest.mark.parametrize(
    "invalid_length",
    [
        None,
        "6",
        6.0,
        [],
        {},
    ]
)
def test_generate_security_code_rejects_non_integer(
    invalid_length
):

    with pytest.raises(
        TypeError,
        match="must be an integer"
    ):

        Passport.generate_security_code(
            invalid_length
        )


# =========================================================
# OPEN passport creation
# =========================================================

def test_create_open_passport():

    passport = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
        security_code=CUSTOM_SECURITY_CODE,
    )

    assert isinstance(
        passport,
        Passport,
    )

    assert UUID(
        passport.uid
    )

    assert (
        passport.domain_uid
        == DOMAIN_UID
    )

    assert passport.entity_uid is None
    assert passport.entity_pik is None

    assert (
        passport.protocol
        == PASSPORT_TYPE.OPEN.value
    )

    assert (
        passport.predefined_role
        == ROLE_AGENT
    )

    assert (
        passport.status
        == PASSPORT_STATUS.ACTIVE.value
    )

    assert (
        passport.security_code
        == CUSTOM_SECURITY_CODE
    )

    assert passport.fingerprint
    assert passport.verify_fingerprint()
    assert passport.validate()


def test_open_passport_properties(
    open_passport
):

    assert open_passport.is_open
    assert not open_passport.is_closed
    assert open_passport.is_active


def test_open_passport_rejects_entity_uid():

    with pytest.raises(
        ValueError,
        match=(
            "OPEN passports cannot define "
            "entity_uid"
        )
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=ROLE_AGENT,
            entity_uid=ENTITY_UID,
        )


def test_open_passport_rejects_entity_pik():

    with pytest.raises(
        ValueError,
        match=(
            "OPEN passports cannot define "
            "entity_pik"
        )
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=ROLE_AGENT,
            entity_pik=ENTITY_PIK,
        )


def test_open_passport_accepts_any_authenticated_entity(
    open_passport
):

    assert open_passport.matches_entity(
        entity_uid=ENTITY_UID,
        entity_pik=ENTITY_PIK,
    )

    assert open_passport.matches_entity(
        entity_uid=OTHER_ENTITY_UID,
        entity_pik=OTHER_ENTITY_PIK,
    )


# =========================================================
# CLOSED passport creation
# =========================================================

def test_create_closed_passport():

    passport = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.CLOSED.value,
        predefined_role=ROLE_CONSOLE,
        entity_uid=ENTITY_UID,
        entity_pik=ENTITY_PIK,
        security_code=CUSTOM_SECURITY_CODE,
    )

    assert isinstance(
        passport,
        Passport,
    )

    assert passport.entity_uid == ENTITY_UID
    assert passport.entity_pik == ENTITY_PIK

    assert (
        passport.protocol
        == PASSPORT_TYPE.CLOSED.value
    )

    assert passport.is_closed
    assert not passport.is_open
    assert passport.is_active

    assert passport.verify_fingerprint()
    assert passport.validate()


def test_closed_passport_requires_entity_uid():

    with pytest.raises(
        ValueError,
        match=(
            "CLOSED passports require "
            "entity_uid"
        )
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.CLOSED.value,
            predefined_role=ROLE_CONSOLE,
            entity_pik=ENTITY_PIK,
        )


def test_closed_passport_requires_entity_pik():

    with pytest.raises(
        ValueError,
        match=(
            "CLOSED passports require "
            "entity_pik"
        )
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.CLOSED.value,
            predefined_role=ROLE_CONSOLE,
            entity_uid=ENTITY_UID,
        )


def test_closed_passport_matches_expected_identity(
    closed_passport
):

    assert closed_passport.matches_entity(
        entity_uid=ENTITY_UID,
        entity_pik=ENTITY_PIK,
    )


def test_closed_passport_rejects_different_uid(
    closed_passport
):

    assert not closed_passport.matches_entity(
        entity_uid=OTHER_ENTITY_UID,
        entity_pik=ENTITY_PIK,
    )


def test_closed_passport_rejects_different_pik(
    closed_passport
):

    assert not closed_passport.matches_entity(
        entity_uid=ENTITY_UID,
        entity_pik=OTHER_ENTITY_PIK,
    )


def test_closed_passport_rejects_invalid_identity_data(
    closed_passport
):

    assert not closed_passport.matches_entity(
        entity_uid="invalid-uuid",
        entity_pik=ENTITY_PIK,
    )

    assert not closed_passport.matches_entity(
        entity_uid=ENTITY_UID,
        entity_pik="",
    )


# =========================================================
# Normalization
# =========================================================

def test_create_normalizes_protocol_role_status_and_code():

    passport = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=" open ",
        predefined_role=" agent ",
        security_code=" a3c9m1 ",
        status=" active ",
    )

    assert (
        passport.protocol
        == PASSPORT_TYPE.OPEN.value
    )

    assert (
        passport.predefined_role
        == "AGENT"
    )

    assert (
        passport.security_code
        == "A3C9M1"
    )

    assert (
        passport.status
        == PASSPORT_STATUS.ACTIVE.value
    )


def test_uuid_is_normalized():

    upper_domain_uid = (
        DOMAIN_UID.upper()
    )

    passport = Passport.create(
        domain_uid=upper_domain_uid,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
    )

    assert (
        passport.domain_uid
        == DOMAIN_UID.lower()
    )


# =========================================================
# Fingerprint
# =========================================================

def test_fingerprint_is_sha256_hexadecimal(
    open_passport
):

    assert re.fullmatch(
        r"[0-9a-f]{64}",
        open_passport.fingerprint
    )


def test_fingerprint_is_deterministic():

    passport = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
        security_code=CUSTOM_SECURITY_CODE,
    )

    first = (
        passport.calculate_fingerprint()
    )

    second = (
        passport.calculate_fingerprint()
    )

    assert first == second
    assert first == passport.fingerprint


def test_fingerprint_detects_security_code_mutation(
    open_passport
):

    original_fingerprint = (
        open_passport.fingerprint
    )

    open_passport.security_code = "ZZZZZZ"

    assert (
        open_passport.fingerprint
        == original_fingerprint
    )

    assert not open_passport.verify_fingerprint()


def test_fingerprint_detects_role_mutation(
    open_passport
):

    open_passport.predefined_role = (
        "ADMINISTRATOR"
    )

    assert not open_passport.verify_fingerprint()


def test_fingerprint_detects_status_mutation(
    open_passport
):

    open_passport.status = (
        PASSPORT_STATUS.REVOKED.value
    )

    assert not open_passport.verify_fingerprint()


def test_refresh_fingerprint_accepts_intentional_mutation(
    open_passport
):

    original_fingerprint = (
        open_passport.fingerprint
    )

    open_passport.predefined_role = (
        "ADMINISTRATOR"
    )

    assert not open_passport.verify_fingerprint()

    refreshed = (
        open_passport.refresh_fingerprint()
    )

    assert refreshed != original_fingerprint
    assert open_passport.verify_fingerprint()


def test_validate_rejects_tampered_passport(
    open_passport
):

    open_passport.security_code = "TAMPERED"

    with pytest.raises(
        ValueError,
        match="Invalid passport fingerprint"
    ):

        open_passport.validate()


# =========================================================
# Status management
# =========================================================

@pytest.mark.parametrize(
    "status",
    [
        PASSPORT_STATUS.ACTIVE.value,
        PASSPORT_STATUS.CONSUMED.value,
        PASSPORT_STATUS.REVOKED.value,
        PASSPORT_STATUS.EXPIRED.value,
        PASSPORT_STATUS.SUSPENDED.value,
    ]
)
def test_set_supported_status(
    open_passport,
    status
):

    original_fingerprint = (
        open_passport.fingerprint
    )

    result = open_passport.set_status(
        status
    )

    assert result is True
    assert open_passport.status == status
    assert open_passport.verify_fingerprint()

    if status != PASSPORT_STATUS.ACTIVE.value:

        assert (
            open_passport.fingerprint
            != original_fingerprint
        )


def test_set_status_updates_is_active(
    open_passport
):

    assert open_passport.is_active

    open_passport.set_status(
        PASSPORT_STATUS.REVOKED.value
    )

    assert not open_passport.is_active


def test_set_status_rejects_unknown_status(
    open_passport
):

    with pytest.raises(
        ValueError,
        match="Unsupported passport status"
    ):

        open_passport.set_status(
            "UNKNOWN"
        )


# =========================================================
# Security code comparison
# =========================================================

def test_verify_security_code(
    open_passport
):

    assert open_passport.verify_security_code(
        CUSTOM_SECURITY_CODE
    )


def test_verify_security_code_normalizes_input(
    open_passport
):

    assert open_passport.verify_security_code(
        " a3c9m1 "
    )


def test_verify_security_code_rejects_invalid_code(
    open_passport
):

    assert not open_passport.verify_security_code(
        "WRONG1"
    )


@pytest.mark.parametrize(
    "invalid_code",
    [
        None,
        "",
        "   ",
        123456,
        [],
        {},
    ]
)
def test_verify_security_code_rejects_invalid_input(
    open_passport,
    invalid_code
):

    assert not open_passport.verify_security_code(
        invalid_code
    )


# =========================================================
# Integration code
# =========================================================

def test_open_passport_integration_code(
    open_passport
):

    code = (
        open_passport
        .to_integration_code()
    )

    expected = (
        f"{open_passport.uid}."
        f"{DOMAIN_UID}."
        f"#."
        f"{CUSTOM_SECURITY_CODE}"
    )

    assert code == expected


def test_closed_passport_integration_code(
    closed_passport
):

    code = (
        closed_passport
        .to_integration_code()
    )

    expected = (
        f"{closed_passport.uid}."
        f"{DOMAIN_UID}."
        f"{ENTITY_UID}."
        f"{CUSTOM_SECURITY_CODE}"
    )

    assert code == expected


def test_parse_open_integration_code(
    open_passport
):

    parsed = Passport.parse_integration_code(
        open_passport.to_integration_code()
    )

    assert parsed == {
        "passport_uid": open_passport.uid,
        "domain_uid": DOMAIN_UID,
        "entity_uid": None,
        "security_code": CUSTOM_SECURITY_CODE,
    }


def test_parse_closed_integration_code(
    closed_passport
):

    parsed = Passport.parse_integration_code(
        closed_passport.to_integration_code()
    )

    assert parsed == {
        "passport_uid": closed_passport.uid,
        "domain_uid": DOMAIN_UID,
        "entity_uid": ENTITY_UID,
        "security_code": CUSTOM_SECURITY_CODE,
    }


@pytest.mark.parametrize(
    "invalid_code",
    [
        "",
        "abc",
        "a.b",
        "a.b.c",
        "a.b.c.d.e",
        None,
        123,
    ]
)
def test_parse_integration_code_rejects_invalid_format(
    invalid_code
):

    with pytest.raises(
        (
            TypeError,
            ValueError,
        )
    ):

        Passport.parse_integration_code(
            invalid_code
        )


def test_parse_integration_code_rejects_invalid_passport_uid():

    code = (
        f"invalid."
        f"{DOMAIN_UID}."
        f"#."
        f"{CUSTOM_SECURITY_CODE}"
    )

    with pytest.raises(
        ValueError,
        match="passport_uid must be a valid UUID"
    ):

        Passport.parse_integration_code(
            code
        )


def test_parse_integration_code_rejects_invalid_domain_uid():

    passport_uid = str(
        UUID(
            "019f8255-e043-758d-8b1a-c541d8d00174"
        )
    )

    code = (
        f"{passport_uid}."
        f"invalid."
        f"#."
        f"{CUSTOM_SECURITY_CODE}"
    )

    with pytest.raises(
        ValueError,
        match="domain_uid must be a valid UUID"
    ):

        Passport.parse_integration_code(
            code
        )


def test_parse_integration_code_rejects_empty_security_code():

    passport_uid = (
        "019f8255-e043-758d-8b1a-c541d8d00174"
    )

    code = (
        f"{passport_uid}."
        f"{DOMAIN_UID}."
        f"#."
    )

    with pytest.raises(
        ValueError,
        match="security_code cannot be empty"
    ):

        Passport.parse_integration_code(
            code
        )


# =========================================================
# Serialization
# =========================================================

def test_to_dict_open_passport(
    open_passport
):

    data = open_passport.to_dict()

    assert data == {
        "uid": open_passport.uid,
        "domain_uid": DOMAIN_UID,
        "fingerprint": (
            open_passport.fingerprint
        ),
        "entity_uid": None,
        "entity_pik": None,
        "security_code": CUSTOM_SECURITY_CODE,
        "protocol": PASSPORT_TYPE.OPEN.value,
        "predefined_role": ROLE_AGENT,
        "status": PASSPORT_STATUS.ACTIVE.value,
    }


def test_to_dict_closed_passport(
    closed_passport
):

    data = closed_passport.to_dict()

    assert data["entity_uid"] == ENTITY_UID
    assert data["entity_pik"] == ENTITY_PIK
    assert (
        data["protocol"]
        == PASSPORT_TYPE.CLOSED.value
    )


def test_to_json_returns_valid_json(
    closed_passport
):

    serialized = closed_passport.to_json()

    decoded = json.loads(
        serialized
    )

    assert isinstance(decoded, dict)
    assert decoded == closed_passport.to_dict()


def test_from_dict_open_roundtrip(
    open_passport
):

    restored = Passport.from_dict(
        open_passport.to_dict()
    )

    assert restored == open_passport
    assert restored is not open_passport
    assert restored.verify_fingerprint()


def test_from_dict_closed_roundtrip(
    closed_passport
):

    restored = Passport.from_dict(
        closed_passport.to_dict()
    )

    assert restored == closed_passport
    assert restored.matches_entity(
        ENTITY_UID,
        ENTITY_PIK,
    )


def test_from_json_roundtrip(
    closed_passport
):

    restored = Passport.from_json(
        closed_passport.to_json()
    )

    assert restored == closed_passport
    assert restored.verify_fingerprint()


def test_from_dict_rejects_non_dictionary():

    with pytest.raises(
        TypeError,
        match="must be a dictionary"
    ):

        Passport.from_dict(
            "invalid"
        )


def test_from_json_rejects_invalid_json():

    with pytest.raises(
        ValueError,
        match="Invalid Passport JSON"
    ):

        Passport.from_json(
            "{invalid-json}"
        )


def test_from_json_rejects_non_string():

    with pytest.raises(
        TypeError,
        match="must be a string"
    ):

        Passport.from_json(
            {}
        )


def test_from_dict_rejects_modified_payload(
    closed_passport
):

    data = closed_passport.to_dict()

    data["entity_uid"] = (
        OTHER_ENTITY_UID
    )

    with pytest.raises(
        ValueError,
        match="Invalid passport fingerprint"
    ):

        Passport.from_dict(
            data
        )


# =========================================================
# Compatibility properties
# =========================================================

def test_passport_uid_alias(
    open_passport
):

    assert (
        open_passport.passport_uid
        == open_passport.uid
    )


def test_passport_fingerprint_alias(
    open_passport
):

    assert (
        open_passport.passport_fingerprint
        == open_passport.fingerprint
    )


# =========================================================
# Representation
# =========================================================

def test_repr_hides_security_code(
    closed_passport
):

    representation = repr(
        closed_passport
    )

    assert (
        "security_code=<HIDDEN>"
        in representation
    )

    assert (
        CUSTOM_SECURITY_CODE
        not in representation
    )


def test_repr_hides_entity_pik(
    closed_passport
):

    representation = repr(
        closed_passport
    )

    assert (
        "entity_pik=<HIDDEN>"
        in representation
    )

    assert (
        ENTITY_PIK
        not in representation
    )


def test_repr_marks_undefined_entity_pik(
    open_passport
):

    representation = repr(
        open_passport
    )

    assert (
        "entity_pik=<UNDEFINED>"
        in representation
    )


# =========================================================
# Invalid protocol
# =========================================================

@pytest.mark.parametrize(
    "protocol",
    [
        "",
        "UNKNOWN",
        "PUBLIC",
        "PRIVATE",
    ]
)
def test_create_rejects_unknown_protocol(
    protocol
):

    with pytest.raises(
        ValueError,
        match="Unsupported passport protocol"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=protocol,
            predefined_role=ROLE_AGENT,
        )


@pytest.mark.parametrize(
    "protocol",
    [
        None,
        1,
        [],
        {},
    ]
)
def test_create_rejects_non_string_protocol(
    protocol
):

    with pytest.raises(
        TypeError,
        match="protocol must be a string"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=protocol,
            predefined_role=ROLE_AGENT,
        )


# =========================================================
# Invalid UUID values
# =========================================================

@pytest.mark.parametrize(
    "domain_uid",
    [
        "",
        "invalid",
        "123",
        None,
        [],
        {},
    ]
)
def test_create_rejects_invalid_domain_uid(
    domain_uid
):

    with pytest.raises(
        ValueError,
        match="domain_uid must be a valid UUID"
    ):

        Passport.create(
            domain_uid=domain_uid,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=ROLE_AGENT,
        )


def test_create_closed_rejects_invalid_entity_uid():

    with pytest.raises(
        ValueError,
        match="entity_uid must be a valid UUID"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.CLOSED.value,
            predefined_role=ROLE_CONSOLE,
            entity_uid="invalid",
            entity_pik=ENTITY_PIK,
        )


# =========================================================
# Invalid role
# =========================================================

@pytest.mark.parametrize(
    "role",
    [
        "",
        "   ",
    ]
)
def test_create_rejects_empty_role(
    role
):

    with pytest.raises(
        ValueError,
        match="predefined_role cannot be empty"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=role,
        )


@pytest.mark.parametrize(
    "role",
    [
        None,
        1,
        [],
        {},
    ]
)
def test_create_rejects_non_string_role(
    role
):

    with pytest.raises(
        TypeError,
        match="predefined_role must be a string"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=role,
        )


# =========================================================
# Invalid security code
# =========================================================

@pytest.mark.parametrize(
    "security_code",
    [
        "",
        "   ",
    ]
)
def test_create_rejects_empty_security_code(
    security_code
):

    with pytest.raises(
        ValueError,
        match="security_code cannot be empty"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=ROLE_AGENT,
            security_code=security_code,
        )


@pytest.mark.parametrize(
    "security_code",
    [
        123456,
        [],
        {},
    ]
)
def test_create_rejects_non_string_security_code(
    security_code
):

    with pytest.raises(
        TypeError,
        match="security_code must be a string"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.OPEN.value,
            predefined_role=ROLE_AGENT,
            security_code=security_code,
        )


# =========================================================
# Invalid entity PIK
# =========================================================

@pytest.mark.parametrize(
    "entity_pik",
    [
        "",
        "   ",
    ]
)
def test_create_rejects_empty_entity_pik(
    entity_pik
):

    with pytest.raises(
        ValueError,
        match="entity_pik cannot be empty"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.CLOSED.value,
            predefined_role=ROLE_CONSOLE,
            entity_uid=ENTITY_UID,
            entity_pik=entity_pik,
        )


@pytest.mark.parametrize(
    "entity_pik",
    [
        123,
        [],
        {},
    ]
)
def test_create_rejects_non_string_entity_pik(
    entity_pik
):

    with pytest.raises(
        TypeError,
        match="entity_pik must be a string"
    ):

        Passport.create(
            domain_uid=DOMAIN_UID,
            protocol=PASSPORT_TYPE.CLOSED.value,
            predefined_role=ROLE_CONSOLE,
            entity_uid=ENTITY_UID,
            entity_pik=entity_pik,
        )


# =========================================================
# Distinct passport creation
# =========================================================

def test_create_generates_distinct_passport_uids():

    first = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
        security_code=CUSTOM_SECURITY_CODE,
    )

    second = Passport.create(
        domain_uid=DOMAIN_UID,
        protocol=PASSPORT_TYPE.OPEN.value,
        predefined_role=ROLE_AGENT,
        security_code=CUSTOM_SECURITY_CODE,
    )

    assert first.uid != second.uid

    assert (
        first.fingerprint
        != second.fingerprint
    )