from dataclasses import dataclass, field as dc_field, replace
import json
import re
from typing import Any
from uuid import UUID

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field, model_validator

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek
from openhound_okta.kinds import nodes as nk
from openhound_okta.main import app


SAML_CONTRACT_VERSION = "opengraph-saml-v0.3.0"
ACCOUNT_RESOLUTION_PROFILE = "saml_account_resolution_v1"
EMAIL_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
UNSPECIFIED_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified"
TRANSIENT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
PERSISTENT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
UNSPECIFIED_ATTRIBUTE_NAME_FORMAT = (
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _dedupe(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = _clean(value)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def saml_provider_id(app_id: str) -> str:
    return f"okta:saml:provider:{app_id}"


def saml_issuer_id(app_id: str) -> str:
    return f"okta:saml:issuer:{app_id}"


def saml_acs_id(app_id: str, index: int = 0) -> str:
    return f"okta:saml:acs:{app_id}:{index}"


def saml_claim_mapping_id(app_id: str, index: int = 0) -> str:
    return f"okta:saml:claim-mapping:{app_id}:{index}"


def saml_service_provider_id(idp_id: str) -> str:
    return f"okta:saml:service-provider:{idp_id}"


def saml_trusted_issuer_id(idp_id: str) -> str:
    return f"okta:saml:trusted-issuer:{idp_id}"


def saml_sp_acs_id(idp_id: str, index: int = 0) -> str:
    return f"okta:saml:sp-acs:{idp_id}:{index}"


def saml_account_resolution_rule_id(idp_id: str) -> str:
    return f"okta:saml:account-resolution-rule:{idp_id}"


def saml_account_resolution_field_id(idp_id: str) -> str:
    return f"okta:saml:account-resolution-field:{idp_id}:login"


def _sign_on(application) -> Any:
    settings = getattr(application, "settings", None)
    return getattr(settings, "sign_on", None)


def _app_settings(application) -> dict[str, Any]:
    settings = getattr(application, "settings", None)
    app_settings = getattr(settings, "app", None)
    return app_settings if isinstance(app_settings, dict) else {}


def _idp_issuer(application, sign_on: Any) -> str | None:
    return _clean(
        getattr(sign_on, "idp_issuer", None)
        or getattr(application, "saml_metadata_entity_id", None)
    )


@dataclass(frozen=True)
class _SamlRouteEvidence:
    acs_url: str
    sp_entity_id: str
    index: int | None
    binding: str | None
    is_default: bool | None
    target_product_family: str
    route_source: str
    extraction_mode: str
    acs_source_field: str
    sp_entity_source_field: str
    route_conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ExplicitRouteExtraction:
    routes: tuple[_SamlRouteEvidence, ...] = ()
    acs_urls: tuple[str, ...] = ()
    sp_entity_id: str | None = None
    diagnostics: tuple[str, ...] = ()
    contradictory: bool = False


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_GITHUB_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$")


def _valid_host_scope(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    if not value or len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return value


def _valid_github_slug(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    return value if _GITHUB_SLUG.fullmatch(value) else None


def _explicit_sp_entity(sign_on: Any) -> tuple[str | None, str | None, list[str]]:
    audience_override = _clean(getattr(sign_on, "audience_override", None))
    if audience_override:
        return audience_override, "settings.signOn.audienceOverride", []

    slo = getattr(sign_on, "slo", None) or {}
    candidates = [
        (
            _clean(getattr(sign_on, "sp_issuer", None)),
            "settings.signOn.spIssuer",
        ),
        (_clean(getattr(sign_on, "audience", None)), "settings.signOn.audience"),
        (_clean(slo.get("spIssuer")), "settings.signOn.slo.spIssuer"),
    ]
    populated = [(value, source) for value, source in candidates if value]
    if len({value for value, _ in populated}) > 1:
        return None, None, ["conflicting_explicit_sp_entity_fields"]
    if populated:
        value, source = populated[0]
        return value, source, []
    return None, None, []


def _primary_explicit_acs(sign_on: Any) -> tuple[str | None, str | None]:
    candidates = [
        (
            _clean(getattr(sign_on, "sso_acs_url_override", None)),
            "settings.signOn.ssoAcsUrlOverride",
        ),
        (
            _clean(getattr(sign_on, "sso_acs_url", None)),
            "settings.signOn.ssoAcsUrl",
        ),
        (
            _clean(getattr(sign_on, "recipient_override", None)),
            "settings.signOn.recipientOverride",
        ),
        (
            _clean(getattr(sign_on, "destination_override", None)),
            "settings.signOn.destinationOverride",
        ),
        (
            _clean(getattr(sign_on, "recipient", None)),
            "settings.signOn.recipient",
        ),
        (
            _clean(getattr(sign_on, "destination", None)),
            "settings.signOn.destination",
        ),
    ]
    return next(
        ((value, source) for value, source in candidates if value), (None, None)
    )


def _explicit_acs_endpoints(sign_on: Any) -> list[tuple[Any, str]]:
    direct = [
        (endpoint, f"settings.signOn.acsEndpoints[{index}].url")
        for index, endpoint in enumerate(getattr(sign_on, "acs_endpoints", None) or [])
    ]
    assertion_encryption = getattr(sign_on, "assertion_encryption", None)
    encrypted = [
        (
            endpoint,
            f"settings.signOn.assertionEncryption.acsEndpoints[{index}].url",
        )
        for index, endpoint in enumerate(
            getattr(assertion_encryption, "acs_endpoints", None) or []
        )
    ]
    return [*direct, *encrypted]


def _explicit_saml_routes(application) -> _ExplicitRouteExtraction:
    sign_on = _sign_on(application)
    if not sign_on:
        return _ExplicitRouteExtraction()

    sp_entity_id, sp_entity_source, diagnostics = _explicit_sp_entity(sign_on)
    primary_acs_url, primary_acs_source = _primary_explicit_acs(sign_on)
    acs_candidates: list[tuple[str, str, int | None, str | None, bool | None]] = []
    if primary_acs_url and primary_acs_source:
        acs_candidates.append((primary_acs_url, primary_acs_source, 0, None, True))
    for endpoint, source_field in _explicit_acs_endpoints(sign_on):
        acs_url = _clean(getattr(endpoint, "url", None))
        if acs_url:
            acs_candidates.append(
                (
                    acs_url,
                    source_field,
                    getattr(endpoint, "index", None),
                    _clean(getattr(endpoint, "binding", None)),
                    getattr(endpoint, "is_default", None),
                )
            )

    acs_urls = tuple(dict.fromkeys(item[0] for item in acs_candidates))
    if diagnostics:
        return _ExplicitRouteExtraction(
            acs_urls=acs_urls,
            diagnostics=tuple(diagnostics),
            contradictory=True,
        )
    if not sp_entity_id or not sp_entity_source or not acs_candidates:
        return _ExplicitRouteExtraction(
            acs_urls=acs_urls,
            sp_entity_id=sp_entity_id,
        )

    routes: list[_SamlRouteEvidence] = []
    route_keys: set[tuple[str, str]] = set()
    for acs_url, acs_source, index, binding, is_default in acs_candidates:
        route_key = (acs_url, sp_entity_id)
        if route_key in route_keys:
            continue
        route_keys.add(route_key)
        routes.append(
            _SamlRouteEvidence(
                acs_url=acs_url,
                sp_entity_id=sp_entity_id,
                index=index,
                binding=binding,
                is_default=is_default,
                target_product_family="generic_saml",
                route_source="settings.signOn",
                extraction_mode="explicit_generic",
                acs_source_field=acs_source,
                sp_entity_source_field=sp_entity_source,
            )
        )
    return _ExplicitRouteExtraction(
        routes=tuple(routes),
        acs_urls=acs_urls,
        sp_entity_id=sp_entity_id,
    )


def _oin_saml_route(
    application,
) -> tuple[_SamlRouteEvidence | None, list[str]]:
    app_settings = _app_settings(application)
    app_name = getattr(application, "name", None)

    if app_name == "okta_org2org":
        acs_url = _clean(app_settings.get("acsUrl"))
        sp_entity_id = _clean(app_settings.get("audRestriction"))
        missing = []
        if not acs_url:
            missing.append("missing_settings.app.acsUrl")
        if not sp_entity_id:
            missing.append("missing_settings.app.audRestriction")
        if missing:
            return None, missing
        assert acs_url is not None and sp_entity_id is not None
        return (
            _SamlRouteEvidence(
                acs_url=acs_url,
                sp_entity_id=sp_entity_id,
                index=0,
                binding=None,
                is_default=True,
                target_product_family="okta_org2org",
                route_source="settings.app",
                extraction_mode="oin_explicit_fields",
                acs_source_field="settings.app.acsUrl",
                sp_entity_source_field="settings.app.audRestriction",
            ),
            [],
        )

    if app_name == "jamfsoftwareserver":
        domain = _valid_host_scope(app_settings.get("domain"))
        if not domain:
            return None, ["missing_or_malformed_settings.app.domain"]
        return (
            _SamlRouteEvidence(
                acs_url=f"https://{domain}/saml/SSO",
                sp_entity_id=f"https://{domain}/saml/metadata",
                index=0,
                binding=None,
                is_default=True,
                target_product_family="jamf_pro",
                route_source="settings.app+documented_jamf_route",
                extraction_mode="allowlisted_deterministic_route",
                acs_source_field="settings.app.domain",
                sp_entity_source_field="settings.app.domain",
            ),
            [],
        )

    if app_name == "githubenterprisemanageduser":
        enterprise_name = _valid_github_slug(app_settings.get("enterpriseName"))
        if not enterprise_name:
            return None, ["missing_or_malformed_settings.app.enterpriseName"]
        return (
            _SamlRouteEvidence(
                acs_url=(
                    f"https://github.com/enterprises/{enterprise_name}/saml/consume"
                ),
                sp_entity_id=f"https://github.com/enterprises/{enterprise_name}",
                index=0,
                binding=None,
                is_default=True,
                target_product_family="github_enterprise",
                route_source="settings.app+documented_github_route",
                extraction_mode="allowlisted_deterministic_route",
                acs_source_field="settings.app.enterpriseName",
                sp_entity_source_field="settings.app.enterpriseName",
            ),
            [],
        )

    if app_name == "githubcloud":
        org_field = "githubOrg" if app_settings.get("githubOrg") else "orgName"
        org_name = _valid_github_slug(app_settings.get(org_field))
        if not org_name:
            return None, ["missing_or_malformed_settings.app.githubOrg_or_orgName"]
        source_field = f"settings.app.{org_field}"
        return (
            _SamlRouteEvidence(
                acs_url=f"https://github.com/orgs/{org_name}/saml/consume",
                sp_entity_id=f"https://github.com/orgs/{org_name}",
                index=0,
                binding=None,
                is_default=True,
                target_product_family="github_organization",
                route_source="settings.app+documented_github_route",
                extraction_mode="allowlisted_deterministic_route",
                acs_source_field=source_field,
                sp_entity_source_field=source_field,
            ),
            [],
        )

    return None, []


def _saml_routes(
    application,
) -> tuple[list[_SamlRouteEvidence], list[str]]:
    if not is_saml_application(application):
        return [], []

    explicit = _explicit_saml_routes(application)
    oin_route, oin_diagnostics = _oin_saml_route(application)
    if explicit.contradictory:
        return [], list(explicit.diagnostics)

    if explicit.routes:
        diagnostics = list(explicit.diagnostics)
        explicit_keys = {
            (route.acs_url, route.sp_entity_id) for route in explicit.routes
        }
        if (
            oin_route
            and (
                oin_route.acs_url,
                oin_route.sp_entity_id,
            )
            not in explicit_keys
        ):
            conflict = "explicit_generic_route_overrides_conflicting_oin_route"
            diagnostics.append(conflict)
            return [
                replace(
                    route,
                    route_conflicts=(*route.route_conflicts, conflict),
                )
                for route in explicit.routes
            ], diagnostics
        return list(explicit.routes), diagnostics

    if oin_route:
        partial_conflicts = []
        if explicit.acs_urls and oin_route.acs_url not in explicit.acs_urls:
            partial_conflicts.append("partial_explicit_acs_conflicts_with_oin_route")
        if explicit.sp_entity_id and explicit.sp_entity_id != oin_route.sp_entity_id:
            partial_conflicts.append(
                "partial_explicit_sp_entity_conflicts_with_oin_route"
            )
        if partial_conflicts:
            return [], partial_conflicts
        return [oin_route], []

    if oin_diagnostics:
        return [], oin_diagnostics
    if explicit.acs_urls and not explicit.sp_entity_id:
        return [], ["missing_authoritative_sp_entity_evidence"]
    if explicit.sp_entity_id and not explicit.acs_urls:
        return [], ["missing_authoritative_acs_evidence"]
    return [], ["missing_authoritative_acs_and_sp_entity_evidence"]


def _field_value(source: Any, field_name: str) -> str | None:
    return _clean(getattr(source, field_name, None))


def _profile_value(profile: Any, field_name: str) -> str | None:
    return _field_value(profile, field_name) if profile else None


def _template_field(template: str | None) -> str | None:
    value = _clean(template)
    if not value:
        return None
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    return value


def _application_user_value(template: str | None, application_user: Any) -> str | None:
    field = _template_field(template)
    credentials = getattr(application_user, "credentials", None)
    profile = getattr(application_user, "profile", None)
    username = _field_value(credentials, "username") if credentials else None

    if not field:
        return username
    if field in {"appuser.userName", "source.login", "user.login"}:
        return username or _profile_value(profile, "login")
    if field in {"source.email", "user.email"}:
        return _profile_value(profile, "email")
    if field in {"source.firstName", "user.firstName"}:
        return _profile_value(profile, "first_name")
    if field in {"source.lastName", "user.lastName"}:
        return _profile_value(profile, "last_name")
    return None


_DIRECT_PROFILE_EXPRESSION = re.compile(
    r"^(source|user|appuser)\.([A-Za-z_][A-Za-z0-9_]*)$"
)
_EMAIL_CLAIM_NAMES = {
    "email",
    "mail",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
}
_UPN_CLAIM_NAMES = {
    "upn",
    "userprincipalname",
    "http://schemas.xmlsoap.org/claims/upn",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
}
_ENTRA_OBJECT_ID_CLAIM_NAMES = {
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
}
_COMMON_ASSERTION_FIELDS = (
    "email_match_values",
    "upn_match_values",
    "entra_object_id_match_values",
    "scoped_exact_match_values",
)
_MISSING = object()


def _mapping_get(mapping: Any, name: str, default: Any = None) -> Any:
    if isinstance(mapping, dict):
        return mapping.get(name, default)
    return getattr(mapping, name, default)


def _direct_profile_field(expression: Any) -> tuple[str, str] | None:
    value = _clean(expression)
    if not value:
        return None
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    match = _DIRECT_PROFILE_EXPRESSION.fullmatch(value)
    if not match:
        return None
    return match.group(1), match.group(2)


def _profile_dict(profile: Any) -> dict[str, Any] | None:
    if profile is None:
        return None
    if isinstance(profile, dict):
        return profile
    model_dump = getattr(profile, "model_dump", None)
    if callable(model_dump):
        return model_dump(by_alias=True)
    return None


def _profile_field(profile: Any, field_name: str) -> Any:
    values = _profile_dict(profile)
    if values is None:
        return _MISSING
    if field_name in values:
        return values[field_name]
    casefolded = {
        key.casefold(): value for key, value in values.items() if isinstance(key, str)
    }
    return casefolded.get(field_name.casefold(), _MISSING)


def _source_exact_values(value: Any) -> list[str]:
    if value is _MISSING or value is None or isinstance(value, dict):
        return []
    candidates = value if isinstance(value, (list, tuple, set)) else [value]
    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate is None or isinstance(candidate, (dict, list, tuple, set)):
            continue
        source_exact = candidate if isinstance(candidate, str) else str(candidate)
        if not source_exact.strip() or source_exact in seen:
            continue
        seen.add(source_exact)
        result.append(source_exact)
    return result


def _dedupe_exact(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _application_user_direct_values(
    direct_field: tuple[str, str],
    application_user: Any,
    source_profile: Any = _MISSING,
) -> list[str]:
    namespace, field_name = direct_field
    profile = getattr(application_user, "profile", None)
    credentials = getattr(application_user, "credentials", None)

    if namespace == "appuser":
        if field_name.casefold() == "username":
            value = getattr(credentials, "username", _MISSING)
        else:
            value = _profile_field(profile, field_name)
        return _source_exact_values(value)

    if source_profile is not _MISSING:
        return _source_exact_values(_profile_field(source_profile, field_name))

    # Legacy collections did not expose the source-user lookup. Preserve their
    # resolved application username for the common source.login template.
    if field_name.casefold() == "login" and credentials is not None:
        username = getattr(credentials, "username", _MISSING)
        values = _source_exact_values(username)
        if values:
            return values
    return _source_exact_values(_profile_field(profile, field_name))


def _claim_family(mapping: Any, direct_field: tuple[str, str] | None) -> str:
    claim_type = _clean(_mapping_get(mapping, "claim_type"))
    if claim_type == "name_id":
        name_id_format = _clean(
            _mapping_get(mapping, "format") or _mapping_get(mapping, "name_id_format")
        )
        if name_id_format == TRANSIENT_NAME_ID_FORMAT:
            return "transient"
        if name_id_format == EMAIL_NAME_ID_FORMAT:
            return "email_match_values"
        if name_id_format == PERSISTENT_NAME_ID_FORMAT:
            return "scoped_exact_match_values"
        if _mapping_get(mapping, "mapping_origin") == "application_user_name":
            return "scoped_exact_match_values"
        if direct_field:
            field_name = direct_field[1].casefold()
            if field_name in {"email", "mail"}:
                return "email_match_values"
            if field_name in {"upn", "userprincipalname"}:
                return "upn_match_values"
        return "raw_name_id"

    claim_name = (_clean(_mapping_get(mapping, "claim_name")) or "").casefold()
    if claim_name in _EMAIL_CLAIM_NAMES:
        return "email_match_values"
    if claim_name in _UPN_CLAIM_NAMES:
        return "upn_match_values"
    if claim_name in _ENTRA_OBJECT_ID_CLAIM_NAMES:
        return "entra_object_id_match_values"
    return "exceptional"


def _canonical_common_value(family: str, source_exact: str) -> str | None:
    value = source_exact.strip()
    if family in {"email_match_values", "upn_match_values"}:
        return value.casefold()
    if family == "entra_object_id_match_values":
        try:
            return str(UUID(value))
        except ValueError:
            return None
    if family == "scoped_exact_match_values":
        return value
    return None


def _fallback_application_claim_mapping(application_user: Any) -> dict[str, Any]:
    subject_template = getattr(application_user, "app_subject_name_id_template", None)
    user_name_template = getattr(application_user, "app_user_name_template", None)
    return {
        "id": saml_claim_mapping_id(getattr(application_user, "app_id"), 0),
        "claim_name": "NameID",
        "mapping_type": "name_id",
        "mapping_origin": (
            "subject_name_id" if subject_template else "application_user_name"
        ),
        "claim_type": "name_id",
        "source_property": saml_match_source(
            subject_template or user_name_template or "appuser.userName"
        ),
        "expression": subject_template or user_name_template or "appuser.userName",
        "format": _clean(getattr(application_user, "app_subject_name_id_format", None))
        or UNSPECIFIED_NAME_ID_FORMAT,
    }


def saml_application_assertion_evidence(
    application_user: Any,
    claim_mappings: list[Any] | tuple[Any, ...] | None = None,
    source_profile: Any = _MISSING,
) -> dict[str, Any]:
    """Resolve every source-proven outbound assertion value for one assignment."""

    mappings = (
        [_fallback_application_claim_mapping(application_user)]
        if claim_mappings is None
        else list(claim_mappings)
    )
    evidence: dict[str, Any] = {
        "match_values": [],
        "email_match_values": [],
        "upn_match_values": [],
        "entra_object_id_match_values": [],
        "scoped_exact_match_values": [],
        "incomplete_match_value_fields": [],
        "source_properties": [],
        "claim_values": [],
    }

    # A SAML application always has a NameID mapping. An explicitly empty
    # preprocessed mapping set therefore means the authoritative configuration
    # was unavailable, not that the application asserts no identity values.
    if claim_mappings is not None and not mappings:
        evidence["incomplete_match_value_fields"] = list(_COMMON_ASSERTION_FIELDS)
        return evidence

    incomplete_fields: set[str] = set()
    for mapping in mappings:
        expression = _mapping_get(mapping, "expression")
        direct_field = _direct_profile_field(expression)
        declared_source = _mapping_get(mapping, "source_property")
        declared_direct = (
            _direct_profile_field(declared_source) if declared_source else direct_field
        )
        source_conflict = bool(
            direct_field and declared_source and declared_direct != direct_field
        )
        resolvable = direct_field is not None and not source_conflict
        values = (
            _application_user_direct_values(
                direct_field, application_user, source_profile
            )
            if resolvable and direct_field
            else []
        )
        family = _claim_family(mapping, direct_field)
        mapping_id = _clean(_mapping_get(mapping, "id"))
        source_property = (
            f"{direct_field[0]}.{direct_field[1]}" if direct_field else None
        )

        if family in _COMMON_ASSERTION_FIELDS:
            canonical_values = [
                canonical
                for value in values
                if (canonical := _canonical_common_value(family, value)) is not None
            ]
            if not resolvable or len(canonical_values) != len(values) or not values:
                incomplete_fields.add(family)
            evidence["match_values"].extend(values)
            evidence[family].extend(canonical_values)
            if values and source_property:
                evidence["source_properties"].append(source_property)
            continue

        if family == "raw_name_id" and values:
            evidence["match_values"].extend(values)
            if source_property:
                evidence["source_properties"].append(source_property)
            continue

        if not mapping_id:
            continue
        exceptional = {
            "mapping_id": mapping_id,
            "match_values": values,
            "canonical_match_values": ([] if family == "transient" else list(values)),
            "unsafe_match_values": list(values) if family == "transient" else [],
            "incomplete": not resolvable or not values,
            "source_property": source_property,
        }
        evidence["claim_values"].append(exceptional)

    evidence["match_values"] = _dedupe_exact(evidence["match_values"])
    for field_name in _COMMON_ASSERTION_FIELDS:
        evidence[field_name] = _dedupe_exact(evidence[field_name])
    evidence["source_properties"] = _dedupe_exact(evidence["source_properties"])
    evidence["incomplete_match_value_fields"] = [
        field_name
        for field_name in _COMMON_ASSERTION_FIELDS
        if field_name in incomplete_fields
    ]
    return evidence


def _idp_user_value(template: str | None, idp_user: Any) -> str | None:
    field = _template_field(template)
    profile = getattr(idp_user, "profile", None)

    if not field:
        return None
    if field == "idpuser.email":
        return _profile_value(profile, "email")
    if field == "idpuser.subjectNameId":
        return _profile_value(profile, "subject_name_id")
    if field == "idpuser.subjectNameQualifier":
        return _profile_value(profile, "subject_name_qualifier")
    if field == "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier":
        subject = _profile_value(profile, "subject_name_id")
        qualifier = _profile_value(profile, "subject_name_qualifier")
        if subject and qualifier:
            return f"{subject}@{qualifier}"
    return None


def saml_application_match_values(application_user: Any) -> list[str]:
    return saml_application_identity_evidence(application_user)["match_values"]


def saml_application_identity_evidence(
    application_user: Any,
) -> dict[str, list[str]]:
    """Resolve the legacy selected NameID view for API compatibility."""

    evidence = saml_application_assertion_evidence(application_user)
    return {
        "match_values": evidence["match_values"],
        "email_match_values": evidence["email_match_values"],
        "scoped_exact_match_values": evidence["scoped_exact_match_values"],
    }


def saml_idp_user_match_values(idp_user: Any) -> list[str]:
    return saml_idp_user_identity_evidence(idp_user)["match_values"]


def saml_idp_user_identity_evidence(idp_user: Any) -> dict[str, list[str]]:
    """Preserve values from Okta's native resolved inbound-IdP user link."""

    template = getattr(idp_user, "idp_subject_user_name_template", None)
    subject_value = _idp_user_value(template, idp_user)
    external_id = _clean(getattr(idp_user, "external_id", None))
    profile = getattr(idp_user, "profile", None)
    ms_object_identifier = _profile_value(profile, "ms_object_identifier")
    match_values = _dedupe([subject_value, external_id, ms_object_identifier])
    source_property = saml_match_source(template)

    email_values = (
        [subject_value.casefold()]
        if subject_value and source_property == "idpuser.email"
        else []
    )
    entra_object_ids: list[str] = []
    idp_url = _clean(getattr(idp_user, "idp_url", None))
    if ms_object_identifier and idp_url and "microsoftonline.com" in idp_url.casefold():
        try:
            entra_object_ids.append(str(UUID(ms_object_identifier)))
        except ValueError:
            pass

    classified = {*email_values, *entra_object_ids}
    scoped_exact_values = [
        value
        for value in match_values
        if value.casefold() not in {item.casefold() for item in classified}
    ]
    return {
        "match_values": match_values,
        "email_match_values": email_values,
        "entra_object_id_match_values": entra_object_ids,
        "scoped_exact_match_values": scoped_exact_values,
    }


def saml_match_source(template: str | None) -> str | None:
    return _template_field(template)


def _statement_source_property(expression: str | None) -> str | None:
    """Return a readable source field only when Okta supplied an expression."""

    value = _clean(expression)
    if not value or value.startswith(("{", "[")):
        return None
    return saml_match_source(value)


def _statement_value(statement: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = statement.get(key)
        if isinstance(value, list):
            cleaned_values = _dedupe([str(item) for item in value])
            if cleaned_values:
                return ",".join(cleaned_values)
        cleaned_value = _clean(value)
        if cleaned_value:
            return cleaned_value
    return None


def _statement_expression(statement: dict[str, Any]) -> str | None:
    value = _statement_value(
        statement,
        "value",
        "expression",
        "filterValue",
        "values",
        "attributeValue",
    )
    if value:
        return value
    if statement:
        return json.dumps(statement, sort_keys=True, separators=(",", ":"))
    return None


def is_saml_application(application) -> bool:
    return getattr(application, "sign_on_mode", None) == "SAML_2_0"


def is_saml_identity_provider(identity_provider) -> bool:
    protocol = getattr(identity_provider, "protocol", None)
    return (
        getattr(identity_provider, "type", None) == "SAML2"
        and getattr(protocol, "type", None) == "SAML2"
    )


def normalize_okta_account_state(status: Any) -> str:
    """Map authoritative Okta lifecycle status to the v0.3 vocabulary."""

    native_status = _clean(status)
    if native_status is None:
        return "unknown"
    return {
        "ACTIVE": "enabled",
        "SUSPENDED": "suspended",
        "DEPROVISIONED": "deprovisioned",
        "LOCKED_OUT": "login_blocked",
    }.get(native_status, "unknown")


@dataclass(frozen=True)
class _AccountResolutionEvidence:
    assertion_field: str | None = None
    expression: str | None = None
    summary: str | None = None
    diagnostics: tuple[str, ...] = ()


def _empty_policy_filter(value: Any) -> bool:
    return value is None or value == "" or value == {} or value == []


def _account_resolution_evidence(identity_provider) -> _AccountResolutionEvidence:
    """Fail closed unless Okta fully proves automatic exact login matching."""

    if not is_saml_identity_provider(identity_provider):
        return _AccountResolutionEvidence()

    policy = getattr(identity_provider, "policy", None)
    if policy is None:
        return _AccountResolutionEvidence(
            diagnostics=("missing_identity_provider_policy",)
        )

    account_link = getattr(policy, "account_link", None)
    subject = getattr(policy, "subject", None)
    diagnostics: list[str] = []
    if not isinstance(account_link, dict):
        diagnostics.append("missing_policy.accountLink")
        account_link = {}
    if not isinstance(subject, dict):
        diagnostics.append("missing_policy.subject")
        subject = {}

    if _clean(account_link.get("action")) != "AUTO":
        diagnostics.append("policy.accountLink.action_must_be_AUTO")
    if not _empty_policy_filter(account_link.get("filter")):
        diagnostics.append("policy.accountLink.filter_is_scoped_or_unsupported")

    if _clean(subject.get("matchType")) != "USERNAME":
        diagnostics.append("policy.subject.matchType_must_be_USERNAME")
    if not _empty_policy_filter(subject.get("filter")):
        diagnostics.append("policy.subject.filter_is_unsupported")
    if not _empty_policy_filter(subject.get("matchAttribute")):
        diagnostics.append("policy.subject.matchAttribute_conflicts_with_username")
    if getattr(policy, "transformed_username_matching_enabled", None) is True:
        diagnostics.append("transformed_username_matching_is_unsupported")

    user_name_template = subject.get("userNameTemplate")
    template = (
        _clean(user_name_template.get("template"))
        if isinstance(user_name_template, dict)
        else None
    )
    assertion_field = (
        {
            "idpuser.email": "email_match_values",
            "idpuser.subjectNameId": "scoped_exact_match_values",
            "saml.subjectNameId": "scoped_exact_match_values",
        }.get(template)
        if template is not None
        else None
    )
    if assertion_field is None:
        diagnostics.append("policy.subject.userNameTemplate_is_unsupported")

    if diagnostics:
        return _AccountResolutionEvidence(diagnostics=tuple(diagnostics))

    assert assertion_field is not None
    assertion_label = {
        "email_match_values": "email value",
        "scoped_exact_match_values": "route-scoped exact value",
    }[assertion_field]
    return _AccountResolutionEvidence(
        assertion_field=assertion_field,
        expression=(
            'account.fields.exists(field, field.name == "login" && '
            f"assertion.{assertion_field}.exists(value, value in "
            "field.match_values))"
        ),
        summary=f'Any assertion {assertion_label} exactly matches account field "login"',
    )


def _idp_trust(identity_provider) -> Any:
    protocol = getattr(identity_provider, "protocol", None)
    credentials = getattr(protocol, "credentials", None)
    return getattr(credentials, "trust", None)


def _trusted_issuer(identity_provider) -> str | None:
    return _clean(getattr(_idp_trust(identity_provider), "issuer", None))


def _trusted_audience(identity_provider) -> str | None:
    return _clean(getattr(_idp_trust(identity_provider), "audience", None))


def _idp_sp_entity_id(identity_provider) -> str | None:
    return _clean(
        getattr(identity_provider, "saml_metadata_entity_id", None)
    ) or _trusted_audience(identity_provider)


def _idp_acs_url(identity_provider) -> str | None:
    links = getattr(identity_provider, "links", None) or {}
    acs = links.get("acs") if isinstance(links, dict) else None
    if isinstance(acs, dict):
        return _clean(acs.get("href"))
    return _clean(getattr(acs, "href", None))


def saml_federation_provider_row(application) -> dict[str, Any] | None:
    sign_on = _sign_on(application)
    if not is_saml_application(application):
        return None
    idp_issuer = _idp_issuer(application, sign_on)
    routes, route_diagnostics = _saml_routes(application)
    acs_rows = _saml_acs_rows(application, routes)
    claim_mapping_rows = saml_claim_mapping_rows(application)
    return {
        "id": saml_provider_id(application.id),
        "app_id": application.id,
        "app_name": application.name,
        "app_label": application.label,
        "app_status": application.status,
        "issuer_id": saml_issuer_id(application.id) if idp_issuer else None,
        "acs_ids": [row["id"] for row in acs_rows],
        "claim_mapping_ids": [row["id"] for row in claim_mapping_rows],
        "enabled": application.status == "ACTIVE",
        "route_diagnostics": route_diagnostics,
    }


def saml_claim_mapping_rows(application) -> list[dict[str, Any]]:
    sign_on = _sign_on(application)
    if not is_saml_application(application) or not sign_on:
        return []

    rows: list[dict[str, Any]] = []
    subject_template = _clean(getattr(sign_on, "subject_name_id_template", None))
    user_name_template = None
    credentials = getattr(application, "credentials", None)
    user_name_template_value = getattr(credentials, "user_name_template", None)
    if isinstance(user_name_template_value, dict):
        user_name_template = _clean(user_name_template_value.get("template"))

    if subject_template or user_name_template:
        native_format = _clean(getattr(sign_on, "subject_name_id_format", None))
        rows.append(
            {
                "id": saml_claim_mapping_id(application.id, len(rows)),
                "app_id": application.id,
                "app_name": application.name,
                "app_label": application.label,
                "claim_name": "NameID",
                "mapping_type": "name_id",
                "mapping_origin": (
                    "subject_name_id" if subject_template else "application_user_name"
                ),
                "claim_type": "name_id",
                "source_property": saml_match_source(
                    subject_template or user_name_template
                ),
                "expression": subject_template or user_name_template,
                "name_id_format": native_format,
                "format": native_format or UNSPECIFIED_NAME_ID_FORMAT,
                "format_was_omitted": native_format is None,
                "name_format": None,
                "name_format_was_omitted": None,
            }
        )

    statements = [
        ("attribute", item)
        for item in getattr(sign_on, "attribute_statements", None) or []
    ]
    statements.extend(
        [
            ("configured_attribute", item)
            for item in getattr(sign_on, "configured_attribute_statements", None) or []
        ]
    )
    for mapping_type, statement in statements:
        if not isinstance(statement, dict):
            continue
        expression = _statement_expression(statement)
        claim_name = _statement_value(statement, "name", "attributeName", "type")
        if not expression and not claim_name:
            continue
        native_name_format = _statement_value(
            statement,
            "nameFormat",
            "name_format",
        )
        rows.append(
            {
                "id": saml_claim_mapping_id(application.id, len(rows)),
                "app_id": application.id,
                "app_name": application.name,
                "app_label": application.label,
                "claim_name": claim_name or "attribute",
                "mapping_type": mapping_type,
                "mapping_origin": "attribute_statement",
                "claim_type": "attribute",
                "source_property": _statement_source_property(expression),
                "expression": expression,
                "name_id_format": None,
                "format": None,
                "format_was_omitted": None,
                "name_format": (
                    native_name_format or UNSPECIFIED_ATTRIBUTE_NAME_FORMAT
                ),
                "name_format_was_omitted": native_name_format is None,
            }
        )

    return rows


def saml_issuer_row(application) -> dict[str, Any] | None:
    sign_on = _sign_on(application)
    if not is_saml_application(application) or not sign_on:
        return None
    entity_id = _idp_issuer(application, sign_on)
    if not entity_id:
        return None
    return {
        "id": saml_issuer_id(application.id),
        "app_id": application.id,
        "app_name": application.name,
        "app_label": application.label,
        "source_object_kind": nk.APPLICATION,
        "entity_id": entity_id,
    }


def saml_acs_rows(application) -> list[dict[str, Any]]:
    routes, _ = _saml_routes(application)
    return _saml_acs_rows(application, routes)


def _saml_acs_rows(
    application,
    routes: list[_SamlRouteEvidence],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    used_id_indexes: set[int] = set()
    for route in routes:
        preferred_id_index = route.index if route.index is not None else len(rows)
        id_index = int(preferred_id_index)
        while id_index in used_id_indexes:
            id_index += 1
        used_id_indexes.add(id_index)
        row = {
            "id": saml_acs_id(application.id, id_index),
            "app_id": application.id,
            "app_name": application.name,
            "app_label": application.label,
            "source_object_kind": nk.APPLICATION,
            "acs_url": route.acs_url,
            "sp_entity_id": route.sp_entity_id,
            "index": route.index if route.index is not None else id_index,
            "binding": route.binding,
            "is_default": route.is_default,
            "source_technology": "okta",
            "provider_family": "okta",
            "target_product_family": route.target_product_family,
            "route_source": route.route_source,
            "extraction_mode": route.extraction_mode,
            "acs_source_field": route.acs_source_field,
            "sp_entity_source_field": route.sp_entity_source_field,
            "route_conflicts": list(route.route_conflicts),
        }
        rows.append(row)

    return rows


def saml_service_provider_row(identity_provider) -> dict[str, Any] | None:
    if not is_saml_identity_provider(identity_provider):
        return None

    issuer = _trusted_issuer(identity_provider)
    acs_rows = saml_sp_acs_rows(identity_provider)
    resolution = _account_resolution_evidence(identity_provider)
    rule_id = (
        saml_account_resolution_rule_id(identity_provider.id)
        if resolution.expression
        else None
    )
    return {
        "id": saml_service_provider_id(identity_provider.id),
        "idp_id": identity_provider.id,
        "idp_name": identity_provider.name,
        "idp_type": identity_provider.type,
        "idp_status": identity_provider.status,
        "sp_entity_id": _idp_sp_entity_id(identity_provider),
        "issuer_id": saml_trusted_issuer_id(identity_provider.id) if issuer else None,
        "acs_ids": [row["id"] for row in acs_rows],
        "account_resolution_rule_id": rule_id,
        "account_resolution_field_id": (
            saml_account_resolution_field_id(identity_provider.id) if rule_id else None
        ),
        "account_resolution_diagnostics": list(resolution.diagnostics),
        "enabled": identity_provider.status == "ACTIVE",
    }


def saml_account_resolution_rule_row(
    identity_provider,
) -> dict[str, Any] | None:
    resolution = _account_resolution_evidence(identity_provider)
    if not resolution.expression or not resolution.summary:
        return None
    return {
        "id": saml_account_resolution_rule_id(identity_provider.id),
        "idp_id": identity_provider.id,
        "idp_name": identity_provider.name,
        "field_id": saml_account_resolution_field_id(identity_provider.id),
        "expression_language": "cel",
        "expression_profile": ACCOUNT_RESOLUTION_PROFILE,
        "expression": resolution.expression,
        "summary": resolution.summary,
    }


def saml_account_resolution_field_row(
    identity_provider,
) -> dict[str, Any] | None:
    resolution = _account_resolution_evidence(identity_provider)
    if not resolution.expression:
        return None
    return {
        "id": saml_account_resolution_field_id(identity_provider.id),
        "idp_id": identity_provider.id,
        "idp_name": identity_provider.name,
        "account_field_name": "login",
    }


def saml_trusted_issuer_row(identity_provider) -> dict[str, Any] | None:
    if not is_saml_identity_provider(identity_provider):
        return None
    entity_id = _trusted_issuer(identity_provider)
    if not entity_id:
        return None
    return {
        "id": saml_trusted_issuer_id(identity_provider.id),
        "app_id": identity_provider.id,
        "app_name": identity_provider.name,
        "app_label": identity_provider.name,
        "source_object_kind": nk.IDP,
        "entity_id": entity_id,
    }


def saml_sp_acs_rows(identity_provider) -> list[dict[str, Any]]:
    if not is_saml_identity_provider(identity_provider):
        return []

    sp_entity_id = _idp_sp_entity_id(identity_provider)
    if not sp_entity_id:
        return []

    metadata_routes = []
    seen_urls: set[str] = set()
    for endpoint in (
        getattr(identity_provider, "saml_metadata_acs_endpoints", None) or []
    ):
        acs_url = _clean(getattr(endpoint, "url", None))
        if not acs_url or acs_url in seen_urls:
            continue
        seen_urls.add(acs_url)
        metadata_routes.append(
            {
                "acs_url": acs_url,
                "index": getattr(endpoint, "index", None),
                "binding": _clean(getattr(endpoint, "binding", None)),
                "is_default": getattr(endpoint, "is_default", None),
            }
        )

    if metadata_routes:
        return [
            {
                "id": saml_sp_acs_id(identity_provider.id, row_index),
                "app_id": identity_provider.id,
                "app_name": identity_provider.name,
                "app_label": identity_provider.name,
                "source_object_kind": nk.IDP,
                "acs_url": route["acs_url"],
                "sp_entity_id": sp_entity_id,
                "index": (
                    route["index"]
                    if route["index"] is not None
                    else row_index
                ),
                "binding": route["binding"],
                "is_default": route["is_default"],
                "route_source": "identity_provider_metadata",
                "extraction_mode": "explicit_metadata",
                "acs_source_field": (
                    "metadata.SPSSODescriptor.AssertionConsumerService.Location"
                ),
                "sp_entity_source_field": "metadata.EntityDescriptor.entityID",
            }
            for row_index, route in enumerate(metadata_routes)
        ]

    acs_url = _idp_acs_url(identity_provider)
    if not acs_url:
        return []

    return [
        {
            "id": saml_sp_acs_id(identity_provider.id, 0),
            "app_id": identity_provider.id,
            "app_name": identity_provider.name,
            "app_label": identity_provider.name,
            "source_object_kind": nk.IDP,
            "acs_url": acs_url,
            "sp_entity_id": sp_entity_id,
            "index": 0,
            "binding": _clean(
                getattr(
                    getattr(identity_provider.protocol.endpoints, "acs", None),
                    "binding",
                    None,
                )
            ),
            "is_default": True,
        }
    ]


def saml_match_values(*values: str | None) -> list[str]:
    return _dedupe(list(values))


@dataclass
class SamlFederationProviderProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML federation provider.

    Attributes:
        app_id: The Okta application ID that implements the provider.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        app_status: The Okta application lifecycle status.
        enabled: Whether the application is active.
        route_diagnostics: Missing or conflicting route evidence retained for review.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    app_id: str
    app_name: str
    app_label: str
    app_status: str
    enabled: bool
    route_diagnostics: list[str] = dc_field(default_factory=list)
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlIssuerProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML issuer.

    Attributes:
        app_id: The Okta application ID that owns the issuer.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        source_object_kind: The native OpenGraph kind that owns this SAML issuer.
        entity_id: The byte-exact SAML issuer entity ID.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    app_id: str
    app_name: str
    app_label: str
    entity_id: str
    source_object_kind: str = nk.APPLICATION
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlAssertionConsumerServiceProperties(OktaNodeProperties):
    """Properties for a normalized Okta-targeted SAML ACS route.

    Attributes:
        app_id: The Okta application ID that owns the ACS route.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        source_object_kind: The native OpenGraph kind that owns this ACS route.
        acs_url: The byte-exact SAML assertion consumer service URL.
        sp_entity_id: The byte-exact SAML service provider entity ID.
        index: The ACS endpoint index from Okta.
        binding: The SAML binding for this ACS endpoint, when present.
        is_default: Whether Okta marks this ACS endpoint as default.
        source_technology: The native technology that produced the route evidence.
        provider_family: The SAML identity-provider technology family.
        target_product_family: The allowlisted downstream product family.
        route_source: The native settings source used for the route tuple.
        extraction_mode: Whether the route was explicit or deterministically derived.
        acs_source_field: The exact native field that proved or scoped the ACS URL.
        sp_entity_source_field: The exact native field that proved or scoped the SP entity.
        route_conflicts: Conflicting lower-precedence route evidence retained for review.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    app_id: str
    app_name: str
    app_label: str
    acs_url: str
    sp_entity_id: str
    index: int
    source_object_kind: str = nk.APPLICATION
    binding: str | None = None
    is_default: bool | None = None
    source_technology: str = "okta"
    provider_family: str = "okta"
    target_product_family: str = "generic_saml"
    route_source: str = "settings.signOn"
    extraction_mode: str = "explicit_generic"
    acs_source_field: str | None = None
    sp_entity_source_field: str | None = None
    route_conflicts: list[str] = dc_field(default_factory=list)
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlServiceProviderProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML service provider.

    Attributes:
        idp_id: The Okta identity provider ID that implements the SP role.
        idp_name: The Okta identity provider display name.
        idp_type: The Okta identity provider type.
        idp_status: The Okta identity provider lifecycle status.
        sp_entity_id: The byte-exact Okta SP entity ID or audience.
        enabled: Whether the identity provider is active.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    idp_id: str
    idp_name: str
    idp_type: str
    idp_status: str
    sp_entity_id: str | None = None
    enabled: bool = False
    account_resolution_diagnostics: list[str] = dc_field(default_factory=list)
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlAccountResolutionRuleProperties(OktaNodeProperties):
    """Properties for a source-proven Okta account-resolution rule."""

    idp_id: str
    idp_name: str
    expression_language: str
    expression_profile: str
    expression: str
    summary: str
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlAccountResolutionFieldProperties(OktaNodeProperties):
    """Properties for the Okta login field used by an inbound SAML policy."""

    idp_id: str
    idp_name: str
    account_field_name: str
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlClaimMappingProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML claim mapping.

    Attributes:
        app_id: The Okta application ID that owns the claim mapping.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        claim_name: The SAML claim or NameID slot being populated.
        mapping_type: The Okta mapping source, such as name_id or attribute.
        mapping_origin: The native configuration slot that supplied the mapping.
        source_property: The portable source field name when it can be resolved.
        expression: The raw Okta expression or statement payload.
        name_id_format: The requested SAML NameID format when the mapping is NameID.
        claim_type: Contract claim type, either name_id or attribute.
        format: Effective NameID format for a name_id mapping.
        format_was_omitted: Whether the native NameID format was omitted.
        name_format: Effective attribute NameFormat for an attribute mapping.
        name_format_was_omitted: Whether the native attribute NameFormat was omitted.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    app_id: str
    app_name: str
    app_label: str
    claim_name: str
    mapping_type: str
    claim_type: str
    mapping_origin: str | None = None
    source_property: str | None = None
    expression: str | None = None
    name_id_format: str | None = None
    format: str | None = None
    format_was_omitted: bool | None = None
    name_format: str | None = None
    name_format_was_omitted: bool | None = None
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlRelationshipProperties(EdgeProperties):
    """Fact-local metadata for normalized Okta SAML topology.

    Attributes:
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlMatchValuesEdgeProperties(EdgeProperties):
    """Properties for normalized Okta SAML match-value edges.

    Attributes:
        match_values: Identity values Okta can assert for the assignment.
        source_property: The Okta field or expression source for the match values.
        email_match_values: Canonical email values justified by native semantics.
        scoped_exact_match_values: Route-scoped exact NameID or provider-subject values.
        schema_contract_version: Fact-local normalized SAML contract version.
    """

    match_values: list[str] = dc_field(default_factory=list)
    source_property: str | None = None
    source_properties: list[str] = dc_field(default_factory=list)
    email_match_values: list[str] = dc_field(default_factory=list)
    upn_match_values: list[str] = dc_field(default_factory=list)
    entra_object_id_match_values: list[str] = dc_field(default_factory=list)
    scoped_exact_match_values: list[str] = dc_field(default_factory=list)
    incomplete_match_value_fields: list[str] = dc_field(default_factory=list)
    assignment_source: str | None = None
    schema_contract_version: str = SAML_CONTRACT_VERSION


@dataclass
class SamlAccountEdgeProperties(SamlMatchValuesEdgeProperties):
    """Properties for normalized Okta SAML service-provider account edges.

    Attributes:
        match_values: Concrete values accepted for SAML account matching.
        source_property: The Okta IdP user field used to resolve match values.
        account_state: Account reachability state when known.
        entra_object_id_match_values: Entra object IDs proven by the inbound provider link.
        direct_binding: Whether Okta directly resolved this provider-scoped account link.
        direct_binding_source: Native Okta source that proved the resolved link.
    """

    account_state: str | None = None
    entra_object_id_match_values: list[str] = dc_field(default_factory=list)
    direct_binding: bool = False
    direct_binding_source: str | None = None


@dataclass
class SamlResolutionValueEdgeProperties(EdgeProperties):
    """Source and canonical values for an exceptional account field."""

    match_values: list[str] = dc_field(default_factory=list)
    canonical_match_values: list[str] = dc_field(default_factory=list)
    unsafe_match_values: list[str] = dc_field(default_factory=list)
    source_property: str | None = None
    incomplete: bool = False
    schema_contract_version: str = SAML_CONTRACT_VERSION


@app.asset(
    node=NodeDef(
        icon="id-card",
        kind=nk.SAML_FEDERATION_PROVIDER,
        description="Normalized SAML federation provider implemented by an Okta SAML app",
        properties=SamlFederationProviderProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.SAML_FEDERATION_PROVIDER,
            kind=ek.SAML_IMPLEMENTS,
            description="Okta application implements a normalized SAML provider",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_ISSUER,
            kind=ek.SAML_ISSUES_AS,
            description="SAML provider issues assertions as an issuer entity ID",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_ASSERTION_CONSUMER_SERVICE,
            kind=ek.SAML_ISSUES_ASSERTIONS_TO,
            description="SAML provider issues assertions to an SP ACS route",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_CLAIM_MAPPING,
            kind=ek.SAML_HAS_CLAIM_MAPPING,
            description="SAML provider has a claim mapping explanation",
            traversable=False,
        ),
    ],
)
class SamlFederationProvider(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    app_status: str
    issuer_id: str | None = None
    acs_ids: list[str] = Field(default_factory=list)
    claim_mapping_ids: list[str] = Field(default_factory=list)
    enabled: bool
    route_diagnostics: list[str] = Field(default_factory=list)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_FEDERATION_PROVIDER],
            properties=SamlFederationProviderProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.app_name,
                displayname=self.app_label or self.app_name,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                app_status=self.app_status,
                enabled=self.enabled,
                route_diagnostics=self.route_diagnostics,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.SAML_IMPLEMENTS,
            start=EdgePath(value=self.app_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=SamlRelationshipProperties(traversable=False),
        )
        if self.issuer_id:
            yield Edge(
                kind=ek.SAML_ISSUES_AS,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.issuer_id, match_by="id"),
                properties=SamlRelationshipProperties(traversable=False),
            )
        for acs_id in self.acs_ids:
            yield Edge(
                kind=ek.SAML_ISSUES_ASSERTIONS_TO,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=acs_id, match_by="id"),
                properties=SamlRelationshipProperties(traversable=False),
            )
        for claim_mapping_id in self.claim_mapping_ids:
            yield Edge(
                kind=ek.SAML_HAS_CLAIM_MAPPING,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=claim_mapping_id, match_by="id"),
                properties=SamlRelationshipProperties(traversable=False),
            )


@app.asset(
    node=NodeDef(
        icon="split",
        kind=nk.SAML_CLAIM_MAPPING,
        description="Normalized SAML claim mapping for an Okta SAML app",
        properties=SamlClaimMappingProperties,
    ),
)
class SamlClaimMapping(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def hydrate_legacy_claim_type(cls, value):
        """Keep v0.2 collections convertible after the v0.3 schema upgrade."""
        if not isinstance(value, dict) or value.get("claim_type"):
            return value
        mapping_type = value.get("mapping_type")
        if not mapping_type:
            return value
        hydrated = dict(value)
        hydrated["claim_type"] = "name_id" if mapping_type == "name_id" else "attribute"
        return hydrated

    id: str
    app_id: str
    app_name: str
    app_label: str
    claim_name: str
    mapping_type: str
    claim_type: str
    mapping_origin: str | None = None
    source_property: str | None = None
    expression: str | None = None
    name_id_format: str | None = None
    format: str | None = None
    format_was_omitted: bool | None = None
    name_format: str | None = None
    name_format_was_omitted: bool | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_CLAIM_MAPPING],
            properties=SamlClaimMappingProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.claim_name,
                displayname=f"{self.app_label}:{self.claim_name}",
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                claim_name=self.claim_name,
                mapping_type=self.mapping_type,
                claim_type=self.claim_type,
                mapping_origin=self.mapping_origin,
                source_property=self.source_property,
                expression=self.expression,
                name_id_format=self.name_id_format,
                format=self.format,
                format_was_omitted=self.format_was_omitted,
                name_format=self.name_format,
                name_format_was_omitted=self.name_format_was_omitted,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        icon="key-round",
        kind=nk.SAML_ISSUER,
        description="Normalized SAML issuer entity ID for an Okta SAML app",
        properties=SamlIssuerProperties,
    ),
)
class SamlIssuer(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    entity_id: str
    source_object_kind: str = nk.APPLICATION

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ISSUER],
            properties=SamlIssuerProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.entity_id,
                displayname=self.entity_id,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                entity_id=self.entity_id,
                source_object_kind=self.source_object_kind,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        icon="key-round",
        kind=nk.SAML_ISSUER,
        description="Normalized SAML issuer trusted by an Okta inbound IdP",
        properties=SamlIssuerProperties,
    ),
)
class SamlTrustedIssuer(SamlIssuer):
    """Distinct conversion asset for inbound trusted issuers.

    OpenHound derives output filenames from the asset class name. Keeping inbound
    and outbound issuer streams on the same class causes the later stream to
    overwrite the earlier ``samlissuer`` graph file during conversion.
    """


@app.asset(
    node=NodeDef(
        icon="route",
        kind=nk.SAML_ASSERTION_CONSUMER_SERVICE,
        description="Normalized SAML ACS route for an Okta SAML app",
        properties=SamlAssertionConsumerServiceProperties,
    ),
)
class SamlAssertionConsumerService(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    acs_url: str
    sp_entity_id: str
    index: int
    source_object_kind: str = nk.APPLICATION
    binding: str | None = None
    is_default: bool | None = None
    source_technology: str = "okta"
    provider_family: str = "okta"
    target_product_family: str = "generic_saml"
    route_source: str = "settings.signOn"
    extraction_mode: str = "explicit_generic"
    acs_source_field: str | None = None
    sp_entity_source_field: str | None = None
    route_conflicts: list[str] = Field(default_factory=list)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ASSERTION_CONSUMER_SERVICE],
            properties=SamlAssertionConsumerServiceProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.acs_url,
                displayname=self.acs_url,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                acs_url=self.acs_url,
                sp_entity_id=self.sp_entity_id,
                index=self.index,
                source_object_kind=self.source_object_kind,
                binding=self.binding,
                is_default=self.is_default,
                source_technology=self.source_technology,
                provider_family=self.provider_family,
                target_product_family=self.target_product_family,
                route_source=self.route_source,
                extraction_mode=self.extraction_mode,
                acs_source_field=self.acs_source_field,
                sp_entity_source_field=self.sp_entity_source_field,
                route_conflicts=self.route_conflicts,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        icon="route",
        kind=nk.SAML_ASSERTION_CONSUMER_SERVICE,
        description="Normalized SAML ACS route owned by an Okta inbound IdP",
        properties=SamlAssertionConsumerServiceProperties,
    ),
)
class SamlServiceProviderAssertionConsumerService(SamlAssertionConsumerService):
    """Distinct conversion asset for inbound service-provider ACS routes."""


@app.asset(
    node=NodeDef(
        icon="plug",
        kind=nk.SAML_SERVICE_PROVIDER,
        description="Normalized SAML service provider implemented by an Okta inbound IdP",
        properties=SamlServiceProviderProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.IDP,
            end=nk.SAML_SERVICE_PROVIDER,
            kind=ek.SAML_IMPLEMENTS,
            description="Okta identity provider implements a normalized SAML service provider",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ISSUER,
            kind=ek.SAML_TRUSTS_ISSUER,
            description="SAML service provider trusts an issuer entity ID",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ASSERTION_CONSUMER_SERVICE,
            kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
            description="SAML service provider owns an ACS route",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ACCOUNT_RESOLUTION_RULE,
            kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE,
            description="SAML service provider uses an exact Okta login-resolution rule",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.USER,
            kind=ek.SAML_HAS_ACCOUNT,
            description="SAML service provider can resolve assertions to an Okta account",
            traversable=False,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
            kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE,
            description="Okta account supplies an exact login-resolution value",
            traversable=False,
        ),
    ],
)
class SamlServiceProvider(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    idp_id: str
    idp_name: str
    idp_type: str
    idp_status: str
    sp_entity_id: str | None = None
    issuer_id: str | None = None
    acs_ids: list[str] = Field(default_factory=list)
    account_resolution_rule_id: str | None = None
    account_resolution_field_id: str | None = None
    account_resolution_diagnostics: list[str] = Field(default_factory=list)
    enabled: bool

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_SERVICE_PROVIDER],
            properties=SamlServiceProviderProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.idp_name,
                displayname=self.idp_name,
                environmentid=self._lookup.org_id(),
                idp_id=self.idp_id,
                idp_name=self.idp_name,
                idp_type=self.idp_type,
                idp_status=self.idp_status,
                sp_entity_id=self.sp_entity_id,
                enabled=self.enabled,
                account_resolution_diagnostics=self.account_resolution_diagnostics,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def _account_resolution_edges(self):
        if not self.account_resolution_rule_id or not self.account_resolution_field_id:
            return

        yield Edge(
            kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.account_resolution_rule_id, match_by="id"),
            properties=SamlRelationshipProperties(traversable=False),
        )

        try:
            lookup = self._lookup
        except AttributeError:
            return

        for account_id, native_status, login in lookup.iter_user_saml_accounts():
            match_values = _dedupe([login])
            if not match_values:
                continue
            yield Edge(
                kind=ek.SAML_HAS_ACCOUNT,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=account_id, match_by="id"),
                properties=SamlAccountEdgeProperties(
                    traversable=False,
                    match_values=match_values,
                    source_property="profile.login",
                    account_state=normalize_okta_account_state(native_status),
                    direct_binding=False,
                ),
            )
            yield Edge(
                kind=ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE,
                start=EdgePath(value=account_id, match_by="id"),
                end=EdgePath(value=self.account_resolution_field_id, match_by="id"),
                properties=SamlResolutionValueEdgeProperties(
                    traversable=False,
                    match_values=match_values,
                    canonical_match_values=match_values,
                ),
            )

    @property
    def edges(self):
        yield Edge(
            kind=ek.SAML_IMPLEMENTS,
            start=EdgePath(value=self.idp_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=SamlRelationshipProperties(traversable=False),
        )
        if self.issuer_id:
            yield Edge(
                kind=ek.SAML_TRUSTS_ISSUER,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.issuer_id, match_by="id"),
                properties=SamlRelationshipProperties(traversable=False),
            )
        for acs_id in self.acs_ids:
            yield Edge(
                kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=acs_id, match_by="id"),
                properties=SamlRelationshipProperties(traversable=False),
            )
        yield from self._account_resolution_edges


@app.asset(
    node=NodeDef(
        icon="link",
        kind=nk.SAML_ACCOUNT_RESOLUTION_RULE,
        description="Normalized source-proven Okta account-resolution rule",
        properties=SamlAccountResolutionRuleProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.SAML_ACCOUNT_RESOLUTION_RULE,
            end=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
            kind=ek.SAML_USES_ACCOUNT_RESOLUTION_FIELD,
            description="Okta account-resolution rule reads the native login field",
            traversable=False,
        )
    ],
)
class SamlAccountResolutionRule(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    idp_id: str
    idp_name: str
    field_id: str
    expression_language: str
    expression_profile: str
    expression: str
    summary: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ACCOUNT_RESOLUTION_RULE],
            properties=SamlAccountResolutionRuleProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=f"{self.idp_name} exact login resolution",
                displayname=f"{self.idp_name} exact login resolution",
                environmentid=self._lookup.org_id(),
                idp_id=self.idp_id,
                idp_name=self.idp_name,
                expression_language=self.expression_language,
                expression_profile=self.expression_profile,
                expression=self.expression,
                summary=self.summary,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.SAML_USES_ACCOUNT_RESOLUTION_FIELD,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.field_id, match_by="id"),
            properties=SamlRelationshipProperties(traversable=False),
        )


@app.asset(
    node=NodeDef(
        icon="tag",
        kind=nk.SAML_ACCOUNT_RESOLUTION_FIELD,
        description="Normalized Okta login field used for SAML account resolution",
        properties=SamlAccountResolutionFieldProperties,
    ),
)
class SamlAccountResolutionField(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    idp_id: str
    idp_name: str
    account_field_name: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ACCOUNT_RESOLUTION_FIELD],
            properties=SamlAccountResolutionFieldProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.account_field_name,
                displayname=f"{self.idp_name} account {self.account_field_name}",
                environmentid=self._lookup.org_id(),
                idp_id=self.idp_id,
                idp_name=self.idp_name,
                account_field_name=self.account_field_name,
                schema_contract_version=SAML_CONTRACT_VERSION,
            ),
        )

    @property
    def edges(self):
        return iter(())
