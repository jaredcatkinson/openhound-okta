from dataclasses import asdict
import json

import duckdb

from openhound_okta.lookup import OktaLookup
from openhound_okta.kinds import edges as ek
from openhound_okta.models.application import Application
from openhound_okta.models.application_users import ApplicationUser
from openhound_okta.models.idp import IdentityProvider
from openhound_okta.models.idp_user import IDPUser
from openhound_okta.models.saml import (
    ACCOUNT_RESOLUTION_PROFILE,
    SAML_CONTRACT_VERSION,
    SamlAccountResolutionField,
    SamlAccountResolutionRule,
    SamlAssertionConsumerService,
    SamlClaimMapping,
    SamlFederationProvider,
    SamlIssuer,
    SamlServiceProviderAssertionConsumerService,
    SamlServiceProvider,
    SamlTrustedIssuer,
    normalize_okta_account_state,
    saml_account_resolution_field_row,
    saml_account_resolution_rule_row,
    saml_acs_rows,
    saml_application_match_values,
    saml_claim_mapping_rows,
    saml_federation_provider_row,
    saml_idp_user_match_values,
    saml_issuer_row,
    saml_service_provider_row,
    saml_sp_acs_rows,
    saml_trusted_issuer_row,
)


def _application(**overrides) -> Application:
    data = {
        "id": "0oa_saml",
        "orn": "orn:okta:idp:00o:apps:custom_saml:0oa_saml",
        "name": "custom_saml",
        "label": "Custom SAML",
        "status": "ACTIVE",
        "created": "2026-01-01T00:00:00.000Z",
        "lastUpdated": "2026-01-01T00:00:00.000Z",
        "signOnMode": "SAML_2_0",
        "features": [],
        "credentials": {"signing": {}},
        "settings": {
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
            },
        },
    }
    data.update(overrides)
    return Application.model_validate(data)


class _ApplicationLookup:
    def org_id(self) -> str:
        return "00o_example"


def test_application_node_emits_native_idp_id_when_present() -> None:
    app = _application(
        settings={
            "app": {"idpId": "0oa_inbound_idp"},
            "signOn": {},
        }
    )
    app._lookup = _ApplicationLookup()
    app._extras = {"tenant": "example.okta.test"}

    assert asdict(app.as_node)["properties"]["idp_id"] == "0oa_inbound_idp"


def test_application_node_omits_native_idp_id_when_absent() -> None:
    app = _application()
    app._lookup = _ApplicationLookup()
    app._extras = {"tenant": "example.okta.test"}

    assert asdict(app.as_node)["properties"]["idp_id"] is None


def _identity_provider(**overrides) -> IdentityProvider:
    data = {
        "id": "0oa_idp",
        "type": "SAML2",
        "name": "Example inbound SAML",
        "status": "ACTIVE",
        "created": "2026-01-01T00:00:00.000Z",
        "lastUpdated": "2026-01-01T00:00:00.000Z",
        "protocol": {
            "type": "SAML2",
            "endpoints": {
                "sso": {
                    "url": "https://idp.example.test/saml/sso",
                    "binding": "HTTP-POST",
                    "destination": "https://idp.example.test/saml/sso",
                },
                "acs": {
                    "binding": "HTTP-POST",
                    "type": "INSTANCE",
                },
            },
            "credentials": {
                "trust": {
                    "issuer": "https://idp.example.test/saml/issuer",
                    "audience": "http://www.okta.com/0oa_idp",
                }
            },
        },
        "_links": {
            "acs": {
                "href": "https://example.okta.test/sso/saml2/0oa_idp",
                "type": "application/xml",
            }
        },
    }
    data.update(overrides)
    return IdentityProvider.model_validate(data)


def _application_user(**overrides) -> ApplicationUser:
    data = {
        "id": "00u_saml_user",
        "created": "2026-01-01T00:00:00.000Z",
        "profile": {
            "login": "alice@example.test",
            "email": "alice@example.test",
            "firstName": "Alice",
            "lastName": "Example",
        },
        "credentials": {"userName": "alice.saml@example.test"},
        "status": "ACTIVE",
        "app_id": "0oa_saml",
        "app_features": [],
        "app_name": "custom_saml",
        "app_label": "Custom SAML",
        "app_sign_on_mode": "SAML_2_0",
        "app_user_name_template": "${source.login}",
    }
    data.update(overrides)
    return ApplicationUser.model_validate(data)


def _idp_user(**overrides) -> IDPUser:
    data = {
        "id": "00u_okta_user",
        "externalId": "external-user-id",
        "created": "2026-01-01T00:00:00.000Z",
        "profile": {
            "email": "alice@example.test",
            "firstName": "Alice",
            "lastName": "Example",
            "subjectNameId": "alice",
            "subjectNameQualifier": "example.test",
        },
        "idp_id": "0oa_idp",
        "idp_type": "SAML2",
        "idp_protocol_type": "SAML2",
        "idp_name": "Example inbound SAML",
        "idp_status": "ACTIVE",
        "idp_subject_user_name_template": "idpuser.subjectNameId",
    }
    data.update(overrides)
    return IDPUser.model_validate(data)


def _automatic_username_policy(template: str = "idpuser.email") -> dict:
    return {
        "accountLink": {"action": "AUTO", "filter": None},
        "subject": {
            "userNameTemplate": {"template": template},
            "filter": "",
            "matchType": "USERNAME",
            "matchAttribute": None,
        },
        "transformedUsernameMatchingEnabled": False,
    }


class _SamlLookup:
    def __init__(
        self,
        accounts=(),
        status: str | None = None,
        source_profile: dict | None = None,
        claim_mappings: tuple[dict, ...] = (),
    ):
        self.accounts = accounts
        self.status = status
        self.source_profile = source_profile
        self.claim_mappings = claim_mappings

    def iter_user_saml_accounts(self):
        yield from self.accounts

    def user_status(self, user_id: str) -> str | None:
        assert user_id in {"00u_okta_user", "00u_saml_user"}
        return self.status

    def user_profile(self, user_id: str) -> dict | None:
        assert user_id == "00u_saml_user"
        return self.source_profile

    def saml_claim_mappings(self, app_id: str) -> tuple[dict, ...]:
        assert app_id == "0oa_saml"
        return self.claim_mappings


def _claim_mapping(index: int, **overrides) -> dict:
    row = {
        "id": f"okta:saml:claim-mapping:0oa_saml:{index}",
        "app_id": "0oa_saml",
        "claim_name": "NameID",
        "mapping_type": "name_id",
        "claim_type": "name_id",
        "source_property": "source.login",
        "expression": "${source.login}",
        "format": "urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified",
        "name_format": None,
    }
    row.update(overrides)
    return row


def test_saml_lookup_reads_source_profile_and_ordered_claim_mappings() -> None:
    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA okta")
    connection.execute(
        "CREATE TABLE okta.users (id VARCHAR, status VARCHAR, profile JSON)"
    )
    connection.execute(
        "INSERT INTO okta.users VALUES (?, ?, ?)",
        ["00u_saml_user", "ACTIVE", '{"login":"Alice.Login","custom":"C-1"}'],
    )
    connection.execute(
        """
        CREATE TABLE okta.saml_claim_mappings (
            id VARCHAR,
            app_id VARCHAR,
            claim_name VARCHAR,
            mapping_type VARCHAR,
            mapping_origin VARCHAR,
            claim_type VARCHAR,
            source_property VARCHAR,
            expression VARCHAR,
            name_id_format VARCHAR,
            format VARCHAR,
            name_format VARCHAR
        )
        """
    )
    for index in (10, 2):
        connection.execute(
            """
            INSERT INTO okta.saml_claim_mappings
            VALUES (?, '0oa_saml', 'claim', 'attribute', 'attribute_statement',
                    'attribute', 'user.custom', 'user.custom', NULL, NULL, NULL)
            """,
            [f"okta:saml:claim-mapping:0oa_saml:{index}"],
        )

    lookup = OktaLookup(connection)

    assert lookup.user_profile("00u_saml_user") == {
        "login": "Alice.Login",
        "custom": "C-1",
    }
    assert [row["id"] for row in lookup.saml_claim_mappings("0oa_saml")] == [
        "okta:saml:claim-mapping:0oa_saml:2",
        "okta:saml:claim-mapping:0oa_saml:10",
    ]

    missing_mapping_connection = duckdb.connect(":memory:")
    missing_mapping_connection.execute("CREATE SCHEMA okta")
    missing_mapping_lookup = OktaLookup(missing_mapping_connection)
    assert missing_mapping_lookup.user_status("00u_saml_user") is None
    assert missing_mapping_lookup.user_profile("00u_saml_user") is None
    assert missing_mapping_lookup.saml_claim_mappings("0oa_saml") == ()


def test_saml_provider_is_emitted_when_route_metadata_is_partial():
    app = _application(settings={"app": {}, "signOn": {}})

    row = saml_federation_provider_row(app)

    assert row is not None
    assert row["id"] == "okta:saml:provider:0oa_saml"
    assert row["issuer_id"] is None
    assert row["acs_ids"] == []

    edge_kinds = [
        edge.kind for edge in SamlFederationProvider.model_validate(row).edges
    ]
    assert edge_kinds == [ek.SAML_IMPLEMENTS]


def test_saml_provider_links_only_to_resolved_route_nodes():
    app = _application()

    provider = saml_federation_provider_row(app)
    issuer = saml_issuer_row(app)
    acs_rows = saml_acs_rows(app)

    assert provider is not None
    assert issuer is not None
    assert provider["issuer_id"] == issuer["id"]
    assert provider["acs_ids"] == [acs_rows[0]["id"]]

    edge_kinds = [
        edge.kind for edge in SamlFederationProvider.model_validate(provider).edges
    ]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_ISSUES_AS,
        ek.SAML_ISSUES_ASSERTIONS_TO,
    ]


def test_inbound_and_outbound_route_assets_have_distinct_conversion_names():
    assert SamlIssuer.__name__ != SamlTrustedIssuer.__name__
    assert (
        SamlAssertionConsumerService.__name__
        != SamlServiceProviderAssertionConsumerService.__name__
    )


def test_saml_provider_emits_claim_mapping_explanation():
    app = _application(
        credentials={
            "signing": {},
            "userNameTemplate": {"template": "${source.login}"},
        },
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
                "subjectNameIdTemplate": "${source.login}",
                "subjectNameIdFormat": (
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                ),
                "configuredAttributeStatements": [
                    {"name": "email", "value": "user.email"},
                ],
            },
        },
    )

    provider = saml_federation_provider_row(app)
    rows = saml_claim_mapping_rows(app)

    assert provider is not None
    assert provider["claim_mapping_ids"] == [
        "okta:saml:claim-mapping:0oa_saml:0",
        "okta:saml:claim-mapping:0oa_saml:1",
    ]
    assert rows[0]["claim_name"] == "NameID"
    assert rows[0]["claim_type"] == "name_id"
    assert rows[0]["format"] == (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    assert rows[0]["format_was_omitted"] is False
    assert rows[0]["source_property"] == "source.login"
    assert rows[1]["claim_name"] == "email"
    assert rows[1]["claim_type"] == "attribute"
    assert rows[1]["source_property"] == "user.email"
    assert rows[1]["name_format"] == (
        "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
    )
    assert rows[1]["name_format_was_omitted"] is True
    assert rows[1]["expression"] == "user.email"

    edge_kinds = [
        edge.kind for edge in SamlFederationProvider.model_validate(provider).edges
    ]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_ISSUES_AS,
        ek.SAML_ISSUES_ASSERTIONS_TO,
        ek.SAML_HAS_CLAIM_MAPPING,
        ek.SAML_HAS_CLAIM_MAPPING,
    ]
    assert SamlClaimMapping.model_validate(rows[0]).claim_name == "NameID"


def test_group_claim_mapping_keeps_raw_statement_without_fake_source_property():
    app = _application(
        credentials={"signing": {}},
        settings={
            "app": {},
            "signOn": {
                "configuredAttributeStatements": [
                    {
                        "name": "http://schemas.xmlsoap.org/claims/Group",
                        "type": "GROUP",
                        "filterType": None,
                        "filterValue": None,
                    }
                ]
            },
        },
    )

    rows = saml_claim_mapping_rows(app)

    assert len(rows) == 1
    assert rows[0]["source_property"] is None
    assert rows[0]["expression"].startswith("{")


def test_claim_mapping_accepts_pre_v03_rows_without_claim_type():
    claim = SamlClaimMapping.model_validate(
        {
            "id": "okta:saml:claim-mapping:0oa_saml:0",
            "app_id": "0oa_saml",
            "app_name": "custom_saml",
            "app_label": "Custom SAML",
            "claim_name": "NameID",
            "mapping_type": "name_id",
            "source_property": "source.login",
            "expression": "${source.login}",
        }
    )

    assert claim.claim_type == "name_id"


def test_saml_acs_rows_dedup_repeated_acs_url_and_entity():
    app = _application(
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
                "acsEndpoints": [
                    {"url": "https://sp.example.test/saml/consume"},
                    {
                        "url": "https://sp.example.test/saml/consume/alternate",
                        "index": 5,
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    },
                ],
            },
        },
    )

    rows = saml_acs_rows(app)

    assert [row["acs_url"] for row in rows] == [
        "https://sp.example.test/saml/consume",
        "https://sp.example.test/saml/consume/alternate",
    ]
    assert [row["id"] for row in rows] == [
        "okta:saml:acs:0oa_saml:0",
        "okta:saml:acs:0oa_saml:5",
    ]


def test_github_emu_oin_route_uses_enterprise_slug_contract():
    app = _application(
        name="githubenterprisemanageduser",
        settings={
            "app": {"enterpriseName": "k-nexus-global"},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
            },
        },
    )

    rows = saml_acs_rows(app)

    assert rows == [
        {
            "id": "okta:saml:acs:0oa_saml:0",
            "app_id": "0oa_saml",
            "app_name": "githubenterprisemanageduser",
            "app_label": "Custom SAML",
            "source_object_kind": "Okta_Application",
            "acs_url": "https://github.com/enterprises/k-nexus-global/saml/consume",
            "sp_entity_id": "https://github.com/enterprises/k-nexus-global",
            "index": 0,
            "binding": None,
            "is_default": True,
            "source_technology": "okta",
            "provider_family": "okta",
            "target_product_family": "github_enterprise",
            "route_source": "settings.app+documented_github_route",
            "extraction_mode": "allowlisted_deterministic_route",
            "acs_source_field": "settings.app.enterpriseName",
            "sp_entity_source_field": "settings.app.enterpriseName",
            "route_conflicts": [],
        }
    ]


def test_generic_saml_route_records_explicit_field_provenance():
    rows = saml_acs_rows(_application())

    assert len(rows) == 1
    assert rows[0]["route_source"] == "settings.signOn"
    assert rows[0]["extraction_mode"] == "explicit_generic"
    assert rows[0]["acs_source_field"] == "settings.signOn.ssoAcsUrl"
    assert rows[0]["sp_entity_source_field"] == "settings.signOn.audience"
    assert rows[0]["target_product_family"] == "generic_saml"
    assert rows[0]["route_conflicts"] == []


def test_org2org_saml_uses_exact_oin_acs_and_audience_fields():
    app = _application(
        name="okta_org2org",
        settings={
            "app": {
                "acsUrl": "https://target.example.test/sso/saml2/0oa_target",
                "audRestriction": (
                    "https://www.okta.com/saml2/service-provider/target"
                ),
                "baseUrl": "https://target.example.test/",
            },
            "signOn": {"idpIssuer": None},
        },
        saml_metadata_entity_id="http://www.okta.com/exk_org2org",
        saml_metadata_sso_url=(
            "https://source.example.test/app/okta_org2org/exk_org2org/sso/saml"
        ),
    )

    rows = saml_acs_rows(app)

    assert len(rows) == 1
    assert rows[0]["acs_url"] == ("https://target.example.test/sso/saml2/0oa_target")
    assert rows[0]["sp_entity_id"] == (
        "https://www.okta.com/saml2/service-provider/target"
    )
    assert rows[0]["route_source"] == "settings.app"
    assert rows[0]["extraction_mode"] == "oin_explicit_fields"
    assert rows[0]["acs_source_field"] == "settings.app.acsUrl"
    assert rows[0]["sp_entity_source_field"] == "settings.app.audRestriction"
    assert rows[0]["target_product_family"] == "okta_org2org"


def test_oidc_org2org_never_enters_saml_route_extraction():
    app = _application(
        name="okta_org2org",
        signOnMode="OPENID_CONNECT",
        settings={
            "app": {
                "acsUrl": "https://target.example.test/sso/saml2/0oa_target",
                "audRestriction": "https://www.okta.com/saml2/service-provider",
            }
        },
    )

    assert saml_acs_rows(app) == []
    assert saml_federation_provider_row(app) is None


def test_org2org_requires_exact_saml_mode_for_every_normalized_fact():
    for sign_on_mode in ("OPENID_CONNECT", "OIDC", "SWA", None, "unknown"):
        app = _application(
            name="okta_org2org",
            signOnMode=sign_on_mode,
            settings={
                "app": {
                    "acsUrl": "https://target.example.test/sso/saml2/target",
                    "audRestriction": (
                        "https://www.okta.com/saml2/service-provider/target"
                    ),
                    "baseUrl": "https://target.example.test/",
                },
                "signOn": {
                    "idpIssuer": "http://www.okta.com/exk_org2org",
                    "subjectNameIdTemplate": "${source.login}",
                },
            },
            saml_metadata_entity_id="http://www.okta.com/exk_org2org",
            saml_metadata_sso_url=(
                "https://source.example.test/app/okta_org2org/exk/sso/saml"
            ),
        )
        app_user = _application_user(
            app_name="okta_org2org",
            app_sign_on_mode=sign_on_mode,
        )

        assert saml_federation_provider_row(app) is None
        assert saml_issuer_row(app) is None
        assert saml_acs_rows(app) == []
        assert saml_claim_mapping_rows(app) == []
        assert ek.SAML_ELIGIBLE_FOR not in {edge.kind for edge in app_user.edges}


def test_inbound_normalization_requires_saml_idp_type_and_protocol():
    for idp_type, protocol_type in (("OIDC", "SAML2"), ("SAML2", "OIDC")):
        idp = _identity_provider(
            type=idp_type,
            protocol={
                "type": protocol_type,
                "endpoints": {
                    "sso": {"url": "https://idp.example.test/sso"},
                    "acs": {"type": "INSTANCE"},
                    "authorization": {"url": "https://idp.example.test/authorize"},
                },
                "credentials": {
                    "trust": {
                        "issuer": "https://idp.example.test/saml/issuer",
                        "audience": "http://www.okta.com/0oa_idp",
                    }
                },
            },
        )
        idp_user = _idp_user(
            idp_type=idp_type,
            idp_protocol_type=protocol_type,
        )

        assert saml_service_provider_row(idp) is None
        assert saml_trusted_issuer_row(idp) is None
        assert saml_sp_acs_rows(idp) == []
        edge_kinds = {edge.kind for edge in idp_user.edges}
        assert ek.IDENTITY_PROVIDER_FOR in edge_kinds
        assert ek.SAML_HAS_ACCOUNT not in edge_kinds


def test_jamf_oin_route_uses_allowlisted_documented_paths():
    app = _application(
        name="jamfsoftwareserver",
        settings={
            "app": {"domain": "sol.jamfcloud.com"},
            "signOn": {"idpIssuer": None},
        },
        saml_metadata_entity_id="http://www.okta.com/exk_jamf",
    )

    rows = saml_acs_rows(app)

    assert len(rows) == 1
    assert rows[0]["acs_url"] == "https://sol.jamfcloud.com/saml/SSO"
    assert rows[0]["sp_entity_id"] == "https://sol.jamfcloud.com/saml/metadata"
    assert rows[0]["route_source"] == "settings.app+documented_jamf_route"
    assert rows[0]["extraction_mode"] == "allowlisted_deterministic_route"
    assert rows[0]["acs_source_field"] == "settings.app.domain"
    assert rows[0]["sp_entity_source_field"] == "settings.app.domain"
    assert rows[0]["target_product_family"] == "jamf_pro"


def test_jamf_oin_route_fails_closed_for_absent_or_malformed_domain():
    invalid_domains = [
        None,
        "",
        "https://sol.jamfcloud.com",
        "sol.jamfcloud.com/saml",
        "sol..jamfcloud.com",
        '"sol.jamfcloud.com"',
    ]

    for domain in invalid_domains:
        app = _application(
            name="jamfsoftwareserver",
            settings={
                "app": {"domain": domain},
                "signOn": {"idpIssuer": None},
            },
            saml_metadata_entity_id="http://www.okta.com/exk_jamf",
        )
        assert saml_acs_rows(app) == []
        provider = saml_federation_provider_row(app)
        assert provider is not None
        assert provider["acs_ids"] == []
        assert any(
            "settings.app.domain" in item for item in provider["route_diagnostics"]
        )


def test_github_organization_oin_route_uses_recognized_org_setting():
    app = _application(
        name="githubcloud",
        settings={
            "app": {"githubOrg": "k-nexus-global"},
            "signOn": {"idpIssuer": "http://www.okta.com/exk123"},
        },
    )

    rows = saml_acs_rows(app)

    assert len(rows) == 1
    assert rows[0]["acs_url"] == ("https://github.com/orgs/k-nexus-global/saml/consume")
    assert rows[0]["sp_entity_id"] == "https://github.com/orgs/k-nexus-global"
    assert rows[0]["target_product_family"] == "github_organization"
    assert rows[0]["acs_source_field"] == "settings.app.githubOrg"


def test_explicit_generic_route_wins_over_conflicting_oin_default():
    app = _application(
        name="jamfsoftwareserver",
        settings={
            "app": {"domain": "derived.jamfcloud.com"},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrlOverride": "https://explicit.example.test/saml/consume",
                "audienceOverride": "https://explicit.example.test/saml/metadata",
            },
        },
    )

    rows = saml_acs_rows(app)

    assert len(rows) == 1
    assert rows[0]["acs_url"] == "https://explicit.example.test/saml/consume"
    assert rows[0]["sp_entity_id"] == ("https://explicit.example.test/saml/metadata")
    assert rows[0]["extraction_mode"] == "explicit_generic"
    assert rows[0]["acs_source_field"] == "settings.signOn.ssoAcsUrlOverride"
    assert rows[0]["sp_entity_source_field"] == ("settings.signOn.audienceOverride")
    assert rows[0]["route_conflicts"] == [
        "explicit_generic_route_overrides_conflicting_oin_route"
    ]

    provider = saml_federation_provider_row(app)
    assert provider is not None
    assert provider["route_diagnostics"] == rows[0]["route_conflicts"]


def test_explicit_acs_array_does_not_cross_product_with_conflicting_audiences():
    app = _application(
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "spIssuer": "https://sp-one.example.test/saml",
                "audience": "https://sp-two.example.test/saml",
                "acsEndpoints": [
                    {"url": "https://sp.example.test/saml/one", "index": 0},
                    {"url": "https://sp.example.test/saml/two", "index": 1},
                ],
            },
        },
    )

    assert saml_acs_rows(app) == []
    provider = saml_federation_provider_row(app)
    assert provider is not None
    assert provider["acs_ids"] == []
    assert "conflicting_explicit_sp_entity_fields" in provider["route_diagnostics"]


def test_multiple_explicit_acs_endpoints_preserve_one_to_one_route_tuples():
    app = _application(
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "audience": "https://sp.example.test/saml",
                "acsEndpoints": [
                    {"url": "https://sp.example.test/saml/one", "index": 0},
                    {"url": "https://sp.example.test/saml/two", "index": 1},
                ],
            },
        },
    )

    rows = saml_acs_rows(app)

    assert [(row["acs_url"], row["sp_entity_id"]) for row in rows] == [
        (
            "https://sp.example.test/saml/one",
            "https://sp.example.test/saml",
        ),
        (
            "https://sp.example.test/saml/two",
            "https://sp.example.test/saml",
        ),
    ]
    assert [row["acs_source_field"] for row in rows] == [
        "settings.signOn.acsEndpoints[0].url",
        "settings.signOn.acsEndpoints[1].url",
    ]


def test_okta_metadata_is_issuer_evidence_not_downstream_route_evidence():
    app = _application(
        name="unknown_oin_saml",
        settings={"app": {"domain": "sp.example.test"}, "signOn": {}},
        saml_metadata_entity_id="http://www.okta.com/exk_metadata",
        saml_metadata_sso_url=(
            "https://source.example.test/app/unknown/exk_metadata/sso/saml"
        ),
    )

    issuer = saml_issuer_row(app)
    provider = saml_federation_provider_row(app)

    assert issuer is not None
    assert issuer["entity_id"] == "http://www.okta.com/exk_metadata"
    assert saml_acs_rows(app) == []
    assert provider is not None
    assert provider["acs_ids"] == []
    assert provider["route_diagnostics"] == [
        "missing_authoritative_acs_and_sp_entity_evidence"
    ]


def test_saml_eligible_for_uses_configured_match_value():
    app_user = _application_user()

    assert saml_application_match_values(app_user) == ["alice.saml@example.test"]

    edges = list(app_user.edges)
    eligible = [edge for edge in edges if edge.kind == ek.SAML_ELIGIBLE_FOR]
    assert len(eligible) == 1
    assert eligible[0].start.value == "00u_saml_user"
    assert eligible[0].end.value == "okta:saml:provider:0oa_saml"
    assert eligible[0].properties.match_values == ["alice.saml@example.test"]
    assert eligible[0].properties.email_match_values == []
    assert eligible[0].properties.scoped_exact_match_values == [
        "alice.saml@example.test"
    ]
    assert eligible[0].properties.schema_contract_version == SAML_CONTRACT_VERSION
    assert eligible[0].properties.source_property == "source.login"
    assert eligible[0].properties.assignment_source == "direct_assignment"


def test_saml_eligible_for_promotes_standard_email_nameid() -> None:
    app_user = _application_user(
        app_subject_name_id_template="${source.login}",
        app_subject_name_id_format=(
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
    )

    eligible = next(
        edge for edge in app_user.edges if edge.kind == ek.SAML_ELIGIBLE_FOR
    )

    assert eligible.properties.match_values == ["alice.saml@example.test"]
    assert eligible.properties.email_match_values == ["alice.saml@example.test"]
    assert eligible.properties.scoped_exact_match_values == []


def test_saml_assignment_materializes_all_resolvable_claim_values() -> None:
    app_user = _application_user(
        app_status="ACTIVE",
        scope="GROUP",
        profile={
            "login": "app-alice",
            "email": "app-alice@example.test",
            "employeeNumber": "APP-1007",
        },
    )
    app_user._lookup = _SamlLookup(
        status="ACTIVE",
        source_profile={
            "login": "Alice.Login",
            "email": "Alice@Example.TEST",
            "employeeNumber": "E-1007",
            "blankCode": "   ",
        },
        claim_mappings=(
            _claim_mapping(0),
            _claim_mapping(
                1,
                claim_name="email",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.email",
                expression="user.email",
                format=None,
                name_format=("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"),
            ),
            _claim_mapping(
                2,
                claim_name="UPN",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.email",
                expression="user.email",
                format=None,
            ),
            _claim_mapping(
                3,
                claim_name="urn:example:employeeNumber",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.employeeNumber",
                expression="user.employeeNumber",
                format=None,
            ),
            _claim_mapping(
                4,
                claim_name="email",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.email",
                expression="user.email",
                format=None,
            ),
            _claim_mapping(
                5,
                claim_name="http://schemas.microsoft.com/identity/claims/objectidentifier",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.objectId",
                expression="user.objectId",
                format=None,
            ),
            _claim_mapping(
                6,
                claim_name="urn:example:blankCode",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.blankCode",
                expression="user.blankCode",
                format=None,
            ),
            _claim_mapping(
                7,
                claim_name="email",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="String.toLowerCase(user.email)",
                expression="String.toLowerCase(user.email)",
                format=None,
            ),
            _claim_mapping(
                8,
                claim_name="http://schemas.xmlsoap.org/claims/Group",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property=None,
                expression='{"name":"groups","type":"GROUP"}',
                format=None,
            ),
            _claim_mapping(
                9,
                claim_name="email",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.login",
                expression="user.email",
                format=None,
            ),
            _claim_mapping(
                10,
                claim_name="urn:example:applicationEmployeeNumber",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="appuser.employeeNumber",
                expression="appuser.employeeNumber",
                format=None,
            ),
        ),
    )

    saml_edges = [
        edge
        for edge in app_user.edges
        if edge.kind in {ek.SAML_ELIGIBLE_FOR, ek.SAML_HAS_CLAIM_VALUE}
    ]
    eligible = next(edge for edge in saml_edges if edge.kind == ek.SAML_ELIGIBLE_FOR)

    assert eligible.properties.match_values == [
        "Alice.Login",
        "Alice@Example.TEST",
    ]
    assert eligible.properties.email_match_values == ["alice@example.test"]
    assert eligible.properties.upn_match_values == ["alice@example.test"]
    assert eligible.properties.entra_object_id_match_values == []
    assert eligible.properties.scoped_exact_match_values == []
    assert eligible.properties.incomplete_match_value_fields == [
        "email_match_values",
        "entra_object_id_match_values",
    ]
    assert eligible.properties.assignment_source == "group_assignment"
    assert eligible.properties.source_properties == [
        "source.login",
        "user.email",
    ]

    claim_edges = {
        edge.end.value: edge
        for edge in saml_edges
        if edge.kind == ek.SAML_HAS_CLAIM_VALUE
    }
    assert claim_edges[
        "okta:saml:claim-mapping:0oa_saml:3"
    ].properties.match_values == ["E-1007"]
    assert claim_edges[
        "okta:saml:claim-mapping:0oa_saml:3"
    ].properties.canonical_match_values == ["E-1007"]
    assert claim_edges[
        "okta:saml:claim-mapping:0oa_saml:10"
    ].properties.match_values == ["APP-1007"]
    for mapping_id in (
        "okta:saml:claim-mapping:0oa_saml:6",
        "okta:saml:claim-mapping:0oa_saml:8",
    ):
        assert claim_edges[mapping_id].properties.match_values == []
        assert claim_edges[mapping_id].properties.canonical_match_values == []
        assert claim_edges[mapping_id].properties.incomplete is True

    emitted = json.loads(json.dumps([asdict(edge) for edge in saml_edges]))
    assert len(emitted) == 5
    assert emitted[0]["properties"]["schema_contract_version"] == (
        SAML_CONTRACT_VERSION
    )


def test_saml_assignment_fails_closed_when_mapping_data_is_unavailable() -> None:
    app_user = _application_user(app_status="ACTIVE")
    app_user._lookup = _SamlLookup(
        status="ACTIVE",
        source_profile={
            "login": "must-not-be-inferred",
            "email": "must-not-be-inferred@example.test",
        },
        claim_mappings=(),
    )

    eligible = next(
        edge for edge in app_user.edges if edge.kind == ek.SAML_ELIGIBLE_FOR
    )

    assert eligible.properties.match_values == []
    assert eligible.properties.email_match_values == []
    assert eligible.properties.upn_match_values == []
    assert eligible.properties.entra_object_id_match_values == []
    assert eligible.properties.scoped_exact_match_values == []
    assert eligible.properties.incomplete_match_value_fields == [
        "email_match_values",
        "upn_match_values",
        "entra_object_id_match_values",
        "scoped_exact_match_values",
    ]


def test_saml_assignment_does_not_substitute_app_profile_for_missing_source() -> None:
    app_user = _application_user(
        app_status="ACTIVE",
        profile={"email": "app-profile@example.test"},
        credentials={"userName": "app-username@example.test"},
    )
    app_user._lookup = _SamlLookup(
        status="ACTIVE",
        source_profile=None,
        claim_mappings=(
            _claim_mapping(
                1,
                claim_name="email",
                mapping_type="configured_attribute",
                claim_type="attribute",
                source_property="user.email",
                expression="user.email",
                format=None,
            ),
        ),
    )

    eligible = next(
        edge for edge in app_user.edges if edge.kind == ek.SAML_ELIGIBLE_FOR
    )

    assert eligible.properties.match_values == []
    assert eligible.properties.email_match_values == []
    assert eligible.properties.incomplete_match_value_fields == ["email_match_values"]


def test_transient_nameid_is_explanatory_only() -> None:
    app_user = _application_user(app_status="ACTIVE")
    app_user._lookup = _SamlLookup(
        status="ACTIVE",
        source_profile={"login": "temporary-subject-123"},
        claim_mappings=(
            _claim_mapping(
                0,
                format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            ),
        ),
    )

    saml_edges = [
        edge
        for edge in app_user.edges
        if edge.kind in {ek.SAML_ELIGIBLE_FOR, ek.SAML_HAS_CLAIM_VALUE}
    ]
    eligible = next(edge for edge in saml_edges if edge.kind == ek.SAML_ELIGIBLE_FOR)
    claim_value = next(
        edge for edge in saml_edges if edge.kind == ek.SAML_HAS_CLAIM_VALUE
    )

    assert eligible.properties.match_values == []
    assert eligible.properties.email_match_values == []
    assert eligible.properties.upn_match_values == []
    assert eligible.properties.scoped_exact_match_values == []
    assert claim_value.properties.match_values == ["temporary-subject-123"]
    assert claim_value.properties.canonical_match_values == []
    assert claim_value.properties.unsafe_match_values == ["temporary-subject-123"]


def test_saml_assertion_edges_respect_provider_and_principal_lifecycle() -> None:
    mappings = (_claim_mapping(0),)
    for app_status, principal_status in (
        ("INACTIVE", "ACTIVE"),
        ("ACTIVE", "SUSPENDED"),
        ("ACTIVE", "LOCKED_OUT"),
    ):
        app_user = _application_user(app_status=app_status)
        app_user._lookup = _SamlLookup(
            status=principal_status,
            source_profile={"login": "Alice.Login"},
            claim_mappings=mappings,
        )

        assert not [
            edge
            for edge in app_user.edges
            if edge.kind in {ek.SAML_ELIGIBLE_FOR, ek.SAML_HAS_CLAIM_VALUE}
        ]


def test_saml_service_provider_links_only_to_resolved_route_nodes():
    idp = _identity_provider()

    service_provider = saml_service_provider_row(idp)
    issuer = saml_trusted_issuer_row(idp)
    acs_rows = saml_sp_acs_rows(idp)

    assert service_provider is not None
    assert issuer is not None
    assert service_provider["id"] == "okta:saml:service-provider:0oa_idp"
    assert service_provider["issuer_id"] == issuer["id"]
    assert service_provider["acs_ids"] == [acs_rows[0]["id"]]
    assert issuer["entity_id"] == "https://idp.example.test/saml/issuer"
    assert acs_rows == [
        {
            "id": "okta:saml:sp-acs:0oa_idp:0",
            "app_id": "0oa_idp",
            "app_name": "Example inbound SAML",
            "app_label": "Example inbound SAML",
            "source_object_kind": "Okta_IdentityProvider",
            "acs_url": "https://example.okta.test/sso/saml2/0oa_idp",
            "sp_entity_id": "http://www.okta.com/0oa_idp",
            "index": 0,
            "binding": "HTTP-POST",
            "is_default": True,
        }
    ]

    edge_kinds = [
        edge.kind for edge in SamlServiceProvider.model_validate(service_provider).edges
    ]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_TRUSTS_ISSUER,
        ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
    ]


def test_saml_service_provider_prefers_inbound_idp_metadata_routes():
    idp = _identity_provider(
        _links={
            "acs": {
                "href": "https://example.okta.test/sso/saml2",
                "type": "application/xml",
            }
        },
        saml_metadata_entity_id="https://www.okta.com/saml2/service-provider",
        saml_metadata_acs_endpoints=[
            {
                "url": "https://example.okta.test/sso/saml2/0oa_idp",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "index": 0,
                "is_default": True,
            },
            {
                "url": "https://example.okta.test/sso/saml2/alternate",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "index": 2,
                "is_default": False,
            },
        ],
    )

    service_provider = saml_service_provider_row(idp)
    acs_rows = saml_sp_acs_rows(idp)

    assert service_provider is not None
    assert service_provider["sp_entity_id"] == (
        "https://www.okta.com/saml2/service-provider"
    )
    assert service_provider["acs_ids"] == [row["id"] for row in acs_rows]
    assert [row["acs_url"] for row in acs_rows] == [
        "https://example.okta.test/sso/saml2/0oa_idp",
        "https://example.okta.test/sso/saml2/alternate",
    ]
    assert [row["index"] for row in acs_rows] == [0, 2]
    assert [row["is_default"] for row in acs_rows] == [True, False]
    assert {row["route_source"] for row in acs_rows} == {
        "identity_provider_metadata"
    }


def test_saml_service_provider_is_emitted_when_route_metadata_is_partial():
    idp = _identity_provider(
        protocol={
            "type": "SAML2",
            "endpoints": {
                "sso": {
                    "url": "https://idp.example.test/saml/sso",
                    "binding": "HTTP-POST",
                },
                "acs": {"binding": "HTTP-POST", "type": "INSTANCE"},
            },
            "credentials": {"trust": {}},
        },
        _links={},
    )

    row = saml_service_provider_row(idp)

    assert row is not None
    assert row["issuer_id"] is None
    assert row["acs_ids"] == []

    edge_kinds = [edge.kind for edge in SamlServiceProvider.model_validate(row).edges]
    assert edge_kinds == [ek.SAML_IMPLEMENTS]


def test_saml_has_account_uses_inbound_idp_subject_template():
    idp_user = _idp_user(
        idp_subject_user_name_template=(
            "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier"
        )
    )

    assert saml_idp_user_match_values(idp_user) == [
        "alice@example.test",
        "external-user-id",
    ]

    edges = list(idp_user.edges)
    account_edges = [edge for edge in edges if edge.kind == ek.SAML_HAS_ACCOUNT]
    assert len(account_edges) == 1
    assert account_edges[0].start.value == "okta:saml:service-provider:0oa_idp"
    assert account_edges[0].end.value == "00u_okta_user"
    assert account_edges[0].properties.match_values == [
        "alice@example.test",
        "external-user-id",
    ]
    assert account_edges[0].properties.scoped_exact_match_values == [
        "alice@example.test",
        "external-user-id",
    ]
    assert account_edges[0].properties.direct_binding is True
    assert account_edges[0].properties.schema_contract_version == (
        SAML_CONTRACT_VERSION
    )
    assert (
        account_edges[0].properties.source_property
        == "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier"
    )


def test_saml_has_account_types_entra_object_id_from_resolved_link() -> None:
    object_id = "10ce139c-c176-470e-98b7-a2467ed97576"
    idp_user = _idp_user(
        externalId=None,
        profile={
            "email": "alice@example.test",
            "firstName": "Alice",
            "lastName": "Example",
            "subjectNameId": "alice",
            "subjectNameQualifier": "example.test",
            "msObjectIdentifier": object_id.upper(),
        },
        idp_url="https://login.microsoftonline.com/example/saml2",
        idp_subject_user_name_template="idpuser.email",
    )

    account = next(edge for edge in idp_user.edges if edge.kind == ek.SAML_HAS_ACCOUNT)

    assert account.properties.email_match_values == ["alice@example.test"]
    assert account.properties.entra_object_id_match_values == [object_id]
    assert account.properties.scoped_exact_match_values == []

    inbound_sso = next(edge for edge in idp_user.edges if edge.kind == ek.INBOUND_SSO)
    assert inbound_sso.start.value == object_id.upper()


def test_inbound_automatic_username_policy_emits_canonical_rule_and_accounts():
    idp = _identity_provider(policy=_automatic_username_policy())

    rule_row = saml_account_resolution_rule_row(idp)
    field_row = saml_account_resolution_field_row(idp)
    service_provider_row = saml_service_provider_row(idp)

    assert rule_row == {
        "id": "okta:saml:account-resolution-rule:0oa_idp",
        "idp_id": "0oa_idp",
        "idp_name": "Example inbound SAML",
        "field_id": "okta:saml:account-resolution-field:0oa_idp:login",
        "expression_language": "cel",
        "expression_profile": ACCOUNT_RESOLUTION_PROFILE,
        "expression": (
            'account.fields.exists(field, field.name == "login" && '
            "assertion.email_match_values.exists(value, value in "
            "field.match_values))"
        ),
        "summary": ('Any assertion email value exactly matches account field "login"'),
    }
    assert field_row == {
        "id": "okta:saml:account-resolution-field:0oa_idp:login",
        "idp_id": "0oa_idp",
        "idp_name": "Example inbound SAML",
        "account_field_name": "login",
    }
    assert service_provider_row is not None
    assert service_provider_row["account_resolution_rule_id"] == rule_row["id"]
    assert service_provider_row["account_resolution_field_id"] == field_row["id"]
    assert service_provider_row["account_resolution_diagnostics"] == []

    rule = SamlAccountResolutionRule.model_validate(rule_row)
    field = SamlAccountResolutionField.model_validate(field_row)
    assert [edge.kind for edge in rule.edges] == [ek.SAML_USES_ACCOUNT_RESOLUTION_FIELD]
    assert list(field.edges) == []

    service_provider = SamlServiceProvider.model_validate(service_provider_row)
    service_provider._lookup = _SamlLookup(
        accounts=(
            ("00u_enabled", "ACTIVE", "alice@example.test"),
            ("00u_blocked", "SUSPENDED", "blocked@example.test"),
            ("00u_missing", None, None),
        )
    )
    edges = list(service_provider.edges)
    assert ek.SAML_HAS_ACCOUNT_RESOLUTION_RULE in {edge.kind for edge in edges}
    account_edges = [edge for edge in edges if edge.kind == ek.SAML_HAS_ACCOUNT]
    value_edges = [
        edge for edge in edges if edge.kind == ek.SAML_HAS_ACCOUNT_RESOLUTION_VALUE
    ]
    assert [edge.end.value for edge in account_edges] == [
        "00u_enabled",
        "00u_blocked",
    ]
    assert [edge.properties.account_state for edge in account_edges] == [
        "enabled",
        "suspended",
    ]
    assert all(edge.properties.direct_binding is False for edge in account_edges)
    assert [edge.properties.canonical_match_values for edge in value_edges] == [
        ["alice@example.test"],
        ["blocked@example.test"],
    ]


def test_inbound_subject_nameid_policy_uses_route_scoped_exact_values():
    row = saml_account_resolution_rule_row(
        _identity_provider(policy=_automatic_username_policy("saml.subjectNameId"))
    )

    assert row is not None
    assert "assertion.scoped_exact_match_values" in row["expression"]
    assert row["summary"] == (
        'Any assertion route-scoped exact value exactly matches account field "login"'
    )


def test_incomplete_or_conflicting_inbound_policy_fails_closed_with_diagnostic():
    invalid_policies = [
        None,
        _automatic_username_policy("idpuser.unsupported"),
        {
            **_automatic_username_policy(),
            "accountLink": {"action": "DISABLED", "filter": None},
        },
        {
            **_automatic_username_policy(),
            "subject": {
                **_automatic_username_policy()["subject"],
                "matchType": "USERNAME_OR_EMAIL",
            },
        },
        {
            **_automatic_username_policy(),
            "subject": {
                **_automatic_username_policy()["subject"],
                "filter": "^.+@example.test$",
            },
        },
        {
            **_automatic_username_policy(),
            "transformedUsernameMatchingEnabled": True,
        },
    ]

    for policy in invalid_policies:
        idp = _identity_provider(policy=policy)
        service_provider = saml_service_provider_row(idp)

        assert saml_account_resolution_rule_row(idp) is None
        assert saml_account_resolution_field_row(idp) is None
        assert service_provider is not None
        assert service_provider["account_resolution_rule_id"] is None
        assert service_provider["account_resolution_diagnostics"]


def test_direct_idp_user_binding_uses_authoritative_okta_lifecycle_state():
    expected = {
        "ACTIVE": "enabled",
        "SUSPENDED": "suspended",
        "DEPROVISIONED": "deprovisioned",
        "LOCKED_OUT": "login_blocked",
        "PASSWORD_EXPIRED": "unknown",
        None: "unknown",
    }

    for native_status, normalized_status in expected.items():
        idp_user = _idp_user()
        idp_user._lookup = _SamlLookup(status=native_status)
        account = next(
            edge for edge in idp_user.edges if edge.kind == ek.SAML_HAS_ACCOUNT
        )

        assert normalize_okta_account_state(native_status) == normalized_status
        assert account.properties.account_state == normalized_status
        assert account.properties.direct_binding is True
        assert account.properties.direct_binding_source == (
            "GET /api/v1/idps/{idpId}/users"
        )
