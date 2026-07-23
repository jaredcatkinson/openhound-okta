from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgePath,
    EdgeProperties,
)
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class ApplicationProperties(OktaNodeProperties):
    """Properties for the Okta_ApplicationNode node.

    Attributes:
        label: Human-readable application label.
        status: Okta application lifecycle status.
        created: Timestamp when the application was created.
        last_updated: Timestamp when the application was last updated.
        sign_on_mode: Authentication mode configured for the application.
        orn: Okta Resource Name for the application.
        idp_id: Native inbound identity-provider ID referenced by the application.
    """

    label: str
    status: str
    created: datetime
    last_updated: datetime | None = None
    sign_on_mode: str | None = None
    orn: str | None = None
    idp_id: str | None = None


class JWK(BaseModel):
    id: str
    kid: str | None = None
    alf: str | None = None
    use: str | None = None
    n: str | None = None
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime | None = None


class OauthKeys(BaseModel):
    keys: list[JWK] = Field(default_factory=list)


class OauthClientSettings(BaseModel):
    client_uri: str | None = None
    response_types: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)
    application_type: str | None = None
    issuer_mode: str | None = None
    consent_method: str | None = None
    jwks: OauthKeys | None = None


class SamlAcsEndpoint(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    url: str | None = None
    index: int | None = None
    binding: str | None = None
    is_default: bool | None = Field(default=None, alias="isDefault")


class AssertionEncryptionSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    acs_endpoints: list[SamlAcsEndpoint] = Field(
        default_factory=list,
        alias="acsEndpoints",
    )


class SignOnSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    idp_issuer: str | None = Field(default=None, alias="idpIssuer")
    sso_acs_url: str | None = Field(default=None, alias="ssoAcsUrl")
    sso_acs_url_override: str | None = Field(default=None, alias="ssoAcsUrlOverride")
    sp_issuer: str | None = Field(default=None, alias="spIssuer")
    audience: str | None = None
    audience_override: str | None = Field(default=None, alias="audienceOverride")
    recipient: str | None = None
    recipient_override: str | None = Field(default=None, alias="recipientOverride")
    destination: str | None = None
    destination_override: str | None = Field(default=None, alias="destinationOverride")
    subject_name_id_template: str | None = Field(
        default=None,
        alias="subjectNameIdTemplate",
    )
    subject_name_id_format: str | None = Field(
        default=None,
        alias="subjectNameIdFormat",
    )
    attribute_statements: list[dict] = Field(
        default_factory=list,
        alias="attributeStatements",
    )
    configured_attribute_statements: list[dict] = Field(
        default_factory=list,
        alias="configuredAttributeStatements",
    )
    acs_endpoints: list[SamlAcsEndpoint] = Field(
        default_factory=list,
        alias="acsEndpoints",
    )
    assertion_encryption: AssertionEncryptionSettings | None = Field(
        default=None,
        alias="assertionEncryption",
    )
    slo: dict | None = None


class Settings(BaseModel):
    app: dict | None = None
    notifications: dict | None = None
    sign_on: SignOnSettings | None = Field(default=None, alias="signOn")
    manual_provisioning: bool | None = Field(default=None, alias="manualProvisioning")
    implicit_assignment: bool | None = Field(default=None, alias="implicitAssignment")
    em_opt_in_status: str | None = Field(default=None, alias="emOptInStatus")
    notes: dict | None = None
    oauth_client: OauthClientSettings | None = Field(default=None, alias="oauthClient")


class OAuthCredential(BaseModel):
    auto_key_rotation: bool | None = Field(default=None, alias="autoKeyRotation")
    client_id: str | None = None
    token_endpoint_auth_method: str
    pkce_required: bool | None = None


class Credentials(BaseModel):
    user_name_template: dict | None = Field(default=None, alias="userNameTemplate")
    signing: dict | None = None
    oauth_client: OAuthCredential | None = Field(default=None, alias="oauthClient")


@app.asset(
    description="Okta application asset",
    node=NodeDef(
        icon="window-maximize",
        kind=nk.APPLICATION,
        description="Okta application node",
        properties=ApplicationProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.APPLICATION,
            kind=ek.CONTAINS,
            description="Organization contains application",
            traversable=True,
        ),
    ],
)
class Application(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    orn: str
    name: str
    label: str
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime
    sign_on_mode: str | None = Field(default=None, alias="signOnMode")
    credentials: Credentials | None = None
    settings: Settings | None = None
    features: list[str] = Field(default_factory=list)
    saml_metadata_entity_id: str | None = None
    saml_metadata_sso_url: str | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.APPLICATION],
            properties=ApplicationProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.label or self.name,
                label=self.label,
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                sign_on_mode=self.sign_on_mode,
                orn=self.orn,
                idp_id=(
                    self.settings.app.get("idpId")
                    if self.settings and self.settings.app
                    else None
                ),
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _outbound_jamf_sso_edge(self):
        # SAML == SAML_2_0
        # SWA == SECURE_PASSWORD_STORE, BROWSER_PLUGIN or AUTO_LOGIN
        if self.name == "jamfsoftwareserver":
            jamf_domain = self.settings.app.get("domain")
            if jamf_domain:
                jamf_domain = jamf_domain.replace('"', "")
                yield Edge(
                    kind=ek.OUTBOUND_ORG_SSO,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=f"{jamf_domain}-SSO", match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    # @property
    # def _outbount_github_sso_edge(self):
    # TODO: Wait for the Github Enterprise (v.s. org) implementation is finalized
    #     if self.name == "githubcloud":
    #         yield Edge(
    #             kind=ek.OUTBOUND_ORG_SSO,
    #             start=EdgePath(value=self.id, match_by="id"),
    #             ....
    #             properties=EdgeProperties(traversable=True),
    #         )
    #

    # @property
    # def _kerberos_sso_edge(self):
    #     # TODO: matching against arrays needs to be supported by the BH API before this will
    #     # match with nodes
    #     if self.name == "active_directory":
    #         domain = self.label.split(".")[-2]
    #         end_spn = f"HTTP/{domain}.kerberos.okta.com"
    #         condition = PropertyMatch(key="serviceprincipalnames", value=end_spn)
    #         yield Edge(
    #             kind=ek.KERBEROS_SSO,
    #             start=ConditionalEdgePath(kind="User", property_matchers=[condition]),
    #             end=EdgePath(value=self.id, match_by="id"),
    #             properties=EdgeProperties(traversable=True),
    #         )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        # Disabled until BHE supports array-based matching
        # yield from self._kerberos_sso_edge
        yield from self._contains_edge
        yield from self._outbound_jamf_sso_edge
