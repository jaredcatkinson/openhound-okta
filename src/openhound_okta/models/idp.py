from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field, computed_field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class IdentityProviderProperties(OktaNodeProperties):
    """Properties for the Okta_IdentityProvider node"""

    type: str
    name: str
    status: str
    created: datetime
    last_updated: datetime
    issuer_mode: str | None = None
    url: str | None = None
    auto_user_provisioning: bool = False


class SSO(BaseModel):
    url: str
    binding: str | None = None
    destination: str | None = None


class SLO(BaseModel):
    url: str | None = None
    binding: str | None = None


class ACS(BaseModel):
    type: str | None = None
    binding: str | None = None


class SamlMetadataAcsEndpoint(BaseModel):
    url: str
    binding: str | None = None
    index: int | None = None
    is_default: bool | None = None


class Authorization(BaseModel):
    binding: str | None = None
    url: str


class Endpoint(BaseModel):
    sso: SSO | None = None
    slo: SLO | None = None
    acs: ACS | None = None
    authorization: Authorization | None = None


class ProvisioningGroups(BaseModel):
    assignments: list[str] = Field(default_factory=list)
    filter: list[str] = Field(default_factory=list)


class Provisioning(BaseModel):
    action: str
    profile_master: bool | None = Field(default=None, alias="profileMaster")
    groups: ProvisioningGroups | None = None


class Policy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    provisioning: Provisioning | None = None
    account_link: dict | None = Field(default=None, alias="accountLink")
    subject: dict | None = None
    map_amr_claims: bool | None = Field(default=None, alias="mapAMRClaims")
    trust_claims: bool | None = Field(default=None, alias="trustClaims")
    max_clock_skew: int | None = Field(default=None, alias="maxClockSkew")
    transformed_username_matching_enabled: bool | None = Field(
        default=None,
        alias="transformedUsernameMatchingEnabled",
    )


class Client(BaseModel):
    client_id: str | None = None


class Trust(BaseModel):
    issuer: str | None = None
    audience: str | None = None
    kid: str | None = None
    additional_kids: list[str] = Field(default_factory=list, alias="additionalKids")


class Credential(BaseModel):
    client: Client | None = None
    trust: Trust | None = None


class Protocol(BaseModel):
    type: str
    endpoints: Endpoint
    credentials: Credential | None = None
    algorithms: dict | None = None
    settings: dict | None = None


@app.asset(
    description="Okta identity provider asset",
    node=NodeDef(
        icon="right-to-bracket",
        kind=nk.IDP,
        description="Okta identity provider node",
        properties=IdentityProviderProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.IDP,
            kind=ek.CONTAINS,
            description="Organization contains identity provider",
            traversable=True,
        ),
        EdgeDef(
            start=nk.IDP,
            end=nk.GROUP,
            kind=ek.IDP_GROUP_ASSIGNMENT,
            description="Group provisioned by IDP",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ORG,
            end=nk.IDP,
            kind=ek.INBOUND_ORG_SSO,
            description="Organization SSO via identity provider",
            traversable=True,
        ),
    ],
)
class IdentityProvider(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    type: str
    name: str
    status: str
    created: datetime
    last_updated: datetime = Field(alias="lastUpdated")
    protocol: Protocol
    policy: Policy | None = None
    links: dict | None = Field(default=None, alias="_links")
    saml_metadata_entity_id: str | None = None
    saml_metadata_acs_endpoints: list[SamlMetadataAcsEndpoint] = Field(
        default_factory=list
    )

    @computed_field
    @property
    def idp_url(self) -> str | None:
        url = None
        if self.protocol.type == "SAML2" and self.protocol.endpoints.sso:
            url = self.protocol.endpoints.sso.url

        if self.protocol.type == "OIDC" and self.protocol.endpoints.authorization:
            url = self.protocol.endpoints.authorization.url

        if self.protocol.type == "OAUTH2" and self.protocol.endpoints.authorization:
            url = self.protocol.endpoints.authorization.url

        if self.protocol.type == "MTLS" and self.protocol.endpoints.sso:
            url = self.protocol.endpoints.sso.url

        if (
            self.protocol.type == "ID_PROOFING"
            and self.protocol.endpoints.authorization
        ):
            url = self.protocol.endpoints.authorization.url

        return url

    @property
    def as_node(self):

        return OktaNode(
            kinds=[nk.IDP],
            properties=IdentityProviderProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.name,
                type=self.type,
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                # issuer_mode=self.issuermode <-- check where this is available,
                environmentid=self._lookup.org_id(),
                url=self.idp_url,
                auto_user_provisioning=self.policy.provisioning.action == "AUTO"
                if self.policy and self.policy.provisioning
                else False,
            ),
        )

    @property
    def _group_assignment_edges(self):
        if self.policy and self.policy.provisioning and self.policy.provisioning.groups:
            for group in self.policy.provisioning.groups.assignments:
                yield Edge(
                    kind=ek.IDP_GROUP_ASSIGNMENT,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=group, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _inbound_org_sso_edge(self):
        uri = self.idp_url
        if self.type == "SAML2" and uri and "microsoftonline.com" in uri:
            tenant_id = uri.split("/")[-2]
            yield Edge(
                kind=ek.INBOUND_ORG_SSO,
                start=EdgePath(value=tenant_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def edges(self):
        yield from self._contains_edge
        yield from self._group_assignment_edges
        yield from self._inbound_org_sso_edge
