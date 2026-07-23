from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class UserProperties(OktaNodeProperties):
    """Properties for the Okta_User node"""

    status: str
    created: datetime
    enabled: bool = False
    login: str | None = None
    email: str | None = None
    last_login: datetime | None = None
    last_updated: datetime | None = None
    activated: datetime | None = None
    title: str | None = None
    department: str | None = None
    city: str | None = None
    state: str | None = None
    country_code: str | None = None
    organization: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    password_changed: datetime | None = None
    user_type: str | None = None
    employee_number: str | None = None
    division: str | None = None
    realm_id: str | None = None
    manager_id: str | None = None
    credential_provider_type: str | None = None
    credential_provider_name: str | None = None


class Provider(BaseModel):
    name: str
    type: str


class Credentials(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    provider: Provider | None = None


class Profile(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    email: str | None = None
    first_name: str | None = Field(default=None, alias="firstName")
    last_name: str | None = Field(default=None, alias="lastName")
    department: str | None = None
    city: str | None = None
    country_code: str | None = Field(default=None, alias="countryCode")
    employee_number: str | None = Field(default=None, alias="employeeNumber")
    division: str | None = None
    organization: str | None = None
    title: str | None = None
    user_type: str | None = Field(default=None, alias="userType")
    manager_id: str | None = Field(default=None, alias="managerId")
    login: str
    state: str | None = None


@app.asset(
    description="Okta user asset",
    node=NodeDef(
        icon="user",
        kind=nk.USER,
        description="Okta user node",
        properties=UserProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.USER,
            kind=ek.CONTAINS,
            description="Organization contains user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.REALM,
            end=nk.USER,
            kind=ek.REALM_CONTAINS,
            description="Realm contains user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.USER,
            kind=ek.MANAGER_OF,
            description="User is a manager of another user",
            traversable=False,
        ),
    ],
)
class User(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    created: datetime
    activated: datetime | None = None
    last_login: datetime | None = Field(default=None, alias="lastLogin")
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    password_changed: datetime | None = Field(default=None, alias="passwordChanged")
    profile: Profile
    status: str
    realm_id: str | None = Field(default=None, alias="realmId")
    credentials: Credentials | None = None

    @property
    def enabled(self) -> bool:
        disabled_statuses = {"SUSPENDED", "DEPROVISIONED", "STAGED"}
        return self.status not in disabled_statuses

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.USER],
            properties=UserProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.profile.login,
                displayname=self.profile.login
                if self.profile and self.profile.login
                else self.id,
                enabled=self.enabled,
                login=self.profile.login,
                email=self.profile.email,
                first_name=self.profile.first_name,
                last_name=self.profile.last_name,
                status=self.status,
                created=self.created,
                password_changed=self.password_changed,
                last_login=self.last_login,
                last_updated=self.last_updated,
                activated=self.activated,
                title=self.profile.title,
                department=self.profile.department,
                city=self.profile.city,
                state=self.profile.state,
                country_code=self.profile.country_code,
                organization=self.profile.organization,
                user_type=self.profile.user_type,
                employee_number=self.profile.employee_number,
                division=self.profile.division,
                realm_id=self.realm_id,
                manager_id=self.profile.manager_id,
                credential_provider_type=self.credentials.provider.type
                if self.credentials and self.credentials.provider
                else None,
                credential_provider_name=self.credentials.provider.name
                if self.credentials and self.credentials.provider
                else None,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _contains_edges(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _realm_contains_edges(self):
        if self.realm_id:
            yield Edge(
                kind=ek.REALM_CONTAINS,
                start=EdgePath(value=self.realm_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _manager_of_edges(self):
        if self.profile and self.profile.manager_id:
            manager_id = self._lookup.manager_id(self.profile.manager_id)
            if manager_id:
                yield Edge(
                    kind=ek.MANAGER_OF,
                    start=EdgePath(value=manager_id, match_by="id"),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def edges(self):
        yield from self._contains_edges
        yield from self._realm_contains_edges
        yield from self._manager_of_edges
