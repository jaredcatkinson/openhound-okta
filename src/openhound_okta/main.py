from urllib.parse import urlparse

import dlt
from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext

from openhound_okta.lookup import OktaLookup
from openhound_okta.transforms import transforms

app = OpenHound("okta", source_kind="Okta", help="OpenGraph collector for Okta")


def _tenant_domain_from_config() -> str:
    # DLT resolves source environment variables under sources.okta, while existing
    # secrets.toml bundles use sources.source.okta. Check both so a missing value
    # cannot become b"" and leak DLT's U+F02B bytes marker into tenant_domain.
    tenant_url: str | None = dlt.secrets.get(
        "sources.okta.credentials.base_url"
    ) or dlt.secrets.get("sources.source.okta.credentials.base_url")
    if not isinstance(tenant_url, str) or not tenant_url.strip():
        raise ValueError("Okta base URL is unavailable during conversion")

    tenant_domain = urlparse(tenant_url.strip()).netloc
    if not tenant_domain:
        raise ValueError("Okta base URL must include a URL scheme and hostname")
    return tenant_domain


@app.collect()
def collect(ctx: CollectContext) -> DltSource:
    """Register a Typer CLI command that collects Okta resources and stores them (filtered) on disk.

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    return okta_source()


@app.convert(lookup=OktaLookup)
def convert(ctx: ConvertContext):
    """Register a Typer CLI command that converts previously collected Okta resources into OpenGraph nodes and edges.

    Args:
        ctx (ConvertContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    return okta_source(), {"tenant": _tenant_domain_from_config()}


@app.preproc(transformer=transforms)
def preprocess(ctx: PreProcContext):
    return {
        "organization": "organization",
        "users": "users",
        "groups": "groups",
        "applications": "applications",
        "saml_federation_providers": "saml_federation_providers",
        "saml_issuers": "saml_issuers",
        "saml_assertion_consumer_services": "saml_assertion_consumer_services",
        "saml_claim_mappings": "saml_claim_mappings",
        "saml_service_providers": "saml_service_providers",
        "saml_account_resolution_rules": "saml_account_resolution_rules",
        "saml_account_resolution_fields": "saml_account_resolution_fields",
        "saml_trusted_issuers": "saml_trusted_issuers",
        "saml_sp_assertion_consumer_services": "saml_sp_assertion_consumer_services",
        "application_secrets": "application_secrets",
        "devices": "devices",
        "authorization_servers": "authorization_servers",
        "identity_providers": "identity_providers",
        "identity_provider_users": "identity_provider_users",
        "policies": "policies",
        "resources": "resources",
        "user_role_assignments": "user_role_assignments",
        "group_role_assignments": "group_role_assignments",
        "client_role_assignments": "client_role_assignments",
        "custom_role_permissions": "custom_role_permissions",
    }
