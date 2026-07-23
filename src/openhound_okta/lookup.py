from functools import lru_cache
import json
from typing import Any

from duckdb import DuckDBPyConnection, Error as DuckDBError
from openhound.core.lookup import LookupManager


class OktaLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "okta"):
        super().__init__(client, schema)
        self.schema = schema
        self.client = client

    @lru_cache
    def org_id(self) -> str | None:
        res = self._find_single_object(f"""SELECT id FROM {self.schema}.organization""")
        return res

    @lru_cache
    def has_role_permission(self, role_id: str, permission: str) -> bool:
        res = self._find_single_object(
            f"""SELECT label FROM {self.schema}.custom_role_permissions WHERE role_id = ? AND label = ?""",
            [role_id, permission],
        )
        return res

    @lru_cache
    def application_by_id(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def application_settings(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT settings FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def all_groups(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.groups""")
        return res

    @lru_cache
    def non_admin_groups(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.non_admin_groups"""
        )
        return res

    @lru_cache
    def all_users(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.users""")
        return res

    def iter_user_saml_accounts(self):
        """Stream authoritative Okta account IDs, lifecycle states, and logins."""

        cursor = self.client.execute(
            f"""
            SELECT id, status, json_extract_string(profile, '$.login') AS login
            FROM {self.schema}.users
            ORDER BY id
            """
        )
        while rows := cursor.fetchmany(1000):
            yield from rows

    @lru_cache
    def user_status(self, user_id: str) -> str | None:
        try:
            return self._find_single_object(
                f"""SELECT status FROM {self.schema}.users WHERE id = ?""",
                [user_id],
            )
        except DuckDBError:
            return None

    @lru_cache
    def user_profile(self, user_id: str) -> dict[str, Any] | None:
        try:
            profile = self._find_single_object(
                f"""SELECT profile FROM {self.schema}.users WHERE id = ?""",
                [user_id],
            )
        except DuckDBError:
            return None
        if isinstance(profile, str):
            try:
                decoded = json.loads(profile)
            except (json.JSONDecodeError, TypeError):
                return None
            return decoded if isinstance(decoded, dict) else None
        return profile if isinstance(profile, dict) else None

    @lru_cache
    def saml_claim_mappings(self, app_id: str) -> tuple[dict[str, Any], ...]:
        try:
            available_columns = {
                row[0]
                for row in self._find_all_objects(
                    f"""DESCRIBE {self.schema}.saml_claim_mappings"""
                )
            }
        except DuckDBError:
            return ()
        required_columns = {
            "id",
            "app_id",
            "claim_name",
            "mapping_type",
            "claim_type",
            "expression",
        }
        if not required_columns <= available_columns:
            return ()
        selected_columns = [
            column
            for column in (
                "id",
                "claim_name",
                "mapping_type",
                "mapping_origin",
                "claim_type",
                "source_property",
                "expression",
                "name_id_format",
                "format",
                "format_was_omitted",
                "name_format",
                "name_format_was_omitted",
            )
            if column in available_columns
        ]
        rows = self._find_all_objects(
            f"""
            SELECT {", ".join(selected_columns)}
            FROM {self.schema}.saml_claim_mappings
            WHERE app_id = ?
            ORDER BY TRY_CAST(regexp_extract(id, '([0-9]+)$', 1) AS INTEGER), id
            """,
            [app_id],
        )
        return tuple(dict(zip(selected_columns, row, strict=True)) for row in rows)

    @lru_cache
    def all_api_services(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.api_services""")
        return res

    @lru_cache
    def all_applications(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.applications""")
        return res

    @lru_cache
    def application_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.applications WHERE name = ?""",
            [app_name],
        )
        return res

    @lru_cache
    def application_secret_ids(self, app_id: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.application_secrets WHERE app_id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def resource_set_application_ids(self, resource_set_id: str):
        return self._resource_set_resource_ids(
            resource_set_id, "apps", self.all_applications()
        )

    @lru_cache
    def resource_set_group_ids(self, resource_set_id: str):
        return self._resource_set_resource_ids(
            resource_set_id, "groups", self.all_groups()
        )

    @lru_cache
    def resource_set_non_admin_group_ids(self, resource_set_id: str):
        resource_set_groups = set(self.resource_set_group_ids(resource_set_id))
        non_admin_groups = {group_id for (group_id,) in self.non_admin_groups()}
        return tuple(sorted(resource_set_groups & non_admin_groups))

    def _resource_set_resource_ids(
        self, resource_set_id: str, resource_type: str, all_resource_rows
    ):
        rows = self._find_all_objects(
            f"""SELECT orn FROM {self.schema}.resources WHERE resource_set_id = ? AND contains(orn, ?)""",
            [resource_set_id, f":{resource_type}"],
        )

        resource_ids: set[str] = set()
        for (orn,) in rows:
            split_orn = orn.split(":")
            if len(split_orn) == 5 and split_orn[-1] == resource_type:
                resource_ids.update(resource_id for (resource_id,) in all_resource_rows)
            elif len(split_orn) == 6 and split_orn[-2] == resource_type:
                resource_ids.add(split_orn[-1])
        return tuple(sorted(resource_ids))

    @lru_cache
    def all_policies(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.policies""")
        return res

    @lru_cache
    def all_identity_providers(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.identity_providers"""
        )
        return res

    @lru_cache
    def all_auth_servers(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.authorization_servers"""
        )
        return res

    @lru_cache
    def all_devices(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.devices""")
        return res

    @lru_cache
    def manager_id(self, manager_login: str):
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.users WHERE json_extract_string(profile, '$.login') = ?""",
            [manager_login],
        )
        return res
