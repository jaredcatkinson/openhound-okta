from threading import Event, Thread
from types import SimpleNamespace

import pytest
import requests
from requests import Request
from requests.adapters import BaseAdapter
from requests.exceptions import ChunkedEncodingError
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator
from dlt.sources.helpers.requests.session import Session

from openhound_okta.source import (
    APPLICATION_USERS_PAGE_SIZE,
    GROUP_PUSH_MAPPINGS_PAGE_SIZE,
    IDENTITY_PROVIDER_USERS_PAGE_SIZE,
    _saml_idp_metadata_fields,
    _saml_metadata_fields,
    application_group_push_mappings,
    application_user_rows,
    identity_provider_users,
    user_role_assignment_rows,
)
from openhound_okta.utils.http import (
    EndpointThrottle,
    OktaRESTClient,
    OktaRetryContext,
    OktaRetryExhaustedError,
)


class FakeClock:
    def __init__(self):
        self.now = 1_000.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


def _response(status_code: int, url: str, headers: dict[str, str] | None = None):
    response = requests.Response()
    response.status_code = status_code
    response.url = url
    response.headers.update(headers or {})
    response._content = b"[]"
    return response


class SequencedOktaClient(OktaRESTClient):
    def __init__(self, responses, **kwargs):
        self.responses = list(responses)
        self.requested_urls: list[str] = []
        super().__init__(
            base_url="https://example.okta.test",
            endpoint_family="/api/v1/apps*",
            **kwargs,
        )

    def _send_once(self, request, **kwargs):
        self.requested_urls.append(request.url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if response.status_code >= 400:
            raise requests.HTTPError(response=response)
        return response


def _client(
    responses,
    *,
    max_attempts=5,
    throttle=None,
    clock=None,
    rate_limit_max_elapsed_seconds=900.0,
):
    fake_clock = clock or FakeClock()
    return SequencedOktaClient(
        responses,
        throttle=throttle
        or EndpointThrottle(clock=fake_clock.time, sleep=fake_clock.sleep),
        max_attempts=max_attempts,
        rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
        clock=fake_clock.time,
        elapsed_clock=fake_clock.time,
        sleep=fake_clock.sleep,
        jitter=lambda: 0.0,
    ), fake_clock


class SequencedAdapter(BaseAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.requested_urls: list[str] = []

    def send(self, request, **kwargs):
        self.requested_urls.append(request.url)
        response = self.responses.pop(0)
        response.request = request
        response.connection = self
        return response

    def close(self):
        pass


def test_retries_the_same_application_users_cursor_after_429():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=50"
    )
    client, clock = _client(
        [
            _response(429, cursor_url, {"Retry-After": "2"}),
            _response(200, cursor_url),
        ]
    )

    response = client._send_request(Request("GET", cursor_url))

    assert response.status_code == 200
    assert client.requested_urls == [cursor_url, cursor_url]
    assert clock.sleeps == [2.0]


def test_dlt_paginator_retries_the_same_cursor_through_the_real_session_path():
    clock = FakeClock()
    first_url = "https://example.okta.test/api/v1/apps/0oa123/users?limit=500"
    cursor_url = f"{first_url}&after=00u456"
    first_page = _response(
        200,
        first_url,
        {"Link": f'<{cursor_url}>; rel="next"'},
    )
    first_page._content = b'[{"id":"00u123"}]'
    rate_limited_page = _response(429, cursor_url, {"Retry-After": "1"})
    second_page = _response(200, cursor_url)
    second_page._content = b'[{"id":"00u456"}]'
    adapter = SequencedAdapter([first_page, rate_limited_page, second_page])
    session = Session(raise_for_status=False)
    session.mount("https://", adapter)
    client = OktaRESTClient(
        base_url="https://example.okta.test",
        endpoint_family="/api/v1/apps*",
        throttle=EndpointThrottle(clock=clock.time, sleep=clock.sleep),
        paginator=HeaderLinkPaginator(),
        session=session,
        clock=clock.time,
        elapsed_clock=clock.time,
        sleep=clock.sleep,
        jitter=lambda: 0.0,
    )

    pages = list(client.paginate(first_url))

    assert [list(page) for page in pages] == [
        [{"id": "00u123"}],
        [{"id": "00u456"}],
    ]
    assert adapter.requested_urls == [first_url, cursor_url, cursor_url]
    assert clock.sleeps == [1.0]


def test_retry_exhaustion_includes_app_and_cursor_context():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=50"
    )
    client, _ = _client(
        [
            _response(429, cursor_url, {"Retry-After": "1"}),
            _response(429, cursor_url, {"Retry-After": "1"}),
            _response(429, cursor_url, {"Retry-After": "1"}),
        ],
        max_attempts=3,
        rate_limit_max_elapsed_seconds=3.0,
    )

    with pytest.raises(OktaRetryExhaustedError) as exc:
        client._send_request(Request("GET", cursor_url))

    assert exc.value.context.endpoint_family == "/api/v1/apps*"
    assert exc.value.context.status_code == 429
    assert exc.value.context.attempts == 3
    assert exc.value.context.app_id == "0oa123"
    assert exc.value.context.cursor == "00u456"
    assert "app_id=0oa123" in str(exc.value)
    assert "cursor=00u456" in str(exc.value)


def test_retries_the_same_application_users_cursor_after_timeout():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=50"
    )
    client, clock = _client(
        [
            requests.Timeout("timed out"),
            _response(200, cursor_url),
        ]
    )

    response = client._send_request(Request("GET", cursor_url))

    assert response.status_code == 200
    assert client.requested_urls == [cursor_url, cursor_url]
    assert clock.sleeps == [1.0]


def test_retries_truncated_responses():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=500"
    )
    client, clock = _client(
        [
            ChunkedEncodingError("response ended early"),
            _response(200, cursor_url),
        ]
    )

    response = client._send_request(Request("GET", cursor_url))

    assert response.status_code == 200
    assert client.requested_urls == [cursor_url, cursor_url]
    assert clock.sleeps == [1.0]


def test_rate_limit_attempts_do_not_inflate_server_error_backoff():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=500"
    )
    client, clock = _client(
        [
            _response(429, cursor_url, {"Retry-After": "1"}),
            _response(500, cursor_url),
            _response(200, cursor_url),
        ]
    )

    response = client._send_request(Request("GET", cursor_url))

    assert response.status_code == 200
    assert clock.sleeps == [1.0, 1.0]


def test_transient_request_exhaustion_includes_app_and_cursor_context():
    cursor_url = (
        "https://example.okta.test/api/v1/apps/0oa123/users?after=00u456&limit=50"
    )
    client, _ = _client(
        [
            requests.ConnectionError("connection failed"),
            requests.ConnectionError("connection failed"),
            requests.ConnectionError("connection failed"),
        ],
        max_attempts=3,
    )

    with pytest.raises(OktaRetryExhaustedError) as exc:
        client._send_request(Request("GET", cursor_url))

    assert exc.value.context.endpoint_family == "/api/v1/apps*"
    assert exc.value.context.status_code is None
    assert exc.value.context.attempts == 3
    assert exc.value.context.app_id == "0oa123"
    assert exc.value.context.cursor == "00u456"


def test_endpoint_throttle_honors_a_shared_cooldown():
    clock = FakeClock()
    throttle = EndpointThrottle(clock=clock.time, sleep=clock.sleep)
    throttle.defer(5)
    client, _ = _client(
        [_response(200, "https://example.okta.test/api/v1/apps/0oa789/users")],
        throttle=throttle,
        clock=clock,
    )

    client._send_request(Request("GET", "/api/v1/apps/0oa789/users"))

    assert clock.sleeps == [5.0]


def test_endpoint_throttle_rechecks_a_cooldown_extended_while_sleeping():
    clock = FakeClock()
    extended = False
    throttle = None

    def sleep(delay):
        nonlocal extended
        if not extended:
            extended = True
            throttle.defer(10)
        clock.sleep(delay)

    throttle = EndpointThrottle(clock=clock.time, sleep=sleep)
    throttle.defer(5)

    throttle.wait()

    assert clock.sleeps == [5.0, 5.0]
    assert clock.now == 1_010.0


def test_endpoint_throttle_bounds_concurrent_requests():
    throttle = EndpointThrottle(max_concurrency=1)
    second_acquired = Event()

    throttle.acquire()

    def acquire_second_slot():
        throttle.acquire()
        second_acquired.set()
        throttle.release()

    worker = Thread(target=acquire_second_slot)
    worker.start()
    assert not second_acquired.wait(0.05)

    throttle.release()

    assert second_acquired.wait(1.0)
    worker.join(timeout=1.0)
    assert not worker.is_alive()


def test_successful_rate_headers_pace_the_next_request():
    clock = FakeClock()
    throttle = EndpointThrottle(
        clock=clock.time,
        wall_clock=clock.time,
        sleep=clock.sleep,
        remaining_reserve=1,
    )
    response = _response(
        200,
        "https://example.okta.test/api/v1/apps/0oa123/users",
        {
            "X-Rate-Limit-Limit": "10",
            "X-Rate-Limit-Remaining": "5",
            "X-Rate-Limit-Reset": "1010",
        },
    )

    throttle.observe_response(response)
    throttle.wait()

    assert clock.sleeps == [2.5]


def test_out_of_order_headers_keep_the_lowest_remaining_value_for_a_window():
    clock = FakeClock()
    throttle = EndpointThrottle(
        clock=clock.time,
        wall_clock=clock.time,
        sleep=clock.sleep,
        remaining_reserve=1,
    )
    newest_response = _response(
        200,
        "https://example.okta.test/api/v1/apps/0oa123/users",
        {
            "X-Rate-Limit-Remaining": "2",
            "X-Rate-Limit-Reset": "1010",
        },
    )
    older_response = _response(
        200,
        "https://example.okta.test/api/v1/apps/0oa456/users",
        {
            "X-Rate-Limit-Remaining": "9",
            "X-Rate-Limit-Reset": "1010",
        },
    )

    throttle.observe_response(newest_response)
    throttle.observe_response(older_response)

    assert throttle._request_interval == 10.0


def test_server_retry_delay_is_clamped_to_configured_maximum():
    cursor_url = "https://example.okta.test/api/v1/apps/0oa123/users"
    client, clock = _client([])
    response = _response(
        429,
        cursor_url,
        {"X-Rate-Limit-Reset": str(int(clock.now + 10_000))},
    )

    assert client._retry_delay(response, 1) == 300.0


def test_successful_rate_header_cooldown_is_clamped():
    clock = FakeClock()
    throttle = EndpointThrottle(
        clock=clock.time,
        wall_clock=clock.time,
        sleep=clock.sleep,
        max_cooldown_seconds=300.0,
    )
    response = _response(
        200,
        "https://example.okta.test/api/v1/apps/0oa123/users",
        {
            "X-Rate-Limit-Remaining": "0",
            "X-Rate-Limit-Reset": "11000",
        },
    )

    throttle.observe_response(response)
    throttle.wait()

    assert clock.sleeps == [300.0]


class RecordingPool:
    def __init__(self, pages=None):
        self.pages = pages or []
        self.path = None
        self.kwargs = None

    def paginate(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs
        yield from self.pages


def test_group_push_mappings_request_the_maximum_page_size():
    application = SimpleNamespace(
        id="0oa123",
        features=["GROUP_PUSH"],
        name="example_app",
    )
    pool = RecordingPool(pages=[[{"id": "gpm123"}]])
    ctx = SimpleNamespace(
        pool=pool,
        group_push_mappings_page_size=GROUP_PUSH_MAPPINGS_PAGE_SIZE,
    )

    rows = list(application_group_push_mappings.__wrapped__(application, ctx))

    assert rows == [{"app_id": "0oa123", "app_name": "example_app", "id": "gpm123"}]
    assert pool.path == "/api/v1/apps/0oa123/group-push/mappings"
    assert pool.kwargs == {"params": {"limit": 1000}}


def test_identity_provider_users_request_the_maximum_page_size():
    identity_provider = SimpleNamespace(
        id="0oa123",
        name="example_idp",
        type="SAML2",
        status="ACTIVE",
        idp_url="https://idp.example.test",
        policy=None,
    )
    pool = RecordingPool(pages=[[{"id": "00u123"}]])
    ctx = SimpleNamespace(
        pool=pool,
        identity_provider_users_page_size=IDENTITY_PROVIDER_USERS_PAGE_SIZE,
    )

    rows = list(identity_provider_users.__wrapped__(identity_provider, ctx))

    assert rows == [
        {
            "idp_id": "0oa123",
            "idp_name": "example_idp",
            "idp_type": "SAML2",
            "idp_protocol_type": None,
            "idp_status": "ACTIVE",
            "idp_url": "https://idp.example.test",
            "idp_subject_user_name_template": None,
            "idp_subject_match_type": None,
            "idp_subject_filter": None,
            "id": "00u123",
        }
    ]
    assert pool.path == "/api/v1/idps/0oa123/users"
    assert pool.kwargs == {"params": {"limit": 200}}


def test_saml_metadata_retry_exhaustion_is_not_silently_discarded():
    error = OktaRetryExhaustedError(
        OktaRetryContext(
            endpoint_family="/api/v1/apps*",
            url="https://example.okta.test/api/v1/apps/0oa123/sso/saml/metadata",
            status_code=429,
            attempts=4,
        )
    )

    class FailingMetadataPool:
        def get_saml_metadata(self, path):
            raise error

    application = {
        "id": "0oa123",
        "_links": {"metadata": {"href": "https://example.okta.test/metadata"}},
    }
    ctx = SimpleNamespace(pool=FailingMetadataPool())

    with pytest.raises(OktaRetryExhaustedError) as exc:
        _saml_metadata_fields(ctx, application)

    assert exc.value is error


def test_inbound_idp_metadata_preserves_entity_and_all_acs_routes():
    metadata = """\
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://www.okta.com/saml2/service-provider">
  <md:SPSSODescriptor>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://example.okta.test/sso/saml2/0oa123"
        index="0"
        isDefault="true"/>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://example.okta.test/sso/saml2/alternate"
        index="2"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""

    class MetadataPool:
        def get_saml_metadata(self, path):
            assert path == "/api/v1/idps/0oa123/metadata.xml"
            return SimpleNamespace(text=metadata)

    identity_provider = {
        "id": "0oa123",
        "_links": {
            "metadata": {
                "href": "https://example.okta.test/api/v1/idps/0oa123/metadata.xml"
            }
        },
    }

    assert _saml_idp_metadata_fields(
        SimpleNamespace(pool=MetadataPool()),
        identity_provider,
    ) == {
        "saml_metadata_entity_id": (
            "https://www.okta.com/saml2/service-provider"
        ),
        "saml_metadata_acs_endpoints": [
            {
                "url": "https://example.okta.test/sso/saml2/0oa123",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "index": 0,
                "is_default": True,
            },
            {
                "url": "https://example.okta.test/sso/saml2/alternate",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                "index": 2,
                "is_default": None,
            },
        ],
    }


def test_inbound_idp_metadata_retry_exhaustion_is_not_silently_discarded():
    error = OktaRetryExhaustedError(
        OktaRetryContext(
            endpoint_family="/api/v1/idps*",
            url="https://example.okta.test/api/v1/idps/0oa123/metadata.xml",
            status_code=429,
            attempts=4,
        )
    )

    class FailingMetadataPool:
        def get_saml_metadata(self, path):
            raise error

    identity_provider = {
        "id": "0oa123",
        "_links": {"metadata": {"href": "https://example.okta.test/metadata"}},
    }
    ctx = SimpleNamespace(pool=FailingMetadataPool())

    with pytest.raises(OktaRetryExhaustedError) as exc:
        _saml_idp_metadata_fields(ctx, identity_provider)

    assert exc.value is error


def test_user_role_retry_exhaustion_is_not_silently_discarded():
    error = OktaRetryExhaustedError(
        OktaRetryContext(
            endpoint_family="/api/v1/users*",
            url="https://example.okta.test/api/v1/users/00u123/roles",
            status_code=429,
            attempts=4,
        )
    )

    class FailingRolePool:
        def paginate(self, path):
            raise error
            yield

    ctx = SimpleNamespace(pool=FailingRolePool())

    with pytest.raises(OktaRetryExhaustedError) as exc:
        next(user_role_assignment_rows("00u123", ctx))

    assert exc.value is error


class FailingPool:
    def __init__(self):
        self.path = None
        self.kwargs = None

    def paginate(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs
        yield [{"id": "00u_first"}]
        raise RuntimeError("cursor failed")


def test_application_users_streams_rows_and_requests_the_maximum_page_size():
    application = SimpleNamespace(
        id="0oa123",
        features=[],
        name="example_app",
        label="Example App",
        status="ACTIVE",
        settings=None,
        credentials=None,
        sign_on_mode="SAML_2_0",
    )
    pool = FailingPool()
    ctx = SimpleNamespace(
        pool=pool,
        application_users_page_size=APPLICATION_USERS_PAGE_SIZE,
    )
    rows = application_user_rows(application, ctx)

    first_row = next(rows)
    assert first_row["id"] == "00u_first"
    assert first_row["app_status"] == "ACTIVE"
    with pytest.raises(RuntimeError, match="cursor failed"):
        next(rows)

    assert pool.path == "/api/v1/apps/0oa123/users"
    assert pool.kwargs == {"params": {"limit": 500}}
