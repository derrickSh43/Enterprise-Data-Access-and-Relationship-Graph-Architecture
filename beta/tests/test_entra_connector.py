from types import SimpleNamespace
import httpx
import pytest
from eda.connectors.entra import EntraConnector
from eda.connectors.sdk import collect_snapshot


class Credential:
    def get_token(self, scope):
        assert scope == "https://graph.microsoft.com/.default"
        return SimpleNamespace(token="fake-credential-not-for-export")


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_users_groups_members_and_disabled_users():
    def respond(request):
        assert request.headers["Authorization"].startswith("Bearer ")
        if request.url.path.endswith("/users"):
            data = [{"id": "u", "displayName": "User", "accountEnabled": True},
                    {"id": "disabled", "displayName": "Disabled", "accountEnabled": False}]
        elif request.url.path.endswith("/groups"):
            data = [{"id": "g", "displayName": "Group"}]
        else:
            data = [{"id": "u", "@odata.type": "#microsoft.graph.user"},
                    {"id": "disabled", "@odata.type": "#microsoft.graph.user"}]
        return httpx.Response(200, json={"value": data})
    messages = list(collect_snapshot(EntraConnector(source_id="entra", credential=Credential(), client=client(respond))))
    assert sum(len(m.objects) for m in messages) == 2
    assert sum(len(m.relationships) for m in messages) == 1
    assert "fake-credential" not in str([m.model_dump() for m in messages])


def test_pagination_cannot_exfiltrate_bearer_token():
    requests = []
    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://attacker.example/users"})
    connector = EntraConnector(source_id="entra", credential=Credential(), client=client(respond))
    with pytest.raises(ValueError, match="pagination target"):
        list(collect_snapshot(connector))
    assert len(requests) == 1


def test_hidden_membership_error_aborts_and_redacts_body():
    connector = EntraConnector(source_id="entra", credential=Credential(),
        client=client(lambda request: httpx.Response(403, text="sensitive-error-data")))
    stream = collect_snapshot(connector)
    assert next(stream).operation == "begin"
    with pytest.raises(RuntimeError, match="HTTP 403") as error:
        next(stream)
    assert "sensitive-error-data" not in str(error.value)


def test_rate_limit_retries_are_bounded():
    calls, delays = [], []
    def respond(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "9999"})
    connector = EntraConnector(source_id="entra", credential=Credential(), client=client(respond), sleep=delays.append)
    with pytest.raises(RuntimeError):
        list(collect_snapshot(connector))
    assert len(calls) == 4
    assert delays == [30, 30, 30]


def test_missing_account_state_does_not_complete():
    connector = EntraConnector(source_id="entra", credential=Credential(),
        client=client(lambda req: httpx.Response(200, json={"value": [{"id": "u", "displayName": "U"}]})))
    with pytest.raises(ValueError, match="accountEnabled"):
        list(collect_snapshot(connector))
