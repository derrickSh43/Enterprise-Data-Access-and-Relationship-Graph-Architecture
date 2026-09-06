import httpx
import pytest
from eda.connectors.client import SyncClient, DeliveryError
from eda.connectors.contracts import SyncMessage

MSG = SyncMessage(sequence=1, operation="begin", snapshot_id="test")
def receipt(**changes):
    return {"source_id": "entra", "sequence": 1, "operation": "begin", **changes}

def test_lost_response_replays_identical_bytes():
    requests = []
    def handler(request):
        requests.append(request.content)
        assert request.headers["Authorization"] == "Bearer private-token"
        if len(requests) == 1:
            raise httpx.ReadTimeout("sensitive transport details")
        return httpx.Response(200, json=receipt(replayed=True))
    with SyncClient("https://eda.example", "entra", "private-token",
                    transport=httpx.MockTransport(handler), sleep=lambda _: None) as client:
        assert client.send(MSG)["replayed"]
    assert len(requests) == 2 and requests[0] == requests[1]

@pytest.mark.parametrize("url", ["http://eda.example", "https://user:pass@eda.example", "https://eda.example/path", "https://eda.example?q=x"])
def test_invalid_origin(url):
    with pytest.raises(ValueError):
        SyncClient(url, "entra", "token")

@pytest.mark.parametrize("status,body", [(302, {}), (403, {}), (409, {}), (200, receipt(sequence=2)), (200, receipt(source_id="other"))])
def test_rejection_never_acknowledges_or_leaks_body(status, body):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={**body, "secret": "private-token"}, headers={"Location": "https://evil.example"})
    with SyncClient("https://eda.example", "entra", "private-token", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(DeliveryError) as error:
            client.send(MSG)
    assert "private-token" not in str(error.value)
    assert len(calls) == 1

def test_retry_budget_is_bounded():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(503)
    with SyncClient("https://eda.example", "entra", "token", transport=httpx.MockTransport(handler), sleep=lambda _: None) as client:
        with pytest.raises(DeliveryError):
            client.send(MSG)
    assert len(calls) == 4
