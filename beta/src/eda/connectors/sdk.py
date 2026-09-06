"""Small synchronous SDK with bounded pages and explicit snapshot completion."""
from abc import ABC, abstractmethod
from collections.abc import Iterator
from uuid import uuid4

from .contracts import Manifest, ObjectRecord, RelationshipRecord, SyncMessage


class Connector(ABC):
    @abstractmethod
    def describe(self) -> Manifest: ...

    @abstractmethod
    def check_connection(self) -> dict: ...

    @abstractmethod
    def snapshot(self) -> Iterator[tuple[list[ObjectRecord], list[RelationshipRecord]]]:
        """Raise on incomplete collection; yielding no pages is a complete empty inventory."""
        ...


class Registry:
    def __init__(self):
        self._factories = {}

    def register(self, name: str, factory):
        if name in self._factories:
            raise ValueError("connector already registered")
        self._factories[name] = factory

    def create(self, name: str, **configuration) -> Connector:
        return self._factories[name](**configuration)


def collect_snapshot(connector: Connector, *, first_sequence: int = 1) -> Iterator[SyncMessage]:
    """No complete event is emitted after a provider error or partial visibility.

    Caller persists acknowledged sequence numbers and aborts interrupted snapshots
    before retrying. This generator never retries or guesses source completeness.
    """
    health = connector.check_connection()
    if health.get("coverage") != "complete":
        raise ValueError("connector cannot establish complete source visibility")
    if "snapshot" not in connector.describe().capabilities:
        raise ValueError("snapshot capability required")
    snapshot_id = uuid4().hex
    seq = first_sequence
    yield SyncMessage(sequence=seq, operation="begin", snapshot_id=snapshot_id)
    for objects, relationships in connector.snapshot():
        seq += 1
        yield SyncMessage(sequence=seq, operation="page", snapshot_id=snapshot_id,
                          objects=objects, relationships=relationships)
    yield SyncMessage(sequence=seq + 1, operation="complete", snapshot_id=snapshot_id, coverage="complete")
