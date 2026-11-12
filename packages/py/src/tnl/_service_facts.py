"""immutable build-generated service facts, independent of selection and authority."""

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._protocol import TnlError, service_name

_protocols = frozenset({"http", "postgres", "mysql", "tcp", "kubernetes"})


@dataclass(frozen=True, slots=True, init=False)
class ServiceFacts(Mapping[str, Mapping[str, str]]):
    """capture a validated, private copy of generated service names and protocols."""

    _services: Mapping[str, Mapping[str, str]]

    def __init__(self, services: Mapping[str, Mapping[str, str]]) -> None:
        if not isinstance(services, Mapping) or len(services) > 128:
            raise TnlError("sdk.configuration_invalid", "invalid generated service facts")
        owned: dict[str, Mapping[str, str]] = {}
        for name, fact in services.items():
            try:
                service_name(name)
            except TnlError:
                raise TnlError(
                    "sdk.configuration_invalid", "invalid generated service facts"
                ) from None
            if not isinstance(fact, Mapping) or set(fact) != {"protocol"}:
                raise TnlError("sdk.configuration_invalid", "invalid generated service facts")
            protocol = fact["protocol"]
            if not isinstance(protocol, str) or protocol not in _protocols:
                raise TnlError("sdk.configuration_invalid", "invalid generated service facts")
            owned[name] = MappingProxyType({"protocol": protocol})
        object.__setattr__(self, "_services", MappingProxyType(owned))

    def __getitem__(self, name: str) -> Mapping[str, str]:
        return self._services[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._services)

    def __len__(self) -> int:
        return len(self._services)


@dataclass(frozen=True, slots=True, init=False)
class _BoundServices[Context, Client](ServiceFacts):
    _construct: Callable[[ServiceFacts, Context], Client]

    def __init__(
        self,
        facts: Mapping[str, Mapping[str, str]],
        construct: Callable[[ServiceFacts, Context], Client],
    ) -> None:
        ServiceFacts.__init__(self, facts)
        object.__setattr__(self, "_construct", construct)

    def _new(self, context: Context) -> Client:
        return self._construct(self, context)


def _bind_services[Context, Client](
    facts: Mapping[str, Mapping[str, str]], construct: Callable[[ServiceFacts, Context], Client]
) -> _BoundServices[Context, Client]:
    return _BoundServices(facts, construct)
