from __future__ import annotations

from dataclasses import dataclass
import logging
import threading
from typing import Any, Callable

from arqon_guardian.audit import AuditLogger
from arqon_guardian.events import EventStore


LOGGER = logging.getLogger(__name__)


@dataclass
class _ManagedModule:
    name: str
    factory: Callable[[], Any]
    instance: Any | None = None
    restart_count: int = 0
    last_error: str | None = None
    exhausted: bool = False


class RuntimeSupervisor:
    def __init__(
        self,
        *,
        enabled: bool,
        check_interval_sec: float,
        max_restart_attempts: int,
        event_store: EventStore | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.check_interval_sec = max(0.05, float(check_interval_sec))
        self.max_restart_attempts = max(1, int(max_restart_attempts))
        self.event_store = event_store
        self.audit_logger = audit_logger

        self._modules: dict[str, _ManagedModule] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, name: str, factory: Callable[[], Any]) -> None:
        key = str(name).strip().lower()
        if not key:
            raise ValueError("module name cannot be empty")
        with self._lock:
            if key in self._modules:
                raise ValueError(f"module already registered: {key}")
            self._modules[key] = _ManagedModule(name=key, factory=factory)

    def start(self) -> None:
        self._stop_event.clear()
        specs = self._list_specs()
        for spec in specs:
            self._start_spec(spec, is_restart=False)
        if self.enabled and specs:
            self._thread = threading.Thread(
                target=self._watchdog_loop,
                name="arqon-runtime-watchdog",
                daemon=True,
            )
            self._thread.start()
            LOGGER.info(
                "Runtime watchdog started (interval=%ss max_restart_attempts=%s)",
                self.check_interval_sec,
                self.max_restart_attempts,
            )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None

        for spec in self._list_specs():
            self._stop_instance(spec.instance)
            spec.instance = None

    def statuses(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for spec in self._list_specs():
            output.append(
                {
                    "name": spec.name,
                    "alive": self._is_alive(spec.instance),
                    "restart_count": spec.restart_count,
                    "exhausted": spec.exhausted,
                    "last_error": spec.last_error,
                }
            )
        return output

    def _list_specs(self) -> list[_ManagedModule]:
        with self._lock:
            return list(self._modules.values())

    def _watchdog_loop(self) -> None:
        while not self._stop_event.wait(self.check_interval_sec):
            for spec in self._list_specs():
                if self._stop_event.is_set():
                    return
                if self._is_alive(spec.instance):
                    continue
                if spec.exhausted:
                    continue
                if spec.restart_count >= self.max_restart_attempts:
                    spec.exhausted = True
                    self._emit_event(
                        event_type="module_degraded",
                        level="error",
                        message=f"Module restart budget exhausted: {spec.name}",
                        data={
                            "module": spec.name,
                            "restart_count": spec.restart_count,
                            "max_restart_attempts": self.max_restart_attempts,
                        },
                    )
                    self._emit_audit(
                        action="module_restart_budget",
                        status="failed",
                        details={
                            "module": spec.name,
                            "restart_count": spec.restart_count,
                            "max_restart_attempts": self.max_restart_attempts,
                        },
                    )
                    continue
                self._start_spec(spec, is_restart=True)

    def _start_spec(self, spec: _ManagedModule, *, is_restart: bool) -> None:
        if is_restart:
            self._stop_instance(spec.instance)

        try:
            instance = spec.factory()
            start_fn = getattr(instance, "start", None)
            if not callable(start_fn):
                raise RuntimeError(f"module has no start(): {spec.name}")
            start_fn()
            spec.instance = instance
            spec.last_error = None
            if is_restart:
                spec.restart_count += 1
                self._emit_event(
                    event_type="module_restart",
                    level="warning",
                    message=f"Watchdog restarted module: {spec.name}",
                    data={
                        "module": spec.name,
                        "restart_count": spec.restart_count,
                        "max_restart_attempts": self.max_restart_attempts,
                    },
                )
                self._emit_audit(
                    action="module_restart",
                    status="success",
                    details={
                        "module": spec.name,
                        "restart_count": spec.restart_count,
                    },
                )
            LOGGER.info("Runtime module started: %s", spec.name)
        except Exception as error:
            spec.instance = None
            spec.last_error = str(error)
            if is_restart:
                spec.restart_count += 1
            LOGGER.warning("Runtime module start failed (%s): %s", spec.name, error)
            self._emit_event(
                event_type="module_restart_failed" if is_restart else "module_start_failed",
                level="error",
                message=f"Module start failed: {spec.name}",
                data={
                    "module": spec.name,
                    "error": str(error),
                    "restart_count": spec.restart_count,
                    "max_restart_attempts": self.max_restart_attempts,
                },
            )
            self._emit_audit(
                action="module_restart" if is_restart else "module_start",
                status="failed",
                details={
                    "module": spec.name,
                    "error": str(error),
                    "restart_count": spec.restart_count,
                },
            )

    def _stop_instance(self, instance: Any | None) -> None:
        if instance is None:
            return
        stop_fn = getattr(instance, "stop", None)
        join_fn = getattr(instance, "join", None)
        try:
            if callable(stop_fn):
                stop_fn()
            if callable(join_fn):
                join_fn(timeout=3.0)
        except Exception as error:
            LOGGER.warning("Runtime module stop failed: %s", error)

    def _is_alive(self, instance: Any | None) -> bool:
        if instance is None:
            return False
        is_alive_fn = getattr(instance, "is_alive", None)
        if callable(is_alive_fn):
            try:
                return bool(is_alive_fn())
            except Exception:
                return False
        return True

    def _emit_event(
        self,
        *,
        event_type: str,
        level: str,
        message: str,
        data: dict[str, Any],
    ) -> None:
        if not self.event_store:
            return
        self.event_store.append(
            event_type=event_type,
            level=level,
            message=message,
            data=data,
        )

    def _emit_audit(self, *, action: str, status: str, details: dict[str, Any]) -> None:
        if not self.audit_logger:
            return
        self.audit_logger.log(
            action=action,
            status=status,
            actor="system",
            source="watchdog",
            details=details,
        )
