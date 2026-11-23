"""Background worker that drives rotation one batch at a time.

The worker performs no state of its own: every tick reads the persisted
rotation job from SQLite.  If the process is killed mid-rotation, a new
process simply picks the same job up on startup.
"""

import logging
import threading

log = logging.getLogger(__name__)


class RotationWorker(threading.Thread):
    def __init__(self, service, interval: float):
        super().__init__(name="rotation-worker", daemon=True)
        self._service = service
        self._interval = interval
        # Attribute names must not collide with threading.Thread internals
        # (Thread defines its own _stop() method).
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("rotation worker started")
        while not self._stop_event.is_set():
            try:
                if self._service.current_rotation() is not None:
                    processed = self._service.rotation_tick()
                    if processed == 0:
                        # Job completed or no progress possible; back off.
                        self._stop_event.wait(self._interval)
                else:
                    self._stop_event.wait(self._interval)
            except Exception:
                log.exception("rotation tick failed; will retry")
                self._stop_event.wait(self._interval)
        log.info("rotation worker stopped")
