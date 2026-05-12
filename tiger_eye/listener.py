"""Postgres LISTEN/NOTIFY-driven wakeup for the enrichment loop.

Holds a dedicated asyncpg connection (separate from the SQLAlchemy pool)
that listens on the `article_ingested` channel and signals an
asyncio.Event whenever the tiger2go ingestor commits a new archive row.

The enrichment loop waits on the event OR a poll timer (whichever
fires first), so:

  * Sub-second wake-up when new feed entries arrive (vs up-to-60s
    polling lag in the v0 design).
  * Poll timer survives missed notifies (listener reconnect window,
    container restart, etc.) — no notification is load-bearing.

Auto-reconnects with exponential backoff. Designed to run as a single
asyncio.Task for the process lifetime; cancel on shutdown.
"""

import asyncio
import logging

import asyncpg

from tiger_eye.config import get_settings
from tiger_eye.metrics import LISTENER_CONNECTED, LISTENER_NOTIFIES

log = logging.getLogger(__name__)

ARTICLE_INGESTED_CHANNEL = "article_ingested"

# Reconnect backoff schedule (seconds). Final value repeats indefinitely.
_RECONNECT_BACKOFF = (1, 2, 5, 15, 30, 60)

# Heartbeat probe interval — detects silently-dropped connections that
# asyncpg doesn't surface until the next operation.
_HEARTBEAT_INTERVAL = 60


def _backoff(streak: int) -> float:
    return float(_RECONNECT_BACKOFF[min(streak, len(_RECONNECT_BACKOFF) - 1)])


async def run_listener(wake_event: asyncio.Event) -> None:
    """LISTEN on the article_ingested channel; set wake_event on each notify.

    Idempotent set: many notifies in a short window collapse to one
    wakeup (the enrichment loop catches up by batch on the next poll).
    """
    s = get_settings()
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")

    def _on_notification(_conn, _pid, channel, payload):
        LISTENER_NOTIFIES.inc()
        log.debug(
            "LISTEN notify",
            extra={"channel": channel, "payload": (payload or "")[:64]},
        )
        wake_event.set()

    streak = 0
    while True:
        conn: asyncpg.Connection | None = None
        try:
            conn = await asyncpg.connect(url)
            await conn.add_listener(ARTICLE_INGESTED_CHANNEL, _on_notification)
            LISTENER_CONNECTED.set(1)
            log.info(
                "LISTEN connected",
                extra={"channel": ARTICLE_INGESTED_CHANNEL},
            )
            streak = 0

            # Heartbeat — fail fast if the connection has been dropped
            # by something upstream (server restart, pgbouncer, network).
            while True:
                await asyncio.sleep(_HEARTBEAT_INTERVAL)
                await conn.fetchval("SELECT 1")

        except asyncio.CancelledError:
            log.info("LISTEN cancelled — shutting down")
            LISTENER_CONNECTED.set(0)
            raise
        except Exception:
            LISTENER_CONNECTED.set(0)
            delay = _backoff(streak)
            log.exception(
                "LISTEN error, reconnecting",
                extra={"backoff_s": delay, "streak": streak},
            )
            streak += 1
            await asyncio.sleep(delay)
        finally:
            if conn is not None:
                try:
                    await conn.close()
                except Exception:
                    pass
