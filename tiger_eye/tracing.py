"""OpenTelemetry tracing setup for tiger-eye.

Call init_tracing() once at startup. Creates a TracerProvider with
OTLP exporter (when OTEL_EXPORTER_OTLP_ENDPOINT is set) or a
no-op provider for local development.
"""

import logging
import os

from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

log = logging.getLogger(__name__)


def init_tracing(service_name: str = "tiger-eye") -> None:
    """Initialise the OTel TracerProvider and auto-instrument libraries."""
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            log.info("OTLP tracing enabled", extra={"endpoint": otlp_endpoint})
        except ImportError:
            log.warning("OTLP exporter not installed — falling back to console")
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        log.info("OTEL_EXPORTER_OTLP_ENDPOINT not set — tracing to console disabled")

    trace.set_tracer_provider(provider)


def instrument_app(app) -> None:
    """Auto-instrument FastAPI."""
    FastAPIInstrumentor.instrument_app(app)


def instrument_db(engine) -> None:
    """Auto-instrument SQLAlchemy engine."""
    SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)


def get_tracer(name: str = "tiger-eye") -> trace.Tracer:
    """Convenience: get a tracer for manual span creation."""
    return trace.get_tracer(name)
