"""SENTINEL Integration Framework -- connect to SIEM, SOAR, ticketing, and custom webhooks."""

from integrations.dispatcher import (
    ADAPTER_REGISTRY,
    IntegrationAdapter,
    IntegrationDispatcher,
    format_cef,
    format_leef,
)
