"""Outbound webhook delivery for linked-account lifecycle events.

Currently emits a single signed event, ``aci.linked_account.expired``, to
Lyzr Agent when an OAuth2 refresh attempt fails in a way that can only be
resolved by the user re-authenticating (see
``aci.common.exceptions.OAuth2ReauthenticationRequired``).
"""

import hashlib
import hmac
import json
import time
from base64 import b64encode
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx

from aci.common.db.sql_models import App, LinkedAccount
from aci.common.exceptions import OAuth2ReauthenticationRequired
from aci.common.logging_setup import get_logger
from aci.common.schemas.security_scheme import OAuth2SchemeCredentials
from aci.server import config

logger = get_logger(__name__)

EVENT_TYPE_LINKED_ACCOUNT_EXPIRED = "aci.linked_account.expired"
_DELIVERY_TIMEOUT_SECONDS = 5.0


def _stable_event_id(linked_account: LinkedAccount, stored_expires_at: int | None) -> UUID:
    """Derive a stable event id for the same dead grant.

    Retrying delivery for the same stored ``expires_at`` reuses the same id
    (safe to redeliver/dedupe on the receiver side). A later reconnect stores
    a new ``expires_at`` and therefore produces a new id.
    """
    name = f"aci.linked_account.expired:{linked_account.id}:{stored_expires_at}"
    return uuid5(NAMESPACE_URL, name)


def _sign(webhook_id: str, timestamp: int, raw_body: str, secret: str) -> str:
    signed_content = f"{webhook_id}.{timestamp}.{raw_body}"
    digest = hmac.new(
        secret.encode("utf-8"), signed_content.encode("utf-8"), hashlib.sha256
    ).digest()
    return b64encode(digest).decode("utf-8")


class LinkedAccountEventDeliveryError(Exception):
    """Raised when a linked-account event could not be delivered/acknowledged.

    Covers missing configuration, transport failures, and non-2xx responses.
    Callers must treat this as "leave the account enabled, retry next use".
    """


async def emit_linked_account_expired(
    linked_account: LinkedAccount,
    app: App,
    error: OAuth2ReauthenticationRequired,
) -> None:
    """Deliver a signed ``aci.linked_account.expired`` event to Lyzr Agent.

    Raises LinkedAccountEventDeliveryError unless the receiver acknowledges
    with a 2xx response. Missing configuration, a timeout/connection
    failure, and a non-2xx response are all treated as delivery failure so
    the caller can leave the linked account enabled and retry on the next
    credential use.
    """
    webhook_url = config.LYZR_AGENT_WEBHOOK_URL
    signing_secret = config.LYZR_AGENT_WEBHOOK_SIGNING_SECRET
    if not webhook_url or not signing_secret:
        logger.warning(
            "Skipping linked_account.expired delivery, webhook not configured, "
            f"linked_account_id={linked_account.id}"
        )
        raise LinkedAccountEventDeliveryError("Lyzr Agent webhook is not configured")

    oauth2_credentials = OAuth2SchemeCredentials.model_validate(linked_account.security_credentials)
    event_id = _stable_event_id(linked_account, oauth2_credentials.expires_at)
    created_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    body = {
        "id": str(event_id),
        "type": EVENT_TYPE_LINKED_ACCOUNT_EXPIRED,
        "created_at": created_at,
        "data": {
            "id": str(linked_account.id),
            "linked_account_owner_id": linked_account.linked_account_owner_id,
            "app": {"id": str(app.id), "name": app.name},
            "status": "EXPIRED",
            "status_reason": (
                "The ACI OAuth connection has expired or been revoked. "
                "Reconnect the account to continue using this tool."
            ),
            "reason_code": error.reason_code,
        },
    }
    raw_body = json.dumps(body, sort_keys=True, separators=(",", ":"))

    webhook_id = str(event_id)
    timestamp = int(time.time())
    signature = _sign(webhook_id, timestamp, raw_body, signing_secret)
    headers = {
        "Content-Type": "application/json",
        "webhook-id": webhook_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": signature,
    }

    try:
        async with httpx.AsyncClient(timeout=_DELIVERY_TIMEOUT_SECONDS) as client:
            response = await client.post(webhook_url, content=raw_body, headers=headers)
    except Exception as e:
        # NOTE: never log raw_body/headers, they carry no secrets here but the
        # pattern must hold for any future field additions to this payload.
        logger.error(
            "Failed to deliver linked_account.expired event, "
            f"linked_account_id={linked_account.id}, event_id={event_id}, "
            f"error_type={type(e).__name__}"
        )
        raise LinkedAccountEventDeliveryError("transport failure delivering event") from e

    if not (200 <= response.status_code < 300):
        logger.error(
            "linked_account.expired event not acknowledged, "
            f"linked_account_id={linked_account.id}, event_id={event_id}, "
            f"status_code={response.status_code}"
        )
        raise LinkedAccountEventDeliveryError(
            f"receiver returned status_code={response.status_code}"
        )

    logger.info(
        f"linked_account.expired event acknowledged, linked_account_id={linked_account.id}, "
        f"event_id={event_id}"
    )
