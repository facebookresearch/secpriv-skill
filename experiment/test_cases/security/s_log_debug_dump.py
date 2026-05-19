"""Debug dump endpoint logs the full Stripe payload including PAN."""

import json
import logging

log = logging.getLogger("debug")


def handle_payment(payload: dict) -> None:
    # Payload contains card_number, cvv, exp; dumping it to the log is
    # both a CWE-532 logging violation and a PCI-DSS violation.
    log.debug("payment payload: %s", json.dumps(payload))
    _process(payload)


def _process(p: dict) -> None:
    pass
