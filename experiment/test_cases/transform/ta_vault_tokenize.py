# Copyright (c) Meta Platforms, Inc. and affiliates.

import logging

logger = logging.getLogger(__name__)


def record_payment(card_number: str, vault) -> None:
    # PAN replaced by an opaque vault token before it ever reaches the log
    token = vault.tokenize(card_number)
    logger.info("charged card token=%s", token)  # <<SINK
