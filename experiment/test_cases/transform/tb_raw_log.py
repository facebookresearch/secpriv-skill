# Copyright (c) Meta Platforms, Inc. and affiliates.

import logging

logger = logging.getLogger(__name__)


def audit(email: str, ssn: str) -> None:
    logger.info("user=%s ssn=%s", email, ssn)  # <<SINK
