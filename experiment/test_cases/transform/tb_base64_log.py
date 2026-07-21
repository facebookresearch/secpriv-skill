# Copyright (c) Meta Platforms, Inc. and affiliates.

import base64
import logging

logger = logging.getLogger(__name__)


def audit(email: str) -> None:
    # base64 is encoding, not anonymization -> still a leak
    encoded = base64.b64encode(email.encode()).decode()
    logger.info("user %s", encoded)  # <<SINK
