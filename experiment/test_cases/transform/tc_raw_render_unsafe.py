# Copyright (c) Meta Platforms, Inc. and affiliates.

import logging

logger = logging.getLogger(__name__)


def profile_page(display_name: str) -> str:
    logger.info("render profile for %s", display_name)
    return f"<h1>Welcome {display_name}</h1>"  # <<SINK
