# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""DB password embedded in the connection string literal."""

from sqlalchemy import create_engine

# Hardcoded production database password in source.
engine = create_engine(
    "postgresql://app_user:Pr0d-DB-PaSSw0rd-2024@db.example.com:5432/app"
)


def get_engine():
    return engine
