# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Database connection string disables TLS."""

from sqlalchemy import create_engine


# sslmode=disable means PII flows over the wire in cleartext between
# the app and the database — Art. 32 violation on the transport leg.
engine = create_engine("postgresql://app:pw@db.example.com:5432/app?sslmode=disable")


def get_engine():
    return engine
