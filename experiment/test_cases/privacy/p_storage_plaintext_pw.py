# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User table stores passwords as plaintext."""

from sqlalchemy import Column, create_engine, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    # Plaintext password storage — both a security and Art. 32 violation.
    password = Column(String, nullable=False)


engine = create_engine("postgresql://app@db/app")
