# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User table stores bcrypt-hashed passwords."""

import bcrypt
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    # Stored as bcrypt hash (per-record salted), not plaintext.
    password_hash = Column(String, nullable=False)


def set_password(user: User, plaintext: str) -> None:
    user.password_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(12)).decode()
