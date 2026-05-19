# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User table with PII columns that no application code reads."""

from sqlalchemy import Column, create_engine, Date, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    display_name = Column(String)
    # date_of_birth and home_address were added "in case we need them"
    # but no code reads them. Storing PII without a purpose violates
    # data-minimization.
    date_of_birth = Column(Date)
    home_address = Column(String)


engine = create_engine("postgresql://app@db/app")
