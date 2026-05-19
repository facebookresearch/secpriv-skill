# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User-events table schema — no retention column, no scheduled deletion."""

from sqlalchemy import Column, create_engine, DateTime, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class UserEvent(Base):
    __tablename__ = "user_events"
    id = Column(Integer, primary_key=True)
    user_id = Column(String, nullable=False)
    event_type = Column(String)
    ip_address = Column(String)
    created_at = Column(DateTime)
    # No retention metadata, no expires_at, no purge job referenced anywhere.


engine = create_engine("postgresql://app@db/app")
Base.metadata.create_all(engine)
