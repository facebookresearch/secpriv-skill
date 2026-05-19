"""User profile schema stores PII columns in plaintext."""

from sqlalchemy import Column, create_engine, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    # SSN stored in plaintext — a clear Art. 32 (security of processing)
    # violation. Should be encrypted at rest and field-level access controlled.
    ssn = Column(String)
    phone = Column(String)


engine = create_engine("postgresql://app@db/app")
