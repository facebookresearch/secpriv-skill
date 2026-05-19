"""Database connection string disables TLS."""

from sqlalchemy import create_engine


# sslmode=disable means PII flows over the wire in cleartext between
# the app and the database — Art. 32 violation on the transport leg.
engine = create_engine("postgresql://app:pw@db.example.com:5432/app?sslmode=disable")


def get_engine():
    return engine
