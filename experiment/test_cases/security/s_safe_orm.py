"""Search endpoint using SQLAlchemy ORM (parameterized)."""

from flask import Flask, jsonify, request
from sqlalchemy import Column, create_engine, Integer, select, String
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)


engine = create_engine("sqlite:///app.db")
app = Flask(__name__)


@app.route("/users/search")
def search():
    name = request.args.get("name", "")
    with Session(engine) as session:
        # ORM where() parameterizes the value — SQL injection is prevented.
        stmt = select(User).where(User.name.like(f"%{name}%"))
        rows = session.execute(stmt).scalars().all()
        return jsonify([{"id": r.id, "name": r.name} for r in rows])
