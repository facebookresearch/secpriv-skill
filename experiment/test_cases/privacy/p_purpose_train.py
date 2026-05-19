"""Customer-support transcripts forwarded into the model-training pipeline."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def store_transcript(user_id: str, transcript: str) -> None:
    # Collected for: helping the user resolve their support ticket.
    pass


def add_to_training_corpus(transcript: str) -> None:
    """Pushes the transcript into the next model fine-tune dataset."""
    pass


@app.route("/support/close", methods=["POST"])
def close_ticket():
    user_id = request.json["user_id"]
    transcript = request.json["transcript"]
    store_transcript(user_id, transcript)
    # Repurposing support text for ML training without re-consent.
    add_to_training_corpus(transcript)
    return jsonify({"closed": True})
