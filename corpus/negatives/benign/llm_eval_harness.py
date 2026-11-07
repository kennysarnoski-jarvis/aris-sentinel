# Evaluation harness for the support-bot classifier.
# For each labeled ticket we ask the model for a category, then compare to the human
# label. I'm using an LLM judge for the free-text "reasoning" field because exact-match
# would penalize correct answers phrased differently.
import json
from client import complete

JUDGE = "You are grading a support-ticket classifier. Reply with JSON: {\"correct\": true|false, \"why\": \"...\"}"

def evaluate(cases):
    correct = 0
    for c in cases:
        pred = complete(f"Classify: {c['text']}")
        verdict = json.loads(complete(JUDGE + f"\nExpected: {c['label']}\nGot: {pred}"))
        correct += bool(verdict["correct"])
    return correct / len(cases)
