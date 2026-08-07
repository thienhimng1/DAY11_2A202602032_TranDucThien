"""
Lab 11 — Configuration & API Key Setup
"""
import os


def setup_api_key():
    """Load Google API key from environment, .env file, or set mock."""
    from dotenv import load_dotenv
    import sys
    load_dotenv()

    if "GOOGLE_API_KEY" not in os.environ or not os.environ["GOOGLE_API_KEY"]:
        if sys.stdin and sys.stdin.isatty():
            try:
                os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
            except (EOFError, OSError):
                os.environ["GOOGLE_API_KEY"] = "mock_key_for_testing"
        else:
            os.environ["GOOGLE_API_KEY"] = "mock_key_for_testing"
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
