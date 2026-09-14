import sys

def process(payload: str):
    """Deliberate, deterministic bugs designed to be reachable by
    black-box mutation fuzzing (null bytes and oversized input are both
    part of BlueLine's default candidate corpus, not exotic edge cases)."""
    if "\x00" in payload:
        raise ValueError("null byte not allowed")  # reachable via WEIRD_STRINGS
    if len(payload) > 20000:
        raise MemoryError("payload too large")     # reachable via oversized boundary strings
    return len(payload)

if __name__ == "__main__":
    data = sys.stdin.buffer.read()
    text = data.decode("utf-8", errors="replace")
    print(process(text))
