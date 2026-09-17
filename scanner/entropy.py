import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy for a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
