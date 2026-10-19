"""Shared helpers for working with URL query parameters."""

from __future__ import annotations

from typing import Dict, Iterator, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def iter_param_mutations(url: str, payload: str) -> Iterator[Tuple[str, str]]:
    """Yield (param_name, mutated_url) for each query param replaced by payload.

    If the URL has no query parameters, nothing is yielded.
    """
    parsed = urlparse(url)
    params: Dict[str, list] = parse_qs(parsed.query, keep_blank_values=True)
    for name in params:
        mutated = {k: v[:] for k, v in params.items()}
        mutated[name] = [payload]
        new_query = urlencode(mutated, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        yield name, new_url


def has_query(url: str) -> bool:
    return bool(urlparse(url).query)
