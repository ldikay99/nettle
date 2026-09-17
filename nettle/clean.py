"""CleanPipeline / recipes for scrape output."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .text import clean_text, collapse_ws, decode_entities, remove_invisible, strip_noise


CleanFn = Callable[[Any], Any]


class CleanPipeline:
    """Composable cleaning steps applied to strings / nested structures.

    Example::

        pipe = CleanPipeline.plain()
        pipe(dirty_string)
        pipe.map_dict({"title": "...", "tags": ["a", "b"]})
    """

    def __init__(self, steps: Optional[Sequence[CleanFn]] = None, mode: str = "plain") -> None:
        self.steps: List[CleanFn] = list(steps or [])
        self.mode = mode

    def add(self, fn: CleanFn) -> "CleanPipeline":
        self.steps.append(fn)
        return self

    def __call__(self, value: Any) -> Any:
        return self.apply(value)

    def apply(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self.apply(v) for v in value]
        if isinstance(value, dict):
            return {k: self.apply(v) for k, v in value.items()}
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        for step in self.steps:
            value = step(value)
        return value

    def map_dict(self, data: Dict[str, Any], keys: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        out = dict(data)
        targets = keys if keys is not None else list(out.keys())
        for k in targets:
            if k in out:
                out[k] = self.apply(out[k])
        return out

    # --- recipes -----------------------------------------------------------

    @classmethod
    def plain(cls) -> "CleanPipeline":
        return cls(mode="plain").add(lambda s: clean_text(s, mode="plain"))

    @classmethod
    def strict(cls) -> "CleanPipeline":
        return cls(mode="strict").add(lambda s: clean_text(s, mode="strict"))

    @classmethod
    def keep_newlines(cls) -> "CleanPipeline":
        return cls(mode="keep_newlines").add(lambda s: clean_text(s, mode="keep_newlines"))

    @classmethod
    def entities_only(cls) -> "CleanPipeline":
        return cls(mode="raw").add(decode_entities)

    @classmethod
    def recipe(cls, name: str) -> "CleanPipeline":
        name = (name or "plain").lower()
        recipes = {
            "plain": cls.plain,
            "strict": cls.strict,
            "keep_newlines": cls.keep_newlines,
            "raw": cls.entities_only,
            "entities": cls.entities_only,
        }
        if name not in recipes:
            raise ValueError(f"unknown clean recipe: {name!r}")
        return recipes[name]()


def clean_tree(data: Any, mode: str = "plain") -> Any:
    """Recursively clean all strings in a nested structure."""
    return CleanPipeline.recipe(mode).apply(data)
