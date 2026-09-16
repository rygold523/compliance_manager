from pathlib import Path


def contained_path(root: str | Path, *components: str) -> Path:
    """Return a resolved descendant of root or reject unsafe components."""
    resolved_root = Path(root).resolve()

    for component in components:
        candidate = Path(component)
        if not component or candidate.is_absolute() or component in {".", ".."}:
            raise ValueError("Invalid path component")

    target = resolved_root.joinpath(*components).resolve()
    if target == resolved_root or resolved_root not in target.parents:
        raise ValueError("Path escapes the configured storage root")
    return target
