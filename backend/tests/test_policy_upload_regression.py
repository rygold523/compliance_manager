import ast
from pathlib import Path


def test_policy_upload_uses_computed_framework_mappings():
    source = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "api"
        / "policies.py"
    )

    tree = ast.parse(
        source.read_text(encoding="utf-8")
    )

    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "upload_policy"
    ]

    assert len(functions) == 1

    function = functions[0]

    record_assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "record"
            for target in node.targets
        )
    ]

    assert len(record_assignments) == 1

    record_dict = record_assignments[0].value

    assert isinstance(record_dict, ast.Dict)

    fields = {
        key.value: value
        for key, value in zip(
            record_dict.keys,
            record_dict.values,
        )
        if isinstance(key, ast.Constant)
    }

    mapping_field = fields["mapped_frameworks"]

    assert isinstance(
        mapping_field,
        ast.Subscript,
    )

    assert isinstance(
        mapping_field.value,
        ast.Name,
    )

    assert mapping_field.value.id == "mapping"

    assert isinstance(
        mapping_field.slice,
        ast.Constant,
    )

    assert mapping_field.slice.value == "frameworks"
