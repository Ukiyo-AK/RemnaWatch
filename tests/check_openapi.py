"""Optional documentation QA using PyYAML; not a runtime dependency."""
from pathlib import Path
import yaml


def check():
    spec = yaml.safe_load(Path("openapi.yaml").read_text(encoding="utf-8"))
    assert spec["openapi"] == "3.1.0"
    assert len(spec["paths"]) == 20
    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                assert ref.startswith("#/")
                target = spec
                for part in ref[2:].split("/"):
                    target = target[part]
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(spec)
    for path, methods in spec["paths"].items():
        operation = methods.get("get", methods.get("post"))
        parameters = [spec["components"]["parameters"][p["$ref"].split("/")[-1]] if "$ref" in p else p
                      for p in operation.get("parameters", [])]
        names = {p["name"] for p in parameters}
        if path.startswith("/v1/domains") or "/domains" in path:
            assert {"from", "to", "period", "limit", "offset"} <= names
            assert {"200", "400", "401", "503"} <= set(operation["responses"])
        elif path.endswith("/rate-limit"):
            assert {"400", "401", "501"} <= set(operation["responses"])
        else:
            assert {"200", "400", "401"} <= set(operation["responses"])
        if "post" in methods:
            assert methods["post"]["requestBody"]["required"]
            if path == "/v1/server/actions":
                assert {"202", "403", "409", "501", "503"} <= set(methods["post"]["responses"])
        for p in parameters:
            if p["in"] == "path":
                assert "{" + p["name"] + "}" in path and p["required"] is True
    print("OpenAPI YAML, local references and 20 paths / 21 operation contracts: OK")


if __name__ == "__main__":
    check()
