# Contributing

Policies get better when more pipelines run them. Welcome contributions:

* new OPA policies for Kubernetes or Terraform (host namespaces, read-only root filesystem, capabilities, IAM
  wildcards, logging enabled, tag conventions);
* additional cloud resource types in the existing policies (GCP, further Azure / AWS resources);
* Checkov policies that mirror an OPA policy for teams scanning HCL;
* Sentinel mocks and `sentinel test` coverage for the two untested examples;
* control-mapping corrections with the benchmark version stated;
* false-positive reports from real plans (anonymised — never paste a real plan).

## OPA policies

1. Follow [docs/writing-a-policy.md](docs/writing-a-policy.md): one file per policy, package `<directory>.<file_stem>`,
   `import rego.v1`, `deny contains msg if` rules, header comment with `Controls:`.
2. Sibling `<name>_test.rego` in the same package with at least three tests (pass, fail, edge case).
3. A failing and a passing example under `examples/`, and the counts in `examples/expected.json`.
4. A row in `docs/policy-catalogue.md` — identifiers only, never standard text.
5. `opa fmt --write policies/opa`, `opa test policies/opa -v`, `python scripts/check_policies.py` all clean.

## Checkov and Sentinel

* Checkov: YAML format, unique `CKV2_CUSTOM_<n>` id, listed in `.checkov.yaml`; run
  `checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail` and check the result.
* Sentinel: keep the `UNTESTED` marker on the first line unless you add mocks and passing `sentinel test` output.

## Ground rules

* Fictional names only (`Northwind Logistics`, `Contoso`, `Fabrikam`), placeholder subscription ids, private ranges.
  No real accounts, hostnames, ARNs, keys or plans.
* Respect the [Code of Conduct](CODE_OF_CONDUCT.md).
* By contributing you agree your work is released under the [MIT License](LICENSE).
