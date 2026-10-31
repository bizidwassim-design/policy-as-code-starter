# Writing a policy

A policy in this repository is three files and two table rows. Budget an hour for the first one.

## 1. Pick the input and the package

| Input | Directory | Package prefix | Helper |
|---|---|---|---|
| Kubernetes manifest (one object) | `policies/opa/kubernetes/` | `kubernetes.<file_stem>` | `data.lib.k8s` |
| Terraform plan JSON | `policies/opa/terraform/` | `terraform.<file_stem>` | `data.lib.tfplan` |

The file name is the policy name in snake_case; the package **must** be `<directory>.<file_stem>` —
`scripts/check_policies.py` enforces it, and `opa eval "data.kubernetes"` then returns every Kubernetes policy at once.

## 2. Write the policy

Skeleton (OPA 0.60+ syntax, `import rego.v1`, `if` / `contains` keywords):

```rego
# Policy: <one line>
#
# <Why this matters, two or three lines.>
#
# Controls: <CIS id> · ISO/IEC 27001:2022 <A.x.y> · NIST CSF 2.0 <ID>
package kubernetes.no_host_network

import rego.v1

import data.lib.k8s

deny contains msg if {
	k8s.pod_spec.hostNetwork == true
	msg := sprintf("%s: hostNetwork must not be true", [k8s.object_ref])
}
```

Rules that make policies predictable:

* **One `deny contains msg if` per finding type.** Several rules per package are fine; each produces its own
  message so a reviewer sees every problem, not just the first.
* **Messages start with the object reference** (`k8s.object_ref` or `resource.address`) and say which attribute
  to change. A message a developer cannot act on is noise.
* **Prefer `not x == true` over `x != true`** when the attribute may be absent: a missing attribute makes
  `x != true` *undefined* (no finding), while `not x == true` *fires*. Decide which you want and say so in a comment.
* **Empty strings are truthy.** `not labels[name]` does not catch `name: ""`; compare against `""` explicitly.
* **Plans contain unknowns.** Values computed at apply time are absent from `change.after` and flagged in
  `change.after_unknown`. Use `tfplan.unknown(resource, "attribute")` to avoid false positives on references, and
  document the leniency (see `s3_blob_public_access_blocked.rego`).
* **Filter deletions.** `tfplan.resources` already drops `delete` and `no-op` changes so a bad resource being
  destroyed is not a finding.
* **Keep helpers in `lib/`.** If two policies need the same traversal, it belongs in `lib.k8s` or `lib.tfplan`.
* **Format with `opa fmt --write`** (tabs, one expression per line, blank line between rules).

## 3. Write the tests

Same package, file `<name>_test.rego`, at least three tests: a clean input, a violating input, and an edge case
(absent attribute, different workload kind, unknown value, deletion). Build inputs with small helper functions so
the tests read as sentences:

```rego
package kubernetes.no_host_network

import rego.v1

pod(spec) := {"kind": "Pod", "metadata": {"name": "web"}, "spec": spec}

test_host_network_is_denied if {
	result := deny with input as pod({"hostNetwork": true, "containers": [{"name": "app"}]})
	count(result) == 1
}

test_default_network_passes if {
	result := deny with input as pod({"containers": [{"name": "app"}]})
	count(result) == 0
}

test_host_network_in_deployment_is_denied if {
	deployment := {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": {"hostNetwork": true, "containers": [{"name": "api"}]}}},
	}
	result := deny with input as deployment
	count(result) == 1
}
```

Assert on **counts** and on a substring of the message (`contains(msg, "hostNetwork")`), not on the full string —
message wording changes, behaviour should not.

Run `opa test policies/opa -v` until green.

## 4. Add an example and the expected numbers

* Add or extend a file under `examples/kubernetes/` or `examples/terraform/` so the new policy has at least one
  failing and one passing input. Keep the comment block at the top of each example listing the expected findings.
* Add one row per (input, package) pair to `examples/expected.json`. `scripts/check_policies.py` fails if a policy
  has no row, and (with `opa` installed) if the counts do not match.

## 5. Document it

* Add a row to [policy-catalogue.md](policy-catalogue.md) with the control identifiers (IDs only, never the text).
* If the policy mirrors a Checkov or Sentinel check, say so in both directions.
* Add a line to `CHANGELOG.md`.

## 6. Checklist before the pull request

```bash
opa fmt --write policies/opa
opa test policies/opa -v
python scripts/check_policies.py
checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail   # if you touched Checkov policies
```

## Appendix — Checkov YAML policies

Checkov's custom YAML format is declarative: `metadata` (id, name, category, severity), `scope.provider`, and a
`definition` that is either one condition (`cond_type: attribute | connection`, `resource_types`, `attribute`,
`operator`, `value`) or a boolean composition (`and:` / `or:` lists of conditions). Operators used here: `exists`,
`equals`. IDs must be unique and follow the `CKV2_<NAMESPACE>_<n>` shape; `CKV2_CUSTOM_n` is the convention for
policies that live outside Checkov's own catalogue. Add the new ID to the `check:` list in `.checkov.yaml`.

## Appendix — Sentinel

The Sentinel examples are **untested** and exist to show how the same logic reads in HCP Terraform's policy
language (`tfplan/v2`, `filter`, `func`, `main = rule`). If you can run the Sentinel CLI, contributions that add
mocks and `sentinel test` coverage are very welcome — and remove the UNTESTED marker only once the tests pass.
