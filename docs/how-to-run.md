# How to run

Everything here runs on a laptop in a few minutes. Nothing talks to a cloud account: the Terraform examples are
only ever parsed or rendered to plan JSON, never applied.

## Prerequisites

| Tool | Used for | Install |
|---|---|---|
| OPA 0.60 or later (1.x recommended) | Rego policies and unit tests | binary from the OPA releases page, or `brew install opa` |
| Python 3.12 + PyYAML | `scripts/check_policies.py` | `pip install pyyaml` |
| Checkov | custom YAML policies against the HCL examples | `pip install checkov` |
| Terraform 1.5+ (optional) | produce a real plan JSON from `terraform/example` | from the HashiCorp releases page |
| Sentinel CLI (optional) | the two Sentinel examples — **untested** | from the HashiCorp releases page |

## 1. Unit-test the Rego policies

```bash
opa fmt --list policies/opa          # lists files that are not canonically formatted (opa fmt --write to fix)
opa test policies/opa -v             # runs every *_test.rego, verbose
```

Expected: every test `PASS`. Each policy file has a sibling `_test.rego` in the same package; see
[writing-a-policy.md](writing-a-policy.md) for the pattern.

## 2. Evaluate the example inputs

Kubernetes manifests (OPA reads YAML input directly):

```bash
opa eval -d policies/opa -i examples/kubernetes/pod-fail.yaml "data.kubernetes" --format pretty
opa eval -d policies/opa -i examples/kubernetes/deployment-pass.yaml "data.kubernetes" --format pretty
```

Terraform plan JSON:

```bash
opa eval -d policies/opa -i examples/terraform/aws-plan-fail.json "data.terraform" --format pretty
opa eval -d policies/opa -i examples/terraform/azure-plan-pass.json "data.terraform" --format pretty
```

The output is one `deny` set per policy package. An empty set means the input passes that policy.

To check every example against the numbers in `examples/expected.json` in one go (this is what CI does):

```bash
python scripts/check_policies.py
```

## 3. Produce a real plan JSON

```bash
cd terraform/example/aws
terraform init -backend=false
terraform plan -out tfplan            # needs provider credentials only for the refresh; use -refresh=false if none
terraform show -json tfplan > ../../../plan.json
cd ../../..
opa eval -d policies/opa -i plan.json "data.terraform" --format pretty
```

The policies read `resource_changes[].change.after` and `after_unknown`, so any plan from any workspace works.

## 4. Run the Checkov custom policies

```bash
pip install checkov
checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail
```

`.checkov.yaml` at the repository root limits the run to the three custom checks so the output stays readable;
delete the `check:` list to see Checkov's full built-in catalogue as well. `--soft-fail` keeps the exit code at 0 —
drop it in a real pipeline.

## 5. Sentinel (untested)

The two files in `policies/sentinel/` are written against the `tfplan/v2` import and reviewed for syntax only.
Before relying on them:

```bash
sentinel fmt policies/sentinel/*.sentinel
sentinel apply -trace policies/sentinel/restrict-open-admin-ports.sentinel   # with your own mock data
```

## 6. Use the policies in a pipeline

| Where | How |
|---|---|
| **Pull request on Terraform** | `terraform plan -out tfplan && terraform show -json tfplan > plan.json`, then `opa eval --fail-defined -d policies/opa -i plan.json "data.terraform[_].deny[_]"` — a non-empty result fails the job. |
| **Pull request on Kubernetes manifests** | Loop over rendered manifests (`helm template`, `kustomize build`) and `opa eval --fail-defined ... "data.kubernetes[_].deny[_]"`. [Conftest](https://www.conftest.dev/) wraps exactly this: `conftest test --policy policies/opa manifests/`, with the `deny` convention these policies already follow. |
| **Admission control** | Load the Kubernetes policies into OPA Gatekeeper (wrap in `ConstraintTemplate`s) or run OPA as a validating webhook. The `lib.k8s` helper flattens workload kinds so one rule covers Pods and controllers. |
| **Terraform Cloud / HCP** | Port the logic to Sentinel (examples provided, untested) or run OPA in a run task. |

## 7. CI in this repository

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

1. `actions/setup-python@v5` (3.12) and `open-policy-agent/setup-opa@v2`.
2. `opa fmt --list policies/opa` and `opa test policies/opa -v`.
3. `python scripts/check_policies.py` — structure checks and evaluation of every example against `expected.json`.
4. `pip install checkov` and `checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail`.
