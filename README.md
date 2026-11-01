# Policy-as-Code Starter

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/bizidwassim-design/policy-as-code-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/bizidwassim-design/policy-as-code-starter/actions/workflows/ci.yml) [![Fictional data](https://img.shields.io/badge/sample%20data-fictional-informational)](SECURITY.md)

A small, tested set of **policy-as-code** guardrails you can drop into a pipeline today: eight OPA/Rego policies
for Kubernetes manifests and Terraform plans (each with unit tests and worked pass/fail examples), three Checkov
custom policies, two Sentinel sketches, and a catalogue that maps every policy to the CIS, ISO/IEC 27001 and NIST
CSF 2.0 control it evidences.

> 🇫🇷 Résumé en français en bas de page.

## Layout

```
policies/
  opa/
    lib/              k8s.rego (PodSpec/containers across workload kinds) · tfplan.rego (plan helpers)
    kubernetes/       5 policies + 5 *_test.rego
    terraform/        3 policies + 3 *_test.rego
  checkov/            3 custom YAML policies (attribute, connection, and/combination)
  sentinel/           2 example policies — syntax only, clearly marked UNTESTED
examples/
  kubernetes/         deployment-pass.yaml · pod-fail.yaml · daemonset-fail.yaml
  terraform/          aws-plan-pass.json · aws-plan-fail.json · azure-plan-pass.json · azure-plan-fail.json
  expected.json       expected deny count per (input, policy) — checked by CI
terraform/example/    aws/main.tf · azure/main.tf — resources that intentionally pass and fail
docs/                 how-to-run.md · policy-catalogue.md · writing-a-policy.md
scripts/              check_policies.py — structure checks + evaluation of every example when opa is installed
.checkov.yaml         limits Checkov to the three custom checks
```

## Quick start

```bash
# 1. Rego: format check, unit tests
opa fmt --list policies/opa
opa test policies/opa -v

# 2. Evaluate the examples
opa eval -d policies/opa -i examples/kubernetes/pod-fail.yaml "data.kubernetes" --format pretty
opa eval -d policies/opa -i examples/terraform/aws-plan-fail.json "data.terraform" --format pretty

# 3. Everything at once (structure + expected counts)
pip install pyyaml && python scripts/check_policies.py

# 4. Checkov custom policies against the HCL examples
pip install checkov
checkov -d terraform/example --external-checks-dir policies/checkov --soft-fail
```

Full instructions, including producing a real plan JSON and wiring the checks into a pull-request pipeline:
[docs/how-to-run.md](docs/how-to-run.md).

## What's inside

| Policy | Input | Denies | Controls (IDs) |
|---|---|---|---|
| `kubernetes.no_privileged_containers` | Kubernetes | `privileged: true`, `allowPrivilegeEscalation: true` on any container | CIS K8s 5.2.1, 5.2.5 · ISO A.8.9 · CSF PR.PS-01 |
| `kubernetes.no_latest_tag` | Kubernetes | Untagged or `latest` images (digests pass) | ISO A.8.9, A.8.19 · CSF PR.PS-02 |
| `kubernetes.resource_limits_required` | Kubernetes | Missing CPU/memory limits or requests | ISO A.8.6 · CSF PR.IR-04 |
| `kubernetes.no_hostpath` | Kubernetes | Any `hostPath` volume | CIS K8s 5.2.11 · ISO A.8.9 |
| `kubernetes.required_labels` | Kubernetes | Missing `app.kubernetes.io/name`, `owner`, `environment`; unknown environment | ISO A.5.9 · CSF ID.AM-01 |
| `terraform.s3_blob_public_access_blocked` | Terraform plan | S3 bucket without a full public access block or with a public ACL; Azure storage account / container allowing public blob access | CIS AWS 2.1.4 · CIS Azure 3.7 · ISO A.8.3 |
| `terraform.storage_encryption_required` | Terraform plan | Unencrypted EBS volume or RDS instance; Azure managed disk without a disk encryption set; SQL database with TDE off | CIS AWS 2.2.1, 2.3.1 · ISO A.8.24 · CSF PR.DS-01 |
| `terraform.security_group_no_open_admin_ports` | Terraform plan | 22 / 3389 (or all ports) inbound from `0.0.0.0/0`, `::/0`, `*`, `Internet` on AWS security groups and Azure NSGs | CIS AWS 5.2, 5.3 · CIS Azure 6.1, 6.2 · ISO A.8.20 |
| `CKV2_CUSTOM_1` … `_3` (Checkov) | Terraform HCL | Missing owner tag; S3 bucket not connected to a public access block; Azure storage account without explicit public-access-off and HTTPS-only | see catalogue |
| 2 × Sentinel | Terraform plan (HCP) | Open admin ports; unencrypted EBS/RDS — **untested** | see catalogue |

Full mapping with benchmark versions: [docs/policy-catalogue.md](docs/policy-catalogue.md).

## Design choices

* **Modern Rego only.** `import rego.v1`, `if` / `contains` keywords, no deprecated built-ins — the files work on
  OPA 0.60+ and OPA 1.x unchanged.
* **`deny contains msg` everywhere.** Every policy returns a set of actionable messages prefixed with the object
  reference. The same convention is understood by Conftest and easy to wrap in Gatekeeper.
* **Shared helpers, not copy-paste.** `lib.k8s` finds the PodSpec in Pods, Deployments, StatefulSets, DaemonSets,
  Jobs, ReplicaSets and CronJobs and flattens init and ephemeral containers; `lib.tfplan` keeps only resources the
  plan creates or updates and exposes `after_unknown`, so references resolved at apply time are not false positives.
* **Tests and examples are the spec.** 68 unit tests, plus `examples/expected.json` which pins the number of
  findings for every (input, policy) pair. CI evaluates all of them with a real OPA binary.
* **Honest about what is not tested.** The Sentinel files are syntax-reviewed only and say so in their first line;
  `scripts/check_policies.py` fails if the marker is removed without tests.
* **Standards by identifier.** Benchmark and standard references are IDs only; the requirement text is theirs.

## How it relates to the sibling repositories

| Repository | Relationship |
|---|---|
| [grc-control-crosswalk](https://github.com/bizidwassim-design/grc-control-crosswalk) | Extend the policy → control mapping to further frameworks. |
| [iso27001-iso42001-toolkit](https://github.com/bizidwassim-design/iso27001-iso42001-toolkit) | These policies are the technical evidence for the Annex A controls referenced in the catalogue. |
| [application-risk-assessment-template](https://github.com/bizidwassim-design/application-risk-assessment-template) | Use the application risk rating to decide which policies are blocking versus advisory per workload. |
| [ciso-executive-dashboard](https://github.com/bizidwassim-design/ciso-executive-dashboard) | Policy pass rates per pipeline are a natural metric for the dashboard. |
| [soc-detection-playbooks](https://github.com/bizidwassim-design/soc-detection-playbooks) | Preventive controls here; detective controls there (for example, cloud logging disabled). |
| [public-scripts](https://github.com/bizidwassim-design/public-scripts) | Operational scripts to remediate what the policies find. |

## Contributing

New policies (host namespaces, read-only root filesystem, IAM wildcards, logging enabled), Sentinel tests with
mocks, and mappings to further frameworks are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/writing-a-policy.md](docs/writing-a-policy.md). Run `opa test policies/opa` and
`python scripts/check_policies.py` before opening a pull request.

## Disclaimer

These policies are a starting point, not a complete security baseline. Benchmark section numbers change between
versions; verify them against the edition your auditor uses. The Terraform examples intentionally contain insecure
resources and must never be applied. All names, identifiers and ranges are fictional.

## AI assistance

Built with Claude Code as a coding and writing assistant, which is why it appears as a co-author on some commits.
**Editor and reviewer: Wassim Bizid**, who set the scope, the frameworks and the GRC approach, edited the content
and decided what was published. Automated tests in CI check the published outputs. This is a maintainer review,
not an independent one.

## License

[MIT](LICENSE).

---

## 🇫🇷 Résumé

Kit de démarrage **policy-as-code** : huit politiques OPA/Rego (syntaxe moderne `rego.v1`) pour les manifestes
Kubernetes (conteneurs privilégiés, tag `latest`, limites de ressources, volumes `hostPath`, labels obligatoires)
et les plans Terraform (accès public S3/Blob bloqué, chiffrement du stockage, ports d'administration fermés sur
Internet), chacune avec ses tests unitaires et des exemples qui passent et échouent ; trois politiques
personnalisées Checkov ; deux exemples Sentinel (non testés, signalés comme tels) ; un catalogue reliant chaque
politique aux identifiants CIS, ISO/IEC 27001 et NIST CSF 2.0. L'intégration continue exécute `opa test`, vérifie
le nombre de résultats attendus sur chaque exemple et lance Checkov. Licence MIT ; données fictives uniquement.
