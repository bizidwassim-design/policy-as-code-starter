# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-31

### Added
- Eight OPA/Rego policies (`import rego.v1`): five for Kubernetes manifests (no privileged containers, no latest
  tag, resource limits required, no hostPath, required labels) and three for Terraform plan JSON (S3 / Blob public
  access blocked, storage encryption required, security groups with no admin ports open to the internet), each with
  a `*_test.rego` unit-test file and shared helpers in `policies/opa/lib/`.
- Worked examples: three Kubernetes manifests and four Terraform plan JSON files that intentionally pass and fail,
  with the expected finding counts pinned in `examples/expected.json`.
- Three Checkov custom YAML policies (attribute, connection and `and` composition) and a `.checkov.yaml`.
- Two Sentinel example policies, syntax-reviewed only and marked UNTESTED.
- Minimal AWS and Azure Terraform examples with resources that pass and fail on purpose.
- Documentation: how to run, policy catalogue with CIS / ISO/IEC 27001 / NIST CSF 2.0 identifiers, writing a policy.
- `scripts/check_policies.py` structure validator that also evaluates every example with `opa` when available.
- CI: `open-policy-agent/setup-opa@v2`, `opa fmt --list`, `opa test -v`, the validator, and a Checkov run.
- Governance files: license, code of conduct, security policy, contributing guide, Dependabot.
