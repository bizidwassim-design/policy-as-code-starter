# Policy catalogue

One row per policy, with the control each one evidences. Control references are **identifiers only** — read the
benchmark or standard for the requirement text. Benchmark section numbers move between versions; the versions used
are CIS Kubernetes Benchmark v1.8, CIS AWS Foundations Benchmark v1.5, CIS Azure Foundations Benchmark v2.0,
ISO/IEC 27001:2022 Annex A and NIST CSF 2.0. Verify against the version your auditor uses.

## OPA / Rego policies (`policies/opa/`)

### Kubernetes manifests

| Package | File | What it denies | CIS Kubernetes | ISO/IEC 27001 | NIST CSF 2.0 |
|---|---|---|---|---|---|
| `kubernetes.no_privileged_containers` | `kubernetes/no_privileged_containers.rego` | `securityContext.privileged: true` or `allowPrivilegeEscalation: true` on any container, init container or ephemeral container | 5.2.1, 5.2.5 | A.8.9 | PR.PS-01 |
| `kubernetes.no_latest_tag` | `kubernetes/no_latest_tag.rego` | Images without a tag, with the `latest` tag, or with an empty tag; digests always pass | — | A.8.9, A.8.19 | PR.PS-02 |
| `kubernetes.resource_limits_required` | `kubernetes/resource_limits_required.rego` | Containers missing CPU or memory limits or requests | — | A.8.6, A.8.9 | PR.PS-01, PR.IR-04 |
| `kubernetes.no_hostpath` | `kubernetes/no_hostpath.rego` | Any `hostPath` volume | 5.2.11 | A.8.9 | PR.PS-01 |
| `kubernetes.required_labels` | `kubernetes/required_labels.rego` | Objects missing `app.kubernetes.io/name`, `owner` or `environment`, or with `environment` outside `dev / test / staging / prod` | — | A.5.9, A.8.9 | ID.AM-01, ID.AM-02 |

All five use `lib.k8s`, which resolves the PodSpec for Pods, Deployments, StatefulSets, DaemonSets, Jobs,
ReplicaSets, ReplicationControllers and CronJobs and flattens `containers`, `initContainers` and `ephemeralContainers`.

### Terraform plan JSON

| Package | File | What it denies | CIS AWS / Azure | ISO/IEC 27001 | NIST CSF 2.0 |
|---|---|---|---|---|---|
| `terraform.s3_blob_public_access_blocked` | `terraform/s3_blob_public_access_blocked.rego` | AWS: bucket without a public access block, any of the four block flags not `true`, public ACL on the bucket or an `aws_s3_bucket_acl`. Azure: storage account without `allow_nested_items_to_be_public = false`, container with `blob` or `container` access | AWS 2.1.4 · Azure 3.7 | A.8.3, A.8.20 | PR.AA-05, PR.DS-01 |
| `terraform.storage_encryption_required` | `terraform/storage_encryption_required.rego` | AWS: `aws_ebs_volume` without `encrypted = true`, `aws_db_instance` without `storage_encrypted = true`. Azure: `azurerm_managed_disk` without a `disk_encryption_set_id`, `azurerm_mssql_database` with TDE disabled | AWS 2.2.1, 2.3.1 · Azure 7.3 | A.8.24 | PR.DS-01 |
| `terraform.security_group_no_open_admin_ports` | `terraform/security_group_no_open_admin_ports.rego` | Inbound 22 or 3389 (or all ports) from `0.0.0.0/0`, `::/0`, `*` or `Internet` on `aws_security_group` inline rules, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `azurerm_network_security_rule` and inline NSG `security_rule` blocks | AWS 5.2, 5.3 · Azure 6.1, 6.2 | A.8.20, A.8.22 | PR.IR-01 |

All three use `lib.tfplan`, which keeps only resources the plan will **create or update** and exposes
`after_unknown` so that references resolved at apply time (for example `bucket = aws_s3_bucket.x.id`) are not
reported as missing.

## Checkov custom policies (`policies/checkov/`)

Checkov checks run on the Terraform **source**, not on a plan, so they complement the OPA set on pull requests
where no plan exists yet.

| ID | File | What it checks | Resource types | Controls |
|---|---|---|---|---|
| `CKV2_CUSTOM_1` | `CKV2_CUSTOM_1_owner_tag.yaml` | `tags.owner` exists | `aws_s3_bucket`, `aws_ebs_volume`, `aws_db_instance`, `aws_security_group` | ISO A.5.9 · CSF ID.AM-01 |
| `CKV2_CUSTOM_2` | `CKV2_CUSTOM_2_s3_public_access_block.yaml` | Bucket is connected to an `aws_s3_bucket_public_access_block` (graph connection) | `aws_s3_bucket` | CIS AWS 2.1.4 · ISO A.8.3 · CSF PR.AA-05 |
| `CKV2_CUSTOM_3` | `CKV2_CUSTOM_3_azure_storage_hardening.yaml` | `allow_nested_items_to_be_public = false` **and** `https_traffic_only_enabled = true`, both explicit | `azurerm_storage_account` | CIS Azure 3.1, 3.7 · ISO A.8.20, A.8.24 · CSF PR.DS-02 |

## Sentinel policies (`policies/sentinel/`) — untested

| File | Mirrors | Status |
|---|---|---|
| `restrict-open-admin-ports.sentinel` | AWS half of `terraform.security_group_no_open_admin_ports` | Syntax reviewed only; not executed |
| `require-storage-encryption.sentinel` | AWS half of `terraform.storage_encryption_required` | Syntax reviewed only; not executed |

## Coverage map

| Control theme | Kubernetes (OPA) | Terraform (OPA) | Checkov | Sentinel |
|---|---|---|---|---|
| Least privilege for workloads | no_privileged_containers, no_hostpath | — | — | — |
| Change control / reproducible builds | no_latest_tag | — | — | — |
| Capacity and resilience | resource_limits_required | — | — | — |
| Asset inventory and ownership | required_labels | — | CKV2_CUSTOM_1 | — |
| Public exposure of data | — | s3_blob_public_access_blocked | CKV2_CUSTOM_2, CKV2_CUSTOM_3 | — |
| Encryption at rest | — | storage_encryption_required | CKV2_CUSTOM_3 (in transit) | require-storage-encryption |
| Network exposure of admin services | — | security_group_no_open_admin_ports | — | restrict-open-admin-ports |

Use [grc-control-crosswalk](https://github.com/bizidwassim-design/grc-control-crosswalk) to extend the mapping to
other frameworks.
