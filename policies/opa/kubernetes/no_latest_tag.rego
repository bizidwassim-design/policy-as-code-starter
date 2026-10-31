# Policy: no latest tag
#
# Every container image must be pinned to an explicit tag or a digest. An image
# without a tag resolves to `latest`, which changes silently and makes rollbacks
# and incident timelines impossible to reconstruct.
#
# Controls: ISO/IEC 27001:2022 A.8.9 and A.8.19 · NIST CSF 2.0 PR.PS-02
package kubernetes.no_latest_tag

import rego.v1

import data.lib.k8s

deny contains msg if {
	some container in k8s.containers
	not pinned(container.image)
	msg := sprintf("%s: container %q uses image %q without an explicit tag or digest", [k8s.object_ref, container.name, container.image])
}

# Digest-pinned images are always acceptable.
pinned(image) if {
	contains(image, "@sha256:")
}

# Otherwise the last path segment must carry a tag that is not `latest`.
# The last segment is used so that registry ports (registry.example:5000/app)
# are not mistaken for tags.
pinned(image) if {
	segments := split(image, "/")
	last_segment := segments[count(segments) - 1]
	contains(last_segment, ":")
	tag := split(last_segment, ":")[1]
	tag != "latest"
	tag != ""
}
