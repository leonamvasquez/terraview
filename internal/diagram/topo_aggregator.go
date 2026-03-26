package diagram

import (
	"fmt"
)

// AggregateTopoResult post-processes a TopoResult to:
// 1. Merge groups with the same Service that landed in different layers
// 2. Format service-level labels with primary/total counts
// 3. Deduplicate connections at the service-group level
func AggregateTopoResult(result *TopoResult) {
	// Merge service groups that ended up in different layers due to
	// flat-diagram layer classification (e.g., CloudWatch event_rule →
	// "Messaging" vs log_group → "Monitoring" both map to service "CloudWatch").
	mergeServiceGroupsAcrossLayers(result)

	for _, layer := range result.Layers {
		formatServiceLabels(layer.Groups)
		formatServiceLabels(layer.NetworkGroups)
		formatServiceLabels(layer.ComputeGroups)
		formatServiceLabels(layer.DataGroups)
	}

	result.Connections = deduplicateServiceConnections(result.Connections, result)
}

// mergeServiceGroupsAcrossLayers finds service groups with the same Service name
// scattered across different non-VPC layers and merges them into the first occurrence.
func mergeServiceGroupsAcrossLayers(result *TopoResult) {
	// Track first occurrence of each service: service → (layer index, group ptr)
	type loc struct {
		layerIdx int
		group    *AggregatedGroup
	}
	first := make(map[string]loc)

	for li, layer := range result.Layers {
		if layer.IsVPC {
			continue
		}
		var kept []*AggregatedGroup
		for _, g := range layer.Groups {
			if prev, ok := first[g.Service]; ok {
				// Merge into the first occurrence
				prev.group.PrimaryCount += g.PrimaryCount
				prev.group.TotalCount += g.TotalCount
				prev.group.Addresses = append(prev.group.Addresses, g.Addresses...)
				if prev.group.Action != g.Action {
					prev.group.Action = "mixed"
				}
				_ = li // drop this group from the current layer
			} else {
				first[g.Service] = loc{layerIdx: li, group: g}
				kept = append(kept, g)
			}
		}
		layer.Groups = kept
	}
}

// formatServiceLabels generates display labels with counts.
// Consistent format:
//   Sub-resources present (total > primary): "S3 (8, 35 total)" or "Lambda (1, 13 total)"
//   No sub-resources (total == primary):     "IAM (24)" or "Kinesis (1)"
func formatServiceLabels(groups []*AggregatedGroup) {
	for _, g := range groups {
		if g.TotalCount > g.PrimaryCount && g.PrimaryCount > 0 {
			g.Label = fmt.Sprintf("%s (%d, %d total)", g.Service, g.PrimaryCount, g.TotalCount)
		} else {
			g.Label = fmt.Sprintf("%s (%d)", g.Service, g.TotalCount)
		}
	}
}

// deduplicateServiceConnections collapses connections between the same service groups.
func deduplicateServiceConnections(conns []*Connection, result *TopoResult) []*Connection {
	addrToService := buildAddressServiceMap(result)

	type connKey struct {
		fromSvc string
		toSvc   string
	}

	seen := make(map[connKey]bool)
	var deduped []*Connection

	for _, c := range conns {
		fromSvc := addrToService[c.From]
		toSvc := addrToService[c.To]
		if fromSvc == "" {
			fromSvc = c.From
		}
		if toSvc == "" {
			toSvc = c.To
		}

		// Skip self-connections
		if fromSvc == toSvc {
			continue
		}

		key := connKey{fromSvc: fromSvc, toSvc: toSvc}
		if seen[key] {
			continue
		}
		seen[key] = true

		deduped = append(deduped, &Connection{
			From:  fromSvc,
			To:    toSvc,
			Via:   c.Via,
			Label: c.Via,
		})
	}

	return deduped
}

// buildAddressServiceMap maps each resource address to its service group label.
func buildAddressServiceMap(result *TopoResult) map[string]string {
	m := make(map[string]string)

	for _, layer := range result.Layers {
		mapGroupAddresses(m, layer.Groups)
		mapGroupAddresses(m, layer.NetworkGroups)
		mapGroupAddresses(m, layer.ComputeGroups)
		mapGroupAddresses(m, layer.DataGroups)
	}

	return m
}

func mapGroupAddresses(m map[string]string, groups []*AggregatedGroup) {
	for _, g := range groups {
		// Use VPC-qualified label when group belongs to a specific VPC (multi-VPC)
		label := g.Label
		if g.VPCAddress != "" {
			label = g.VPCAddress + "|" + g.Label
		}
		for _, addr := range g.Addresses {
			m[addr] = label
		}
	}
}
