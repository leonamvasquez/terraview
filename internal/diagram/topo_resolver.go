package diagram

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// ResolveTopology builds a TopoResult from resources and their topology graph.
// Uses a multi-strategy approach:
//  1. Type hierarchy rules (aws_subnet → aws_vpc, aws_eks_addon → aws_eks_cluster)
//  2. Module path matching (resources in same module are related)
//  3. Topology graph edges (when values contain resource addresses)
//  4. Deep attribute walk (find containment keys in nested structures)
//  5. Single-parent auto-assignment (if only 1 VPC, all subnets go there)
func ResolveTopology(resources []parser.NormalizedResource, graph *topology.Graph, configRefs ...map[string][]string) *TopoResult {
	provider := detectProvider(resources)

	// Index resources by address and type
	resByAddr := make(map[string]*parser.NormalizedResource, len(resources))
	typeIndex := make(map[string][]string) // type → []address
	for i := range resources {
		r := &resources[i]
		resByAddr[r.Address] = r
		typeIndex[r.Type] = append(typeIndex[r.Type], r.Address)
	}

	// Also index by ALB alias types
	typeIndex["aws_lb"] = append(typeIndex["aws_lb"], typeIndex["aws_alb"]...)

	// --- Phase 1: Build containment map (child → parent address) ---
	parentOf := make(map[string]string)

	// Strategy 1: Type hierarchy with single-parent auto-assignment
	resolveByTypeHierarchy(resources, typeIndex, parentOf)

	// Strategy 2: Module path matching
	resolveByModulePath(resources, parentOf)

	// Strategy 3: Topology graph edges (containment fields only)
	if graph != nil {
		resolveByGraphEdges(graph, resByAddr, parentOf)
	}

	// Strategy 4: Deep value walk for containment keys
	resolveByDeepValues(resources, resByAddr, parentOf)

	// --- Phase 2: Build connections ---
	var connections []*Connection

	// Explicit connections from topology graph (non-containment edges)
	if graph != nil {
		connections = extractGraphConnections(graph)
	}

	// Inferred connections from type coexistence
	inferredConns := inferConnections(typeIndex)
	connections = append(connections, inferredConns...)

	var cfgRefs map[string][]string
	if len(configRefs) > 0 && configRefs[0] != nil {
		cfgRefs = configRefs[0]
	}

	// --- Phase 3: Build layers ---
	layers := buildTopoLayersV2(resources, parentOf, resByAddr, typeIndex, cfgRefs)

	// --- Phase 4: Split mixed Load Balancer groups ---
	splitMixedLBGroups(layers, resources)

	// --- Phase 4.1: Detect bastion hosts in Auto Scaling groups ---
	detectBastionAsgs(layers)

	// --- Phase 4.5: Repair LB connections after split ---
	// Inferred connections use typeIndex["aws_lb"][0] which may pick the wrong
	// LB after a public/internal split. Remap edge sources → public LB,
	// VPC Link sources → internal LB.
	fixLBTargetConnections(connections, layers, resByAddr)

	// --- Phase 4.6: ConfigRefs-based connections ---
	// Added AFTER fixLBTargetConnections so precise per-resource connections
	// (e.g., CloudFront→specific ALB) are not remapped by the LB fix.
	if cfgRefs != nil {
		cfgConns := connectionsFromConfigRefs(cfgRefs, resByAddr)
		connections = append(connections, cfgConns...)
	}

	// --- Phase 5: Resolve subnet placements ---
	placements := resolveSubnetPlacements(layers, resources)

	return &TopoResult{
		Provider:         provider,
		Title:            providerTitle(provider),
		Layers:           layers,
		Connections:      connections,
		SubnetPlacements: placements,
		ConfigRefs:       cfgRefs,
	}
}

// resolveByTypeHierarchy assigns parents based on typeHierarchy map.
// If there's exactly 1 resource of the parent type, auto-assigns.
func resolveByTypeHierarchy(resources []parser.NormalizedResource, typeIndex map[string][]string, parentOf map[string]string) {
	for _, r := range resources {
		if _, ok := parentOf[r.Address]; ok {
			continue
		}

		parentType, ok := typeHierarchy[r.Type]
		if !ok {
			continue
		}

		parentAddrs := typeIndex[parentType]
		if len(parentAddrs) == 1 {
			parentOf[r.Address] = parentAddrs[0]
		}
	}
}

// resolveByModulePath groups resources by Terraform module prefix.
func resolveByModulePath(resources []parser.NormalizedResource, parentOf map[string]string) {
	moduleResources := make(map[string][]string)
	for _, r := range resources {
		mod := extractModulePath(r.Address)
		if mod != "" {
			moduleResources[mod] = append(moduleResources[mod], r.Address)
		}
	}

	for _, r := range resources {
		if _, ok := parentOf[r.Address]; ok {
			continue
		}

		parentType, ok := typeHierarchy[r.Type]
		if !ok {
			continue
		}

		mod := extractModulePath(r.Address)
		if mod == "" {
			continue
		}

		for _, candidateAddr := range moduleResources[mod] {
			if candidateAddr == r.Address {
				continue
			}
			parts := strings.Split(candidateAddr, ".")
			if len(parts) >= 2 {
				candidateType := extractTypeFromAddress(candidateAddr)
				if candidateType == parentType {
					parentOf[r.Address] = candidateAddr
					break
				}
			}
		}
	}
}

// resolveByGraphEdges uses topology graph containment edges.
func resolveByGraphEdges(graph *topology.Graph, resByAddr map[string]*parser.NormalizedResource, parentOf map[string]string) {
	for _, edge := range graph.Edges {
		if !isContainmentEdge(edge.Via) {
			continue
		}
		if _, ok := parentOf[edge.From]; ok {
			continue
		}
		if _, ok := resByAddr[edge.To]; ok {
			parentOf[edge.From] = edge.To
		}
	}
}

// resolveByDeepValues walks resource Values recursively looking for containment keys.
func resolveByDeepValues(resources []parser.NormalizedResource, resByAddr map[string]*parser.NormalizedResource, parentOf map[string]string) {
	cloudIDIndex := buildCloudIDIndex(resources)

	for _, r := range resources {
		if _, ok := parentOf[r.Address]; ok {
			continue
		}
		if r.Values == nil {
			continue
		}

		parent := findContainmentInValues(r.Values, cloudIDIndex, resByAddr)
		if parent != "" && parent != r.Address {
			parentOf[r.Address] = parent
		}
	}
}

// buildCloudIDIndex maps common ID-like values back to addresses.
func buildCloudIDIndex(resources []parser.NormalizedResource) map[string]string {
	index := make(map[string]string)
	for _, r := range resources {
		if r.Values == nil {
			continue
		}
		if id, ok := r.Values["id"].(string); ok && id != "" {
			index[id] = r.Address
		}
		if arn, ok := r.Values["arn"].(string); ok && arn != "" {
			index[arn] = r.Address
		}
	}
	return index
}

// findContainmentInValues recursively searches values for containment references.
func findContainmentInValues(values map[string]interface{}, cloudIDIndex map[string]string, resByAddr map[string]*parser.NormalizedResource) string {
	containmentKeys := []string{"vpc_id", "subnet_id", "cluster_name", "cluster_id"}

	for _, key := range containmentKeys {
		val := deepGet(values, key)
		if val == "" {
			continue
		}
		if _, ok := resByAddr[val]; ok {
			return val
		}
		if addr, ok := cloudIDIndex[val]; ok {
			return addr
		}
	}

	nestedPaths := [][]string{
		{"vpc_config", "vpc_id"},
		{"vpc_config", "subnet_ids"},
		{"network_configuration", "subnets"},
		{"cluster_config", "vpc_config", "subnet_ids"},
	}

	for _, path := range nestedPaths {
		val := deepGetPath(values, path)
		if val == "" {
			continue
		}
		if _, ok := resByAddr[val]; ok {
			return val
		}
		if addr, ok := cloudIDIndex[val]; ok {
			return addr
		}
	}

	return ""
}

// deepGet retrieves a string value from a map, handling arrays of maps.
func deepGet(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return toStringValue(v)
	}
	for _, v := range m {
		switch arr := v.(type) {
		case []interface{}:
			for _, item := range arr {
				if obj, ok := item.(map[string]interface{}); ok {
					if val, ok := obj[key]; ok {
						return toStringValue(val)
					}
				}
			}
		case map[string]interface{}:
			if val, ok := arr[key]; ok {
				return toStringValue(val)
			}
		}
	}
	return ""
}

// deepGetPath walks a path like ["vpc_config", "vpc_id"] through nested maps/arrays.
func deepGetPath(m map[string]interface{}, path []string) string {
	if len(path) == 0 {
		return ""
	}

	val, ok := m[path[0]]
	if !ok {
		return ""
	}

	if len(path) == 1 {
		return toStringValue(val)
	}

	rest := path[1:]
	switch v := val.(type) {
	case map[string]interface{}:
		return deepGetPath(v, rest)
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				result := deepGetPath(obj, rest)
				if result != "" {
					return result
				}
			}
		}
	}
	return ""
}

// toStringValue extracts a string from an interface value.
func toStringValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []interface{}:
		if len(val) > 0 {
			if s, ok := val[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// extractGraphConnections extracts non-containment connections from the topology graph.
func extractGraphConnections(graph *topology.Graph) []*Connection {
	conns := make([]*Connection, 0, len(graph.Edges))
	for _, edge := range graph.Edges {
		if isContainmentEdge(edge.Via) {
			continue
		}
		conns = append(conns, &Connection{
			From:  edge.From,
			To:    edge.To,
			Via:   edge.Via,
			Label: edge.Via,
		})
	}
	return conns
}

// inferConnections generates connections from type coexistence rules.
func inferConnections(typeIndex map[string][]string) []*Connection {
	conns := make([]*Connection, 0, len(inferredConnectionRules))

	for _, rule := range inferredConnectionRules {
		fromAddrs := typeIndex[rule.FromType]
		toAddrs := typeIndex[rule.ToType]
		if len(fromAddrs) > 0 && len(toAddrs) > 0 {
			conns = append(conns, &Connection{
				From:  fromAddrs[0],
				To:    toAddrs[0],
				Via:   rule.Label,
				Label: rule.Label,
			})
		}
	}

	return conns
}

// --- Layer Building ---

// vpcBucket holds per-VPC grouping data during layer construction.
type vpcBucket struct {
	addr          string
	subnetSummary SubnetSummary
	networkGroups []*AggregatedGroup
	computeGroups []*AggregatedGroup
	dataGroups    []*AggregatedGroup
}

func (b *vpcBucket) resourceCount() int {
	n := b.subnetSummary.Public + b.subnetSummary.Firewall + b.subnetSummary.PrivateApp +
		b.subnetSummary.PrivateData + b.subnetSummary.Private
	for _, g := range b.networkGroups {
		n += g.TotalCount
	}
	for _, g := range b.computeGroups {
		n += g.TotalCount
	}
	for _, g := range b.dataGroups {
		n += g.TotalCount
	}
	return n
}

func buildTopoLayersV2(
	resources []parser.NormalizedResource,
	parentOf map[string]string,
	resByAddr map[string]*parser.NormalizedResource,
	typeIndex map[string][]string,
	configRefs map[string][]string,
) []*TopoLayer {
	vpcAddrs := typeIndex["aws_vpc"]
	hasVPC := len(vpcAddrs) > 0
	multiVPC := len(vpcAddrs) > 1

	// Top-level layers
	topLevelMap := make(map[string]*TopoLayer)

	if !hasVPC {
		// No VPC — all resources go to top-level layers
		for i := range resources {
			r := &resources[i]
			if isHelperProviderType(r.Type) {
				continue
			}
			layerName := classifyTopoLayer(r.Type)
			layer := getOrCreateTopoLayer(topLevelMap, layerName)
			addToLayerGroupV2(layer, r)
		}
		result := make([]*TopoLayer, 0, len(topLevelMap))
		for _, l := range topLevelMap {
			if len(l.Groups) > 0 {
				result = append(result, l)
			}
		}
		sortTopoLayers(result)
		return result
	}

	// Create per-VPC buckets (deterministic order via vpcAddrs slice)
	buckets := make(map[string]*vpcBucket, len(vpcAddrs))
	for _, addr := range vpcAddrs {
		buckets[addr] = &vpcBucket{addr: addr}
	}

	for i := range resources {
		r := &resources[i]

		// Skip VPC itself — used for title only
		if r.Type == "aws_vpc" {
			continue
		}
		if isHelperProviderType(r.Type) {
			continue
		}

		vpcInnerLayer := getTopoVPCLayer(r.Type)

		if vpcInnerLayer != "" {
			// Find which VPC this resource belongs to
			vpcAddr := findVPCForResource(r.Address, parentOf, resByAddr)
			if vpcAddr == "" && multiVPC {
				vpcAddr = findVPCByModule(r.Address, vpcAddrs)
			}
			if vpcAddr == "" && multiVPC {
				vpcAddr = findVPCByNamePrefix(r.Address, vpcAddrs)
			}
			if vpcAddr == "" && multiVPC {
				vpcAddr = findVPCByAncestorName(r.Address, parentOf, vpcAddrs)
			}
			if vpcAddr == "" && multiVPC && configRefs != nil {
				vpcAddr = findVPCByConfigReferences(r.Address, configRefs, vpcAddrs)
			}
			// Reverse lookup: find resources that reference this one, follow their VPC
			if vpcAddr == "" && multiVPC && configRefs != nil {
				vpcAddr = findVPCByReverseConfigRefs(r.Address, configRefs, vpcAddrs)
			}
			if vpcAddr == "" && !multiVPC {
				vpcAddr = vpcAddrs[0] // single VPC fallback
			}
			if vpcAddr == "" {
				// Multi-VPC but can't determine — put in top-level
				layerName := classifyTopoLayer(r.Type)
				layer := getOrCreateTopoLayer(topLevelMap, layerName)
				addToLayerGroupV2(layer, r)
				continue
			}

			bucket := buckets[vpcAddr]
			if bucket == nil {
				continue
			}

			// Subnets become a summary count
			if r.Type == "aws_subnet" {
				tier := classifySubnetTier(r.Address)
				switch tier {
				case "public":
					bucket.subnetSummary.Public++
				case "firewall":
					bucket.subnetSummary.Firewall++
				case "management":
					bucket.subnetSummary.Management++
				case "private_app":
					bucket.subnetSummary.PrivateApp++
				case "private_data":
					bucket.subnetSummary.PrivateData++
				default:
					bucket.subnetSummary.Private++
				}
				continue
			}

			// VPC address tag — only set for multi-VPC
			tag := ""
			if multiVPC {
				tag = vpcAddr
			}

			switch vpcInnerLayer {
			case "Network":
				bucket.networkGroups = addToGroupList(bucket.networkGroups, r, tag)
			case "Compute":
				bucket.computeGroups = addToGroupList(bucket.computeGroups, r, tag)
			case "Data":
				bucket.dataGroups = addToGroupList(bucket.dataGroups, r, tag)
			}
		} else {
			// Top-level layer
			layerName := classifyTopoLayer(r.Type)
			layer := getOrCreateTopoLayer(topLevelMap, layerName)
			addToLayerGroupV2(layer, r)
		}
	}

	// Sort VPCs by resource count (richest first, closest to Internet box)
	if multiVPC {
		for i := 0; i < len(vpcAddrs); i++ {
			for j := i + 1; j < len(vpcAddrs); j++ {
				ci := buckets[vpcAddrs[i]].resourceCount()
				cj := buckets[vpcAddrs[j]].resourceCount()
				if cj > ci {
					vpcAddrs[i], vpcAddrs[j] = vpcAddrs[j], vpcAddrs[i]
				}
			}
		}
	}

	// Create VPC layers (one per VPC, deterministic order)
	for idx, vpcAddr := range vpcAddrs {
		bucket := buckets[vpcAddr]

		vpcLayer := &TopoLayer{
			Name:       "VPC",
			Order:      topoLayerOrder["VPC"] + idx,
			IsVPC:      true,
			VPCAddress: vpcAddr,
		}

		total := bucket.subnetSummary.Public + bucket.subnetSummary.PrivateApp +
			bucket.subnetSummary.PrivateData + bucket.subnetSummary.Private
		if total > 0 {
			ss := bucket.subnetSummary // copy
			vpcLayer.SubnetSummary = &ss
		}

		vpcLayer.NetworkGroups = bucket.networkGroups
		vpcLayer.ComputeGroups = bucket.computeGroups
		vpcLayer.DataGroups = bucket.dataGroups

		// VPC title group
		tag := ""
		if multiVPC {
			tag = vpcAddr
		}
		vpcLayer.Groups = []*AggregatedGroup{
			{Service: "VPC", Label: "VPC", PrimaryCount: 1, TotalCount: 1,
				Addresses: []string{vpcAddr}, VPCAddress: tag},
		}

		// Use indexed key to avoid map collision and ensure deterministic ordering
		topLevelMap[fmt.Sprintf("VPC_%d", idx)] = vpcLayer
	}

	// Collect and sort layers
	result := make([]*TopoLayer, 0, len(topLevelMap))
	for _, l := range topLevelMap {
		if !l.IsVPC && len(l.Groups) == 0 {
			continue
		}
		result = append(result, l)
	}
	sortTopoLayers(result)

	return result
}

// findVPCForResource walks parentOf chains to find the VPC a resource belongs to.
func findVPCForResource(addr string, parentOf map[string]string, resByAddr map[string]*parser.NormalizedResource) string {
	current := addr
	visited := make(map[string]bool)
	for {
		parent, ok := parentOf[current]
		if !ok || visited[parent] {
			break
		}
		visited[parent] = true
		if r := resByAddr[parent]; r != nil && r.Type == "aws_vpc" {
			return parent
		}
		current = parent
	}
	return ""
}

// findVPCByModule matches a resource to a VPC by shared Terraform module path.
func findVPCByModule(addr string, vpcAddrs []string) string {
	mod := extractModulePath(addr)
	if mod == "" {
		return ""
	}
	for _, vpcAddr := range vpcAddrs {
		vpcMod := extractModulePath(vpcAddr)
		if vpcMod != "" && strings.HasPrefix(mod, vpcMod) {
			return vpcAddr
		}
	}
	return ""
}

// findVPCByNamePrefix matches a resource to a VPC by name prefix convention.
// "aws_subnet.prod_public[0]" matches "aws_vpc.prod" because local name starts with "prod_".
func findVPCByNamePrefix(addr string, vpcAddrs []string) string {
	localName := extractLocalName(addr)
	if localName == "" {
		return ""
	}

	var bestMatch string
	bestLen := 0
	for _, vpcAddr := range vpcAddrs {
		vpcName := extractLocalName(vpcAddr)
		if vpcName == "" {
			continue
		}
		// Match: localName starts with vpcName followed by "_" or "[", or is exact
		if strings.HasPrefix(localName, vpcName+"_") ||
			strings.HasPrefix(localName, vpcName+"[") ||
			localName == vpcName {
			if len(vpcName) > bestLen {
				bestMatch = vpcAddr
				bestLen = len(vpcName)
			}
		}
	}
	return bestMatch
}

// findVPCByAncestorName walks the parentOf chain and tries name-prefix matching
// on each ancestor. Useful when a resource (e.g. aws_efs_access_point.data)
// has a parent (e.g. aws_efs_file_system.shared) whose name matches a VPC.
func findVPCByAncestorName(addr string, parentOf map[string]string, vpcAddrs []string) string {
	current := addr
	visited := make(map[string]bool)
	for {
		parent, ok := parentOf[current]
		if !ok || visited[parent] {
			break
		}
		visited[parent] = true
		if vpc := findVPCByNamePrefix(parent, vpcAddrs); vpc != "" {
			return vpc
		}
		current = parent
	}
	return ""
}

// findVPCByConfigReferences checks Terraform configuration references for VPC name hints.
// For example, if an ASG references "local.shared_mgmt_subnet_ids", the "shared" prefix
// matches VPC "aws_vpc.shared".
func findVPCByConfigReferences(addr string, configRefs map[string][]string, vpcAddrs []string) string {
	return findVPCByConfigRefsRecursive(addr, configRefs, vpcAddrs, 0, make(map[string]bool))
}

func findVPCByConfigRefsRecursive(addr string, configRefs map[string][]string, vpcAddrs []string, depth int, visited map[string]bool) string {
	if depth > 2 || visited[addr] {
		return ""
	}
	visited[addr] = true
	refs := configRefs[addr]
	if len(refs) == 0 {
		return ""
	}
	for _, ref := range refs {
		// Extract the meaningful part of the reference (after first dot)
		// e.g. "local.shared_mgmt_subnet_ids" → check "shared_mgmt_subnet_ids"
		// e.g. "aws_security_group.shared_bastion" → check "shared_bastion"
		parts := strings.SplitN(ref, ".", 2)
		var refName string
		if len(parts) == 2 {
			refName = parts[1]
		} else {
			refName = ref
		}
		// Remove trailing .id, .arn, etc.
		if idx := strings.LastIndex(refName, "."); idx > 0 {
			suffix := refName[idx+1:]
			if suffix == "id" || suffix == "arn" || suffix == "name" {
				refName = refName[:idx]
			}
		}
		for _, vpcAddr := range vpcAddrs {
			vpcName := extractLocalName(vpcAddr)
			if vpcName != "" && strings.Contains(strings.ToLower(refName), strings.ToLower(vpcName)) {
				return vpcAddr
			}
		}
	}
	// Follow references transitively: if a ref is a resource address, check its refs
	for _, ref := range refs {
		// Normalize: strip trailing .id/.arn/.name to get resource address
		refAddr := ref
		if idx := strings.LastIndex(refAddr, "."); idx > 0 {
			suffix := refAddr[idx+1:]
			if suffix == "id" || suffix == "arn" || suffix == "name" {
				refAddr = refAddr[:idx]
			}
		}
		if _, ok := configRefs[refAddr]; ok {
			if vpc := findVPCByConfigRefsRecursive(refAddr, configRefs, vpcAddrs, depth+1, visited); vpc != "" {
				return vpc
			}
		}
	}
	return ""
}

// findVPCByReverseConfigRefs finds resources that reference the given address,
// then resolves their VPC via name prefix. Useful when a resource (e.g., launch_template)
// has no VPC-hinting refs but is referenced by a resource (e.g., eks_node_group) that does.
func findVPCByReverseConfigRefs(addr string, configRefs map[string][]string, vpcAddrs []string) string {
	for refOwner, refs := range configRefs {
		for _, ref := range refs {
			// Strip trailing .id, .arn, etc.
			refAddr := ref
			if idx := strings.LastIndex(refAddr, "."); idx > 0 {
				suffix := refAddr[idx+1:]
				if suffix == "id" || suffix == "arn" || suffix == "name" ||
					suffix == "latest_version" || suffix == "version" {
					refAddr = refAddr[:idx]
				}
			}
			if refAddr != addr {
				continue
			}
			// Found: refOwner references addr. Try to resolve refOwner's VPC.
			ownerName := extractLocalName(refOwner)
			if ownerName == "" {
				continue
			}
			for _, vpcAddr := range vpcAddrs {
				vpcName := extractLocalName(vpcAddr)
				if vpcName != "" && strings.HasPrefix(ownerName, vpcName+"_") {
					return vpcAddr
				}
			}
			// Also try forward configRefs on the owner
			if vpc := findVPCByConfigReferences(refOwner, configRefs, vpcAddrs); vpc != "" {
				return vpc
			}
		}
	}
	return ""
}

// ExtractConfigReferences builds a map of resource address → referenced identifiers
// from the Terraform plan configuration block.
func ExtractConfigReferences(config parser.Configuration) map[string][]string {
	refs := make(map[string][]string)
	extractModuleRefs(config.RootModule, "", refs)
	return refs
}

func extractModuleRefs(mod parser.ConfigModule, prefix string, refs map[string][]string) {
	for _, r := range mod.Resources {
		addr := r.Address
		if prefix != "" {
			addr = prefix + "." + addr
		}
		var collected []string
		collectReferences(r.Expressions, &collected)
		if len(collected) > 0 {
			refs[addr] = collected
		}
	}
	for name, call := range mod.ModuleCalls {
		childPrefix := "module." + name
		if prefix != "" {
			childPrefix = prefix + "." + childPrefix
		}
		if call.Module != nil {
			extractModuleRefs(*call.Module, childPrefix, refs)
		}
	}
}

func collectReferences(obj map[string]interface{}, out *[]string) {
	if obj == nil {
		return
	}
	for _, v := range obj {
		collectRefsFromValue(v, out)
	}
}

func collectRefsFromValue(v interface{}, out *[]string) {
	switch val := v.(type) {
	case map[string]interface{}:
		if refs, ok := val["references"]; ok {
			if refList, ok := refs.([]interface{}); ok {
				for _, r := range refList {
					if s, ok := r.(string); ok {
						*out = append(*out, s)
					}
				}
			}
		}
		for _, child := range val {
			collectRefsFromValue(child, out)
		}
	case []interface{}:
		for _, item := range val {
			collectRefsFromValue(item, out)
		}
	}
}

// extractLocalName returns the local resource name from a Terraform address.
// "aws_subnet.prod_public[0]" → "prod_public"
// "module.vpc.aws_vpc.main" → "main"
func extractLocalName(addr string) string {
	parts := strings.Split(addr, ".")
	if len(parts) < 2 {
		return ""
	}
	name := parts[len(parts)-1]
	if idx := strings.Index(name, "["); idx >= 0 {
		name = name[:idx]
	}
	return name
}

// addToGroupList adds a resource to a group list, returning the updated list.
// vpcAddr is set only for multi-VPC to enable VPC-qualified node IDs.
func addToGroupList(groups []*AggregatedGroup, r *parser.NormalizedResource, vpcAddr string) []*AggregatedGroup {
	svc := getServiceGroup(r.Type)
	primary := isPrimaryType(r.Type)

	for _, g := range groups {
		if g.Service == svc {
			g.TotalCount++
			if primary {
				g.PrimaryCount++
			}
			g.Addresses = append(g.Addresses, r.Address)
			if g.Action != r.Action {
				g.Action = "mixed"
			}
			return groups
		}
	}

	pc := 0
	if primary {
		pc = 1
	}
	return append(groups, &AggregatedGroup{
		Service:      svc,
		Type:         r.Type,
		Label:        svc,
		PrimaryCount: pc,
		TotalCount:   1,
		Action:       r.Action,
		Addresses:    []string{r.Address},
		VPCAddress:   vpcAddr,
	})
}

// classifyTopoLayer maps a resource type to a top-level architectural layer name.
func classifyTopoLayer(resType string) string {
	layer := getLayer(resType)

	switch layer {
	case "DNS":
		return "Edge"
	case "Access":
		return "Ingress"
	case "Network":
		return "Supporting"
	case "Compute":
		return "Supporting"
	case "Data":
		return "Supporting"
	case "Messaging":
		return "Supporting"
	case "IAM", "Security", "Secrets":
		return "Supporting"
	case "CICD":
		return "CI/CD"
	case "Monitoring":
		return "Observability"
	default:
		return "Supporting"
	}
}

var topoLayerOrder = map[string]int{
	"Edge":          0,
	"Ingress":       10,
	"VPC":           20,
	"Supporting":    300,
	"Observability": 400,
	"CI/CD":         500,
}

func getOrCreateTopoLayer(layerMap map[string]*TopoLayer, name string) *TopoLayer {
	if l, ok := layerMap[name]; ok {
		return l
	}
	order, ok := topoLayerOrder[name]
	if !ok {
		order = 99
	}
	l := &TopoLayer{
		Name:  name,
		Order: order,
	}
	layerMap[name] = l
	return l
}

func sortTopoLayers(layers []*TopoLayer) {
	for i := 0; i < len(layers); i++ {
		for j := i + 1; j < len(layers); j++ {
			if layers[j].Order < layers[i].Order {
				layers[i], layers[j] = layers[j], layers[i]
			}
		}
	}
}

// addToLayerGroupV2 adds a resource to a layer, grouping by SERVICE (not type).
func addToLayerGroupV2(layer *TopoLayer, r *parser.NormalizedResource) {
	svc := getServiceGroup(r.Type)
	primary := isPrimaryType(r.Type)

	for _, g := range layer.Groups {
		if g.Service == svc {
			g.TotalCount++
			if primary {
				g.PrimaryCount++
			}
			g.Addresses = append(g.Addresses, r.Address)
			if g.Action != r.Action {
				g.Action = "mixed"
			}
			return
		}
	}

	pc := 0
	if primary {
		pc = 1
	}
	layer.Groups = append(layer.Groups, &AggregatedGroup{
		Service:      svc,
		Type:         r.Type,
		Label:        svc,
		PrimaryCount: pc,
		TotalCount:   1,
		Action:       r.Action,
		Addresses:    []string{r.Address},
	})
}

// --- Helpers ---

// extractModulePath returns the module prefix from a Terraform address.
func extractModulePath(address string) string {
	idx := strings.Index(address, "module.")
	if idx == -1 {
		return ""
	}
	rest := address[idx:]
	parts := strings.Split(rest, ".")
	var modParts []string
	for i := 0; i < len(parts)-2; i += 2 {
		if parts[i] == "module" && i+1 < len(parts) {
			modParts = append(modParts, parts[i], parts[i+1])
		} else {
			break
		}
	}
	if len(modParts) == 0 {
		return ""
	}
	return strings.Join(modParts, ".")
}

// extractTypeFromAddress extracts the resource type from a Terraform address.
func extractTypeFromAddress(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) < 2 {
		return ""
	}
	for i := len(parts) - 2; i >= 0; i-- {
		if isResourceTypePrefix(parts[i]) {
			return parts[i]
		}
	}
	return parts[len(parts)-2]
}

// isHelperProviderType returns true for Terraform helper providers
// (random, tls, null, time) that have no cloud infrastructure counterpart.
func isHelperProviderType(resType string) bool {
	return strings.HasPrefix(resType, "random_") ||
		strings.HasPrefix(resType, "tls_") ||
		strings.HasPrefix(resType, "null_") ||
		strings.HasPrefix(resType, "time_")
}

func isResourceTypePrefix(s string) bool {
	return strings.HasPrefix(s, "aws_") ||
		strings.HasPrefix(s, "azurerm_") ||
		strings.HasPrefix(s, "google_") ||
		strings.HasPrefix(s, "null_") ||
		strings.HasPrefix(s, "random_") ||
		strings.HasPrefix(s, "local_") ||
		strings.HasPrefix(s, "tls_") ||
		strings.HasPrefix(s, "helm_") ||
		strings.HasPrefix(s, "kubernetes_")
}

// resolveSubnetPlacements builds a map of service name → subnet tier.
// Uses defaultSubnetPlacement heuristic, with special handling for Lambda vpc_config.
func resolveSubnetPlacements(layers []*TopoLayer, resources []parser.NormalizedResource) map[string]string {
	placements := make(map[string]string)

	// Index resources by address for value lookups
	resByAddr := make(map[string]*parser.NormalizedResource, len(resources))
	for i := range resources {
		resByAddr[resources[i].Address] = &resources[i]
	}

	for _, layer := range layers {
		if !layer.IsVPC {
			continue
		}
		allGroups := append(append(layer.ComputeGroups, layer.DataGroups...), layer.NetworkGroups...)
		for _, g := range allGroups {
			// Lambda: check vpc_config to determine if VPC-bound
			if g.Service == "Lambda" {
				placements[g.Service] = resolveLambdaPlacement(g, resByAddr)
				continue
			}
			placements[g.Service] = getDefaultSubnetPlacement(g.Service)
		}
	}

	return placements
}

// resolveLambdaPlacement checks if Lambda functions have vpc_config.
// Returns "global" if none are VPC-bound, "private_app" if any are.
func resolveLambdaPlacement(g *AggregatedGroup, resByAddr map[string]*parser.NormalizedResource) string {
	vpcCount := 0
	nonVPCCount := 0

	for _, addr := range g.Addresses {
		r := resByAddr[addr]
		if r == nil || r.Values == nil {
			continue
		}
		if r.Type != "aws_lambda_function" {
			continue
		}
		if hasVPCConfig(r.Values) {
			vpcCount++
		} else {
			nonVPCCount++
		}
	}

	if vpcCount == 0 {
		return "global" // all Lambdas are non-VPC
	}
	return "private_app" // at least some Lambdas are VPC-bound
}

// hasVPCConfig checks if a Lambda resource has a vpc_config block.
func hasVPCConfig(values map[string]interface{}) bool {
	vc, ok := values["vpc_config"]
	if !ok {
		return false
	}
	// vpc_config is typically a list in plan JSON
	if list, ok := vc.([]interface{}); ok {
		return len(list) > 0
	}
	// If it's a map, vpc_config is present
	if _, ok := vc.(map[string]interface{}); ok {
		return true
	}
	return false
}

// splitMixedLBGroups splits Load Balancer groups that contain both public and
// internal LBs into separate groups with distinct service names (ALB/NLB).
func splitMixedLBGroups(layers []*TopoLayer, resources []parser.NormalizedResource) {
	resByAddr := make(map[string]*parser.NormalizedResource, len(resources))
	for i := range resources {
		resByAddr[resources[i].Address] = &resources[i]
	}

	for _, layer := range layers {
		layer.Groups = splitLBInSlice(layer.Groups, resByAddr)
		layer.ComputeGroups = splitLBInSlice(layer.ComputeGroups, resByAddr)
	}
}

// detectBastionAsgs renames Auto Scaling groups that contain bastion hosts.
// Follows the same layer-iteration pattern as splitMixedLBGroups.
func detectBastionAsgs(layers []*TopoLayer) {
	for _, layer := range layers {
		renameBastionInSlice(layer.Groups)
		renameBastionInSlice(layer.ComputeGroups)
	}
}

func renameBastionInSlice(groups []*AggregatedGroup) {
	for _, g := range groups {
		if g.Service != "Auto Scaling" {
			continue
		}
		// Classify addresses by pattern
		var bastionAddrs, eksTagAddrs, otherAddrs []string
		for _, addr := range g.Addresses {
			lower := strings.ToLower(addr)
			name := extractLocalName(addr)
			nameLower := strings.ToLower(name)
			switch {
			case strings.Contains(nameLower, "bastion"):
				bastionAddrs = append(bastionAddrs, addr)
			case strings.HasPrefix(lower, "aws_autoscaling_group_tag.") && strings.Contains(nameLower, "eks"):
				eksTagAddrs = append(eksTagAddrs, addr)
			default:
				otherAddrs = append(otherAddrs, addr)
			}
		}
		// Rename when all addresses match a single pattern
		if len(bastionAddrs) > 0 && len(otherAddrs) == 0 && len(eksTagAddrs) == 0 {
			g.Service = "Bastion Host"
			g.Label = "Bastion Host"
		} else if len(eksTagAddrs) > 0 && len(otherAddrs) == 0 && len(bastionAddrs) == 0 {
			g.Service = "EKS Autoscaler"
			g.Label = "EKS Autoscaler"
		}
	}
}

func splitLBInSlice(groups []*AggregatedGroup, resByAddr map[string]*parser.NormalizedResource) []*AggregatedGroup {
	var result []*AggregatedGroup
	for _, g := range groups {
		if g.Service != "Load Balancer" {
			result = append(result, g)
			continue
		}
		result = append(result, splitLBGroup(g, resByAddr)...)
	}
	return result
}

func splitLBGroup(g *AggregatedGroup, resByAddr map[string]*parser.NormalizedResource) []*AggregatedGroup {
	// Classify primary aws_lb/aws_alb by internal flag
	type lbInfo struct {
		addr     string
		internal bool
		lbType   string // "application" or "network"
	}

	lbs := make([]lbInfo, 0, len(g.Addresses))
	for _, addr := range g.Addresses {
		r := resByAddr[addr]
		if r == nil {
			continue
		}
		if r.Type != "aws_lb" && r.Type != "aws_alb" {
			continue
		}

		internal := false
		lbType := "application"
		if r.Values != nil {
			if v, ok := r.Values["internal"].(bool); ok {
				internal = v
			}
			if v, ok := r.Values["load_balancer_type"].(string); ok {
				lbType = v
			}
		}
		lbs = append(lbs, lbInfo{addr: addr, internal: internal, lbType: lbType})
	}

	if len(lbs) == 0 {
		return []*AggregatedGroup{g}
	}

	// Check if mixed scope
	hasPublic := false
	hasPrivate := false
	for _, lb := range lbs {
		if lb.internal {
			hasPrivate = true
		} else {
			hasPublic = true
		}
	}

	if !hasPublic || !hasPrivate {
		// All same scope — no split needed, but rename to specific type
		lbType := lbs[0].lbType
		if hasPrivate && !hasPublic {
			// All internal
			svc := lbTypeName(lbType) + " Internal"
			g.Service = svc
			g.Label = svc
		} else if hasPublic && !hasPrivate {
			// All public
			svc := lbTypeName(lbType)
			g.Service = svc
			g.Label = svc
		}
		return []*AggregatedGroup{g}
	}

	// Mixed — split into public and private groups
	// Build module-path sets for matching sub-resources to parent LBs
	pubLBMods := make(map[string]bool)
	privLBMods := make(map[string]bool)
	var publicLBAddrs, privateLBAddrs []string
	publicPrimary, privatePrimary := 0, 0
	pubLBType, privLBType := "application", "application"

	for _, lb := range lbs {
		mod := extractModulePath(lb.addr)
		if lb.internal {
			privateLBAddrs = append(privateLBAddrs, lb.addr)
			privatePrimary++
			privLBType = lb.lbType
			if mod != "" {
				privLBMods[mod] = true
			}
		} else {
			publicLBAddrs = append(publicLBAddrs, lb.addr)
			publicPrimary++
			pubLBType = lb.lbType
			if mod != "" {
				pubLBMods[mod] = true
			}
		}
	}

	// Associate sub-resources by module path
	var pubSubAddrs, privSubAddrs []string
	pubSubCount, privSubCount := 0, 0
	pubSubPrimary, privSubPrimary := 0, 0

	for _, addr := range g.Addresses {
		r := resByAddr[addr]
		if r == nil {
			continue
		}
		if r.Type == "aws_lb" || r.Type == "aws_alb" {
			continue // already classified
		}

		mod := extractModulePath(addr)
		primary := isPrimaryType(r.Type)

		if mod != "" && privLBMods[mod] {
			privSubAddrs = append(privSubAddrs, addr)
			privSubCount++
			if primary {
				privSubPrimary++
			}
		} else {
			pubSubAddrs = append(pubSubAddrs, addr)
			pubSubCount++
			if primary {
				pubSubPrimary++
			}
		}
	}

	var result []*AggregatedGroup

	// Public LB group
	pubService := lbTypeName(pubLBType)
	result = append(result, &AggregatedGroup{
		Service:      pubService,
		Type:         "aws_lb",
		Label:        pubService,
		PrimaryCount: publicPrimary + pubSubPrimary,
		TotalCount:   publicPrimary + pubSubCount,
		Action:       g.Action,
		Addresses:    append(publicLBAddrs, pubSubAddrs...),
		VPCAddress:   g.VPCAddress,
	})

	// Private LB group
	privService := lbTypeName(privLBType) + " Internal"
	result = append(result, &AggregatedGroup{
		Service:      privService,
		Type:         "aws_lb",
		Label:        privService,
		PrimaryCount: privatePrimary + privSubPrimary,
		TotalCount:   privatePrimary + privSubCount,
		Action:       g.Action,
		Addresses:    append(privateLBAddrs, privSubAddrs...),
		VPCAddress:   g.VPCAddress,
	})

	return result
}

func lbTypeName(lbType string) string {
	if lbType == "network" {
		return "NLB"
	}
	return "ALB"
}

// configRefConnectionRules maps resource types to target types that should be
// connected via configRefs instead of inferred rules. Each entry maps
// fromType → []toType. When a fromType resource's configRefs contain a reference
// to a toType resource, a connection is created.
var configRefConnectionRules = map[string][]string{
	"aws_cloudfront_distribution": {"aws_lb", "aws_alb"},
}

// connectionsFromConfigRefs creates connections by scanning plan configuration
// references. This is more precise than inferred rules for resources that
// reference specific targets (e.g., CloudFront → specific ALB via domain_name).
func connectionsFromConfigRefs(cfgRefs map[string][]string, resByAddr map[string]*parser.NormalizedResource) []*Connection {
	var conns []*Connection
	seen := make(map[string]bool) // dedup "from|to"

	for addr, refs := range cfgRefs {
		// Determine resource type from address
		r := resByAddr[addr]
		if r == nil {
			continue
		}
		targetTypes, ok := configRefConnectionRules[r.Type]
		if !ok {
			continue
		}
		targetSet := make(map[string]bool, len(targetTypes))
		for _, t := range targetTypes {
			targetSet[t] = true
		}

		for _, ref := range refs {
			// Strip trailing .id, .arn, .dns_name, etc. to get resource address
			refAddr := ref
			if idx := strings.LastIndex(refAddr, "."); idx > 0 {
				suffix := refAddr[idx+1:]
				if suffix == "id" || suffix == "arn" || suffix == "name" ||
					suffix == "dns_name" || suffix == "domain_name" {
					refAddr = refAddr[:idx]
				}
			}
			target := resByAddr[refAddr]
			if target == nil || !targetSet[target.Type] {
				continue
			}
			key := addr + "|" + refAddr
			if seen[key] {
				continue
			}
			seen[key] = true
			conns = append(conns, &Connection{
				From:  addr,
				To:    refAddr,
				Via:   "origin",
				Label: "origin",
			})
		}
	}
	return conns
}

// SGCrossRef represents a security group cross-reference: one SG rule's owner SG
// references another SG (e.g., ALB SG ingress rule allows traffic from EKS nodes SG).
type SGCrossRef struct {
	OwnerSG string // SG address that owns the rule (security_group_id)
	PeerSG  string // SG address referenced by the rule (referenced_security_group_id)
}

// ExtractSGCrossRefs walks the Terraform configuration to find SG rules that
// reference another security group (cross-SG references). Returns pairs of
// (ownerSG, peerSG) addresses.
func ExtractSGCrossRefs(config parser.Configuration) []SGCrossRef {
	var refs []SGCrossRef
	extractSGCrossRefsFromModule(config.RootModule, "", &refs)
	return refs
}

func extractSGCrossRefsFromModule(mod parser.ConfigModule, prefix string, refs *[]SGCrossRef) {
	for _, r := range mod.Resources {
		var peerField string
		switch r.Type {
		case "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule":
			peerField = "referenced_security_group_id"
		case "aws_security_group_rule":
			peerField = "source_security_group_id"
		default:
			continue
		}

		ownerSG := extractSGRefFromExpr(r.Expressions, "security_group_id")
		peerSG := extractSGRefFromExpr(r.Expressions, peerField)

		if ownerSG != "" && peerSG != "" && ownerSG != peerSG {
			*refs = append(*refs, SGCrossRef{OwnerSG: ownerSG, PeerSG: peerSG})
		}
	}

	for name, call := range mod.ModuleCalls {
		childPrefix := "module." + name
		if prefix != "" {
			childPrefix = prefix + "." + childPrefix
		}
		if call.Module != nil {
			extractSGCrossRefsFromModule(*call.Module, childPrefix, refs)
		}
	}
}

// extractSGRefFromExpr extracts an aws_security_group.xxx address from a field's
// references list. Returns the bare address (without .id suffix).
func extractSGRefFromExpr(expressions map[string]interface{}, field string) string {
	val, ok := expressions[field]
	if !ok {
		return ""
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return ""
	}
	refsList, ok := m["references"]
	if !ok {
		return ""
	}
	refList, ok := refsList.([]interface{})
	if !ok {
		return ""
	}
	for _, r := range refList {
		s, ok := r.(string)
		if !ok {
			continue
		}
		// Match aws_security_group.xxx (without .id/.arn suffix)
		if strings.HasPrefix(s, "aws_security_group.") && !strings.HasSuffix(s, ".id") && !strings.HasSuffix(s, ".arn") {
			return s
		}
	}
	return ""
}

// fixLBTargetConnections repairs inferred connections after Load Balancer groups
// have been split into public/internal variants. Edge-scoped sources (Route 53,
// CloudFront) are remapped to target public LBs. VPC Link sources are remapped
// to target internal LBs.
func fixLBTargetConnections(conns []*Connection, layers []*TopoLayer, resByAddr map[string]*parser.NormalizedResource) {
	// Find primary LB addresses in each scope after split
	var publicLBAddrs []string
	var internalLBAddrs []string

	for _, layer := range layers {
		// Check both Groups and ComputeGroups (LBs may be in either)
		allGroups := make([]*AggregatedGroup, 0, len(layer.Groups)+len(layer.ComputeGroups))
		allGroups = append(allGroups, layer.Groups...)
		allGroups = append(allGroups, layer.ComputeGroups...)
		for _, g := range allGroups {
			if g.Type != "aws_lb" {
				continue
			}
			for _, addr := range g.Addresses {
				r := resByAddr[addr]
				if r == nil || (r.Type != "aws_lb" && r.Type != "aws_alb") {
					continue
				}
				if strings.Contains(g.Service, "Internal") {
					internalLBAddrs = append(internalLBAddrs, addr)
				} else {
					publicLBAddrs = append(publicLBAddrs, addr)
				}
			}
		}
	}

	// Only fix when both public and internal LBs exist (split happened)
	if len(publicLBAddrs) == 0 || len(internalLBAddrs) == 0 {
		return
	}

	internalSet := make(map[string]bool)
	for _, addr := range internalLBAddrs {
		internalSet[addr] = true
	}
	publicSet := make(map[string]bool)
	for _, addr := range publicLBAddrs {
		publicSet[addr] = true
	}

	for _, c := range conns {
		fromR := resByAddr[c.From]
		if fromR == nil {
			continue
		}

		fromSvc := getServiceGroup(fromR.Type)
		fromScope := getServiceScope(fromSvc)

		// Edge source targeting internal LB → remap to public LB
		if fromScope == "edge" && internalSet[c.To] {
			c.To = publicLBAddrs[0]
		}

		// VPC Link targeting public LB → remap to internal LB
		if (fromR.Type == "aws_api_gateway_vpc_link" || fromR.Type == "aws_apigatewayv2_vpc_link") && publicSet[c.To] {
			c.To = internalLBAddrs[0]
		}
	}
}
