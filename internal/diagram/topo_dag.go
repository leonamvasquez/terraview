package diagram

import "strings"

// ServiceNode represents a service group in the dependency DAG.
type ServiceNode struct {
	ID          string          // service group label (or VPC-qualified ID for multi-VPC)
	Service     string          // clean service name (e.g., "EKS Cluster")
	Label       string          // display label with counts
	Action      string          // dominant action
	Scope       string          // "edge", "vpc", or "global"
	SubnetTier  string          // "public", "private_app", "private_data", "private", "vpc_level"
	VPCAddr     string          // VPC address this node belongs to (multi-VPC support)
	DepsOut     []string        // IDs this node points TO (downstream)
	DepsIn      []string        // IDs that point TO this node (upstream)
	SGRefDeps   []string        // IDs connected via SG cross-reference (dotted edges)
	BiDeps      map[string]bool // node IDs with bidirectional SG relationship
	Addresses   []string        // resource addresses in this group
	Annotations []string        // coupled services shown as tags: [WAF], [ACM]
}

// serviceScope determines where a service renders in the diagram.
// "edge"   → Zone 1 (above VPC)
// "vpc"    → Zone 2 (inside VPC border)
// "global" → Zone 3 (below VPC, grid)
var serviceScope = map[string]string{
	// Edge (Zone 1)
	"Route 53":   "edge",
	"CloudFront": "edge",

	// VPC-bound (Zone 2) — Networking
	"VPC":                  "vpc",
	"Subnet":               "vpc",
	"Internet Gateway":     "vpc",
	"NAT Gateway":          "vpc",
	"Elastic IP":           "vpc",
	"Security Group":       "vpc",
	"Route Table":          "vpc",
	"VPC Endpoint":         "vpc",
	"VPC Endpoint Service": "vpc",
	"VPC Peering":          "vpc",
	"VPN":                  "vpc",
	"Network Firewall":     "vpc",
	"Transit Gateway":      "vpc",
	"VPC Flow Log":         "vpc",
	"RDS Subnet Group":     "vpc",
	"ElastiCache Subnet":   "vpc",
	"Network ACL":          "vpc",
	"ENI":                  "vpc",

	// VPC-bound — Compute
	"EKS Cluster":       "vpc",
	"EKS Node Group":    "vpc",
	"EKS Addon":         "vpc",
	"EKS Fargate":       "vpc",
	"ECS Cluster":       "vpc",
	"ECS":               "vpc",
	"Lambda":            "vpc",
	"Auto Scaling":      "vpc",
	"Launch Template":   "vpc",
	"EC2 Instance":      "vpc",
	"Service Discovery": "vpc",
	"Bastion Host":      "vpc",
	"EKS Autoscaler":    "vpc",

	// VPC-bound — Data
	"Aurora RDS":       "vpc",
	"RDS Instance":     "vpc",
	"RDS Proxy":        "vpc",
	"ElastiCache":      "vpc",
	"DynamoDB":         "vpc",
	"OpenSearch":       "vpc",
	"Kinesis":          "vpc",
	"Kinesis Firehose": "vpc",
	"EFS":              "vpc",

	// VPC-bound — Load Balancing
	"Load Balancer": "vpc",
	"ALB":           "vpc",
	"NLB":           "vpc",
	"ALB Internal":  "vpc",
	"NLB Internal":  "vpc",

	// Edge — API management (AWS-managed, not VPC-bound)
	"API Gateway": "edge",

	// Global/Regional (Zone 3)
	"CloudWatch":          "global",
	"CloudTrail":          "global",
	"AWS Config":          "global",
	"CodePipeline":        "global",
	"CodeBuild":           "global",
	"CodeCommit":          "global",
	"CodeCommit Repo":     "global",
	"ECR":                 "global",
	"SNS":                 "global",
	"SQS":                 "global",
	"S3":                  "global",
	"IAM":                 "global",
	"KMS":                 "global",
	"Secrets Manager":     "global",
	"SSM Parameter Store": "global",
	"SSM":                 "global",
	"GuardDuty":           "global",
	"SecurityHub":         "global",
	"Macie":               "global",
	"Backup":              "global",
	"Prometheus":          "global",
	"Grafana":             "global",
	"X-Ray Sampling":      "global",
	"aws_xray_group":      "global",
	"Synthetics":          "global",
	"EventBridge":         "global",
	"EC2 Key Pair":        "global",
	"AMI":                 "global",
	"EBS Volume":          "vpc",
	"Step Functions":      "global",
	"CodeDeploy":          "global",
}

// getServiceScope returns the rendering zone for a service.
func getServiceScope(service string) string {
	if scope, ok := serviceScope[service]; ok {
		return scope
	}
	return "global" // unknown services default to global grid
}

// skipFromDAGBoxes are VPC networking services rendered in the network section, not as boxes.
var skipFromDAGBoxes = map[string]bool{
	"VPC":                true,
	"Subnet":             true,
	"Security Group":     true,
	"Route Table":        true,
	"Network ACL":        true,
	"VPC Endpoint":       true,
	"VPC Flow Log":       true,
	"Internet Gateway":   true,
	"NAT Gateway":        true,
	"ENI":                true,
	"Elastic IP":         true,
	"Transit Gateway":    true,
	"VPC Peering":        true,
	"PrivateLink":        true,
	"VPN":                true,
	"RDS Subnet Group":   true,
	"ElastiCache Subnet": true,
}

// distributionBarServices are hub services rendered as wide thin bars when 2+ outbound.
var distributionBarServices = map[string]bool{
	"Load Balancer": true,
	"Route 53":      true,
	"API Gateway":   true,
	"CloudFront":    true,
}

// annotationServices are coupled services rendered as tags on their targets,
// not as separate boxes in the DAG. WAF and ACM protect other services —
// they are not steps in the traffic flow.
var annotationServices = map[string]bool{
	"WAF": true,
	"ACM": true,
}

// annotationTargets maps annotation services to their potential target services.
// WAF attaches to ALBs and CloudFront. ACM provides certificates for the same.
var annotationTargets = map[string][]string{
	"WAF": {"CloudFront", "Load Balancer", "ALB", "ALB Internal"},
	"ACM": {"CloudFront", "Load Balancer", "ALB", "ALB Internal"},
}

// nestedServiceMap maps parent service → child services for compound rendering.
var nestedServiceMap = map[string][]string{
	"EKS Cluster":  {"EKS Node Group", "EKS Addon", "EKS Fargate"},
	"ECS Cluster":  {"ECS"},
	"Aurora RDS":   {"RDS Instance", "RDS Proxy"},
	"Auto Scaling": {"Launch Template"},
}

// CompoundNode represents a parent service with nested child service boxes.
type CompoundNode struct {
	ParentID     string
	ParentLabel  string
	ParentAction string
	Children     []*CompoundChild
}

// CompoundChild is a sub-service box inside a compound node.
type CompoundChild struct {
	ID     string
	Label  string
	Action string
	W      int
	H      int
	Lines  []string
}

// buildServiceDAG converts a TopoResult into a DAG of ServiceNode.
func buildServiceDAG(result *TopoResult) map[string]*ServiceNode {
	nodes := make(map[string]*ServiceNode)

	placements := result.SubnetPlacements
	if placements == nil {
		placements = make(map[string]string)
	}

	// Detect which annotation services exist in the plan
	annPresent := make(map[string]bool) // annotation service → exists
	for _, layer := range result.Layers {
		for _, g := range layer.Groups {
			if annotationServices[g.Service] {
				annPresent[g.Service] = true
			}
		}
	}

	for _, layer := range result.Layers {
		for _, g := range layer.Groups {
			if skipFromDAGBoxes[g.Service] || annotationServices[g.Service] {
				continue
			}
			// Skip empty groups (ghost box fix)
			if g.Label == "" {
				continue
			}
			addNodeFromGroup(nodes, g, placements)
		}
		for _, g := range layer.ComputeGroups {
			if g.Label == "" {
				continue
			}
			addNodeFromGroup(nodes, g, placements)
		}
		for _, g := range layer.DataGroups {
			if g.Label == "" {
				continue
			}
			addNodeFromGroup(nodes, g, placements)
		}
	}

	// Apply annotations to target nodes
	// WAF: use configRefs to find actual wafv2_web_acl_association targets per-resource
	// ACM: all-or-nothing (certificates are broadly associated)
	if annPresent["WAF"] {
		applyWAFAnnotations(nodes, result.ConfigRefs)
	}
	if annPresent["ACM"] {
		targets := annotationTargets["ACM"]
		for _, node := range nodes {
			for _, targetSvc := range targets {
				if node.Service == targetSvc {
					node.Annotations = append(node.Annotations, "[ACM]")
					break
				}
			}
		}
	}
	// Sort annotations for deterministic output
	for _, node := range nodes {
		sortStrings(node.Annotations)
	}

	// Wire edges from connections — only between DAG nodes (edge + vpc)
	for _, c := range result.Connections {
		from := nodes[c.From]
		to := nodes[c.To]
		if from == nil || to == nil {
			continue
		}
		// Only wire edges between edge/vpc nodes (not global)
		if from.Scope == "global" || to.Scope == "global" {
			continue
		}
		if c.From == c.To {
			continue
		}
		if !containsStr(from.DepsOut, c.To) {
			from.DepsOut = append(from.DepsOut, c.To)
		}
		if !containsStr(to.DepsIn, c.From) {
			to.DepsIn = append(to.DepsIn, c.From)
		}
	}

	// Wire SG cross-reference edges (visual-only, don't affect topology ordering)
	wireSGRefEdges(nodes, result.SGCrossRefs, result.ConfigRefs)

	return nodes
}

// wireSGRefEdges maps SG cross-references to ServiceNode pairs and adds
// SGRefDeps edges. Uses configRefs to find which node "owns" each security group.
func wireSGRefEdges(nodes map[string]*ServiceNode, crossRefs []SGCrossRef, cfgRefs map[string][]string) {
	if len(crossRefs) == 0 || cfgRefs == nil {
		return
	}

	// Build resource address → node mapping
	addrToNode := make(map[string]*ServiceNode)
	for _, node := range nodes {
		for _, addr := range node.Addresses {
			addrToNode[addr] = node
		}
	}

	// Build SG address → owner node mapping.
	// Strategy 1: For each node's resources, check configRefs for SG references.
	sgToNode := make(map[string]*ServiceNode)
	for _, node := range nodes {
		for _, addr := range node.Addresses {
			refs := cfgRefs[addr]
			for _, ref := range refs {
				refAddr := ref
				if idx := strings.LastIndex(refAddr, "."); idx > 0 {
					suffix := refAddr[idx+1:]
					if suffix == "id" || suffix == "arn" {
						refAddr = refAddr[:idx]
					}
				}
				if strings.HasPrefix(refAddr, "aws_security_group.") {
					if _, exists := sgToNode[refAddr]; !exists {
						sgToNode[refAddr] = node
					}
				}
			}
		}
	}

	// Strategy 2: Name-based fallback for unmapped SGs.
	// Extract service hint from SG name and match to nodes in the same VPC.
	sgNameToService := map[string][]string{
		"eks_node":   {"EKS Node Group", "EKS Cluster"},
		"eks":        {"EKS Cluster"},
		"nlb":        {"NLB", "NLB Internal", "Load Balancer"},
		"alb":        {"ALB", "ALB Internal", "Load Balancer"},
		"ecs":        {"ECS", "ECS Cluster"},
		"efs":        {"EFS"},
		"lambda":     {"Lambda"},
		"rds":        {"Aurora RDS", "RDS Instance", "RDS Cluster"},
		"redis":      {"ElastiCache"},
		"memcached":  {"ElastiCache"},
		"bastion":    {"Bastion Host", "Auto Scaling"},
		"opensearch": {"OpenSearch"},
	}

	// Collect all SGs that need fallback mapping
	unmappedSGs := make(map[string]bool)
	for _, cr := range crossRefs {
		if sgToNode[cr.OwnerSG] == nil {
			unmappedSGs[cr.OwnerSG] = true
		}
		if sgToNode[cr.PeerSG] == nil {
			unmappedSGs[cr.PeerSG] = true
		}
	}

	// Find VPC for each unmapped SG via its own configRefs
	for sgAddr := range unmappedSGs {
		if sgToNode[sgAddr] != nil {
			continue
		}
		// Extract name part: aws_security_group.prod_eks_nodes → "prod_eks_nodes"
		sgName := sgAddr[len("aws_security_group."):]

		// Find VPC from SG's configRefs
		sgVPC := ""
		for _, ref := range cfgRefs[sgAddr] {
			if strings.HasPrefix(ref, "aws_vpc.") && !strings.HasSuffix(ref, ".id") {
				sgVPC = ref
				break
			}
			if strings.HasPrefix(ref, "aws_vpc.") && strings.HasSuffix(ref, ".id") {
				sgVPC = ref[:len(ref)-3]
				break
			}
		}

		// Try matching SG name hints to service nodes
		for hint, services := range sgNameToService {
			if !strings.Contains(sgName, hint) {
				continue
			}
			for _, svc := range services {
				for _, node := range nodes {
					if node.Service != svc {
						continue
					}
					// Match VPC if known
					if sgVPC != "" && node.VPCAddr != "" && node.VPCAddr != sgVPC {
						continue
					}
					sgToNode[sgAddr] = node
					break
				}
				if sgToNode[sgAddr] != nil {
					break
				}
			}
			if sgToNode[sgAddr] != nil {
				break
			}
		}
	}

	// Build directed SG pair set to detect bidirectional relationships
	type sgPair struct{ owner, peer string }
	directedPairs := make(map[sgPair]bool)
	for _, cr := range crossRefs {
		ownerNode := sgToNode[cr.OwnerSG]
		peerNode := sgToNode[cr.PeerSG]
		if ownerNode == nil || peerNode == nil || ownerNode == peerNode {
			continue
		}
		if ownerNode.Scope == "global" || peerNode.Scope == "global" {
			continue
		}
		directedPairs[sgPair{ownerNode.ID, peerNode.ID}] = true
	}

	// Create SGRefDeps from cross-ref pairs
	type edgeKey struct{ a, b string }
	seen := make(map[edgeKey]bool)

	for p := range directedPairs {
		key := edgeKey{p.owner, p.peer}
		rev := edgeKey{p.peer, p.owner}
		if seen[key] || seen[rev] {
			continue
		}
		seen[key] = true

		ownerNode := nodes[p.owner]
		peerNode := nodes[p.peer]
		if ownerNode == nil || peerNode == nil {
			continue
		}
		if !containsStr(ownerNode.SGRefDeps, peerNode.ID) {
			ownerNode.SGRefDeps = append(ownerNode.SGRefDeps, peerNode.ID)
		}

		// Detect bidirectional: both A→B and B→A exist
		if directedPairs[sgPair{p.peer, p.owner}] {
			if ownerNode.BiDeps == nil {
				ownerNode.BiDeps = make(map[string]bool)
			}
			ownerNode.BiDeps[peerNode.ID] = true
			if peerNode.BiDeps == nil {
				peerNode.BiDeps = make(map[string]bool)
			}
			peerNode.BiDeps[ownerNode.ID] = true
		}
	}
}

func addNodeFromGroup(nodes map[string]*ServiceNode, g *AggregatedGroup, placements map[string]string) {
	// Use VPC-qualified ID when group belongs to a specific VPC (multi-VPC)
	id := g.Label
	if g.VPCAddress != "" {
		id = g.VPCAddress + "|" + g.Label
	}
	if _, exists := nodes[id]; exists {
		return
	}
	// Use Service as placement key (Label changes after formatting)
	tier := placements[g.Service]
	if tier == "" {
		tier = getDefaultSubnetPlacement(g.Service)
	}
	scope := getServiceScope(g.Service)
	// Override scope when placement indicates non-VPC resource
	if tier == "global" {
		scope = "global"
	}
	nodes[id] = &ServiceNode{
		ID:         id,
		Service:    g.Service,
		Label:      g.Label,
		Action:     g.Action,
		Scope:      scope,
		SubnetTier: tier,
		VPCAddr:    g.VPCAddress,
		Addresses:  g.Addresses,
	}
}

// applyWAFAnnotations uses configRefs to find actual wafv2_web_acl_association
// targets and applies [WAF] only to nodes whose resources are real association targets.
// This avoids false positives from type-coexistence inference.
func applyWAFAnnotations(nodes map[string]*ServiceNode, configRefs map[string][]string) {
	if configRefs == nil {
		return
	}

	// Build resource address → node mapping
	addrToNode := make(map[string]*ServiceNode)
	for _, node := range nodes {
		for _, addr := range node.Addresses {
			addrToNode[addr] = node
		}
	}

	// WAF association types that link WAF ACLs to target resources
	wafAssocPrefix := "aws_wafv2_web_acl_association."

	// For each WAF association, find its target via configRefs
	targetNodes := make(map[*ServiceNode]bool)
	for addr, refs := range configRefs {
		if !strings.HasPrefix(addr, wafAssocPrefix) {
			continue
		}
		// Check refs for known target resource addresses (LBs, CloudFront, etc.)
		for _, ref := range refs {
			// Strip trailing .id, .arn, .name suffixes to get the resource address
			refAddr := ref
			if idx := strings.LastIndex(refAddr, "."); idx > 0 {
				suffix := refAddr[idx+1:]
				if suffix == "id" || suffix == "arn" || suffix == "name" {
					refAddr = refAddr[:idx]
				}
			}
			if node := addrToNode[refAddr]; node != nil {
				// Only tag annotation target services (CloudFront, ALB, etc.)
				for _, targetSvc := range annotationTargets["WAF"] {
					if node.Service == targetSvc {
						targetNodes[node] = true
						break
					}
				}
			}
		}
	}

	for node := range targetNodes {
		node.Annotations = append(node.Annotations, "[WAF]")
	}
}

// breakBidirectionalEdges removes reverse edges that create 2-node cycles.
// When A→B and B→A both exist, keep only the edge from the "earlier" node
// in the architecture's traffic flow order (edge → public → private → data).
// This prevents configuration-dependency back-edges (e.g., ECS referencing
// an ALB target group) from creating visual cycles in the diagram.
func breakBidirectionalEdges(nodes map[string]*ServiceNode) {
	for id, n := range nodes {
		var cleanOut []string
		for _, depID := range n.DepsOut {
			dep := nodes[depID]
			if dep == nil {
				cleanOut = append(cleanOut, depID)
				continue
			}
			// Check if reverse edge exists (dep→id)
			if containsStr(dep.DepsOut, id) {
				// Both directions exist — keep only the "downward" one
				// (from earlier tier to later tier)
				if tierPriority(n) <= tierPriority(dep) {
					// This node is earlier or same tier: keep this edge
					cleanOut = append(cleanOut, depID)
				}
				// Otherwise: skip (the reverse edge dep→id will be kept)
			} else {
				cleanOut = append(cleanOut, depID)
			}
		}
		n.DepsOut = cleanOut
	}
	// Rebuild DepsIn from the cleaned DepsOut
	for _, n := range nodes {
		n.DepsIn = nil
	}
	for id, n := range nodes {
		for _, depID := range n.DepsOut {
			if dep := nodes[depID]; dep != nil {
				dep.DepsIn = append(dep.DepsIn, id)
			}
		}
	}
}

// tierPriority returns a numeric priority for traffic flow ordering.
// Lower values = earlier in the flow (closer to the user/internet).
func tierPriority(n *ServiceNode) int {
	if n.Scope == "edge" {
		return 0
	}
	switch n.SubnetTier {
	case "public":
		return 1
	case "private_app":
		return 2
	case "private_data":
		return 3
	case "private":
		return 2 // treat generic private as app-tier
	case "vpc_level":
		return 1
	}
	return 4
}

// separateByScope splits nodes into edge, vpc (DAG participants), and global.
func separateByScope(nodes map[string]*ServiceNode) (dagNodes map[string]*ServiceNode, globalNodes []*ServiceNode) {
	dagNodes = make(map[string]*ServiceNode)
	for id, n := range nodes {
		if n.Scope == "global" {
			globalNodes = append(globalNodes, n)
		} else {
			dagNodes[id] = n
		}
	}
	// Sort global nodes alphabetically
	for i := 0; i < len(globalNodes); i++ {
		for j := i + 1; j < len(globalNodes); j++ {
			if globalNodes[j].ID < globalNodes[i].ID {
				globalNodes[i], globalNodes[j] = globalNodes[j], globalNodes[i]
			}
		}
	}
	return
}

// buildCompoundNodes detects parent-child service groups and merges them.
// Children are removed from the nodes map; their connections are remapped to the parent.
func buildCompoundNodes(nodes map[string]*ServiceNode) map[string]*CompoundNode {
	compounds := make(map[string]*CompoundNode)
	consumed := make(map[string]bool) // track consumed child IDs globally

	for parentService, childServices := range nestedServiceMap {
		// Find ALL parent nodes for this service (one per VPC in multi-VPC)
		var parentIDs []string
		for id, n := range nodes {
			if n.Service == parentService && n.Scope != "global" {
				parentIDs = append(parentIDs, id)
			}
		}
		sortStrings(parentIDs)

		for _, parentID := range parentIDs {
			parentNode := nodes[parentID]
			if parentNode == nil {
				continue
			}

			// Find child nodes: prefer exact VPCAddr match, fallback to empty
			var children []*CompoundChild
			childIDs := make(map[string]bool)
			for _, childSvc := range childServices {
				var bestID string
				for id, n := range nodes {
					if consumed[id] || n.Service != childSvc || n.Scope == "global" {
						continue
					}
					if n.VPCAddr == parentNode.VPCAddr {
						bestID = id // exact match — use immediately
						break
					}
					if bestID == "" && (n.VPCAddr == "" || parentNode.VPCAddr == "") {
						bestID = id // fallback candidate
					}
				}
				if bestID != "" {
					n := nodes[bestID]
					w, h, lines := calcBoxSize(n)
					children = append(children, &CompoundChild{
						ID:     bestID,
						Label:  n.Label,
						Action: n.Action,
						W:      w,
						H:      h,
						Lines:  lines,
					})
					childIDs[bestID] = true
					consumed[bestID] = true
				}
			}

			if len(children) == 0 {
				continue
			}

			// Remap external connections from children to parent
			for cid := range childIDs {
				child := nodes[cid]
				for _, depID := range child.DepsOut {
					if depID == parentID || childIDs[depID] {
						continue
					}
					if !containsStr(parentNode.DepsOut, depID) {
						parentNode.DepsOut = append(parentNode.DepsOut, depID)
					}
				}
				for _, srcID := range child.DepsIn {
					if srcID == parentID || childIDs[srcID] {
						continue
					}
					if !containsStr(parentNode.DepsIn, srcID) {
						parentNode.DepsIn = append(parentNode.DepsIn, srcID)
					}
					if srcNode, ok := nodes[srcID]; ok {
						for i, d := range srcNode.DepsOut {
							if d == cid {
								srcNode.DepsOut[i] = parentID
							}
						}
					}
				}
				// Remap SG ref deps and bidirectional deps from children to parent
				for _, sgDep := range child.SGRefDeps {
					if sgDep == parentID || childIDs[sgDep] {
						continue
					}
					if !containsStr(parentNode.SGRefDeps, sgDep) {
						parentNode.SGRefDeps = append(parentNode.SGRefDeps, sgDep)
					}
				}
				for dep := range child.BiDeps {
					if dep == parentID || childIDs[dep] {
						continue
					}
					if parentNode.BiDeps == nil {
						parentNode.BiDeps = make(map[string]bool)
					}
					parentNode.BiDeps[dep] = true
				}
				for _, depID := range child.DepsOut {
					if depNode, ok := nodes[depID]; ok {
						for i, d := range depNode.DepsIn {
							if d == cid {
								depNode.DepsIn[i] = parentID
							}
						}
					}
				}
				// Remap SGRefDeps and BiDeps in other nodes that point to consumed child
				for _, n := range nodes {
					for i, d := range n.SGRefDeps {
						if d == cid {
							n.SGRefDeps[i] = parentID
						}
					}
					if n.BiDeps[cid] {
						delete(n.BiDeps, cid)
						if n.BiDeps == nil {
							n.BiDeps = make(map[string]bool)
						}
						n.BiDeps[parentID] = true
					}
				}
				delete(nodes, cid)
			}

			// Remove internal connections from parent
			var cleanOut []string
			for _, d := range parentNode.DepsOut {
				if !childIDs[d] {
					cleanOut = append(cleanOut, d)
				}
			}
			parentNode.DepsOut = cleanOut

			var cleanIn []string
			for _, d := range parentNode.DepsIn {
				if !childIDs[d] {
					cleanIn = append(cleanIn, d)
				}
			}
			parentNode.DepsIn = cleanIn

			compounds[parentID] = &CompoundNode{
				ParentID:     parentID,
				ParentLabel:  parentNode.Label,
				ParentAction: parentNode.Action,
				Children:     children,
			}
		}
	}

	// Deduplicate DepsOut/DepsIn for all nodes — compound remapping may
	// have replaced child IDs with parent IDs, creating duplicates when a
	// node already had a direct edge to the parent (e.g., ALB→ECS Cluster
	// and ALB→ECS both become ALB→ECS Cluster after ECS is consumed).
	for _, n := range nodes {
		n.DepsOut = deduplicateStrings(n.DepsOut)
		n.DepsIn = deduplicateStrings(n.DepsIn)
		n.SGRefDeps = deduplicateStrings(n.SGRefDeps)
	}

	return compounds
}

// deduplicateStrings removes duplicate entries from a string slice, preserving order.
func deduplicateStrings(s []string) []string {
	if len(s) <= 1 {
		return s
	}
	seen := make(map[string]bool, len(s))
	j := 0
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			s[j] = v
			j++
		}
	}
	return s[:j]
}

// calcCompoundSize computes outer box dimensions for a compound node.
func calcCompoundSize(parentLabel string, children []*CompoundChild) (int, int) {
	innerWidth := 0
	maxChildH := 0
	for i, c := range children {
		if i > 0 {
			innerWidth += 2
		}
		innerWidth += c.W
		if c.H > maxChildH {
			maxChildH = c.H
		}
	}

	w := innerWidth + 4 // outer margins (2 per side)
	h := maxChildH + 5  // title row + blank + inner boxes + blank + bottom border

	if labelW := runeLen(parentLabel) + 4; labelW > w {
		w = labelW
	}
	if w < minBoxWidth {
		w = minBoxWidth
	}

	return w, h
}

// isDistributionBar checks if a node should render as a wide thin bar.
// Only applies to edge-scoped services — VPC services render as regular boxes inside subnet containers.
func isDistributionBar(n *ServiceNode) bool {
	if n.Scope != "edge" {
		return false
	}
	return distributionBarServices[n.Service] && len(n.DepsOut) >= 2
}

// isDataService returns true if the node represents a data-tier service
// (database, cache) that inherently involves both read and write access.
func isDataService(n *ServiceNode) bool {
	if n == nil {
		return false
	}
	switch n.Service {
	case "Aurora RDS", "RDS Instance", "RDS Cluster", "RDS Proxy",
		"ElastiCache", "DynamoDB", "OpenSearch", "EFS":
		return true
	}
	return false
}

// isComputeService returns true if the node represents a compute workload
// that routes outbound traffic through a NAT Gateway.
func isComputeService(n *ServiceNode) bool {
	if n == nil {
		return false
	}
	switch n.Service {
	case "ECS Cluster", "EKS Cluster", "Lambda", "Auto Scaling",
		"EC2", "Bastion Host":
		return true
	}
	return false
}

// topoSortLevels performs Kahn's algorithm on DAG nodes (edge + vpc).
func topoSortLevels(nodes map[string]*ServiceNode) [][]string {
	active := make(map[string]bool)
	for id := range nodes {
		active[id] = true
	}

	// Find nodes with edges (either in or out)
	hasEdge := make(map[string]bool)
	for id, n := range nodes {
		if !active[id] {
			continue
		}
		if len(n.DepsIn) > 0 || len(n.DepsOut) > 0 {
			hasEdge[id] = true
		}
	}

	// Run Kahn's on connected nodes
	inDeg := make(map[string]int)
	for id := range hasEdge {
		inDeg[id] = 0
	}
	for id := range hasEdge {
		n := nodes[id]
		for _, dep := range n.DepsOut {
			if hasEdge[dep] {
				inDeg[dep]++
			}
		}
	}

	var queue []string
	for id := range hasEdge {
		if inDeg[id] == 0 {
			queue = append(queue, id)
		}
	}
	sortStrings(queue)

	var levels [][]string
	for len(queue) > 0 {
		levels = append(levels, queue)
		var next []string
		for _, id := range queue {
			for _, dep := range nodes[id].DepsOut {
				if !hasEdge[dep] {
					continue
				}
				inDeg[dep]--
				if inDeg[dep] == 0 {
					next = append(next, dep)
				}
			}
		}
		sortStrings(next)
		queue = next
	}

	// Handle cycle participants
	placed := make(map[string]bool)
	for _, level := range levels {
		for _, id := range level {
			placed[id] = true
		}
	}
	var cycleNodes []string
	for id := range hasEdge {
		if !placed[id] {
			cycleNodes = append(cycleNodes, id)
		}
	}
	if len(cycleNodes) > 0 {
		sortStrings(cycleNodes)
		levels = append(levels, cycleNodes)
		for _, id := range cycleNodes {
			placed[id] = true
		}
	}

	// Place disconnected nodes by scope
	var disconnectedEdge []string
	var disconnectedVPC []string

	for id := range active {
		if placed[id] {
			continue
		}
		n := nodes[id]
		if n.Scope == "edge" {
			disconnectedEdge = append(disconnectedEdge, id)
		} else {
			disconnectedVPC = append(disconnectedVPC, id)
		}
	}

	if len(disconnectedEdge) > 0 {
		sortStrings(disconnectedEdge)
		levels = append(levels, disconnectedEdge)
	}
	if len(disconnectedVPC) > 0 {
		sortStrings(disconnectedVPC)
		levels = append(levels, disconnectedVPC)
	}

	return levels
}

// isVPCNode checks if a node belongs inside the VPC container.
func isVPCNode(n *ServiceNode) bool {
	return n.Scope == "vpc"
}

// getVPCNodeIDs returns IDs of nodes that belong inside the VPC container.
func getVPCNodeIDs(nodes map[string]*ServiceNode) map[string]bool {
	m := make(map[string]bool)
	for id, n := range nodes {
		if isVPCNode(n) {
			m[id] = true
		}
	}
	return m
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
