package diagram

import (
	"fmt"
	"strings"
)

const (
	canvasDefaultWidth = 120
	boxPadding         = 2 // internal horizontal padding per side
	boxGapH            = 3 // horizontal gap between boxes in same level
	levelGapV          = 3 // vertical gap between levels (for arrows)
	vpcPadX            = 3 // VPC border horizontal inset
	vpcPadY            = 1 // VPC border vertical padding
	minBoxWidth        = 16
	internetLabel      = "Internet / Users"
)

// BoxPos holds the computed position and dimensions of a box on the canvas.
type BoxPos struct {
	NodeID           string
	X                int // left edge
	Y                int // top edge
	W                int // width
	H                int // height
	CenterX          int // center X for arrow connections
	Lines            []string
	Action           string           // dominant action (create, update, replace, mixed)
	IsDistBar        bool             // render as distribution bar
	IsCompound       bool             // render as compound box with inner boxes
	CompoundTitle    string           // parent label for compound rendering
	CompoundChildren []*CompoundChild // inner boxes for compound rendering
}

// ArrowDef describes an arrow to draw between two boxes.
type ArrowDef struct {
	FromID        string
	ToID          string
	FromX         int
	FromY         int
	ToX           int
	ToY           int
	Bidirectional bool // render ◄──► instead of ──►
}

// SubnetContainer holds layout info for a subnet tier box inside the VPC.
type SubnetContainer struct {
	Tier        string
	Title       string
	X, Y, W, H  int
	InfraLabels []string // IGW, NAT, EIP labels (public tier only)
	NodeIDs     []string // service node IDs inside this container
}

// LayoutResult holds all computed positions and arrows.
type LayoutResult struct {
	Boxes            map[string]*BoxPos
	Arrows           []ArrowDef
	DashedArrows     []ArrowDef      // upward dashed arrows (NAT GW outbound)
	DottedArrows     []ArrowDef      // dotted arrows (SG cross-references)
	VPCRects         []*VPCRect      // one per VPC (multi-VPC support)
	NetworkSection   *NetworkSection // legacy, kept for fallback
	SubnetContainers []*SubnetContainer
	GlobalGrid       *GlobalGridResult
	TotalHeight      int
	TotalWidth       int
	Chains           []*FlowChain   // flow chains for column-based layout (nil when <=1)
	NodeToChain      map[string]int // nodeID → chain index
}

// VPCRect defines the VPC container boundary.
type VPCRect struct {
	X, Y, W, H     int
	Title          string
	NetworkSummary string
	SubnetLine     string
}

// SubnetBoxInfo describes a subnet tier box inside the VPC.
type SubnetBoxInfo struct {
	Tier        string // "public", "private_app", "private_data", "private"
	Count       int
	X, Y, W, H  int
	InnerLabels []string // inner components (e.g., "IGW", "NAT (2)")
}

// NetworkSection holds the layout of subnet boxes and utility bar inside VPC.
type NetworkSection struct {
	SubnetBoxes []*SubnetBoxInfo
	UtilBar     *BoxPos
	Height      int
}

// computeMinCanvasWidth determines the minimum canvas width needed to fit all content.
func computeMinCanvasWidth(
	levels [][]string,
	dagNodes map[string]*ServiceNode,
	compounds map[string]*CompoundNode,
	vpcNodeIDs map[string]bool,
	globalNodes []*ServiceNode,
	title string,
) int {
	minW := 80

	// Title needs room
	if tw := runeLen(title) + 4; tw > minW {
		minW = tw
	}

	// Internet label
	if iw := runeLen(internetLabel) + 8; iw > minW {
		minW = iw
	}

	// Each level: compute width needed.
	// Edge nodes are placed in a single row, so sum their widths.
	// VPC nodes are placed inside subnet containers that wrap into rows,
	// so we only need to fit the widest individual box (or pair of small boxes).
	maxVPCBoxW := 0
	for _, level := range levels {
		edgeW := 0
		edgeCount := 0

		for _, id := range level {
			n := dagNodes[id]
			if n == nil {
				continue
			}
			var w int
			if cn, ok := compounds[id]; ok {
				w, _ = calcCompoundSize(cn.ParentLabel, cn.Children)
			} else {
				w, _, _ = calcBoxSize(n)
			}

			if vpcNodeIDs[id] {
				// Track widest individual VPC box (layoutTierContainer wraps)
				if w > maxVPCBoxW {
					maxVPCBoxW = w
				}
			} else {
				if edgeCount > 0 {
					edgeW += boxGapH
				}
				edgeW += w
				edgeCount++
			}
		}

		// Edge width (no VPC padding)
		if edgeNeeded := edgeW + 4; edgeNeeded > minW {
			minW = edgeNeeded
		}
	}

	// VPC width: based on widest individual box + room for a second box + padding.
	// layoutTierContainer wraps rows, so we allow ~2 medium boxes side by side.
	if maxVPCBoxW > 0 {
		// Allow 2 boxes: widest + a typical companion (minBoxWidth) + gap
		pairW := maxVPCBoxW + boxGapH + minBoxWidth
		needed := pairW + 2*vpcPadX + 4 + 8 // VPC border + subnet container padding
		if needed > minW {
			minW = needed
		}
	}

	// Global grid width: compute based on actual label widths, not current minW
	if len(globalNodes) > 0 {
		gridNeeded := computeGlobalGridMinWidth(globalNodes)
		if gridNeeded > minW {
			minW = gridNeeded
		}
	}

	return minW
}

// computeGlobalGridMinWidth determines the minimum canvas width needed for the global grid
// based on actual label widths, independent of current canvas width.
func computeGlobalGridMinWidth(globalNodes []*ServiceNode) int {
	if len(globalNodes) == 0 {
		return 0
	}

	// Compute individual box widths from label text
	boxWidths := make([]int, 0, len(globalNodes))
	for _, n := range globalNodes {
		label := n.Label
		icon := groupActionIcon(n.Action)
		if icon != "[ ]" {
			label = fmt.Sprintf("%s %s", icon, n.Label)
		}
		w := runeLen(label) + 4
		if w < gridBoxMinWidth {
			w = gridBoxMinWidth
		}
		boxWidths = append(boxWidths, w)
	}

	// Find the uniform cell width for gridColumns boxes per row
	cols := gridColumns
	if cols > len(boxWidths) {
		cols = len(boxWidths)
	}

	// Determine the widest box per row of `cols` items, then take the max
	maxCellW := 0
	for i := 0; i < len(boxWidths); i += cols {
		end := i + cols
		if end > len(boxWidths) {
			end = len(boxWidths)
		}
		rowMax := 0
		for _, w := range boxWidths[i:end] {
			if w > rowMax {
				rowMax = w
			}
		}
		if rowMax > maxCellW {
			maxCellW = rowMax
		}
	}

	// Total width: cols * cellWidth + gaps + outer border margins
	return cols*maxCellW + (cols-1)*gridBoxGap + 8
}

// FlowChain represents an independent traffic flow through the diagram.
// Each chain has its own dedicated X column to avoid visual ambiguity.
type FlowChain struct {
	Index   int
	RootID  string          // first non-distribution-bar node in this flow
	NodeIDs map[string]bool // all nodes in this chain
	Width   int             // max row width needed at any single tier
	CenterX int             // assigned center X position
}

// identifyFlowChains traces independent traffic flows through the DAG.
// Distribution bars are "transparent" — the first non-bar node in each
// downstream path becomes a flow root. Returns chains and nodeID→chainIndex.
func identifyFlowChains(
	dagNodes map[string]*ServiceNode,
	levels [][]string,
	boxSizes map[string][2]int,
) ([]*FlowChain, map[string]int) {
	if len(levels) == 0 {
		return nil, nil
	}

	// Phase 1: Find flow roots by walking through distribution bars.
	// BFS from top level, passing through dist bars to find real roots.
	var flowRoots []string
	visited := make(map[string]bool)

	var queue []string
	queue = append(queue, levels[0]...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true

		n := dagNodes[id]
		if n == nil {
			continue
		}

		if isDistributionBar(n) {
			for _, depID := range n.DepsOut {
				if !visited[depID] && dagNodes[depID] != nil {
					queue = append(queue, depID)
				}
			}
		} else {
			flowRoots = append(flowRoots, id)
		}
	}

	if len(flowRoots) <= 1 {
		return nil, nil // single flow — no column separation needed
	}
	sortStrings(flowRoots)

	// Phase 2: BFS from each root to build chains (first come, first served)
	nodeToChain := make(map[string]int)
	chains := make([]*FlowChain, 0, len(flowRoots))

	for i, rootID := range flowRoots {
		chain := &FlowChain{
			Index:   i,
			RootID:  rootID,
			NodeIDs: make(map[string]bool),
		}

		q := []string{rootID}
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if chain.NodeIDs[cur] {
				continue
			}
			if _, claimed := nodeToChain[cur]; claimed {
				continue
			}
			chain.NodeIDs[cur] = true
			nodeToChain[cur] = i

			cn := dagNodes[cur]
			if cn == nil {
				continue
			}
			for _, depID := range cn.DepsOut {
				if !chain.NodeIDs[depID] {
					q = append(q, depID)
				}
			}
		}

		chains = append(chains, chain)
	}

	// Phase 3: Compute chain widths (widest single box, not cumulative row).
	// Using single-box width keeps columns narrow; within a tier, multiple
	// boxes from the same chain pack outward from CenterX.
	for _, chain := range chains {
		maxBoxW := 0
		for nid := range chain.NodeIDs {
			if size, ok := boxSizes[nid]; ok && size[0] > maxBoxW {
				maxBoxW = size[0]
			}
		}
		if maxBoxW < minBoxWidth {
			maxBoxW = minBoxWidth
		}
		chain.Width = maxBoxW
	}

	return chains, nodeToChain
}

// computeFlowColumnPositions assigns CenterX to each flow chain, centering
// all chains within the available width. Compresses gaps if columns don't fit.
func computeFlowColumnPositions(chains []*FlowChain, canvasWidth int) {
	if len(chains) == 0 {
		return
	}

	gap := 6 // preferred horizontal gap between chains (user requested ≥ 4)

	// Compute total width at preferred gap
	totalW := 0
	for i, c := range chains {
		if i > 0 {
			totalW += gap
		}
		totalW += c.Width
	}

	// Compress gaps if total exceeds available width
	availW := canvasWidth - 2*(vpcPadX+4)
	if totalW > availW && len(chains) > 1 {
		boxTotal := 0
		for _, c := range chains {
			boxTotal += c.Width
		}
		gapBudget := availW - boxTotal
		gap = gapBudget / (len(chains) - 1)
		if gap < 4 {
			gap = 4
		}
		totalW = boxTotal + gap*(len(chains)-1)
	}

	startX := (canvasWidth - totalW) / 2
	if startX < vpcPadX+4 {
		startX = vpcPadX + 4
	}

	x := startX
	for i, c := range chains {
		if i > 0 {
			x += gap
		}
		c.CenterX = x + c.Width/2
		x += c.Width
	}
}

// flowColumnCanvasWidth returns the minimum canvas width needed to accommodate
// all flow columns with minimum gap (4) and VPC padding.
func flowColumnCanvasWidth(chains []*FlowChain) int {
	if len(chains) == 0 {
		return 0
	}
	minGap := 4
	totalW := 0
	for i, c := range chains {
		if i > 0 {
			totalW += minGap
		}
		totalW += c.Width
	}
	return totalW + 2*vpcPadX + 8
}

// splitEdgeFromVPCLevels ensures all edge-scoped nodes are placed above all VPC-scoped nodes.
// It splits mixed levels and reorders so edge levels always come first (Zone 1 above VPC).
func splitEdgeFromVPCLevels(levels [][]string, dagNodes map[string]*ServiceNode) [][]string {
	var edgeLevels [][]string
	var vpcLevels [][]string

	for _, level := range levels {
		var edgeIDs []string
		var otherIDs []string
		for _, id := range level {
			n := dagNodes[id]
			if n != nil && n.Scope == "edge" {
				edgeIDs = append(edgeIDs, id)
			} else {
				otherIDs = append(otherIDs, id)
			}
		}
		if len(edgeIDs) > 0 {
			edgeLevels = append(edgeLevels, edgeIDs)
		}
		if len(otherIDs) > 0 {
			vpcLevels = append(vpcLevels, otherIDs)
		}
	}

	// All edge levels first (Zone 1), then all VPC levels (Zone 2)
	var result [][]string
	result = append(result, edgeLevels...)
	result = append(result, vpcLevels...)
	return result
}

// calculateLayout computes positions for all boxes and arrows.
func calculateLayout(
	levels [][]string,
	dagNodes map[string]*ServiceNode,
	compounds map[string]*CompoundNode,
	vpcLayers []*TopoLayer,
	globalNodes []*ServiceNode,
	canvasWidth int,
) *LayoutResult {
	// Split mixed levels so edge nodes are always above VPC nodes
	levels = splitEdgeFromVPCLevels(levels, dagNodes)

	// Collect all VPC node IDs across all VPC layers
	allVPCNodeIDs := make(map[string]bool)
	for id, n := range dagNodes {
		if n.Scope == "vpc" {
			allVPCNodeIDs[id] = true
		}
	}

	result := &LayoutResult{
		Boxes:      make(map[string]*BoxPos),
		TotalWidth: canvasWidth,
	}

	// Calculate box sizes for DAG nodes
	boxSizes := make(map[string][2]int)
	for id, n := range dagNodes {
		if cn, ok := compounds[id]; ok {
			w, h := calcCompoundSize(cn.ParentLabel, cn.Children)
			boxSizes[id] = [2]int{w, h}
			result.Boxes[id] = &BoxPos{
				NodeID:           id,
				W:                w,
				H:                h,
				Action:           cn.ParentAction,
				IsCompound:       true,
				CompoundTitle:    cn.ParentLabel,
				CompoundChildren: cn.Children,
			}
		} else {
			w, h, lines := calcBoxSize(n)
			boxSizes[id] = [2]int{w, h}
			result.Boxes[id] = &BoxPos{NodeID: id, W: w, H: h, Lines: lines, Action: n.Action}
		}
	}

	// Identify flow chains for column-based layout
	chains, nodeToChain := identifyFlowChains(dagNodes, levels, boxSizes)
	if len(chains) > 1 {
		// Only widen canvas when minimum gap (4) still doesn't fit
		minNeeded := flowColumnCanvasWidth(chains)
		if minNeeded > canvasWidth {
			canvasWidth = minNeeded
			result.TotalWidth = canvasWidth
		}
		computeFlowColumnPositions(chains, canvasWidth)
	}
	result.Chains = chains
	result.NodeToChain = nodeToChain

	// Identify which levels are inside VPC vs edge
	vpcStartLevel := -1
	for li, level := range levels {
		for _, id := range level {
			if allVPCNodeIDs[id] {
				if vpcStartLevel == -1 {
					vpcStartLevel = li
				}
			}
		}
	}

	curY := 0
	hasVPC := vpcStartLevel >= 0

	// Internet box at top
	internetW := runeLen(internetLabel) + 4
	internetH := 3
	internetBox := &BoxPos{
		NodeID:  "__internet__",
		X:       (canvasWidth - internetW) / 2,
		Y:       curY,
		W:       internetW,
		H:       internetH,
		CenterX: canvasWidth / 2,
		Lines:   []string{internetLabel},
	}
	result.Boxes["__internet__"] = internetBox
	curY += internetH + levelGapV

	vpcInnerWidth := canvasWidth - 2*vpcPadX - 4
	vpcOffsetX := vpcPadX + 2

	// --- Phase 1: Edge levels (Zone 1 — above VPC) ---
	var deferredEdgeIDs []string

	for li := 0; li < vpcStartLevel && li < len(levels); li++ {
		level := levels[li]
		var levelNodes []string
		for _, id := range level {
			if _, ok := result.Boxes[id]; ok {
				levelNodes = append(levelNodes, id)
			}
		}
		if len(levelNodes) == 0 && len(deferredEdgeIDs) == 0 {
			continue
		}

		var distBarIDs []string
		var regularIDs []string
		for _, id := range levelNodes {
			if n := dagNodes[id]; n != nil && isDistributionBar(n) {
				distBarIDs = append(distBarIDs, id)
			} else {
				regularIDs = append(regularIDs, id)
			}
		}

		for _, id := range distBarIDs {
			bp := result.Boxes[id]
			bp.X = 0
			bp.Y = curY
			bp.W = canvasWidth
			bp.H = 1
			bp.CenterX = canvasWidth / 2
			curY += 1 + levelGapV
		}

		if len(distBarIDs) > 0 && len(regularIDs) > 0 {
			deferredEdgeIDs = append(deferredEdgeIDs, regularIDs...)
			regularIDs = nil
		}

		if len(deferredEdgeIDs) > 0 && len(distBarIDs) == 0 {
			regularIDs = append(deferredEdgeIDs, regularIDs...)
			deferredEdgeIDs = nil
		}

		if len(regularIDs) > 0 {
			placeBoxRow(result, regularIDs, boxSizes, 0, canvasWidth, &curY, chains, nodeToChain)
		}
	}

	if len(deferredEdgeIDs) > 0 {
		placeBoxRow(result, deferredEdgeIDs, boxSizes, 0, canvasWidth, &curY, chains, nodeToChain)
	}

	// --- Phase 2: VPC section(s) with subnet-aware placement (Zone 2) ---
	if hasVPC {
		// Fallback: if VPC-scoped nodes exist but no VPC layer data, create synthetic
		if len(vpcLayers) == 0 {
			vpcLayers = []*TopoLayer{{Name: "VPC", IsVPC: true}}
		}
		multiVPC := len(vpcLayers) > 1

		// Detect Transit Gateway across VPC layers for inter-VPC visual node
		hasTGW := false
		tgwCount := 0
		if multiVPC {
			for _, vl := range vpcLayers {
				for _, g := range vl.NetworkGroups {
					if g.Service == "Transit Gateway" {
						hasTGW = true
						tgwCount += g.PrimaryCount
					}
				}
			}
		}

		placedNodeIDs := make(map[string]bool) // track placed nodes to avoid duplicates
		tgwIdx := 0
		for vi, vpcLayer := range vpcLayers {
			// Insert Transit Gateway visual node between VPCs
			if vi > 0 && hasTGW {
				placeTGWNode(result, &curY, canvasWidth, tgwCount, tgwIdx)
				tgwIdx++
			}

			// Collect node IDs belonging to this VPC
			perVPCNodeIDs := make(map[string]bool)
			for id, n := range dagNodes {
				if n.Scope != "vpc" {
					continue
				}
				if placedNodeIDs[id] {
					continue // already placed in a previous VPC
				}
				if !multiVPC || vpcLayer.VPCAddress == "" {
					// Single VPC or unaddressed layer: take all
					perVPCNodeIDs[id] = true
				} else if n.VPCAddr == vpcLayer.VPCAddress {
					// Multi-VPC: exact match
					perVPCNodeIDs[id] = true
				}
				// Multi-VPC: nodes with empty VPCAddr are skipped (stay unplaced)
			}
			for id := range perVPCNodeIDs {
				placedNodeIDs[id] = true
			}

			layoutVPCWithSubnets(result, dagNodes, compounds, perVPCNodeIDs,
				vpcLayer.SubnetSummary, vpcLayer.NetworkGroups, boxSizes, &curY, canvasWidth,
				vpcInnerWidth, vpcOffsetX, vpcLayer.VPCAddress, chains, nodeToChain)
		}
	}

	// --- Phase 3: Global grid (Zone 3) ---
	grid := buildGlobalGrid(globalNodes, canvasWidth)
	if grid != nil {
		grid.X = (canvasWidth - grid.W) / 2
		if grid.X < 0 {
			grid.X = 0
		}
		grid.Y = curY
		result.GlobalGrid = grid
		curY += grid.H + 1
	}

	result.TotalHeight = curY + 2

	// Build arrows
	result.Arrows = buildArrows(levels, dagNodes, result.Boxes)

	// Build SG cross-reference dotted arrows
	result.DottedArrows = buildSGRefArrows(dagNodes, result.Boxes, result.Arrows)

	// Post-process: stretch distribution bars to span their children
	stretchDistributionBars(dagNodes, result)

	return result
}

// placeBoxRow positions a row of boxes centered within an area.
// When flow chains are active, boxes are placed at their chain's CenterX.
func placeBoxRow(result *LayoutResult, nodeIDs []string, boxSizes map[string][2]int, offsetX, effectiveWidth int, curY *int, chains []*FlowChain, nodeToChain map[string]int) {
	// Flow-column aware placement: position each box at its chain's CenterX
	if len(chains) > 1 && len(nodeToChain) > 0 {
		maxH := 0
		// Group nodes by chain for multi-box-per-chain packing
		chainGroups := make(map[int][]string)
		var unchained []string
		for _, id := range nodeIDs {
			if ci, ok := nodeToChain[id]; ok {
				chainGroups[ci] = append(chainGroups[ci], id)
			} else {
				unchained = append(unchained, id)
			}
		}

		for ci, ids := range chainGroups {
			chain := chains[ci]
			// Pack boxes horizontally centered at chain.CenterX
			rowW := 0
			for j, id := range ids {
				if j > 0 {
					rowW += boxGapH
				}
				rowW += boxSizes[id][0]
			}
			x := chain.CenterX - rowW/2
			if x < offsetX {
				x = offsetX
			}
			for j, id := range ids {
				if j > 0 {
					x += boxGapH
				}
				bp := result.Boxes[id]
				bp.X = x
				bp.Y = *curY
				bp.CenterX = x + bp.W/2
				x += bp.W
				if bp.H > maxH {
					maxH = bp.H
				}
			}
		}

		// Center unchained boxes in remaining space
		if len(unchained) > 0 {
			rowW := 0
			for j, id := range unchained {
				if j > 0 {
					rowW += boxGapH
				}
				rowW += boxSizes[id][0]
			}
			x := offsetX + (effectiveWidth-rowW)/2
			if x < offsetX {
				x = offsetX
			}
			for j, id := range unchained {
				if j > 0 {
					x += boxGapH
				}
				bp := result.Boxes[id]
				bp.X = x
				bp.Y = *curY
				bp.CenterX = x + bp.W/2
				x += bp.W
				if bp.H > maxH {
					maxH = bp.H
				}
			}
		}

		*curY += maxH + levelGapV
		return
	}

	// Default: center all boxes in a single row
	totalW := 0
	for i, id := range nodeIDs {
		if i > 0 {
			totalW += boxGapH
		}
		totalW += boxSizes[id][0]
	}
	startX := offsetX + (effectiveWidth-totalW)/2
	if startX < offsetX {
		startX = offsetX
	}
	x := startX
	maxH := 0
	for i, id := range nodeIDs {
		if i > 0 {
			x += boxGapH
		}
		bp := result.Boxes[id]
		bp.X = x
		bp.Y = *curY
		bp.CenterX = x + bp.W/2
		x += bp.W
		if bp.H > maxH {
			maxH = bp.H
		}
	}
	*curY += maxH + levelGapV
}

// layoutVPCWithSubnets places VPC service nodes inside subnet tier containers.
func layoutVPCWithSubnets(
	result *LayoutResult,
	dagNodes map[string]*ServiceNode,
	compounds map[string]*CompoundNode,
	vpcNodeIDs map[string]bool,
	subnetSummary *SubnetSummary,
	networkGroups []*AggregatedGroup,
	boxSizes map[string][2]int,
	curY *int,
	canvasWidth, vpcInnerWidth, vpcOffsetX int,
	vpcAddress string,
	chains []*FlowChain, nodeToChain map[string]int,
) {
	*curY += 2 // gap before VPC border
	vpcTopY := *curY
	*curY += 1 // VPC top border row

	// Group VPC DAG nodes by SubnetTier (skip network infra handled separately)
	tierNodes := make(map[string][]string)
	for id := range vpcNodeIDs {
		n := dagNodes[id]
		if n == nil || skipFromDAGBoxes[n.Service] {
			continue
		}
		tier := n.SubnetTier
		if tier == "" || tier == "vpc_level" {
			continue // handled in utility bar
		}
		tierNodes[tier] = append(tierNodes[tier], id)
	}

	// Simplify tiers if no app/data split
	hasAppDataSplit := subnetSummary != nil && (subnetSummary.PrivateApp > 0 || subnetSummary.PrivateData > 0)
	if !hasAppDataSplit {
		tierNodes["private"] = append(tierNodes["private"], tierNodes["private_app"]...)
		tierNodes["private"] = append(tierNodes["private"], tierNodes["private_data"]...)
		delete(tierNodes, "private_app")
		delete(tierNodes, "private_data")
	}

	// Sort node IDs within each tier for deterministic layout
	for tier := range tierNodes {
		sortStrings(tierNodes[tier])
	}

	// Determine VPC infrastructure annotations
	var hasIGW bool
	var hasEIP bool
	var natGWLabel string
	var vpnLabel string
	for _, g := range networkGroups {
		switch g.Service {
		case "Internet Gateway":
			hasIGW = true
		case "NAT Gateway":
			if g.PrimaryCount > 1 {
				natGWLabel = fmt.Sprintf("NAT (%d)", g.PrimaryCount)
			} else {
				natGWLabel = "NAT GW"
			}
		case "Elastic IP":
			hasEIP = true
		case "VPN":
			if g.PrimaryCount > 1 {
				vpnLabel = fmt.Sprintf("VPN (%d)", g.PrimaryCount)
			} else {
				vpnLabel = "VPN"
			}
		}
	}

	// Collapse EIP into NAT GW annotation
	if natGWLabel != "" && hasEIP {
		natGWLabel += " [EIP]"
	}

	// Build infra labels for public tier (NAT GW + VPN — IGW on VPC border, EIP collapsed)
	var pubInfraLabels []string
	if natGWLabel != "" {
		pubInfraLabels = append(pubInfraLabels, natGWLabel)
	}
	if vpnLabel != "" {
		pubInfraLabels = append(pubInfraLabels, vpnLabel)
	}

	// Layout each active tier as a subnet container
	for _, tier := range subnetTierOrder {
		nodeIDs := tierNodes[tier]
		subCount := getSubnetCount(tier, subnetSummary)
		if len(nodeIDs) == 0 && subCount == 0 {
			continue
		}

		var infraLabels []string
		if tier == "public" {
			infraLabels = pubInfraLabels
		}

		title := subnetTierTitle(tier, subCount)
		containerH := layoutTierContainer(
			result, nodeIDs, infraLabels, boxSizes,
			vpcOffsetX, *curY, vpcInnerWidth,
			vpcAddress, chains, nodeToChain,
		)

		sc := &SubnetContainer{
			Tier:        tier,
			Title:       title,
			X:           vpcOffsetX,
			Y:           *curY,
			W:           vpcInnerWidth,
			H:           containerH,
			InfraLabels: infraLabels,
			NodeIDs:     nodeIDs,
		}
		result.SubnetContainers = append(result.SubnetContainers, sc)
		*curY += containerH + 2 // gap between containers
	}

	// VPC-level utility bar
	var utilParts []string
	for _, g := range networkGroups {
		switch g.Service {
		case "Internet Gateway", "NAT Gateway", "Elastic IP":
			continue
		case "VPN":
			if vpnLabel != "" {
				continue // rendered as visual box in public tier
			}
		default:
			utilParts = append(utilParts, g.Label)
		}
	}
	// Add vpc_level DAG nodes that aren't in skipFromDAGBoxes
	for id := range vpcNodeIDs {
		n := dagNodes[id]
		if n != nil && n.SubnetTier == "vpc_level" && !skipFromDAGBoxes[n.Service] {
			utilParts = append(utilParts, n.Label)
		}
	}

	if len(utilParts) > 0 {
		maxTextW := vpcInnerWidth - 4 // 2 for border + 1 padding each side
		utilLines := wrapWithSeparator(utilParts, " · ", maxTextW)
		utilW := vpcInnerWidth
		utilH := len(utilLines) + 2 // top border + lines + bottom border
		utilID := fmt.Sprintf("__vpc_util_%s__", vpcAddress)
		result.Boxes[utilID] = &BoxPos{
			NodeID: utilID,
			X:      vpcOffsetX,
			Y:      *curY,
			W:      utilW,
			H:      utilH,
			Lines:  utilLines,
		}
		*curY += utilH + 1
	}

	// NAT GW outbound flow: draw dashed upward arrows from compute resources
	// in private tiers to the NAT GW box in the public tier.
	if natGWLabel != "" {
		// Find NAT box for THIS VPC (match by label + VPC infra ID prefix)
		vpcInfraPrefix := fmt.Sprintf("__infra_%s_", vpcAddress)
		var natBox *BoxPos
		for id, bp := range result.Boxes {
			if len(bp.Lines) > 0 && bp.Lines[0] == natGWLabel &&
				strings.HasPrefix(id, vpcInfraPrefix) {
				natBox = bp
				break
			}
		}
		if natBox != nil {
			natCX := natBox.X + natBox.W/2
			natBotY := natBox.Y + natBox.H
			for _, sc := range result.SubnetContainers {
				if sc.Tier == "public" || sc.Tier == "firewall" {
					continue
				}
				for _, nodeID := range sc.NodeIDs {
					bp := result.Boxes[nodeID]
					if bp == nil || !isComputeService(dagNodes[nodeID]) {
						continue
					}
					// Dashed arrow from compute box top → NAT box bottom
					result.DashedArrows = append(result.DashedArrows, ArrowDef{
						FromID: nodeID,
						ToID:   "__nat__",
						FromX:  natCX,
						FromY:  bp.Y,
						ToX:    natCX,
						ToY:    natBotY,
					})
				}
			}
		}
	}

	*curY += vpcPadY
	vpcBotY := *curY

	// VPC border title: include IGW annotation and VPC name for multi-VPC
	vpcTitle := "VPC"
	if vpcAddress != "" {
		vpcTitle = extractVPCDisplayName(vpcAddress)
	}
	if hasIGW {
		vpcTitle += " [IGW]"
	}

	result.VPCRects = append(result.VPCRects, &VPCRect{
		X:     vpcPadX,
		Y:     vpcTopY,
		W:     canvasWidth - 2*vpcPadX,
		H:     vpcBotY - vpcTopY + 1,
		Title: vpcTitle,
	})

	*curY += 1 + levelGapV
}

// layoutTierContainer positions service boxes and infra labels inside a subnet tier container.
// Returns the container height.
func layoutTierContainer(
	result *LayoutResult,
	nodeIDs []string,
	infraLabels []string,
	boxSizes map[string][2]int,
	containerX, containerY, containerW int,
	vpcAddress string,
	chains []*FlowChain, nodeToChain map[string]int,
) int {
	innerPadX := 2
	innerStartX := containerX + innerPadX
	maxInnerW := containerW - 2*innerPadX

	// Content starts after border (with embedded title) + blank line
	contentStartY := containerY + 2

	// --- Flow-column aware placement ---
	if len(chains) > 1 && len(nodeToChain) > 0 {
		return layoutTierContainerByChain(
			result, nodeIDs, infraLabels, boxSizes,
			innerStartX, maxInnerW, contentStartY,
			containerY, vpcAddress, nodeToChain,
		)
	}

	// --- Default: pack into centered rows ---
	type innerBox struct {
		id    string
		label string
		w, h  int
	}
	allBoxes := make([]innerBox, 0, len(infraLabels)+len(nodeIDs))

	for _, lbl := range infraLabels {
		w := runeLen(lbl) + 4
		if w < 7 {
			w = 7
		}
		allBoxes = append(allBoxes, innerBox{label: lbl, w: w, h: 3})
	}

	for _, id := range nodeIDs {
		size := boxSizes[id]
		allBoxes = append(allBoxes, innerBox{id: id, w: size[0], h: size[1]})
	}

	if len(allBoxes) == 0 {
		return 4
	}

	type rowInfo struct {
		indices []int
		totalW  int
		maxH    int
	}
	var rows []rowInfo
	var cur rowInfo
	for i, b := range allBoxes {
		needed := b.w
		if len(cur.indices) > 0 {
			needed += boxGapH
		}
		if cur.totalW+needed > maxInnerW && len(cur.indices) > 0 {
			rows = append(rows, cur)
			cur = rowInfo{}
			needed = b.w
		}
		cur.indices = append(cur.indices, i)
		cur.totalW += needed
		if b.h > cur.maxH {
			cur.maxH = b.h
		}
	}
	if len(cur.indices) > 0 {
		rows = append(rows, cur)
	}

	rowY := contentStartY
	infraIdx := 0
	for _, row := range rows {
		startX := innerStartX + (maxInnerW-row.totalW)/2
		if startX < innerStartX {
			startX = innerStartX
		}
		x := startX
		for i, boxIdx := range row.indices {
			if i > 0 {
				x += boxGapH
			}
			b := allBoxes[boxIdx]
			if b.id == "" {
				infraID := fmt.Sprintf("__infra_%s_%d__", vpcAddress, infraIdx)
				result.Boxes[infraID] = &BoxPos{
					NodeID: infraID,
					X:      x,
					Y:      rowY,
					W:      b.w,
					H:      b.h,
					Lines:  []string{b.label},
				}
				infraIdx++
			} else {
				bp := result.Boxes[b.id]
				bp.X = x
				bp.Y = rowY
				bp.CenterX = x + bp.W/2
			}
			x += b.w
		}
		rowY += row.maxH + 1
	}

	containerH := rowY - containerY + 1
	if containerH < 4 {
		containerH = 4
	}
	return containerH
}

// layoutTierContainerByChain sorts boxes by chain index within a subnet
// tier container, then packs them into rows with extra gap between chain
// groups. This preserves left-to-right chain ordering without overlap.
func layoutTierContainerByChain(
	result *LayoutResult,
	nodeIDs []string,
	infraLabels []string,
	boxSizes map[string][2]int,
	innerStartX, maxInnerW, contentStartY int,
	containerY int,
	vpcAddress string,
	nodeToChain map[string]int,
) int {
	chainGap := 6 // extra gap between boxes from different chains

	// Build ordered list: infra labels first, then service boxes sorted by chain
	type innerBox struct {
		id      string
		label   string
		w, h    int
		chainID int // -1 for infra/unchained
	}
	allBoxes := make([]innerBox, 0, len(infraLabels)+len(nodeIDs))

	// Infra label boxes
	for _, lbl := range infraLabels {
		w := runeLen(lbl) + 4
		if w < 7 {
			w = 7
		}
		allBoxes = append(allBoxes, innerBox{label: lbl, w: w, h: 3, chainID: -1})
	}

	// Service boxes — sort by chain index for grouping
	type sortEntry struct {
		id      string
		chainID int
	}
	entries := make([]sortEntry, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		ci := -1
		if c, ok := nodeToChain[id]; ok {
			ci = c
		}
		entries = append(entries, sortEntry{id: id, chainID: ci})
	}
	// Stable sort by chainID (unchained=-1 goes first)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].chainID < entries[i].chainID {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	for _, e := range entries {
		size := boxSizes[e.id]
		allBoxes = append(allBoxes, innerBox{id: e.id, w: size[0], h: size[1], chainID: e.chainID})
	}

	if len(allBoxes) == 0 {
		return 4
	}

	// Pack into rows with extra gap between chain groups
	type rowInfo struct {
		indices []int
		totalW  int
		maxH    int
	}
	var rows []rowInfo
	var cur rowInfo
	prevChain := -2 // sentinel
	for i, b := range allBoxes {
		gap := boxGapH
		if len(cur.indices) > 0 && b.chainID >= 0 && prevChain >= 0 && b.chainID != prevChain {
			gap = chainGap // extra gap between different chains
		}
		needed := b.w
		if len(cur.indices) > 0 {
			needed += gap
		}
		if cur.totalW+needed > maxInnerW && len(cur.indices) > 0 {
			rows = append(rows, cur)
			cur = rowInfo{}
			needed = b.w
		}
		cur.indices = append(cur.indices, i)
		cur.totalW += needed
		if b.h > cur.maxH {
			cur.maxH = b.h
		}
		prevChain = b.chainID
	}
	if len(cur.indices) > 0 {
		rows = append(rows, cur)
	}

	// Position boxes in each row (centered)
	rowY := contentStartY
	infraIdx := 0
	for _, row := range rows {
		startX := innerStartX + (maxInnerW-row.totalW)/2
		if startX < innerStartX {
			startX = innerStartX
		}
		x := startX
		prevC := -2
		for k, boxIdx := range row.indices {
			b := allBoxes[boxIdx]
			gap := boxGapH
			if k > 0 && b.chainID >= 0 && prevC >= 0 && b.chainID != prevC {
				gap = chainGap
			}
			if k > 0 {
				x += gap
			}
			if b.id == "" {
				infraID := fmt.Sprintf("__infra_%s_%d__", vpcAddress, infraIdx)
				result.Boxes[infraID] = &BoxPos{
					NodeID: infraID,
					X:      x,
					Y:      rowY,
					W:      b.w,
					H:      b.h,
					Lines:  []string{b.label},
				}
				infraIdx++
			} else {
				bp := result.Boxes[b.id]
				bp.X = x
				bp.Y = rowY
				bp.CenterX = x + bp.W/2
			}
			x += b.w
			prevC = b.chainID
		}
		rowY += row.maxH + 1
	}

	containerH := rowY - containerY + 1
	if containerH < 4 {
		containerH = 4
	}
	return containerH
}

// getSubnetCount returns the subnet count for a tier from the summary.
func getSubnetCount(tier string, summary *SubnetSummary) int {
	if summary == nil {
		return 0
	}
	switch tier {
	case "public":
		return summary.Public
	case "firewall":
		return summary.Firewall
	case "management":
		return summary.Management
	case "private_app":
		return summary.PrivateApp
	case "private_data":
		return summary.PrivateData
	case "private":
		return summary.Private
	}
	return 0
}

// calcBoxSize determines the width, height, and content lines for a node box.
func calcBoxSize(n *ServiceNode) (int, int, []string) {
	lines := []string{n.Label}

	icon := groupActionIcon(n.Action)
	if icon != "[ ]" {
		lines[0] = fmt.Sprintf("%s %s", icon, n.Label)
	}

	// Add annotation line (e.g., "[ACM] [WAF]")
	if len(n.Annotations) > 0 {
		lines = append(lines, strings.Join(n.Annotations, " "))
	}

	w := minBoxWidth
	for _, l := range lines {
		needed := runeLen(l) + 2*boxPadding
		if needed > w {
			w = needed
		}
	}

	h := len(lines) + 2
	return w, h, lines
}

// buildArrows creates ArrowDef entries from the DAG edges.
func buildArrows(levels [][]string, nodes map[string]*ServiceNode, boxes map[string]*BoxPos) []ArrowDef {
	var arrows []ArrowDef

	internetBox := boxes["__internet__"]
	if internetBox != nil && len(levels) > 0 {
		// Identify nodes in level 0 that are children of a distribution bar
		// in the same level — they are reached via the bar, not directly from Internet.
		distBarChildren := make(map[string]bool)
		for _, id := range levels[0] {
			n := nodes[id]
			if n != nil && isDistributionBar(n) {
				for _, depID := range n.DepsOut {
					distBarChildren[depID] = true
				}
			}
		}
		for _, id := range levels[0] {
			if distBarChildren[id] {
				continue // reached via dist bar, not directly from Internet
			}
			bp := boxes[id]
			if bp == nil {
				continue
			}
			arrows = append(arrows, ArrowDef{
				FromID: "__internet__",
				ToID:   id,
				FromX:  internetBox.CenterX,
				FromY:  internetBox.Y + internetBox.H,
				ToX:    bp.CenterX,
				ToY:    bp.Y - 1,
			})
		}
	}

	// Deduplicate arrows by (FromID, ToID) pair — compound node remapping
	// may leave duplicate edges (e.g., ALB→ECS and ALB→ECS Cluster both
	// become ALB→ECS Cluster after child consumption).
	type arrowKey struct{ from, to string }
	seen := make(map[arrowKey]bool)

	for _, level := range levels {
		for _, id := range level {
			n := nodes[id]
			if n == nil {
				continue
			}
			fromBox := boxes[id]
			if fromBox == nil {
				continue
			}
			for _, depID := range n.DepsOut {
				toBox := boxes[depID]
				if toBox == nil {
					continue
				}
				// Only draw arrows to boxes below (toY > fromY)
				if toBox.Y <= fromBox.Y {
					continue
				}
				key := arrowKey{from: id, to: depID}
				if seen[key] {
					continue
				}
				seen[key] = true
				// Check if this edge is bidirectional:
				// 1. Mutual SG cross-references (BiDeps)
				// 2. Data-tier services (cache/database) imply read+write
				bidir := n.BiDeps[depID]
				if !bidir {
					if dep := nodes[depID]; dep != nil {
						bidir = dep.BiDeps[id]
						if !bidir {
							bidir = isDataService(dep)
						}
					}
				}
				arrows = append(arrows, ArrowDef{
					FromID:        id,
					ToID:          depID,
					FromX:         fromBox.CenterX,
					FromY:         fromBox.Y + fromBox.H,
					ToX:           toBox.CenterX,
					ToY:           toBox.Y - 1,
					Bidirectional: bidir,
				})
			}
		}
	}

	return arrows
}

// buildSGRefArrows creates dotted arrows for security group cross-reference edges.
// These are visual-only edges that don't affect topology ordering.
// When a solid arrow already exists, offset the dotted arrow by 2 columns.
func buildSGRefArrows(nodes map[string]*ServiceNode, boxes map[string]*BoxPos, solidArrows []ArrowDef) []ArrowDef {
	// Build set of existing solid arrow pairs
	type arrowKey struct{ from, to string }
	solidSet := make(map[arrowKey]bool)
	for _, a := range solidArrows {
		solidSet[arrowKey{from: a.FromID, to: a.ToID}] = true
		solidSet[arrowKey{from: a.ToID, to: a.FromID}] = true
	}

	var arrows []ArrowDef
	seen := make(map[arrowKey]bool)

	for id, n := range nodes {
		fromBox := boxes[id]
		if fromBox == nil {
			continue
		}
		for _, sgDepID := range n.SGRefDeps {
			toBox := boxes[sgDepID]
			if toBox == nil {
				continue
			}
			// Dedup
			key := arrowKey{from: id, to: sgDepID}
			reverseKey := arrowKey{from: sgDepID, to: id}
			if seen[key] || seen[reverseKey] {
				continue
			}
			seen[key] = true

			// Determine direction: arrow goes from higher box to lower box
			var fromB, toB *BoxPos
			if fromBox.Y < toBox.Y {
				fromB = fromBox
				toB = toBox
			} else {
				fromB = toBox
				toB = fromBox
			}

			// Offset by 2 columns if a solid arrow already connects these nodes
			offset := 0
			if solidSet[arrowKey{from: id, to: sgDepID}] {
				offset = 2
			}

			// Check if this is a bidirectional pair
			bidir := n.BiDeps[sgDepID]
			if !bidir {
				if peerNode := nodes[sgDepID]; peerNode != nil {
					bidir = peerNode.BiDeps[id]
				}
			}

			arrows = append(arrows, ArrowDef{
				FromID:        id,
				ToID:          sgDepID,
				FromX:         fromB.CenterX + offset,
				FromY:         fromB.Y + fromB.H,
				ToX:           toB.CenterX + offset,
				ToY:           toB.Y - 1,
				Bidirectional: bidir,
			})
		}
	}
	return arrows
}

// stretchDistributionBars widens hub services to span their children below.
// Also converts their arrows to vertical drops from the bar.
// placeTGWNode inserts a Transit Gateway visual node between VPCs.
// Renders as:   ◄···► [Transit Gateway (N)] ◄···►
// centered in the gap between the previous VPC bottom and the next VPC top.
func placeTGWNode(result *LayoutResult, curY *int, canvasWidth, attachmentCount, idx int) {
	label := "Transit Gateway"
	if attachmentCount > 0 {
		label = fmt.Sprintf("Transit Gateway (%d)", attachmentCount)
	}
	boxW := runeLen(label) + 2*boxPadding
	if boxW < minBoxWidth {
		boxW = minBoxWidth
	}
	boxH := 3
	boxX := (canvasWidth - boxW) / 2
	boxY := *curY + 1

	tgwID := fmt.Sprintf("__tgw_%d__", idx)
	result.Boxes[tgwID] = &BoxPos{
		NodeID:  tgwID,
		X:       boxX,
		Y:       boxY,
		W:       boxW,
		H:       boxH,
		CenterX: canvasWidth / 2,
		Lines:   []string{label},
	}

	// Dashed horizontal wings: ◄···► on each side of the box
	wingLen := 8
	leftWingX := boxX - wingLen - 1
	rightWingX := boxX + boxW + 1
	midY := boxY + 1 // vertically centered in the box

	if leftWingX < 0 {
		leftWingX = 0
	}
	if rightWingX+wingLen >= canvasWidth {
		rightWingX = canvasWidth - wingLen - 1
	}

	// Store wing positions as dashed arrows for rendering
	// Left wing: ◄···  (arrow pointing left)
	result.DashedArrows = append(result.DashedArrows, ArrowDef{
		FromID: fmt.Sprintf("__tgw_left_%d__", idx),
		ToID:   tgwID,
		FromX:  boxX - 1,
		FromY:  midY,
		ToX:    leftWingX,
		ToY:    midY,
	})
	// Right wing: ···►  (arrow pointing right)
	result.DashedArrows = append(result.DashedArrows, ArrowDef{
		FromID: tgwID,
		ToID:   fmt.Sprintf("__tgw_right_%d__", idx),
		FromX:  boxX + boxW,
		FromY:  midY,
		ToX:    rightWingX + wingLen,
		ToY:    midY,
	})

	*curY = boxY + boxH + 1
}

func stretchDistributionBars(nodes map[string]*ServiceNode, result *LayoutResult) {
	for id, n := range nodes {
		if !isDistributionBar(n) {
			continue
		}
		bp := result.Boxes[id]
		if bp == nil {
			continue
		}

		// Find children boxes (outbound connections)
		minX := bp.X + bp.W
		maxX := bp.X
		var childBoxes []*BoxPos
		for _, depID := range n.DepsOut {
			cb := result.Boxes[depID]
			if cb == nil || cb.Y <= bp.Y {
				continue
			}
			childBoxes = append(childBoxes, cb)
			if cb.X < minX {
				minX = cb.X
			}
			if cb.X+cb.W > maxX {
				maxX = cb.X + cb.W
			}
		}

		if len(childBoxes) < 2 {
			continue
		}

		// Stretch bar to span children with margin
		margin := 2
		barLeft := minX - margin
		barRight := maxX + margin
		if barLeft < 0 {
			barLeft = 0
		}
		barW := barRight - barLeft

		bp.X = barLeft
		bp.W = barW
		bp.H = 1 // single-row bar
		bp.CenterX = barLeft + barW/2
		bp.IsDistBar = true
		bp.Lines = []string{n.Label} // raw label without icon

		// Rebuild arrows: vertical drops FROM bar to children,
		// and fix incoming arrows TO point at bar center
		var newArrows []ArrowDef
		for _, a := range result.Arrows {
			if a.FromID == id {
				// Replace with vertical drop from bar to each child center
				targetBox := result.Boxes[a.ToID]
				if targetBox != nil {
					newArrows = append(newArrows, ArrowDef{
						FromID: id,
						ToID:   a.ToID,
						FromX:  targetBox.CenterX,
						FromY:  bp.Y + 1,
						ToX:    targetBox.CenterX,
						ToY:    targetBox.Y - 1,
					})
				}
			} else if a.ToID == id {
				// Incoming arrow: drop straight down onto the bar.
				// Use FromX as ToX so the arrow is vertical (no L-shape └┐ artifact).
				// The bar spans the full width, so the arrow can land anywhere on it.
				toX := a.FromX
				// Clamp to bar bounds so the arrow head lands on the bar
				if toX < bp.X+1 {
					toX = bp.X + 1
				}
				if toX > bp.X+bp.W-2 {
					toX = bp.X + bp.W - 2
				}
				newArrows = append(newArrows, ArrowDef{
					FromID: a.FromID,
					ToID:   id,
					FromX:  a.FromX,
					FromY:  a.FromY,
					ToX:    toX,
					ToY:    bp.Y - 1,
				})
			} else {
				newArrows = append(newArrows, a)
			}
		}
		result.Arrows = newArrows
	}
}

// buildNetworkSection creates the subnet box layout for the VPC header area.
// Positions are relative to the VPC interior (will be offset when rendered).
func buildNetworkSection(
	subnetSummary *SubnetSummary,
	networkGroups []*AggregatedGroup,
	innerWidth int,
	offsetX int,
) *NetworkSection {
	if subnetSummary == nil {
		return nil
	}
	// Check if there are any subnets at all
	totalSubs := subnetSummary.Public + subnetSummary.PrivateApp +
		subnetSummary.PrivateData + subnetSummary.Private
	if totalSubs == 0 {
		return nil
	}

	ns := &NetworkSection{}
	curY := 1 // start 1 row below VPC border

	// Determine subnet tiers to show
	hasPub := subnetSummary.Public > 0
	hasPrivApp := subnetSummary.PrivateApp > 0
	hasPrivData := subnetSummary.PrivateData > 0
	hasPriv := subnetSummary.Private > 0

	// Collect inner labels for public subnet (IGW, NAT, EIP)
	var pubInners []string
	for _, g := range networkGroups {
		switch g.Service {
		case "Internet Gateway":
			pubInners = append(pubInners, "IGW")
		case "NAT Gateway":
			if g.PrimaryCount > 1 {
				pubInners = append(pubInners, fmt.Sprintf("NAT (%d)", g.PrimaryCount))
			} else {
				pubInners = append(pubInners, "NAT GW")
			}
		case "Elastic IP":
			if g.PrimaryCount > 1 {
				pubInners = append(pubInners, fmt.Sprintf("EIP (%d)", g.PrimaryCount))
			} else {
				pubInners = append(pubInners, "EIP")
			}
		}
	}

	halfW := innerWidth/2 - 2

	// Public subnets box (left side)
	if hasPub {
		h := 4
		if len(pubInners) > 0 {
			h = 6 // room for inner component boxes
		}
		ns.SubnetBoxes = append(ns.SubnetBoxes, &SubnetBoxInfo{
			Tier:        "public",
			Count:       subnetSummary.Public,
			X:           offsetX,
			Y:           curY,
			W:           halfW,
			H:           h,
			InnerLabels: pubInners,
		})
	}

	// Private app or generic private subnets (right side)
	if hasPrivApp {
		h := 4
		ns.SubnetBoxes = append(ns.SubnetBoxes, &SubnetBoxInfo{
			Tier:  "private_app",
			Count: subnetSummary.PrivateApp,
			X:     offsetX + halfW + 3,
			Y:     curY,
			W:     halfW,
			H:     h,
		})
	} else if hasPriv && !hasPrivApp && !hasPrivData {
		h := 4
		ns.SubnetBoxes = append(ns.SubnetBoxes, &SubnetBoxInfo{
			Tier:  "private",
			Count: subnetSummary.Private,
			X:     offsetX + halfW + 3,
			Y:     curY,
			W:     halfW,
			H:     h,
		})
	}

	// Top row height
	topH := 4
	for _, sb := range ns.SubnetBoxes {
		if sb.H > topH {
			topH = sb.H
		}
	}
	curY += topH + 1

	// Private data subnets (below, right-aligned)
	if hasPrivData {
		ns.SubnetBoxes = append(ns.SubnetBoxes, &SubnetBoxInfo{
			Tier:  "private_data",
			Count: subnetSummary.PrivateData,
			X:     offsetX + halfW + 3,
			Y:     curY,
			W:     halfW,
			H:     4,
		})
		curY += 5
	}

	// Network utilities bar (SG, Endpoints, Route Tables, Firewall, etc.)
	var utilParts []string
	for _, g := range networkGroups {
		switch g.Service {
		case "Internet Gateway", "NAT Gateway", "Elastic IP":
			continue // already shown in subnet boxes
		default:
			utilParts = append(utilParts, g.Label)
		}
	}

	if len(utilParts) > 0 {
		utilLabel := strings.Join(utilParts, " · ")
		utilW := runeLen(utilLabel) + 4
		if utilW > innerWidth {
			utilW = innerWidth
		}
		ns.UtilBar = &BoxPos{
			NodeID: "__network_util__",
			X:      offsetX,
			Y:      curY,
			W:      utilW,
			H:      3,
			Lines:  []string{utilLabel},
		}
		curY += 4
	}

	ns.Height = curY
	return ns
}

// extractVPCDisplayName extracts a friendly VPC name from a Terraform address.
// "module.vpc_production.aws_vpc.main" → "VPC Production"
// "aws_vpc.staging" → "VPC Staging"
func extractVPCDisplayName(addr string) string {
	parts := strings.Split(addr, ".")
	// Try module name first (e.g., module.vpc_production.aws_vpc.main)
	for i, p := range parts {
		if p == "module" && i+1 < len(parts) {
			name := parts[i+1]
			name = strings.TrimPrefix(name, "vpc_")
			name = strings.TrimPrefix(name, "vpc-")
			if len(name) > 0 {
				// Capitalize first letter
				runes := []rune(name)
				if runes[0] >= 'a' && runes[0] <= 'z' {
					runes[0] -= 32
				}
				return "VPC " + string(runes)
			}
		}
	}
	// Fallback: use the resource name (last part)
	name := parts[len(parts)-1]
	if name == "main" || name == "this" || name == "default" {
		return "VPC"
	}
	runes := []rune(name)
	if len(runes) > 0 && runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] -= 32
	}
	return "VPC " + string(runes)
}

// subnetTierTitle returns a display title for a subnet tier.
// When count is 0 (subnets referenced externally, not as local aws_subnet resources),
// the count is omitted to avoid displaying misleading "Subnets (0)".
func subnetTierTitle(tier string, count int) string {
	var name string
	switch tier {
	case "public":
		name = "Public Subnets"
	case "private_app":
		name = "Private App Subnets"
	case "private_data":
		name = "Private Data Subnets"
	case "firewall":
		name = "Firewall Subnets"
	case "management":
		name = "Management Subnets"
	case "private":
		name = "Private Subnets"
	default:
		name = "Subnets"
	}
	if count > 0 {
		return fmt.Sprintf("%s (%d)", name, count)
	}
	return name
}
