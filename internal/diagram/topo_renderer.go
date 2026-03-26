package diagram

import (
	"fmt"
	"strings"
)

const (
	topoWidth = 120

	dblCornerTL = "╔"
	dblCornerTR = "╗"
	dblCornerBL = "╚"
	dblCornerBR = "╝"
	dblHoriz    = "═"
	dblVert     = "║"

	sglCornerTL = "┌"
	sglCornerTR = "┐"
	sglCornerBL = "└"
	sglCornerBR = "┘"
	sglHoriz    = "─"
	sglVert     = "│"

	arrowRight    = "──▶"
	topoArrowDown = "▼"
	topoConnector = "│"
)

// renderedBox holds pre-rendered lines for horizontal placement.
type renderedBox struct {
	lines []string
	width int
}

// RenderTopoResult renders a TopoResult into an ASCII DAG diagram with three zones:
// Zone 1 (Edge): Route 53, CloudFront, WAF, ACM — above VPC
// Zone 2 (VPC): Networking, Compute, Data, Load Balancing — inside VPC
// Zone 3 (Global): CloudWatch, IAM, S3, etc. — compact grid below VPC
func RenderTopoResult(result *TopoResult) string {
	// Build the service dependency DAG
	allNodes := buildServiceDAG(result)

	// Collect all VPC layers
	var vpcLayers []*TopoLayer
	for _, layer := range result.Layers {
		if layer.IsVPC {
			vpcLayers = append(vpcLayers, layer)
		}
	}

	// Multi-VPC: reclassify VPC-scoped nodes without a VPC assignment as global
	if len(vpcLayers) > 1 {
		for _, n := range allNodes {
			if n.Scope == "vpc" && n.VPCAddr == "" {
				n.Scope = "global"
			}
		}
	}

	// Separate into DAG (edge+vpc) and global
	dagNodes, globalNodes := separateByScope(allNodes)

	// If there are no DAG nodes, fall back to simple output
	if len(dagNodes) == 0 {
		return renderSimpleFallback(result)
	}

	// Detect and merge compound nodes (EKS+children, ECS+children, etc.)
	compounds := buildCompoundNodes(dagNodes)

	// Break bidirectional edges (e.g., ALB↔ECS Cluster from config refs)
	breakBidirectionalEdges(dagNodes)

	// Topological sort into levels (edge + vpc nodes only)
	levels := topoSortLevels(dagNodes)

	// Identify VPC node IDs
	vpcNodeIDs := getVPCNodeIDs(dagNodes)

	// Title (computed early for dynamic width calculation)
	title := fmt.Sprintf("Infrastructure Diagram — %s", result.Title)

	// Dynamic canvas width based on content
	canvasWidth := computeMinCanvasWidth(levels, dagNodes, compounds, vpcNodeIDs, globalNodes, title)

	// Calculate layout
	layout := calculateLayout(levels, dagNodes, compounds, vpcLayers, globalNodes, canvasWidth)

	// Create canvas
	canvas := NewCanvas(layout.TotalWidth, layout.TotalHeight+5)

	// Title (protected so arrows don't overwrite)
	titleX := (layout.TotalWidth - runeLen(title)) / 2
	if titleX < 0 {
		titleX = 0
	}
	canvas.WriteTextProtected(titleX, 0, title)
	underline := strings.Repeat("═", runeLen(title))
	ulX := (layout.TotalWidth - runeLen(underline)) / 2
	canvas.WriteTextProtected(ulX, 1, underline)

	// Offset all positions by 3 for title
	titleOff := 3
	shiftLayout(layout, titleOff)
	canvas.Grow(layout.TotalHeight + 5)

	// 1. Draw VPC border(s) with label (not protected — arrows pass through)
	for _, vr := range layout.VPCRects {
		canvas.DrawVPCBorderWithLabel(vr.X, vr.Y, vr.W, vr.H, vr.Title)
	}

	// 2. Draw subnet container borders (not protected — arrows pass through)
	for _, sc := range layout.SubnetContainers {
		canvas.DrawSubnetContainerBorder(sc.X, sc.Y, sc.W, sc.H, sc.Title)
	}

	// Populate arrow avoid ranges from box positions so horizontal segments
	// route around boxes (especially subnet tiers like Firewall Subnets).
	// Exclude distribution bars (H=1) — arrows pass through them vertically.
	for _, bp := range layout.Boxes {
		if bp.IsDistBar {
			continue
		}
		canvas.ArrowAvoidRanges = append(canvas.ArrowAvoidRanges, YRange{MinY: bp.Y, MaxY: bp.Y + bp.H - 1})
	}

	// 3. Draw arrows (before boxes, so boxes overwrite if overlapping)
	for _, a := range layout.Arrows {
		if a.Bidirectional {
			canvas.DrawRoutedBidirectionalArrow(a.FromX, a.FromY, a.ToX, a.ToY)
		} else {
			canvas.DrawRoutedArrow(a.FromX, a.FromY, a.ToX, a.ToY)
		}
	}

	// 3.5. Draw dashed arrows (NAT outbound + TGW wings)
	for _, a := range layout.DashedArrows {
		if a.FromY == a.ToY {
			// Horizontal dashed arrow (TGW wing)
			if a.ToX > a.FromX {
				canvas.DrawDashedArrowRight(a.FromX, a.ToX, a.FromY)
			} else {
				canvas.DrawDashedArrowLeft(a.FromX, a.ToX, a.FromY)
			}
		} else {
			// Vertical dashed arrow (NAT outbound)
			canvas.DrawDashedArrowUp(a.FromX, a.FromY, a.ToY)
		}
	}

	// 3.6. Draw dotted arrows (SG cross-references)
	for _, a := range layout.DottedArrows {
		if a.Bidirectional {
			canvas.DrawDottedBidirectionalArrow(a.FromX, a.FromY, a.ToX, a.ToY)
		} else {
			canvas.DrawDottedArrow(a.FromX, a.FromY, a.ToX, a.ToY)
		}
	}

	// 4. Draw all boxes (protected — overwrites arrows where they overlap)
	for _, bp := range layout.Boxes {
		if bp.IsDistBar {
			canvas.DrawDistributionBar(bp.X, bp.Y, bp.W, bp.Lines[0])
			continue
		}
		if bp.IsCompound {
			canvas.DrawCompoundBoxAction(bp.X, bp.Y, bp.W, bp.H, bp.CompoundTitle, bp.CompoundChildren, bp.Action)
			continue
		}
		canvas.DrawBoxAction(bp.X, bp.Y, bp.W, bp.H, bp.Lines, bp.Action)
	}

	// 4.5. Draw inline labels where arrows cross VPC gaps (multi-VPC)
	if len(layout.VPCRects) > 1 {
		drawVPCCrossingLabels(canvas, layout, dagNodes)
	}

	// 4. Draw global services grid (Zone 3)
	if layout.GlobalGrid != nil {
		drawGlobalGrid(canvas, layout.GlobalGrid)
	}

	// 5. Legend
	legendY := layout.TotalHeight
	canvas.Grow(legendY + 2)
	legend := "[+] create  [~] update  [-] delete  [!] replace  [*] mixed"
	legendX := (layout.TotalWidth - runeLen(legend)) / 2
	canvas.WriteText(legendX, legendY, legend)

	return "\n" + canvas.String()
}

// renderSimpleFallback renders when there are no active DAG nodes.
func renderSimpleFallback(result *TopoResult) string {
	var sb strings.Builder
	title := fmt.Sprintf("Infrastructure Diagram — %s", result.Title)
	sb.WriteString(fmt.Sprintf("\n%s\n", centerText(title, topoWidth)))
	sb.WriteString(fmt.Sprintf("%s\n\n", centerText(strings.Repeat("═", runeLen(title)), topoWidth)))

	internet := makeBox([]string{"Internet / Users"}, 0)
	writeBoxRowCentered(&sb, []renderedBox{internet}, topoWidth)

	for _, layer := range result.Layers {
		if len(layer.Groups) == 0 && len(layer.ComputeGroups) == 0 && len(layer.DataGroups) == 0 {
			continue
		}
		writeCenterConnector(&sb, topoWidth, "")
		subtitle := fmt.Sprintf("── %s ──", layer.Name)
		sb.WriteString(centerText(subtitle, topoWidth) + "\n")
		for _, g := range layer.Groups {
			label := fmt.Sprintf("%s %s", groupActionIcon(g.Action), g.Label)
			box := makeBox([]string{label}, 14)
			writeBoxRowCentered(&sb, []renderedBox{box}, topoWidth)
		}
	}

	sb.WriteString("\n")
	legend := "[+] create  [~] update  [-] delete  [!] replace  [*] mixed"
	sb.WriteString(centerText(legend, topoWidth) + "\n")
	return sb.String()
}

// shiftLayout offsets all Y positions by dy.
func shiftLayout(layout *LayoutResult, dy int) {
	for _, bp := range layout.Boxes {
		bp.Y += dy
	}
	for i := range layout.Arrows {
		layout.Arrows[i].FromY += dy
		layout.Arrows[i].ToY += dy
	}
	for i := range layout.DashedArrows {
		layout.DashedArrows[i].FromY += dy
		layout.DashedArrows[i].ToY += dy
	}
	for _, vr := range layout.VPCRects {
		vr.Y += dy
	}
	for _, sc := range layout.SubnetContainers {
		sc.Y += dy
	}
	if layout.GlobalGrid != nil {
		layout.GlobalGrid.Y += dy
	}
	layout.TotalHeight += dy
}

// --- Backward-compatible helpers ---

func makeBox(contentLines []string, minWidth int) renderedBox {
	w := minWidth
	for _, l := range contentLines {
		if needed := runeLen(l) + 4; needed > w {
			w = needed
		}
	}
	var lines []string
	lines = append(lines, sglCornerTL+strings.Repeat(sglHoriz, w-2)+sglCornerTR)
	for _, l := range contentLines {
		rpad := w - 3 - runeLen(l)
		if rpad < 0 {
			rpad = 0
		}
		lines = append(lines, sglVert+" "+l+strings.Repeat(" ", rpad)+sglVert)
	}
	lines = append(lines, sglCornerBL+strings.Repeat(sglHoriz, w-2)+sglCornerBR)
	return renderedBox{lines: lines, width: w}
}

func packIntoRows(boxes []renderedBox, maxWidth, gap int) [][]renderedBox {
	var rows [][]renderedBox
	var current []renderedBox
	currentW := 0
	for _, b := range boxes {
		needed := b.width
		if len(current) > 0 {
			needed += gap
		}
		if currentW+needed > maxWidth && len(current) > 0 {
			rows = append(rows, current)
			current = nil
			currentW = 0
			needed = b.width
		}
		current = append(current, b)
		currentW += needed
	}
	if len(current) > 0 {
		rows = append(rows, current)
	}
	return rows
}

func normalizeRowHeights(row []renderedBox) {
	maxH := 0
	for _, b := range row {
		if len(b.lines) > maxH {
			maxH = len(b.lines)
		}
	}
	for i := range row {
		h := len(row[i].lines)
		if h < maxH {
			bottom := row[i].lines[h-1]
			row[i].lines = row[i].lines[:h-1]
			for j := 0; j < maxH-h; j++ {
				row[i].lines = append(row[i].lines, sglVert+strings.Repeat(" ", row[i].width-2)+sglVert)
			}
			row[i].lines = append(row[i].lines, bottom)
		}
	}
}

func boxRowToLines(row []renderedBox, maxWidth, gap int) []string {
	if len(row) == 0 {
		return nil
	}
	normalizeRowHeights(row)
	numLines := len(row[0].lines)
	rowWidth := 0
	for i, b := range row {
		if i > 0 {
			rowWidth += gap
		}
		rowWidth += b.width
	}
	leftOff := (maxWidth - rowWidth) / 2
	if leftOff < 0 {
		leftOff = 0
	}
	var lines []string
	for li := 0; li < numLines; li++ {
		var sb strings.Builder
		sb.WriteString(strings.Repeat(" ", leftOff))
		for bi, b := range row {
			if bi > 0 {
				sb.WriteString(strings.Repeat(" ", gap))
			}
			sb.WriteString(b.lines[li])
		}
		lines = append(lines, sb.String())
	}
	return lines
}

func writeBoxRowCentered(sb *strings.Builder, row []renderedBox, totalWidth int) {
	for _, line := range boxRowToLines(row, totalWidth, 2) {
		sb.WriteString(line + "\n")
	}
}

func writeVPCLine(sb *strings.Builder, content string, vpcW int) {
	rpad := vpcW - 2 - runeLen(content)
	if rpad < 0 {
		rpad = 0
	}
	sb.WriteString(fmt.Sprintf("  %s  %s%s%s\n", dblVert, content, strings.Repeat(" ", rpad), dblVert))
}

func writeCenterConnector(sb *strings.Builder, totalWidth int, prefix string) {
	center := totalWidth / 2
	sb.WriteString(prefix + strings.Repeat(" ", center) + topoConnector + "\n")
	sb.WriteString(prefix + strings.Repeat(" ", center) + topoArrowDown + "\n")
}

func formatSubnetSummary(s *SubnetSummary) string {
	var parts []string
	if s.Public > 0 {
		parts = append(parts, fmt.Sprintf("%d public", s.Public))
	}
	if s.PrivateApp > 0 {
		parts = append(parts, fmt.Sprintf("%d private_app", s.PrivateApp))
	}
	if s.PrivateData > 0 {
		parts = append(parts, fmt.Sprintf("%d private_data", s.PrivateData))
	}
	if s.Private > 0 {
		parts = append(parts, fmt.Sprintf("%d private", s.Private))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Subnets: " + strings.Join(parts, " · ")
}

func buildCompactLines(groups []*AggregatedGroup, maxWidth int) []string {
	if len(groups) == 0 {
		return nil
	}
	var lines []string
	var current string
	separator := " · "
	for _, g := range groups {
		label := g.Label
		if current == "" {
			current = label
			continue
		}
		candidate := current + separator + label
		if runeLen(candidate) <= maxWidth {
			current = candidate
		} else {
			lines = append(lines, current)
			current = label
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func groupsToLines(groups []*AggregatedGroup) []string {
	var lines []string
	for _, g := range groups {
		icon := groupActionIcon(g.Action)
		lines = append(lines, fmt.Sprintf("%s %s", icon, g.Label))
	}
	return lines
}

func groupActionIcon(action string) string {
	switch action {
	case "create":
		return "[+]"
	case "update":
		return "[~]"
	case "delete":
		return "[-]"
	case "replace":
		return "[!]"
	case "mixed":
		return "[*]"
	default:
		return "[ ]"
	}
}

// wrapWithSeparator joins parts with sep, wrapping into multiple lines at maxWidth.
func wrapWithSeparator(parts []string, sep string, maxWidth int) []string {
	if len(parts) == 0 {
		return nil
	}
	var lines []string
	current := parts[0]
	for _, p := range parts[1:] {
		candidate := current + sep + p
		if runeLen(candidate) <= maxWidth {
			current = candidate
		} else {
			lines = append(lines, current)
			current = p
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func truncateLabel(s string, maxLen int) string {
	if runeLen(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}

// serviceAbbrev maps service names to short abbreviations for inline labels.
var serviceAbbrev = map[string]string{
	"CloudFront":       "CF",
	"API Gateway":      "API-GW",
	"Route 53":         "R53",
	"Load Balancer":    "LB",
	"ALB":              "ALB",
	"NLB":              "NLB",
	"ALB Internal":     "ALB-Int",
	"NLB Internal":     "NLB-Int",
	"Lambda":           "Lambda",
	"EKS Cluster":      "EKS",
	"ECS Cluster":      "ECS",
	"Network Firewall": "NFW",
	"Auto Scaling":     "ASG",
	"Aurora RDS":       "RDS",
	"DynamoDB":         "DDB",
	"ElastiCache":      "Cache",
}

func abbreviateService(service string) string {
	if abbr, ok := serviceAbbrev[service]; ok {
		return abbr
	}
	// Truncate long names
	if len(service) > 10 {
		return service[:10]
	}
	return service
}

// arrowXAtY returns the arrow's X coordinate at a given Y position.
// Accounts for L-shaped routing (vertical at fromX, then vertical at toX).
func arrowXAtY(a ArrowDef, y int) int {
	dx := a.FromX - a.ToX
	if dx < 0 {
		dx = -dx
	}
	// Near-vertical arrows stay at toX
	if dx <= 2 {
		return a.ToX
	}
	midY := a.FromY + (a.ToY-a.FromY)/2
	if y <= midY {
		return a.FromX
	}
	return a.ToX
}

// drawVPCCrossingLabels renders inline labels for arrows that pass through
// VPC gaps. Labels identify the flow chain's edge service (e.g., CF, API-GW),
// not the immediate arrow source, so arrows from internal nodes like RDS don't
// produce noise labels.
func drawVPCCrossingLabels(canvas *Canvas, layout *LayoutResult, dagNodes map[string]*ServiceNode) {
	// Sort VPC rects by Y position
	sorted := make([]*VPCRect, len(layout.VPCRects))
	copy(sorted, layout.VPCRects)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Y < sorted[i].Y {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// For each gap between consecutive VPCs, find passing arrows
	for g := 0; g < len(sorted)-1; g++ {
		gapTopY := sorted[g].Y + sorted[g].H   // bottom border of VPC above
		gapBotY := sorted[g+1].Y               // top border of VPC below
		if gapBotY-gapTopY < 3 {
			continue // gap too small for labels
		}
		labelY := gapTopY + 2 // 2 rows below the VPC bottom border

		// Track used X ranges to avoid label overlap
		type labelEntry struct {
			x    int
			text string
		}
		var labels []labelEntry

		for _, a := range layout.Arrows {
			// Arrow must span this gap (start above, end below)
			if a.FromY >= gapTopY || a.ToY <= gapBotY {
				continue
			}

			// Label from flow chain root (edge service), not the arrow source.
			// Skip arrows from unchained nodes — they don't represent a named flow.
			ci, ok := layout.NodeToChain[a.FromID]
			if !ok {
				// Try destination node's chain as fallback
				ci, ok = layout.NodeToChain[a.ToID]
			}
			if !ok || ci >= len(layout.Chains) {
				continue
			}
			rootNode := dagNodes[layout.Chains[ci].RootID]
			if rootNode == nil {
				continue
			}
			abbr := abbreviateService(rootNode.Service)

			arrowX := arrowXAtY(a, labelY)
			text := "(" + abbr + ")"
			labels = append(labels, labelEntry{x: arrowX, text: text})
		}

		// Deduplicate labels at the same X position
		seen := make(map[int]bool)
		var deduped []labelEntry
		for _, l := range labels {
			if !seen[l.x] {
				seen[l.x] = true
				deduped = append(deduped, l)
			}
		}
		labels = deduped

		// Render labels, avoiding overlap
		for _, l := range labels {
			overlap := false
			for _, other := range labels {
				if other.x == l.x {
					continue
				}
				lEnd := l.x + 1 + runeLen(l.text)
				oEnd := other.x + 1 + runeLen(other.text)
				if l.x+1 < oEnd && lEnd > other.x+1 && other.x < l.x {
					overlap = true
					break
				}
			}
			if !overlap {
				canvas.WriteText(l.x+1, labelY, l.text)
			}
		}
	}
}
