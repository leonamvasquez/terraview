package diagram

import "fmt"

const (
	gridColumns     = 4  // boxes per row
	gridBoxMinWidth = 14 // minimum box width
	gridBoxGap      = 2  // gap between boxes in a row
	gridRowGap      = 1  // gap between rows
)

// GlobalGridResult holds the computed layout for the global services grid.
type GlobalGridResult struct {
	X, Y, W, H int
	Title      string
	Rows       [][]gridBox
}

type gridBox struct {
	Label  string
	Action string
	W      int
}

// globalServiceCategory maps service name to display category for grouping.
var globalServiceCategory = map[string]string{
	"CloudWatch":     "Observability",
	"CloudTrail":     "Observability",
	"AWS Config":     "Observability",
	"Prometheus":     "Observability",
	"Grafana":        "Observability",
	"X-Ray Sampling": "Observability",
	"aws_xray_group": "Observability",
	"Synthetics":     "Observability",

	"SNS":         "Messaging",
	"SQS":         "Messaging",
	"EventBridge": "Messaging",

	"S3":     "Storage",
	"Backup": "Storage",

	"CodePipeline":    "CI/CD",
	"CodeBuild":       "CI/CD",
	"CodeCommit":      "CI/CD",
	"CodeCommit Repo": "CI/CD",
	"ECR":             "CI/CD",

	"IAM":                 "Security",
	"KMS":                 "Security",
	"Secrets Manager":     "Security",
	"SSM Parameter Store": "Security",
	"SSM":                 "Security",
	"GuardDuty":           "Security",
	"SecurityHub":         "Security",
	"Macie":               "Security",
}

// categoryOrder defines the display order for global service categories.
var categoryOrder = []string{
	"Observability", "Messaging", "Storage", "CI/CD", "Security", "Other",
}

// buildGlobalGrid builds a grid layout of global service nodes.
func buildGlobalGrid(globalNodes []*ServiceNode, canvasWidth int) *GlobalGridResult {
	if len(globalNodes) == 0 {
		return nil
	}

	// Sort by category, then alphabetically within category
	sorted := categorizeGlobalServices(globalNodes)

	// Build grid boxes
	boxes := make([]gridBox, 0, len(sorted))
	for _, n := range sorted {
		label := n.Label
		icon := groupActionIcon(n.Action)
		if icon != "[ ]" {
			label = fmt.Sprintf("%s %s", icon, n.Label)
		}
		w := runeLen(label) + 4
		if w < gridBoxMinWidth {
			w = gridBoxMinWidth
		}
		boxes = append(boxes, gridBox{Label: label, Action: n.Action, W: w})
	}

	// Determine column count based on available width
	innerW := canvasWidth - 8 // outer box margins
	cols := gridColumns
	if innerW < cols*gridBoxMinWidth+(cols-1)*gridBoxGap {
		cols = 3
	}
	if cols < 1 {
		cols = 1
	}

	// Normalize widths: each row's boxes get the same width
	var rows [][]gridBox
	for i := 0; i < len(boxes); i += cols {
		end := i + cols
		if end > len(boxes) {
			end = len(boxes)
		}
		row := make([]gridBox, end-i)
		copy(row, boxes[i:end])

		// Find max width in this row
		maxW := 0
		for _, b := range row {
			if b.W > maxW {
				maxW = b.W
			}
		}
		// Cap to fit available width
		maxAllowed := (innerW - (len(row)-1)*gridBoxGap) / len(row)
		if maxW > maxAllowed && maxAllowed > gridBoxMinWidth {
			maxW = maxAllowed
		}
		for j := range row {
			row[j].W = maxW
		}

		rows = append(rows, row)
	}

	// Calculate dimensions
	titleLine := "Global / Regional Services"
	gridInnerH := len(rows)*(3+gridRowGap) - gridRowGap // box rows
	if gridInnerH < 0 {
		gridInnerH = 0
	}
	totalH := gridInnerH + 4 // title + top/bottom borders + padding

	// Width: max of title or widest row
	totalW := runeLen(titleLine) + 8
	for _, row := range rows {
		rowW := 6 // left + right padding
		for i, b := range row {
			if i > 0 {
				rowW += gridBoxGap
			}
			rowW += b.W
		}
		if rowW > totalW {
			totalW = rowW
		}
	}
	if totalW > canvasWidth-4 {
		totalW = canvasWidth - 4
	}

	return &GlobalGridResult{
		W:     totalW,
		H:     totalH,
		Title: titleLine,
		Rows:  rows,
	}
}

// categorizeGlobalServices sorts nodes by category order, then alphabetically.
func categorizeGlobalServices(nodes []*ServiceNode) []*ServiceNode {
	catNodes := make(map[string][]*ServiceNode)
	for _, n := range nodes {
		cat := globalServiceCategory[n.Service]
		if cat == "" {
			cat = "Other"
		}
		catNodes[cat] = append(catNodes[cat], n)
	}

	// Sort within each category
	for _, list := range catNodes {
		for i := 0; i < len(list); i++ {
			for j := i + 1; j < len(list); j++ {
				if list[j].ID < list[i].ID {
					list[i], list[j] = list[j], list[i]
				}
			}
		}
	}

	var result []*ServiceNode
	for _, cat := range categoryOrder {
		result = append(result, catNodes[cat]...)
	}
	return result
}

// drawGlobalGrid renders the grid on the canvas.
func drawGlobalGrid(canvas *Canvas, grid *GlobalGridResult) {
	if grid == nil {
		return
	}

	x, y := grid.X, grid.Y

	// Draw outer container box
	canvas.DrawBox(x, y, grid.W, grid.H, nil)

	// Title
	canvas.WriteTextProtected(x+3, y+1, grid.Title)

	// Draw grid rows
	rowY := y + 3
	for _, row := range grid.Rows {
		boxX := x + 3
		for _, box := range row {
			canvas.DrawBox(boxX, rowY, box.W, 3, []string{box.Label})
			boxX += box.W + gridBoxGap
		}
		rowY += 3 + gridRowGap
	}
}
