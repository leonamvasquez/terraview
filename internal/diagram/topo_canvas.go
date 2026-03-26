package diagram

import "strings"

// YRange represents a vertical range [MinY, MaxY] inclusive.
type YRange struct{ MinY, MaxY int }

// Canvas is a 2D character grid for rendering the diagram.
type Canvas struct {
	Width            int
	Height           int
	Cells            [][]rune
	Protected        [][]bool  // cells owned by boxes — arrows cannot overwrite
	ArrowAvoidRanges []YRange  // Y ranges occupied by boxes; set before arrow drawing
}

// Box-drawing runes for the canvas.
const (
	cBoxTL    = '┌'
	cBoxTR    = '┐'
	cBoxBL    = '└'
	cBoxBR    = '┘'
	cBoxH     = '─'
	cBoxV     = '│'
	cDblTL    = '╔'
	cDblTR    = '╗'
	cDblBL    = '╚'
	cDblBR    = '╝'
	cDblH     = '═'
	cDblV     = '║'
	cArrowD   = '▼'
	cArrowU   = '▲'
	cArrowR   = '▶'
	cDashH    = '╌' // U+254C — dashed horizontal (update border)
	cDashV    = '╎'
	cTeeDown  = '┬'
	cTeeUp    = '┴'
	cTeeRight = '├'
	cTeeLeft  = '┤'
	cCross    = '┼'
)

// NewCanvas creates a canvas filled with spaces.
func NewCanvas(width, height int) *Canvas {
	cells := make([][]rune, height)
	prot := make([][]bool, height)
	for y := range cells {
		cells[y] = make([]rune, width)
		prot[y] = make([]bool, width)
		for x := range cells[y] {
			cells[y][x] = ' '
		}
	}
	return &Canvas{Width: width, Height: height, Cells: cells, Protected: prot}
}

// Set places a rune at (x, y) if within bounds.
func (c *Canvas) Set(x, y int, r rune) {
	if x >= 0 && x < c.Width && y >= 0 && y < c.Height {
		c.Cells[y][x] = r
	}
}

// SetProtected places a rune and marks the cell as protected.
func (c *Canvas) SetProtected(x, y int, r rune) {
	if x >= 0 && x < c.Width && y >= 0 && y < c.Height {
		c.Cells[y][x] = r
		c.Protected[y][x] = true
	}
}

// IsProtected checks if a cell is owned by a box.
func (c *Canvas) IsProtected(x, y int) bool {
	if x >= 0 && x < c.Width && y >= 0 && y < c.Height {
		return c.Protected[y][x]
	}
	return true
}

// Get returns the rune at (x, y), or ' ' if out of bounds.
func (c *Canvas) Get(x, y int) rune {
	if x >= 0 && x < c.Width && y >= 0 && y < c.Height {
		return c.Cells[y][x]
	}
	return ' '
}

// WriteText writes a string starting at (x, y), one rune per column.
func (c *Canvas) WriteText(x, y int, text string) {
	col := 0
	for _, r := range text {
		c.Set(x+col, y, r)
		col++
	}
}

// WriteTextProtected writes a string and marks all cells as protected.
func (c *Canvas) WriteTextProtected(x, y int, text string) {
	col := 0
	for _, r := range text {
		c.SetProtected(x+col, y, r)
		col++
	}
}

// DrawBox draws a single-line bordered box at (x, y) with given width and height.
// All cells are marked as protected so arrows cannot overwrite.
func (c *Canvas) DrawBox(x, y, w, h int, lines []string) {
	if w < 2 || h < 2 {
		return
	}
	// Top border
	c.SetProtected(x, y, cBoxTL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y, cBoxH)
	}
	c.SetProtected(x+w-1, y, cBoxTR)

	// Content rows
	for row := 1; row < h-1; row++ {
		c.SetProtected(x, y+row, cBoxV)
		c.SetProtected(x+w-1, y+row, cBoxV)
		for col := 1; col < w-1; col++ {
			c.SetProtected(x+col, y+row, ' ')
		}
	}

	// Write content lines
	for i, line := range lines {
		row := y + 1 + i
		if row >= y+h-1 {
			break
		}
		pad := (w - 2 - runeLen(line)) / 2
		if pad < 0 {
			pad = 0
		}
		c.WriteTextProtected(x+1+pad, row, line)
	}

	// Bottom border
	c.SetProtected(x, y+h-1, cBoxBL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y+h-1, cBoxH)
	}
	c.SetProtected(x+w-1, y+h-1, cBoxBR)
}

// DrawBoxAction draws a bordered box whose border style encodes the diff action:
//
//	create  → ┌──┐ / └──┘  (standard single-line)
//	update  → ┌╌╌┐ / └╌╌┘  (dashed horizontal)
//	replace → ┌!─┐ / └──┘  (! marker after TL corner)
//	mixed   → ╔══╗ / ╚══╝  (double border)
//	default → same as create
func (c *Canvas) DrawBoxAction(x, y, w, h int, lines []string, action string) {
	if w < 2 || h < 2 {
		return
	}
	switch action {
	case "mixed":
		c.drawBoxDouble(x, y, w, h, lines)
	case "update":
		c.drawBoxDashed(x, y, w, h, lines)
	case "replace":
		c.drawBoxReplace(x, y, w, h, lines)
	default:
		c.DrawBox(x, y, w, h, lines)
	}
}

// drawBoxDouble draws a double-line border (╔══╗ / ╚══╝) for mixed actions.
func (c *Canvas) drawBoxDouble(x, y, w, h int, lines []string) {
	// Top border
	c.SetProtected(x, y, cDblTL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y, cDblH)
	}
	c.SetProtected(x+w-1, y, cDblTR)

	// Content rows
	for row := 1; row < h-1; row++ {
		c.SetProtected(x, y+row, cDblV)
		c.SetProtected(x+w-1, y+row, cDblV)
		for col := 1; col < w-1; col++ {
			c.SetProtected(x+col, y+row, ' ')
		}
	}

	// Write content lines
	for i, line := range lines {
		row := y + 1 + i
		if row >= y+h-1 {
			break
		}
		pad := (w - 2 - runeLen(line)) / 2
		if pad < 0 {
			pad = 0
		}
		c.WriteTextProtected(x+1+pad, row, line)
	}

	// Bottom border
	c.SetProtected(x, y+h-1, cDblBL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y+h-1, cDblH)
	}
	c.SetProtected(x+w-1, y+h-1, cDblBR)
}

// drawBoxDashed draws a dashed-horizontal border (┌╌╌┐ / └╌╌┘) for update actions.
func (c *Canvas) drawBoxDashed(x, y, w, h int, lines []string) {
	// Top border — corners are standard, fill is dashed
	c.SetProtected(x, y, cBoxTL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y, cDashH)
	}
	c.SetProtected(x+w-1, y, cBoxTR)

	// Content rows — standard vertical sides
	for row := 1; row < h-1; row++ {
		c.SetProtected(x, y+row, cBoxV)
		c.SetProtected(x+w-1, y+row, cBoxV)
		for col := 1; col < w-1; col++ {
			c.SetProtected(x+col, y+row, ' ')
		}
	}

	// Write content lines
	for i, line := range lines {
		row := y + 1 + i
		if row >= y+h-1 {
			break
		}
		pad := (w - 2 - runeLen(line)) / 2
		if pad < 0 {
			pad = 0
		}
		c.WriteTextProtected(x+1+pad, row, line)
	}

	// Bottom border — dashed fill
	c.SetProtected(x, y+h-1, cBoxBL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y+h-1, cDashH)
	}
	c.SetProtected(x+w-1, y+h-1, cBoxBR)
}

// drawBoxReplace draws a replace border (┌!─┐ / └──┘) with ! after TL corner.
func (c *Canvas) drawBoxReplace(x, y, w, h int, lines []string) {
	// Top border — standard with ! marker at position 1
	c.SetProtected(x, y, cBoxTL)
	if w > 2 {
		c.SetProtected(x+1, y, '!')
	}
	for i := 2; i < w-1; i++ {
		c.SetProtected(x+i, y, cBoxH)
	}
	c.SetProtected(x+w-1, y, cBoxTR)

	// Content rows
	for row := 1; row < h-1; row++ {
		c.SetProtected(x, y+row, cBoxV)
		c.SetProtected(x+w-1, y+row, cBoxV)
		for col := 1; col < w-1; col++ {
			c.SetProtected(x+col, y+row, ' ')
		}
	}

	// Write content lines
	for i, line := range lines {
		row := y + 1 + i
		if row >= y+h-1 {
			break
		}
		pad := (w - 2 - runeLen(line)) / 2
		if pad < 0 {
			pad = 0
		}
		c.WriteTextProtected(x+1+pad, row, line)
	}

	// Bottom border — standard
	c.SetProtected(x, y+h-1, cBoxBL)
	for i := 1; i < w-1; i++ {
		c.SetProtected(x+i, y+h-1, cBoxH)
	}
	c.SetProtected(x+w-1, y+h-1, cBoxBR)
}

// DrawVPCBorder draws a double-line border for the VPC container.
// NOT protected — arrows can pass through.
func (c *Canvas) DrawVPCBorder(x, y, w, h int) {
	if w < 2 || h < 2 {
		return
	}
	c.Set(x, y, cDblTL)
	for i := 1; i < w-1; i++ {
		c.Set(x+i, y, cDblH)
	}
	c.Set(x+w-1, y, cDblTR)

	for row := 1; row < h-1; row++ {
		c.Set(x, y+row, cDblV)
		c.Set(x+w-1, y+row, cDblV)
	}

	c.Set(x, y+h-1, cDblBL)
	for i := 1; i < w-1; i++ {
		c.Set(x+i, y+h-1, cDblH)
	}
	c.Set(x+w-1, y+h-1, cDblBR)
}

// DrawDistributionBar draws a wide thin bar: ╶─── label ───╴ (protected).
func (c *Canvas) DrawDistributionBar(x, y, w int, label string) {
	if w < 4 {
		return
	}
	right := x + w - 1
	c.SetProtected(x, y, '╶')
	c.SetProtected(right, y, '╴')

	// Center the label with spaces around it
	padded := " " + label + " "
	labelStart := x + (w-runeLen(padded))/2
	if labelStart < x+1 {
		labelStart = x + 1
	}
	runes := []rune(padded)
	for col := x + 1; col < right; col++ {
		ri := col - labelStart
		if ri >= 0 && ri < len(runes) {
			c.SetProtected(col, y, runes[ri])
		} else {
			c.SetProtected(col, y, cBoxH)
		}
	}
}

// DrawCompoundBox draws an outer box with title and inner child boxes (all protected).
func (c *Canvas) DrawCompoundBox(x, y, w, h int, title string, children []*CompoundChild) {
	// Draw outer box (border + protected interior)
	c.DrawBox(x, y, w, h, nil)

	// Write parent title at top-left inside
	c.WriteTextProtected(x+2, y+1, title)

	// Place inner boxes side by side starting at row y+3
	innerX := x + 2
	innerY := y + 3
	for _, child := range children {
		if innerX+child.W > x+w-2 {
			break // don't overflow outer box
		}
		c.DrawBox(innerX, innerY, child.W, child.H, child.Lines)
		innerX += child.W + 2
	}
}

// DrawCompoundBoxAction draws an outer action-styled box with inner child boxes.
// The outer border uses the parent action style; inner children use their own action.
func (c *Canvas) DrawCompoundBoxAction(x, y, w, h int, title string, children []*CompoundChild, action string) {
	// Draw outer box with action-aware border
	c.DrawBoxAction(x, y, w, h, nil, action)

	// Write parent title at top-left inside
	c.WriteTextProtected(x+2, y+1, title)

	// Place inner boxes side by side starting at row y+3
	innerX := x + 2
	innerY := y + 3
	for _, child := range children {
		if innerX+child.W > x+w-2 {
			break // don't overflow outer box
		}
		c.DrawBoxAction(innerX, innerY, child.W, child.H, child.Lines, child.Action)
		innerX += child.W + 2
	}
}

// DrawVPCBorderWithLabel draws a double-line border with label on top: ╔═ VPC ═══╗
// NOT protected — arrows can pass through.
func (c *Canvas) DrawVPCBorderWithLabel(x, y, w, h int, label string) {
	if w < 2 || h < 2 {
		return
	}
	// Top border with embedded label: ╔═ label ═══╗
	c.Set(x, y, cDblTL)
	c.Set(x+1, y, cDblH)
	c.Set(x+2, y, ' ')
	col := x + 3
	for _, r := range label {
		if col < x+w-2 {
			c.Set(col, y, r)
			col++
		}
	}
	if col < x+w-1 {
		c.Set(col, y, ' ')
		col++
	}
	for col < x+w-1 {
		c.Set(col, y, cDblH)
		col++
	}
	c.Set(x+w-1, y, cDblTR)

	// Sides
	for row := 1; row < h-1; row++ {
		c.Set(x, y+row, cDblV)
		c.Set(x+w-1, y+row, cDblV)
	}

	// Bottom
	c.Set(x, y+h-1, cDblBL)
	for i := 1; i < w-1; i++ {
		c.Set(x+i, y+h-1, cDblH)
	}
	c.Set(x+w-1, y+h-1, cDblBR)
}

// DrawSubnetBox draws a subnet box with title and optional inner components (protected).
func (c *Canvas) DrawSubnetBox(x, y, w, h int, title string, innerLabels []string) {
	c.DrawBox(x, y, w, h, nil)
	// Title at top-left
	c.WriteTextProtected(x+2, y+1, title)

	// Inner component boxes (small, side by side)
	if len(innerLabels) > 0 {
		ix := x + 2
		iy := y + 2
		for _, lbl := range innerLabels {
			iw := runeLen(lbl) + 4
			ih := 3
			if ix+iw > x+w-2 {
				break
			}
			c.DrawBox(ix, iy, iw, ih, []string{lbl})
			ix += iw + 1
		}
	}
}

// DrawSubnetContainerBorder draws a single-line border with title centered in the
// top border: ┌──── Title ────┐. NOT protected — arrows can pass through the border.
// Title characters are protected so arrows don't overwrite them.
func (c *Canvas) DrawSubnetContainerBorder(x, y, w, h int, title string) {
	if w < 2 || h < 2 {
		return
	}
	// Top border with centered title: ┌──── Title ────┐
	c.Set(x, y, cBoxTL)
	c.Set(x+w-1, y, cBoxTR)

	if title != "" {
		padded := " " + title + " "
		titleLen := runeLen(padded)
		innerW := w - 2 // space between corners
		labelStart := 1 + (innerW-titleLen)/2
		if labelStart < 1 {
			labelStart = 1
		}
		runes := []rune(padded)
		for i := 1; i < w-1; i++ {
			ri := i - labelStart
			if ri >= 0 && ri < len(runes) {
				c.SetProtected(x+i, y, runes[ri])
			} else {
				c.Set(x+i, y, cBoxH)
			}
		}
	} else {
		for i := 1; i < w-1; i++ {
			c.Set(x+i, y, cBoxH)
		}
	}

	// Sides
	for row := 1; row < h-1; row++ {
		c.Set(x, y+row, cBoxV)
		c.Set(x+w-1, y+row, cBoxV)
	}

	// Bottom
	c.Set(x, y+h-1, cBoxBL)
	for i := 1; i < w-1; i++ {
		c.Set(x+i, y+h-1, cBoxH)
	}
	c.Set(x+w-1, y+h-1, cBoxBR)
}

// DrawDashedBox draws a dashed border for cross-cutting services (protected).
func (c *Canvas) DrawDashedBox(x, y, w, h int) {
	if w < 2 || h < 2 {
		return
	}
	for i := 0; i < w; i++ {
		if i%2 == 0 {
			c.SetProtected(x+i, y, cBoxH)
		} else {
			c.SetProtected(x+i, y, ' ')
		}
	}
	for row := 1; row < h-1; row++ {
		if row%2 == 1 {
			c.SetProtected(x, y+row, cBoxV)
			c.SetProtected(x+w-1, y+row, cBoxV)
		}
	}
	for i := 0; i < w; i++ {
		if i%2 == 0 {
			c.SetProtected(x+i, y+h-1, cBoxH)
		} else {
			c.SetProtected(x+i, y+h-1, ' ')
		}
	}
}

// setArrow writes an arrow character, respecting protected cells.
func (c *Canvas) setArrow(x, y int, r rune) {
	if c.IsProtected(x, y) {
		return
	}
	existing := c.Get(x, y)
	// Handle junction characters
	switch {
	case existing == cBoxV && (r == cBoxH || isHorizConnector(r)):
		c.Set(x, y, cCross)
	case existing == cBoxH && (r == cBoxV || isVertConnector(r)):
		c.Set(x, y, cCross)
	case existing == cDblH && r == cBoxV:
		// Arrow passes through VPC border
		c.Set(x, y, cBoxV)
	case existing == cDblV:
		// Arrow passes through VPC side border
		c.Set(x, y, cBoxV)
	case (r == cDashV || r == '·') && existing == cBoxH:
		// Dashed/dotted lines must not corrupt horizontal tier borders
		return
	default:
		c.Set(x, y, r)
	}
}

// DrawRoutedArrow draws an arrow from (fromX, fromY) to (toX, toY).
// Uses an L-shaped route through a midpoint row.
func (c *Canvas) DrawRoutedArrow(fromX, fromY, toX, toY int) {
	if fromY >= toY {
		return
	}

	// Treat near-vertical arrows (offset ≤ 2 cols) as straight vertical
	// to avoid tiny L-shaped artifacts like └┐
	dx := fromX - toX
	if dx < 0 {
		dx = -dx
	}
	if dx <= 2 {
		for y := fromY; y < toY; y++ {
			c.setArrow(toX, y, cBoxV)
		}
		c.setArrow(toX, toY, cArrowD)
		return
	}

	// Route: down from source to midY, horizontal to toX, then down to target.
	// Place the elbow close to the destination so it doesn't float in empty space.
	midY := toY - 2

	// Avoid placing horizontal segment on rows occupied by boxes.
	// Uses ArrowAvoidYRanges set by the renderer before arrow drawing.
	midY = c.avoidBoxRows(midY, fromY+1, toY-1)

	// Vertical from source to mid
	for y := fromY; y < midY; y++ {
		c.setArrow(fromX, y, cBoxV)
	}

	// Corner at (fromX, midY)
	if fromX < toX {
		c.setArrow(fromX, midY, cBoxBL)
	} else {
		c.setArrow(fromX, midY, cBoxBR)
	}

	// Horizontal from fromX to toX at midY
	hStart, hEnd := fromX, toX
	if hStart > hEnd {
		hStart, hEnd = hEnd, hStart
	}
	for x := hStart + 1; x < hEnd; x++ {
		c.setArrow(x, midY, cBoxH)
	}

	// Corner at (toX, midY)
	if fromX < toX {
		c.setArrow(toX, midY, cBoxTR)
	} else {
		c.setArrow(toX, midY, cBoxTL)
	}

	// Vertical from midY+1 to target
	for y := midY + 1; y < toY; y++ {
		c.setArrow(toX, y, cBoxV)
	}
	c.setArrow(toX, toY, cArrowD)
}

// DrawRoutedBidirectionalArrow draws a routed arrow with ◄ at the top (source) and ▼ at the bottom (target).
func (c *Canvas) DrawRoutedBidirectionalArrow(fromX, fromY, toX, toY int) {
	if fromY >= toY {
		return
	}

	dx := fromX - toX
	if dx < 0 {
		dx = -dx
	}
	if dx <= 2 {
		c.setArrow(toX, fromY, '◄')
		for y := fromY + 1; y < toY; y++ {
			c.setArrow(toX, y, cBoxV)
		}
		c.setArrow(toX, toY, cArrowD)
		return
	}

	// Same routing as DrawRoutedArrow but with ◄ at source
	midY := toY - 2
	midY = c.avoidBoxRows(midY, fromY+1, toY-1)

	c.setArrow(fromX, fromY, '◄')
	for y := fromY + 1; y < midY; y++ {
		c.setArrow(fromX, y, cBoxV)
	}
	if fromX < toX {
		c.setArrow(fromX, midY, cBoxBL)
	} else {
		c.setArrow(fromX, midY, cBoxBR)
	}
	hStart, hEnd := fromX, toX
	if hStart > hEnd {
		hStart, hEnd = hEnd, hStart
	}
	for x := hStart + 1; x < hEnd; x++ {
		c.setArrow(x, midY, cBoxH)
	}
	if fromX < toX {
		c.setArrow(toX, midY, cBoxTR)
	} else {
		c.setArrow(toX, midY, cBoxTL)
	}
	for y := midY + 1; y < toY; y++ {
		c.setArrow(toX, y, cBoxV)
	}
	c.setArrow(toX, toY, cArrowD)
}

// DrawDottedBidirectionalArrow draws a dotted arrow with ◄ at top and ▼ at bottom.
func (c *Canvas) DrawDottedBidirectionalArrow(fromX, fromY, toX, toY int) {
	if fromY >= toY {
		return
	}

	dx := fromX - toX
	if dx < 0 {
		dx = -dx
	}
	if dx <= 2 {
		c.setArrow(toX, fromY, '◄')
		for y := fromY + 1; y < toY; y++ {
			c.setArrow(toX, y, '·')
		}
		c.setArrow(toX, toY, cArrowD)
		return
	}

	midY := fromY + (toY-fromY)/2
	midY = c.avoidBoxRows(midY, fromY+1, toY-1)

	c.setArrow(fromX, fromY, '◄')
	for y := fromY + 1; y < midY; y++ {
		c.setArrow(fromX, y, '·')
	}
	c.setArrow(fromX, midY, '·')
	hStart, hEnd := fromX, toX
	if hStart > hEnd {
		hStart, hEnd = hEnd, hStart
	}
	for x := hStart + 1; x < hEnd; x++ {
		c.setArrow(x, midY, '·')
	}
	c.setArrow(toX, midY, '·')
	for y := midY + 1; y < toY; y++ {
		c.setArrow(toX, y, '·')
	}
	c.setArrow(toX, toY, cArrowD)
}

// String renders the canvas to a string, trimming trailing spaces per line
// and removing trailing empty lines.
func (c *Canvas) String() string {
	var sb strings.Builder
	lastNonEmpty := 0
	for y := 0; y < c.Height; y++ {
		line := string(c.Cells[y])
		trimmed := strings.TrimRight(line, " ")
		if trimmed != "" {
			lastNonEmpty = y
		}
	}
	for y := 0; y <= lastNonEmpty+1 && y < c.Height; y++ {
		line := string(c.Cells[y])
		sb.WriteString(strings.TrimRight(line, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Grow increases the canvas height if needed.
func (c *Canvas) Grow(newHeight int) {
	if newHeight <= c.Height {
		return
	}
	for y := c.Height; y < newHeight; y++ {
		row := make([]rune, c.Width)
		prot := make([]bool, c.Width)
		for x := range row {
			row[x] = ' '
		}
		c.Cells = append(c.Cells, row)
		c.Protected = append(c.Protected, prot)
	}
	c.Height = newHeight
}

// avoidBoxRows adjusts preferredY so it doesn't land inside a box Y range.
// Searches alternately above/below for a row not inside any ArrowAvoidRanges.
func (c *Canvas) avoidBoxRows(preferredY, minY, maxY int) int {
	if len(c.ArrowAvoidRanges) == 0 {
		return preferredY
	}
	inBox := func(y int) bool {
		for _, r := range c.ArrowAvoidRanges {
			if y >= r.MinY && y <= r.MaxY {
				return true
			}
		}
		return false
	}
	if !inBox(preferredY) {
		return preferredY
	}
	for offset := 1; offset <= (maxY-minY)/2+1; offset++ {
		if up := preferredY - offset; up >= minY && !inBox(up) {
			return up
		}
		if down := preferredY + offset; down <= maxY && !inBox(down) {
			return down
		}
	}
	return preferredY
}

// DrawDottedArrow draws a routed arrow using dotted characters (·) instead of
// solid box-drawing characters. Used for SG cross-reference visual edges.
func (c *Canvas) DrawDottedArrow(fromX, fromY, toX, toY int) {
	if fromY >= toY {
		return
	}

	dx := fromX - toX
	if dx < 0 {
		dx = -dx
	}
	// Near-vertical: straight dotted line
	if dx <= 2 {
		for y := fromY; y < toY; y++ {
			c.setArrow(toX, y, '·')
		}
		c.setArrow(toX, toY, cArrowD)
		return
	}

	// Route: down → horizontal → down (same routing as DrawRoutedArrow)
	midY := fromY + (toY-fromY)/2
	midY = c.avoidBoxRows(midY, fromY+1, toY-1)

	for y := fromY; y < midY; y++ {
		c.setArrow(fromX, y, '·')
	}
	c.setArrow(fromX, midY, '·')

	hStart, hEnd := fromX, toX
	if hStart > hEnd {
		hStart, hEnd = hEnd, hStart
	}
	for x := hStart + 1; x < hEnd; x++ {
		c.setArrow(x, midY, '·')
	}
	c.setArrow(toX, midY, '·')

	for y := midY + 1; y < toY; y++ {
		c.setArrow(toX, y, '·')
	}
	c.setArrow(toX, toY, cArrowD)
}

// DrawDashedArrowUp draws a dashed vertical arrow going upward with ▲ at top.
// Used for NAT GW outbound traffic flow from private subnets.
func (c *Canvas) DrawDashedArrowUp(x, fromY, toY int) {
	if fromY <= toY {
		return
	}
	// Arrow head at top
	c.setArrow(x, toY, cArrowU)
	// Dashed line body
	for y := toY + 1; y <= fromY; y++ {
		if (fromY-y)%2 == 0 {
			c.setArrow(x, y, cDashV)
		}
	}
}

// DrawDashedArrowLeft draws a horizontal dashed arrow going left: ◄···
func (c *Canvas) DrawDashedArrowLeft(fromX, toX, y int) {
	if fromX <= toX {
		return
	}
	c.setArrow(toX, y, '◄')
	for x := toX + 1; x <= fromX; x++ {
		if (fromX-x)%2 == 0 {
			c.setArrow(x, y, '·')
		}
	}
}

// DrawDashedArrowRight draws a horizontal dashed arrow going right: ···►
func (c *Canvas) DrawDashedArrowRight(fromX, toX, y int) {
	if toX <= fromX {
		return
	}
	c.setArrow(toX, y, '►')
	for x := fromX; x < toX; x++ {
		if (x-fromX)%2 == 0 {
			c.setArrow(x, y, '·')
		}
	}
}

func isVertConnector(r rune) bool {
	return r == cBoxV || r == cArrowD || r == cTeeDown || r == cTeeUp
}

func isHorizConnector(r rune) bool {
	return r == cBoxH || r == cTeeRight || r == cTeeLeft
}
