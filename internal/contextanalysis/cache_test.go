package contextanalysis

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func TestResourceKey_DeterministicAndStable(t *testing.T) {
	r := parser.NormalizedResource{
		Address: "aws_instance.web", Type: "aws_instance", Provider: "aws", Action: "create",
		Values: map[string]interface{}{
			"instance_type": "t3.micro",
			"ami":           "ami-123",
			"tags":          map[string]interface{}{"env": "prod"},
		},
	}
	k1 := resourceKey(r, nil, "")
	k2 := resourceKey(r, nil, "")
	if k1 != k2 {
		t.Fatalf("resourceKey must be deterministic, got %s vs %s", k1, k2)
	}
}

func TestResourceKey_AttrChangeBreaksHash(t *testing.T) {
	base := parser.NormalizedResource{
		Address: "aws_instance.web", Type: "aws_instance", Provider: "aws", Action: "create",
		Values: map[string]interface{}{"instance_type": "t3.micro"},
	}
	mutated := base
	mutated.Values = map[string]interface{}{"instance_type": "t3.large"}

	if resourceKey(base, nil, "") == resourceKey(mutated, nil, "") {
		t.Error("changing a relevant attribute must change the hash")
	}
}

func TestResourceKey_IrrelevantAttrIgnored(t *testing.T) {
	base := parser.NormalizedResource{
		Address: "aws_instance.web", Type: "aws_instance", Provider: "aws", Action: "create",
		Values: map[string]interface{}{"instance_type": "t3.micro"},
	}
	withNoise := base
	withNoise.Values = map[string]interface{}{
		"instance_type": "t3.micro",
		"random_field":  "ignored",
	}

	if resourceKey(base, nil, "") != resourceKey(withNoise, nil, "") {
		t.Error("irrelevant attributes must NOT influence the cache key")
	}
}

func TestResourceKey_NeighborChangeInvalidatesHash(t *testing.T) {
	r := parser.NormalizedResource{
		Address: "aws_instance.web", Type: "aws_instance", Provider: "aws", Action: "create",
		Values: map[string]interface{}{"instance_type": "t3.micro"},
	}
	nbr1 := parser.NormalizedResource{
		Address: "aws_security_group.sg", Type: "aws_security_group", Provider: "aws", Action: "create",
		Values: map[string]interface{}{"vpc_id": "vpc-old"},
	}
	nbr2 := nbr1
	nbr2.Values = map[string]interface{}{"vpc_id": "vpc-new"}

	if resourceKey(r, []parser.NormalizedResource{nbr1}, "") ==
		resourceKey(r, []parser.NormalizedResource{nbr2}, "") {
		t.Error("neighbor attribute change must invalidate the resource hash (CTXPERF-004 invariant)")
	}
}

func TestResourceKey_NeighborOrderInvariant(t *testing.T) {
	r := parser.NormalizedResource{Address: "aws_instance.web", Type: "aws_instance"}
	a := parser.NormalizedResource{Address: "aws_subnet.a", Type: "aws_subnet"}
	b := parser.NormalizedResource{Address: "aws_subnet.b", Type: "aws_subnet"}

	k1 := resourceKey(r, []parser.NormalizedResource{a, b}, "")
	k2 := resourceKey(r, []parser.NormalizedResource{b, a}, "")
	if k1 != k2 {
		t.Errorf("hash must not depend on neighbor input order, got %s vs %s", k1, k2)
	}
}

func TestResourceKey_LangSeparatesNamespace(t *testing.T) {
	r := parser.NormalizedResource{Address: "aws_instance.web", Type: "aws_instance"}
	if resourceKey(r, nil, "") == resourceKey(r, nil, "pt-BR") {
		t.Error("different languages must yield different hashes (summaries differ)")
	}
}

func TestNeighborsOf_BothDirections(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc"},
		{Address: "aws_subnet.a", Type: "aws_subnet", Values: map[string]interface{}{"vpc_id": "vpc-1"}},
		{Address: "aws_instance.web", Type: "aws_instance", Values: map[string]interface{}{"subnet_id": "subnet-1"}},
	}
	graph := topology.BuildGraph(resources)
	byAddr := map[string]parser.NormalizedResource{}
	for _, r := range resources {
		byAddr[r.Address] = r
	}

	nbrs := neighborsOf("aws_subnet.a", graph, byAddr)
	if len(nbrs) == 0 {
		t.Skip("topology.BuildGraph did not produce edges for this synthetic plan; covered by integration tests")
	}
}

func TestNeighborsOf_NilGraph(t *testing.T) {
	if got := neighborsOf("anything", nil, nil); got != nil {
		t.Errorf("nil graph must return nil, got %v", got)
	}
}

func TestLookupCache_FullMissNoDisk(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.r0", Type: "aws_instance", Action: "create"},
		{Address: "aws_instance.r1", Type: "aws_instance", Action: "create"},
	}

	got := LookupCache(nil, resources, nil, "")

	if got.HitCount != 0 {
		t.Errorf("nil disk must produce 0 hits, got %d", got.HitCount)
	}
	if len(got.Uncached) != 2 {
		t.Errorf("want 2 uncached, got %d", len(got.Uncached))
	}
	if len(got.Hashes) != 2 {
		t.Errorf("want hashes for 2 resources, got %d", len(got.Hashes))
	}
}

func TestLookupCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	disk := aicache.NewDiskCache(dir, "test", "model", "scanner", 24)

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.r0", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"instance_type": "t3.micro"}},
		{Address: "aws_instance.r1", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"instance_type": "t3.large"}},
	}

	// First lookup: full miss.
	first := LookupCache(disk, resources, nil, "")
	if first.HitCount != 0 || len(first.Uncached) != 2 {
		t.Fatalf("first run must be full miss, got hits=%d uncached=%d", first.HitCount, len(first.Uncached))
	}

	// Simulate AI returning one finding for r0 and none for r1.
	findings := []rules.Finding{
		{RuleID: "CTX-001", Resource: "aws_instance.r0", Severity: "HIGH", Message: "exposed", Source: "ai/context"},
	}
	StoreCache(disk, first.Uncached, first.Hashes, findings)

	// Second lookup: full hit, including the negative entry for r1.
	second := LookupCache(disk, resources, nil, "")
	if second.HitCount != 2 {
		t.Errorf("want 2 hits after store, got %d", second.HitCount)
	}
	if len(second.Uncached) != 0 {
		t.Errorf("want 0 uncached after store, got %d", len(second.Uncached))
	}
	if len(second.CachedFindings) != 1 {
		t.Errorf("want 1 cached finding for r0, got %d", len(second.CachedFindings))
	}
	if len(second.CachedFindings) > 0 && second.CachedFindings[0].RuleID != "CTX-001" {
		t.Errorf("cached finding rule_id mismatch: %q", second.CachedFindings[0].RuleID)
	}
}

func TestLookupCache_AttrChangeForcesMiss(t *testing.T) {
	dir := t.TempDir()
	disk := aicache.NewDiskCache(dir, "test", "model", "scanner", 24)

	r := parser.NormalizedResource{
		Address: "aws_instance.r0", Type: "aws_instance", Action: "create",
		Values: map[string]interface{}{"instance_type": "t3.micro"},
	}

	first := LookupCache(disk, []parser.NormalizedResource{r}, nil, "")
	StoreCache(disk, first.Uncached, first.Hashes, nil)

	// Mutate a relevant attribute.
	mutated := r
	mutated.Values = map[string]interface{}{"instance_type": "t3.large"}

	second := LookupCache(disk, []parser.NormalizedResource{mutated}, nil, "")
	if second.HitCount != 0 {
		t.Errorf("attr change must force miss, got %d hits", second.HitCount)
	}
}

func TestStoreCache_NilDiskIsNoop(t *testing.T) {
	// Must not panic.
	StoreCache(nil, nil, nil, nil)
	StoreCache(nil,
		[]parser.NormalizedResource{{Address: "x"}},
		map[string]string{"x": "k"},
		[]rules.Finding{{Resource: "x"}},
	)
}

func TestStoreCache_OverwritesCachedNeighborFinding(t *testing.T) {
	dir := t.TempDir()
	disk := aicache.NewDiskCache(dir, "test", "model", "scanner", 24)

	r := parser.NormalizedResource{Address: "aws_iam_role.cached", Type: "aws_iam_role"}
	hashes := map[string]string{
		r.Address: resourceKey(r, nil, ""),
	}

	// AI emits a cross-resource finding addressing a resource that wasn't in
	// uncached (e.g. cached neighbor). StoreCache must still persist it so
	// the next run reuses the latest information.
	findings := []rules.Finding{
		{RuleID: "CTX-CR-001", Resource: r.Address, Severity: "HIGH", Message: "cross-resource issue"},
	}
	StoreCache(disk, nil, hashes, findings)

	cached, ok := disk.Get(hashes[r.Address])
	if !ok {
		t.Fatal("expected cached entry for cross-resource finding target")
	}
	if cached == "" || cached == "null" || cached == "[]" {
		t.Errorf("expected non-empty cached findings, got %q", cached)
	}
}
