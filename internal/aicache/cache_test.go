package aicache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/feature"
	"github.com/leonamvasquez/terraview/internal/riskvec"
)

func TestHashKey_Deterministic(t *testing.T) {
	sr := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"wildcard-cidr", "no-tags"},
		},
		RiskVector: riskvec.RiskVector{Network: 3, Governance: 1},
	}

	key1 := HashKey(sr)
	key2 := HashKey(sr)

	if key1 != key2 {
		t.Errorf("hash keys should be deterministic: %q != %q", key1, key2)
	}
	if len(key1) != 64 { // SHA256 hex length
		t.Errorf("expected SHA256 hex (64 chars), got %d chars", len(key1))
	}
}

func TestHashKey_FlagsSorted(t *testing.T) {
	sr1 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"wildcard-cidr", "no-tags"},
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	sr2 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"no-tags", "wildcard-cidr"},
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	if HashKey(sr1) != HashKey(sr2) {
		t.Error("hash keys should be identical regardless of flag order")
	}
}

func TestHashKey_DifferentResources(t *testing.T) {
	sr1 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	sr2 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_s3_bucket",
			Provider:     "aws",
		},
		RiskVector: riskvec.RiskVector{Encryption: 3},
	}

	if HashKey(sr1) == HashKey(sr2) {
		t.Error("different resources should have different hash keys")
	}
}

func TestCache_PutGet(t *testing.T) {
	cache := NewCache()
	key := "test-key"
	resp := Response{
		Severity:          "HIGH",
		ArchitecturalRisk: "test risk",
		RiskCategories:    []string{"security"},
		Confidence:        0.95,
	}

	cache.Put(key, resp)
	got, ok := cache.Get(key)

	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", got.Severity)
	}
}

func TestCache_Miss(t *testing.T) {
	cache := NewCache()
	_, ok := cache.Get("nonexistent")
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestGetOrCompute_Hit(t *testing.T) {
	cache := NewCache()
	key := "pre-cached"
	expected := Response{Severity: "LOW", Confidence: 0.8}
	cache.Put(key, expected)

	callCount := 0
	got, cached, err := cache.GetOrCompute(key, func() (Response, error) {
		callCount++
		return Response{Severity: "HIGH"}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Error("expected cache hit flag to be true")
	}
	if callCount != 0 {
		t.Error("compute function should not be called on cache hit")
	}
	if got.Severity != "LOW" {
		t.Errorf("expected cached severity LOW, got %q", got.Severity)
	}
}

func TestGetOrCompute_Miss(t *testing.T) {
	cache := NewCache()

	got, cached, err := cache.GetOrCompute("new-key", func() (Response, error) {
		return Response{Severity: "CRITICAL", Confidence: 0.99}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Error("expected cache miss flag to be false")
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("expected computed severity CRITICAL, got %q", got.Severity)
	}

	// Should be cached now
	cachedResp, ok := cache.Get("new-key")
	if !ok {
		t.Fatal("expected value to be cached after compute")
	}
	if cachedResp.Severity != "CRITICAL" {
		t.Errorf("expected cached severity CRITICAL, got %q", cachedResp.Severity)
	}
}

func TestGetOrCompute_Error(t *testing.T) {
	cache := NewCache()

	_, _, err := cache.GetOrCompute("err-key", func() (Response, error) {
		return Response{}, fmt.Errorf("provider unavailable")
	})

	if err == nil {
		t.Fatal("expected error from compute function")
	}

	// Should NOT be cached on error
	_, ok := cache.Get("err-key")
	if ok {
		t.Error("error responses should not be cached")
	}
}

func TestCache_ConcurrencySafety(t *testing.T) {
	cache := NewCache()
	var wg sync.WaitGroup
	const goroutines = 250

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", n%10) // 10 unique keys
			cache.GetOrCompute(key, func() (Response, error) {
				return Response{
					Severity:   "HIGH",
					Confidence: float64(n) / float64(goroutines),
				}, nil
			})
		}(i)
	}

	wg.Wait()

	_, _, size := cache.Stats()
	if size != 10 {
		t.Errorf("expected 10 unique keys, got %d", size)
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewCache()
	cache.Put("k1", Response{Severity: "LOW"})
	cache.Get("k1") // hit
	cache.Get("k2") // miss
	cache.Get("k1") // hit

	hits, misses, size := cache.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
}

func TestDiskCache_HitWithoutProvider(t *testing.T) {
	dir := t.TempDir()
	planData := []byte(`{"resources":[{"type":"aws_s3_bucket"}]}`)
	planHash := PlanHash(planData)

	// Primeira instância: armazenar um valor
	dc1 := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc1.Put(planHash, `{"findings":[],"summary":"all good"}`)

	// Segunda instância: mesmo provider/model → hit
	dc2 := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	got, ok := dc2.Get(planHash)
	if !ok {
		t.Fatal("esperado cache hit com mesmo provider/model")
	}
	if got != `{"findings":[],"summary":"all good"}` {
		t.Errorf("valor inesperado: %q", got)
	}

	// Terceira instância: provider diferente → miss
	dc3 := NewDiskCache(dir, "ollama", "llama3.1:8b", "checkov", 24)
	_, ok = dc3.Get(planHash)
	if ok {
		t.Error("esperado cache miss para provider diferente")
	}
}

func TestDiskCache_TTLExpiration(t *testing.T) {
	dir := t.TempDir()
	planData := []byte(`{"resources":[{"type":"aws_instance"}]}`)
	planHash := PlanHash(planData)

	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	// Armazenar entrada com relógio fixo
	dc1 := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc1.now = func() time.Time { return now }
	dc1.Put(planHash, `{"findings":[],"summary":"cached"}`)

	// Ler dentro do TTL (12 horas depois)
	dc2 := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc2.now = func() time.Time { return now.Add(12 * time.Hour) }
	_, ok := dc2.Get(planHash)
	if !ok {
		t.Fatal("esperado cache hit dentro do TTL")
	}

	// Ler após TTL (25 horas depois)
	dc3 := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc3.now = func() time.Time { return now.Add(25 * time.Hour) }
	_, ok = dc3.Get(planHash)
	if ok {
		t.Error("esperado cache miss após expiração TTL")
	}
}

func TestDiskCache_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	planData := []byte(`{"resources":[]}`)
	planHash := PlanHash(planData)

	dc := NewDiskCache(dir, "ollama", "llama3.1:8b", "tfsec", 24)
	dc.Put(planHash, "test-value")

	// Verificar que ambos os arquivos foram escritos
	metaPath := filepath.Join(dir, planHash+".meta")
	dataPath := filepath.Join(dir, planHash+".json")

	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("arquivo .meta não escrito: %v", err)
	}
	if _, err := os.Stat(dataPath); err != nil {
		t.Fatalf("arquivo .json não escrito: %v", err)
	}

	// Verificar conteúdo do arquivo de dados
	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("falha ao ler .json: %v", err)
	}
	if string(data) != "test-value" {
		t.Errorf("conteúdo inesperado: %q", string(data))
	}

	// Verificar metadados
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("falha ao ler .meta: %v", err)
	}
	var meta CacheMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("falha ao decodificar .meta: %v", err)
	}
	if meta.Provider != "ollama" {
		t.Errorf("provider esperado 'ollama', obteve %q", meta.Provider)
	}
	if meta.Model != "llama3.1:8b" {
		t.Errorf("model esperado 'llama3.1:8b', obteve %q", meta.Model)
	}
	if meta.Scanner != "tfsec" {
		t.Errorf("scanner esperado 'tfsec', obteve %q", meta.Scanner)
	}
	if meta.PlanHash != planHash {
		t.Errorf("plan_hash esperado %q, obteve %q", planHash, meta.PlanHash)
	}
	if meta.TTLHours != 24 {
		t.Errorf("ttl_hours esperado 24, obteve %d", meta.TTLHours)
	}
}

func TestDiskCache_Stats(t *testing.T) {
	dir := t.TempDir()
	plan1 := PlanHash([]byte(`plan-1`))
	plan2 := PlanHash([]byte(`plan-2`))

	dc := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc.Put(plan1, "v1")
	dc.Get(plan1) // hit
	dc.Get(plan2) // miss

	hits, misses, size := dc.Stats()
	if hits != 1 {
		t.Errorf("esperado 1 hit, obteve %d", hits)
	}
	if misses != 1 {
		t.Errorf("esperado 1 miss, obteve %d", misses)
	}
	if size != 1 {
		t.Errorf("esperado tamanho 1, obteve %d", size)
	}
}

func TestAnalysisKey_Deterministic(t *testing.T) {
	data := []byte(`[{"type":"aws_s3_bucket"}]`)
	k1 := AnalysisKey(data, "claude", "sonnet")
	k2 := AnalysisKey(data, "claude", "sonnet")
	if k1 != k2 {
		t.Errorf("chaves de análise devem ser determinísticas: %q != %q", k1, k2)
	}

	// Provider diferente = chave diferente
	k3 := AnalysisKey(data, "ollama", "sonnet")
	if k1 == k3 {
		t.Error("providers diferentes devem produzir chaves diferentes")
	}
}

func TestPlanHash_Deterministic(t *testing.T) {
	plan := []byte(`{"resource_changes":[{"type":"aws_instance"}]}`)
	h1 := PlanHash(plan)
	h2 := PlanHash(plan)
	if h1 != h2 {
		t.Errorf("PlanHash deve ser determinístico: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("esperado SHA256 hex (64 chars), obteve %d chars", len(h1))
	}
}

func TestPlanHash_DifferentPlans(t *testing.T) {
	plan1 := []byte(`{"resource_changes":[{"type":"aws_instance"}]}`)
	plan2 := []byte(`{"resource_changes":[{"type":"aws_s3_bucket"}]}`)
	h1 := PlanHash(plan1)
	h2 := PlanHash(plan2)
	if h1 == h2 {
		t.Error("planos diferentes devem produzir hashes diferentes")
	}
}

func TestClearDisk(t *testing.T) {
	dir := t.TempDir()
	planHash := PlanHash([]byte(`test-plan`))

	dc := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	dc.Put(planHash, "v1")

	// Verificar que os arquivos existem
	metaPath := filepath.Join(dir, planHash+".meta")
	dataPath := filepath.Join(dir, planHash+".json")
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("arquivo .meta deveria existir antes do clear: %v", err)
	}

	if err := ClearDisk(dir); err != nil {
		t.Fatalf("ClearDisk falhou: %v", err)
	}

	if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
		t.Error("arquivo .meta deveria ser removido após ClearDisk")
	}
	if _, err := os.Stat(dataPath); !os.IsNotExist(err) {
		t.Error("arquivo .json deveria ser removido após ClearDisk")
	}

	// Clear em diretório vazio não deve errar
	if err := ClearDisk(dir); err != nil {
		t.Errorf("ClearDisk em diretório vazio não deveria errar: %v", err)
	}
}

func TestDiskStats(t *testing.T) {
	dir := t.TempDir()

	// Sem arquivos = entradas legado
	_, _, _, _, err := DiskStats(dir)
	if err == nil {
		t.Error("esperado erro para diretório sem cache")
	}

	// Escrever entradas
	dc := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	dc.now = func() time.Time { return now }
	plan1 := PlanHash([]byte(`plan-1`))
	dc.Put(plan1, "v1")

	dc.now = func() time.Time { return now.Add(2 * time.Hour) }
	plan2 := PlanHash([]byte(`plan-2`))
	dc.Put(plan2, "v2")

	entries, totalSize, oldest, newest, err := DiskStats(dir)
	if err != nil {
		t.Fatalf("DiskStats falhou: %v", err)
	}
	if entries != 2 {
		t.Errorf("esperado 2 entradas, obteve %d", entries)
	}
	if totalSize == 0 {
		t.Error("esperado tamanho total > 0")
	}
	if !oldest.Equal(now) {
		t.Errorf("esperado oldest=%v, obteve %v", now, oldest)
	}
	if !newest.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("esperado newest=%v, obteve %v", now.Add(2*time.Hour), newest)
	}
}

// ── Novos testes: cache baseado em hash de conteúdo ──────────────────────

func TestDiskCache_SamePlan_CacheHit(t *testing.T) {
	dir := t.TempDir()
	plan := []byte(`{"resource_changes":[{"type":"aws_instance","change":{"actions":["create"]}}]}`)
	planHash := PlanHash(plan)

	// Armazenar resultado
	dc1 := NewDiskCache(dir, "gemini", "gemini-2.5-flash", "checkov", 24)
	dc1.Put(planHash, `{"findings":[{"rule":"CKV_001"}],"summary":"1 finding"}`)

	// Mesmo plano → hit
	dc2 := NewDiskCache(dir, "gemini", "gemini-2.5-flash", "checkov", 24)
	got, ok := dc2.Get(planHash)
	if !ok {
		t.Fatal("mesmo plano deveria resultar em cache hit")
	}
	if got != `{"findings":[{"rule":"CKV_001"}],"summary":"1 finding"}` {
		t.Errorf("resposta inesperada: %q", got)
	}
}

func TestDiskCache_DifferentPlan_CacheMiss(t *testing.T) {
	dir := t.TempDir()
	plan1 := []byte(`{"resource_changes":[{"type":"aws_instance"}]}`)
	plan2 := []byte(`{"resource_changes":[{"type":"aws_s3_bucket","change":{"actions":["create"]}}]}`)
	hash1 := PlanHash(plan1)
	hash2 := PlanHash(plan2)

	// Armazenar resultado para plan1
	dc := NewDiskCache(dir, "gemini", "gemini-2.5-flash", "checkov", 24)
	dc.Put(hash1, `{"findings":[],"summary":"ok"}`)

	// Buscar com plan2 (hash diferente) → miss, mesmo dentro do TTL
	_, ok := dc.Get(hash2)
	if ok {
		t.Error("plano diferente deveria resultar em cache miss, mesmo dentro do TTL")
	}
}

func TestDiskCache_SamePlanTTLExpired_CacheMiss(t *testing.T) {
	dir := t.TempDir()
	plan := []byte(`{"resource_changes":[{"type":"aws_rds_instance"}]}`)
	planHash := PlanHash(plan)

	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	// Armazenar resultado
	dc1 := NewDiskCache(dir, "claude", "opus", "tfsec", 24)
	dc1.now = func() time.Time { return now }
	dc1.Put(planHash, `{"findings":[],"summary":"cached"}`)

	// Mesmo plano, mas TTL expirado (48h depois)
	dc2 := NewDiskCache(dir, "claude", "opus", "tfsec", 24)
	dc2.now = func() time.Time { return now.Add(48 * time.Hour) }
	_, ok := dc2.Get(planHash)
	if ok {
		t.Error("mesmo plano com TTL expirado deveria resultar em cache miss")
	}
}

func TestDiskCache_ClearRemovesAll(t *testing.T) {
	dir := t.TempDir()

	dc := NewDiskCache(dir, "gemini", "gemini-2.5-flash", "checkov", 24)
	for i := 0; i < 5; i++ {
		h := PlanHash([]byte(fmt.Sprintf("plan-%d", i)))
		dc.Put(h, fmt.Sprintf("response-%d", i))
	}

	// Verificar que 5 entradas existem
	metas, _ := filepath.Glob(filepath.Join(dir, "*.meta"))
	if len(metas) != 5 {
		t.Fatalf("esperado 5 entradas antes do clear, obteve %d", len(metas))
	}

	// Limpar tudo
	if err := ClearDisk(dir); err != nil {
		t.Fatalf("ClearDisk falhou: %v", err)
	}

	// Verificar que tudo foi removido
	remaining, _ := filepath.Glob(filepath.Join(dir, "*.meta"))
	if len(remaining) != 0 {
		t.Errorf("esperado 0 entradas após clear, obteve %d", len(remaining))
	}
	remainJSON, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(remainJSON) != 0 {
		t.Errorf("esperado 0 arquivos .json após clear, obteve %d", len(remainJSON))
	}
}

func TestDiskCache_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	dc := NewDiskCache(dir, "gemini", "gemini-2.5-flash", "checkov", 24)

	var wg sync.WaitGroup
	const goroutines = 50

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			h := PlanHash([]byte(fmt.Sprintf("concurrent-plan-%d", n%10)))
			dc.Put(h, fmt.Sprintf(`{"n":%d}`, n))
			dc.Get(h)
		}(i)
	}

	wg.Wait()

	// Verificar que exatamente 10 entradas únicas existem (sem corrupção)
	metas, _ := filepath.Glob(filepath.Join(dir, "*.meta"))
	if len(metas) != 10 {
		t.Errorf("esperado 10 entradas únicas, obteve %d", len(metas))
	}

	// Verificar que cada .meta é JSON válido
	for _, mp := range metas {
		data, err := os.ReadFile(mp)
		if err != nil {
			t.Errorf("falha ao ler %s: %v", mp, err)
			continue
		}
		var meta CacheMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			t.Errorf("arquivo .meta corrompido %s: %v", mp, err)
		}
	}
}

func TestDiskCache_MetaContainsAllFields(t *testing.T) {
	dir := t.TempDir()
	plan := []byte(`{"resource_changes":[]}`)
	planHash := PlanHash(plan)
	now := time.Date(2026, 3, 2, 14, 30, 0, 0, time.UTC)

	dc := NewDiskCache(dir, "openrouter", "anthropic/claude-3.5-sonnet", "terrascan", 48)
	dc.now = func() time.Time { return now }
	dc.Put(planHash, `{"findings":[],"summary":"clean"}`)

	// Ler e validar metadados
	meta, err := LookupPlanHash(dir, planHash)
	if err != nil {
		t.Fatalf("LookupPlanHash falhou: %v", err)
	}

	if !meta.CreatedAt.Equal(now) {
		t.Errorf("created_at: esperado %v, obteve %v", now, meta.CreatedAt)
	}
	if meta.PlanHash != planHash {
		t.Errorf("plan_hash: esperado %q, obteve %q", planHash, meta.PlanHash)
	}
	if meta.Provider != "openrouter" {
		t.Errorf("provider: esperado 'openrouter', obteve %q", meta.Provider)
	}
	if meta.Model != "anthropic/claude-3.5-sonnet" {
		t.Errorf("model: esperado 'anthropic/claude-3.5-sonnet', obteve %q", meta.Model)
	}
	if meta.Scanner != "terrascan" {
		t.Errorf("scanner: esperado 'terrascan', obteve %q", meta.Scanner)
	}
	if meta.TTLHours != 48 {
		t.Errorf("ttl_hours: esperado 48, obteve %d", meta.TTLHours)
	}
}

func TestDiskCache_LegacyEntriesTreatedAsExpired(t *testing.T) {
	dir := t.TempDir()

	// Simular entrada legada (ai-cache.json) sem arquivos .meta
	legacyData := `{"abc123":{"response":"legacy","cached_at":"2025-01-01T00:00:00Z","provider":"claude","model":"sonnet"}}`
	legacyPath := filepath.Join(dir, "ai-cache.json")
	os.WriteFile(legacyPath, []byte(legacyData), 0600)

	// Novo DiskCache não encontra .meta para o hash → miss
	dc := NewDiskCache(dir, "claude", "sonnet", "checkov", 24)
	_, ok := dc.Get("abc123")
	if ok {
		t.Error("entradas legadas sem .meta devem ser tratadas como cache miss")
	}

	// DiskStats em diretório sem .meta cai no fallback legado
	entries, _, _, _, err := DiskStats(dir)
	if err != nil {
		t.Fatalf("DiskStats falhou com fallback legado: %v", err)
	}
	if entries != 1 {
		t.Errorf("DiskStats legado deveria encontrar 1 entrada, obteve %d", entries)
	}
}

func TestDiskCache_ListEntries(t *testing.T) {
	dir := t.TempDir()

	dc := NewDiskCache(dir, "gemini", "2.5-flash", "checkov", 24)
	dc.Put(PlanHash([]byte("plan-a")), "resp-a")
	dc.Put(PlanHash([]byte("plan-b")), "resp-b")
	dc.Put(PlanHash([]byte("plan-c")), "resp-c")

	entries, err := ListEntries(dir)
	if err != nil {
		t.Fatalf("ListEntries falhou: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("esperado 3 entradas, obteve %d", len(entries))
	}
	for _, e := range entries {
		if e.Provider != "gemini" {
			t.Errorf("provider esperado 'gemini', obteve %q", e.Provider)
		}
	}
}

func TestDiskCache_OverwriteOnProviderChange(t *testing.T) {
	dir := t.TempDir()
	plan := []byte(`{"resource_changes":[{"type":"aws_vpc"}]}`)
	planHash := PlanHash(plan)

	// Armazenar com provider A
	dc1 := NewDiskCache(dir, "gemini", "2.5-flash", "checkov", 24)
	dc1.Put(planHash, `{"findings":[],"summary":"gemini result"}`)

	// Provider B com mesmo plano → miss (meta tem provider A)
	dc2 := NewDiskCache(dir, "claude", "opus", "checkov", 24)
	_, ok := dc2.Get(planHash)
	if ok {
		t.Error("provider diferente deveria resultar em miss")
	}

	// Provider B escreve → sobrescreve
	dc2.Put(planHash, `{"findings":[],"summary":"claude result"}`)

	// Agora provider B encontra o resultado
	dc3 := NewDiskCache(dir, "claude", "opus", "checkov", 24)
	got, ok := dc3.Get(planHash)
	if !ok {
		t.Fatal("esperado hit após sobrescrita")
	}
	if got != `{"findings":[],"summary":"claude result"}` {
		t.Errorf("resultado inesperado: %q", got)
	}

	// Provider A agora recebe miss
	dc4 := NewDiskCache(dir, "gemini", "2.5-flash", "checkov", 24)
	_, ok = dc4.Get(planHash)
	if ok {
		t.Error("provider original deveria receber miss após sobrescrita")
	}
}
