package contextanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sort"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// CacheNamespace tags per-resource cache keys so they cannot collide with
// the legacy plan-level entries that still live in the same disk directory.
// Bump the suffix when the resource hash schema changes (forces full miss).
const CacheNamespace = "ctxres-v1"

// resourceKey computes a deterministic SHA-256 key for a resource using:
//   - its type/provider/action
//   - its security-relevant attributes (per-type whitelist from CTXPERF-002)
//   - its 1-hop neighbor signatures (CTXPERF-004 invariant: any neighbor
//     attribute change invalidates this resource's cache entry, preserving
//     cross-resource finding quality)
//   - the analysis language (pt-BR vs en summaries differ)
//
// Hash schema must remain stable across versions of attribute whitelists;
// any breaking change should bump CacheNamespace so old entries cannot
// be served as false hits.
func resourceKey(r parser.NormalizedResource, neighbors []parser.NormalizedResource, lang string) string {
	h := sha256.New()
	fmt.Fprintf(h, "ns=%s\nlang=%s\n", CacheNamespace, lang)
	fmt.Fprintf(h, "addr=%s\ntype=%s\nprov=%s\naction=%s\n", r.Address, r.Type, r.Provider, r.Action)
	writeRelevantAttrs(h, r.Type, r.Values)

	sortedNbrs := make([]parser.NormalizedResource, len(neighbors))
	copy(sortedNbrs, neighbors)
	sort.Slice(sortedNbrs, func(i, j int) bool { return sortedNbrs[i].Address < sortedNbrs[j].Address })
	for _, n := range sortedNbrs {
		fmt.Fprintf(h, "nbr=%s|%s|%s\n", n.Address, n.Type, n.Action)
		writeRelevantAttrs(h, n.Type, n.Values)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// writeRelevantAttrs feeds the per-type whitelist + fallback attributes into
// the hasher in deterministic key order so the same logical state always
// yields the same hash regardless of map iteration order.
func writeRelevantAttrs(h hash.Hash, resourceType string, values map[string]interface{}) {
	relevant := extractRelevantAttributesForType(resourceType, values)
	keys := make([]string, 0, len(relevant))
	for k := range relevant {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, _ := json.Marshal(relevant[k])
		fmt.Fprintf(h, "  attr.%s=%s\n", k, b)
	}
}

// neighborsOf returns the 1-hop neighbor resources of addr (both directions)
// resolved against byAddr. Returns nil for orphan resources or when the graph
// is empty.
func neighborsOf(addr string, graph *topology.Graph, byAddr map[string]parser.NormalizedResource) []parser.NormalizedResource {
	if graph == nil {
		return nil
	}
	seen := map[string]bool{addr: true}
	var out []parser.NormalizedResource
	for _, e := range graph.Edges {
		if e.From == addr && !seen[e.To] {
			seen[e.To] = true
			if r, ok := byAddr[e.To]; ok {
				out = append(out, r)
			}
		}
		if e.To == addr && !seen[e.From] {
			seen[e.From] = true
			if r, ok := byAddr[e.From]; ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// LookupResult is the outcome of a per-resource cache lookup over the active
// resource set of a plan.
type LookupResult struct {
	// CachedFindings are findings reused verbatim from disk for resources
	// whose hash matched an existing entry.
	CachedFindings []rules.Finding
	// Uncached lists resources that must be sent to the AI on this run.
	Uncached []parser.NormalizedResource
	// Hashes maps every resource address to its computed cache key, so the
	// caller can persist new findings under the same keys after the AI call.
	Hashes map[string]string
	// HitCount is the number of cache hits (len(resources) - len(Uncached)).
	HitCount int
}

// LookupCache splits the active resource set into cached findings and the
// subset that still needs an AI call. A nil disk cache yields a full miss
// (every resource ends up in Uncached) and is the safe default for tests.
func LookupCache(disk *aicache.DiskCache, resources []parser.NormalizedResource, graph *topology.Graph, lang string) LookupResult {
	byAddr := make(map[string]parser.NormalizedResource, len(resources))
	for _, r := range resources {
		byAddr[r.Address] = r
	}

	out := LookupResult{Hashes: make(map[string]string, len(resources))}

	for _, r := range resources {
		nbrs := neighborsOf(r.Address, graph, byAddr)
		key := resourceKey(r, nbrs, lang)
		out.Hashes[r.Address] = key

		if disk == nil {
			out.Uncached = append(out.Uncached, r)
			continue
		}

		if cached, ok := disk.Get(key); ok {
			var fs []rules.Finding
			if err := json.Unmarshal([]byte(cached), &fs); err == nil {
				out.CachedFindings = append(out.CachedFindings, fs...)
				out.HitCount++
				continue
			}
		}
		out.Uncached = append(out.Uncached, r)
	}
	return out
}

// StoreCache persists per-resource findings to disk. It writes:
//  1. an entry for every uncached resource (including those that produced
//     zero findings — the negative result is reused on the next run);
//  2. an entry for any cross-resource finding whose target address was
//     cached on this run, so the new information is not lost when that
//     target's neighborhood is later unchanged.
func StoreCache(disk *aicache.DiskCache, uncached []parser.NormalizedResource, hashes map[string]string, findings []rules.Finding) {
	if disk == nil {
		return
	}

	byResource := make(map[string][]rules.Finding, len(uncached)+len(findings))
	for _, f := range findings {
		byResource[f.Resource] = append(byResource[f.Resource], f)
	}

	written := make(map[string]bool, len(uncached))
	for _, r := range uncached {
		key := hashes[r.Address]
		if key == "" {
			continue
		}
		b, err := json.Marshal(byResource[r.Address])
		if err != nil {
			continue
		}
		disk.Put(key, string(b))
		written[r.Address] = true
	}

	for addr, fs := range byResource {
		if written[addr] {
			continue
		}
		key := hashes[addr]
		if key == "" {
			continue
		}
		b, err := json.Marshal(fs)
		if err != nil {
			continue
		}
		disk.Put(key, string(b))
	}
}
