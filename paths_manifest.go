// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"context"
	"sort"
)

func sortedTreePaths(nodes map[string]TreeEntry) []string {
	paths := make([]string, 0, len(nodes))
	for p := range nodes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// Paths derives paths solely from logical parent/name facts. Resource policy
// bounds deep/long derived paths; path values never replace FileID/FolderID.
func (m Manifest) Paths(ctx context.Context, l Limits) (map[UUID]string, error) {
	if err := m.Validate(ctx, l); err != nil {
		return nil, err
	}
	byID := map[UUID]Entry{}
	for _, e := range m.Entries {
		byID[e.ID()] = e
	}
	out := map[UUID]string{}
	depths := map[UUID]int{}
	for _, e := range m.Entries {
		id := e.ID()
		chain := []UUID{}
		for id != "" {
			if _, ok := out[id]; ok {
				break
			}
			chain = append(chain, id)
			if len(chain) > l.MaxTreeDepth {
				return nil, protocolError(ReasonResourceLimit, "derived tree depth limit")
			}
			p := byID[id].ParentFolderID
			id = ""
			if p != nil {
				id = UUID(*p)
			}
		}
		prefix := ""
		depth := 0
		if id != "" {
			prefix = out[id]
			depth = depths[id]
		}
		for n := len(chain) - 1; n >= 0; n-- {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			depth++
			if depth > l.MaxTreeDepth {
				return nil, protocolError(ReasonResourceLimit, "derived tree depth limit")
			}
			part := byID[chain[n]].Name
			extra := 0
			if prefix != "" {
				extra = 1
			}
			if len(prefix) > l.MaxPathBytes-len(part)-extra {
				return nil, protocolError(ReasonResourceLimit, "derived path byte limit")
			}
			if prefix != "" {
				prefix += "/"
			}
			prefix += part
			out[chain[n]] = prefix
			depths[chain[n]] = depth
		}
	}
	return out, nil
}
