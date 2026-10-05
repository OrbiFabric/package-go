// SPDX-License-Identifier: Apache-2.0
package packagego

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
)

var knownEventTypes = []string{"PACKAGE_CREATED", "FILE_ADDED", "FILE_REMOVED", "FILE_MOVED", "FILE_RENAMED", "FILE_CONTENT_CHANGED", "VERSION_CREATED", "TAG_ADDED", "TAG_REMOVED", "NOTE_CREATED", "NOTE_UPDATED", "NOTE_DELETED", "PACKAGE_ARCHIVED", "PACKAGE_RESTORED", "DELIVERY_CREATED", "DELIVERY_COMPLETED", "WITNESS_ATTACHED", "PACKAGE_IMPORTED", "PACKAGE_EXPORTED"}

func ReadEvent(ctx context.Context, r io.Reader, l Limits) (Event, error) {
	v, err := ReadProtocolJSON(ctx, r, l)
	if err != nil {
		return Event{}, err
	}
	m, err := closedObject(v, "schema", "event_id", "package_id", "type", "schema_version", "occurred_at", "actor", "subject", "data")
	if err != nil {
		return Event{}, err
	}
	e := Event{Schema: asString(m["schema"]), EventID: EventID(asString(m["event_id"])), PackageID: PackageID(asString(m["package_id"])), Type: asString(m["type"]), OccurredAt: asString(m["occurred_at"])}
	var ok bool
	e.SchemaVersion, ok = m["schema_version"].(int64)
	if e.Schema != "orbifabric.package.event.v1" || !ok || e.SchemaVersion != 1 {
		return Event{}, schemaError("invalid event schema/version")
	}
	for _, id := range []UUID{UUID(e.EventID), UUID(e.PackageID)} {
		if err = id.Validate(); err != nil {
			return Event{}, err
		}
	}
	if !containsText(knownEventTypes, e.Type) && !namespacePattern.MatchString(e.Type) {
		return Event{}, schemaError("invalid event vocabulary/namespace")
	}
	if _, err = ParseTimestamp(e.OccurredAt); err != nil {
		return Event{}, err
	}
	if m["actor"] != nil {
		a, err := closedObject(m["actor"], "kind", "id")
		if err != nil {
			return Event{}, err
		}
		kind := asString(a["kind"])
		if !containsText([]string{"person", "application", "unknown"}, kind) {
			return Event{}, schemaError("invalid event actor kind")
		}
		id, err := textField(a, "id")
		if err != nil {
			return Event{}, err
		}
		e.Actor = &EventActor{kind, id}
	}
	e.Subject, err = parseMemoryTarget(m["subject"])
	if err != nil {
		return Event{}, err
	}
	e.Data, ok = m["data"].(map[string]any)
	if !ok {
		return Event{}, schemaError("event explanation must be an object")
	}
	return e, nil
}

// ReadEvents enforces byte/line/collection budgets before growing a line. The
// line budget includes LF. Total JSON budget includes every event byte; the
// caller accounts for other documents when combining observations. Zero bytes
// are valid. Record order is preserved, including equal/reversed timestamps.
func ReadEvents(ctx context.Context, r io.Reader, l Limits) ([]Event, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, schemaError("missing event stream")
	}
	lineLimit := min(l.MaxNDJSONLineBytes, l.MaxJSONBytes, l.MaxFileBytes)
	totalLimit := min(l.MaxTotalJSONBytes, l.MaxFileBytes, l.MaxTotalBytes)
	reader := bufio.NewReaderSize(contextReader{ctx, r}, 4096)
	out := []Event{}
	seen := map[EventID]bool{}
	line := []byte{}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		part, err := reader.ReadSlice('\n')
		if int64(len(part)) > lineLimit-int64(len(line)) || int64(len(part)) > totalLimit-total {
			return nil, protocolError(ReasonResourceLimit, "event line/total byte policy")
		}
		total += int64(len(part))
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err == io.EOF {
			if len(line) != 0 {
				return nil, protocolError(ReasonInvalidMetadata, "event line lacks LF")
			}
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(out) >= l.MaxEntries {
			return nil, protocolError(ReasonResourceLimit, "event count policy")
		}
		if len(line) == 1 || bytes.ContainsRune(line, '\r') || bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf}) {
			return nil, protocolError(ReasonInvalidMetadata, "empty/CR/BOM event line")
		}
		e, err := ReadEvent(ctx, bytes.NewReader(line[:len(line)-1]), l)
		if err != nil {
			return nil, err
		}
		if seen[e.EventID] {
			return nil, protocolError(ReasonInvalidMetadata, "duplicate event ID")
		}
		seen[e.EventID] = true
		out = append(out, e)
		line = line[:0]
	}
}
