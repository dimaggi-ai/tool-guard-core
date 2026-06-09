//go:build pg_strict

package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v5"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// walk descends the entire Node tree under root, calling visit for every
// *pg_query.Node it finds (including root itself). The traversal uses
// protobuf reflection so it follows every message-typed field without us
// having to hand-code a switch over the ~250 node kinds.
func walk(root *pg_query.Node, visit func(*pg_query.Node)) {
	if root == nil {
		return
	}
	visit(root)
	descend(root.ProtoReflect(), visit)
}

func descend(m protoreflect.Message, visit func(*pg_query.Node)) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch fd.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			if fd.IsList() {
				ls := v.List()
				for i := 0; i < ls.Len(); i++ {
					handleMessage(ls.Get(i).Message(), visit)
				}
			} else if fd.IsMap() {
				mp := v.Map()
				mp.Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					if fd.MapValue().Kind() == protoreflect.MessageKind {
						handleMessage(mv.Message(), visit)
					}
					return true
				})
			} else {
				handleMessage(v.Message(), visit)
			}
		}
		return true
	})
}

func handleMessage(m protoreflect.Message, visit func(*pg_query.Node)) {
	if m == nil || !m.IsValid() {
		return
	}
	// If this is a *pg_query.Node, invoke the visitor and recurse from
	// the Node level (the oneof inside Node is walked from there).
	if node, ok := m.Interface().(*pg_query.Node); ok && node != nil {
		walk(node, visit)
		return
	}
	descend(m, visit)
}
