package util

import (
	"gitlab.adtelligent.com/common/shared/log"
	"reflect"
	"sort"
)

// KV represents (key, value) item obtained from the map.
type KV struct {
	// K holds map item's key.
	K interface{}

	// V holds map item's value.
	V interface{}
}

// SortMapByKey sorts the given map items by key.
//
// Returns (key, value) pairs obtained from the map sorted by key.
// Supported key types: string, int.
//
// Warning: this function is SLOW, so do not use it in hot paths.
func SortMapByKey(m interface{}) []*KV {
	kvs := getMapKVs(m)
	sort.Slice(kvs, func(i, j int) bool {
		ak := kvs[i].K
		bk := kvs[j].K
		switch v := ak.(type) {
		case int:
			return v < bk.(int)
		case string:
			return v < bk.(string)
		default:
			log.Panicf("unexpected key type=%T", ak)
		}
		panic("unreachable")
	})
	return kvs
}

func getMapKVs(m interface{}) []*KV {
	v := reflect.ValueOf(m)
	var kvs []*KV
	for _, vk := range v.MapKeys() {
		kvs = append(kvs, &KV{
			K: vk.Interface(),
			V: v.MapIndex(vk).Interface(),
		})
	}
	return kvs
}
