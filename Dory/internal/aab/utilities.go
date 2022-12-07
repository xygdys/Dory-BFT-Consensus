package aab

import "sync"

type state struct {
	b     [][]bool
	mutex *sync.Mutex
}
type store struct {
	b     [][]bool
	data  [][][]byte
	mutex *sync.Mutex
}
type index struct {
	epoch uint32
	pid   uint32
}

//state
func (s *state) grow(n uint32) {
	s.mutex.Lock()
	s.b = append(s.b, make([]bool, n))
	s.mutex.Unlock()
}
func (s *state) set(e, i uint32) {
	s.mutex.Lock()
	s.b[e-1][i] = true
	s.mutex.Unlock()
}

//store
func (s *store) grow(n uint32) {
	s.mutex.Lock()
	s.b = append(s.b, make([]bool, n))
	s.data = append(s.data, make([][]byte, n))
	s.mutex.Unlock()
}
func (s *store) store(e, i uint32, data []byte) {
	s.mutex.Lock()
	s.b[e-1][i] = true
	s.data[e-1][i] = data
	s.mutex.Unlock()
}
func (s *store) isStored(e, i uint32) bool {
	var ok bool
	s.mutex.Lock()
	ok = s.b[e-1][i]
	s.mutex.Unlock()
	return ok
}
func (s *store) load(e, i uint32) ([]byte, bool) {
	var v []byte
	var ok bool
	s.mutex.Lock()
	ok = s.b[e-1][i]
	if ok {
		v = s.data[e-1][i]
	}
	s.mutex.Unlock()
	return v, ok
}
