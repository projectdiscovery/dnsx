package wildcards

import (
	"bufio"
	"errors"
	"os"

	mapsutil "github.com/projectdiscovery/utils/maps"
)

type Store struct {
	wildcards *mapsutil.SyncLockMap[string, struct{}]
}

func NewStore() *Store {
	m := mapsutil.NewSyncLockMap[string, struct{}]()
	return &Store{wildcards: m}
}

func (s *Store) Set(wildcard string) error {
	return s.wildcards.Set(wildcard, struct{}{})
}

func (s *Store) Has(wildcard string) bool {
	return s.wildcards.Has(wildcard)
}

func (s *Store) Delete(wildcard string) {
	s.wildcards.Delete(wildcard)
}

func (s *Store) Clear() {
	s.wildcards.Clear()
}

func (s *Store) Iterate(f func(wildcard string) error) error {
	return s.wildcards.Iterate(func(k string, v struct{}) error {
		return f(k)
	})
}

func (s *Store) IsEmpty() bool {
	return s.wildcards.IsEmpty()
}

func (s *Store) SaveToFile(file string) error {
	if s.wildcards.IsEmpty() {
		return errors.New("no wildcards")
	}

	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	bw := bufio.NewWriter(f)
	err = s.Iterate(func(k string) error {
		_, err := bw.WriteString(k + "\n")
		return err
	})
	if err != nil {
		return err
	}

	return bw.Flush()
}

func (s *Store) LoadFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		item := scanner.Text()
		if err := s.wildcards.Set(item, struct{}{}); err != nil {
			return err
		}
	}
	return nil
}
