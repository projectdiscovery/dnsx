package wildcards

import (
	"bufio"
	"os"
)

func LoadResolversFromFile(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		servers = append(servers, text+":53")
	}
	return servers, nil
}
