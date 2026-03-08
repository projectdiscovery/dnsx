// Import necessary packages
package main

import (
    "flag"
    "fmt"
    "strings"
    "github.com/projectdiscovery/dnsx" // Assuming this package handles DNS queries
)

// Function to check for wildcard DNS
func checkWildcard(domain string) bool {
    // Common subdomains to check for wildcard
    subdomains := []string{"www", "ftp", "mail", "api", "test"}

    for _, subdomain := range subdomains {
        query := subdomain + "." + domain
        result := dnsx.Query(query)  // Assuming dnsx.Query performs DNS queries
        if strings.Contains(result, "NXDOMAIN") {
            return false
        }
    }
    return true
}

func main() {
    autoWildcard := flag.Bool("auto-wildcard", false, "Enable automatic wildcard detection")
    flag.Parse()

    domains := flag.Args()
    for _, domain := range domains {
        if *autoWildcard && checkWildcard(domain) {
            fmt.Printf("[INFO] Wildcard detected for domain: %s\n", domain)
            continue // Skip the wildcard domain
        }
        fmt.Printf("Checking domain: %s\n", domain)
    }
}
