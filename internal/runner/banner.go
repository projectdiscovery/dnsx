package runner

import "github.com/projectdiscovery/gologger"

const banner = `
      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  / 
 | (_| || | | |\__ \ /  \ 
  \__,_||_| |_||___//_/\_\ v1.0.1
`

// Version is the current version of dnsx
const Version = `1.0.1`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
