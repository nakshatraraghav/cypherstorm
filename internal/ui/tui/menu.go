package tui

// menuSection groups related operations before the user enters a form.
type menuSection uint8

const (
	menuSecure menuSection = iota
	menuArchive
	menuTools
)

type menuItem struct {
	title       string
	description string
	tag         string
	target      screen
}

type menuSectionInfo struct {
	title       string
	description string
	tag         string
	items       []menuItem
}

func sectionInfo(section menuSection) menuSectionInfo {
	switch section {
	case menuSecure:
		return menuSectionInfo{
			title:       "Secure files",
			description: "Create or restore authenticated encrypted archives.",
			tag:         "PROTECT",
			items: []menuItem{
				{title: "Protect files", description: "Archive, compress, and encrypt a file or folder.", tag: "CREATE", target: screenProtect},
				{title: "Restore files", description: "Authenticate and recover an archive into a new destination.", tag: "RECOVER", target: screenRestore},
			},
		}
	case menuArchive:
		return menuSectionInfo{
			title:       "Inspect & validate",
			description: "Understand a protected file before restoring it.",
			tag:         "ARCHIVE",
			items: []menuItem{
				{title: "Inspect header", description: "Read public container properties without a credential.", tag: "READ", target: screenInspect},
				{title: "Verify archive", description: "Authenticate the archive and validate its contents.", tag: "VERIFY", target: screenVerify},
				{title: "Browse contents", description: "Authenticate and list archived paths before restore.", tag: "LIST", target: screenList},
			},
		}
	case menuTools:
		return menuSectionInfo{
			title:       "Tools & reports",
			description: "Measure input and compare local protection settings.",
			tag:         "TOOLS",
			items: []menuItem{
				{title: "Hash input", description: "Calculate deterministic file or folder digests.", tag: "HASH", target: screenHash},
				{title: "Benchmark", description: "Compare every compression and encryption combination.", tag: "REPORT", target: screenBenchmark},
			},
		}
	default:
		return menuSectionInfo{}
	}
}

func homeMenu() []menuItem {
	return []menuItem{
		{title: "Secure files", description: "Protect new files or restore an existing archive.", tag: "01", target: screenSection},
		{title: "Inspect & validate", description: "Inspect, verify, or browse a protected archive.", tag: "02", target: screenSection},
		{title: "Tools & reports", description: "Hash input or benchmark local protection settings.", tag: "03", target: screenSection},
		{title: "Help & about", description: "Keyboard controls and security model.", tag: "?", target: screenHelp},
	}
}

func sectionForHomeIndex(index int) menuSection {
	switch index {
	case 0:
		return menuSecure
	case 1:
		return menuArchive
	default:
		return menuTools
	}
}
