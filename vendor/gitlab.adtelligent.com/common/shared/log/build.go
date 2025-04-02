package log

// These variables must be set via '-ldflags X' during compile time.
// See https://www.atatus.com/blog/golang-auto-build-versioning/ .
var (
	buildTime       = "unknown"
	buildRevision   = "unknown"
	buildVersion    = "unknown"
	buildDebPkgName = "unknown"
)

func GetBuildRevision() string {
	return buildRevision
}

func GetBuildVersion() string {
	return buildVersion
}

func GetBuildTime() string {
	return buildTime
}

func GetBuildDebPkgName() string {
	return buildDebPkgName
}
