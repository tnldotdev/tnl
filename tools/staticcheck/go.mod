module github.com/tnldotdev/tnl/tools/staticcheck

go 1.27.2

require honnef.co/go/tools v0.8.1

// staticcheck v0.8.1 needs a newer export reader for go 1.27.2.
replace golang.org/x/tools => golang.org/x/tools v0.51.0
