module github.com/vietanhduong/profiling

go 1.21

require (
	github.com/avvmoto/buf-readerat v0.0.0-20171115124131-a17c8cb89270
	github.com/cilium/ebpf v0.12.3
	github.com/golang/glog v1.1.2
	github.com/google/go-cmp v0.5.9
	github.com/ianlancetaylor/demangle v0.0.0-20230524184225-eabc099b10ab
	github.com/samber/lo v1.38.1
	github.com/stretchr/testify v1.8.4
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa
	golang.org/x/sys v0.14.1-0.20231108175955-e4099bfacb8c
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/dgraph-io/badger/v2 => github.com/dgraph-io/badger/v2 v2.2007.4

	// Replace memberlist with our fork which includes some fixes that haven't been
	// merged upstream yet.
	github.com/hashicorp/memberlist => github.com/grafana/memberlist v0.3.1-0.20220708130638-bd88e10a3d91
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v0.45.0

	// Replaced with fork, to allow prefix listing, see https://github.com/simonswine/objstore/commit/84f91ea90e721f17d2263cf479fff801cab7cf27
	github.com/thanos-io/objstore => github.com/grafana/objstore v0.0.0-20231121154247-84f91ea90e72

	// Changed slices.SortFunc signature, which breaks dependencies:
	// https://github.com/golang/exp/commit/302865e7556b4ae5de27248ce625d443ef4ad3ed
	golang.org/x/exp => golang.org/x/exp v0.0.0-20230713183714-613f0c0eb8a1
	// gopkg.in/yaml.v3
	// + https://github.com/go-yaml/yaml/pull/691
	// + https://github.com/go-yaml/yaml/pull/876
	gopkg.in/yaml.v3 => github.com/colega/go-yaml-yaml v0.0.0-20220720105220-255a8d16d094
)
