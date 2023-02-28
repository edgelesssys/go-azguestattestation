module github.com/edgelesssys/go-azguestattestation

go 1.19

replace (
	github.com/google/go-tpm => github.com/thomasten/go-tpm v0.0.0-20230222180349-bb3cc5560299
	github.com/google/go-tpm-tools => github.com/daniel-weisse/go-tpm-tools v0.0.0-20230105122812-f7474d459dfc
)

require (
	github.com/go-jose/go-jose/v3 v3.0.0
	github.com/google/go-attestation v0.4.4-0.20220404204839-8820d49b18d9
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.10
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-sev-guest v0.4.1 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.0.0-20220608164250-635b8c9b7f68 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
