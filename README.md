# Distribution auth

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/distribution-auth/auth/ci.yaml?style=flat-square)](https://github.com/distribution-auth/auth/actions/workflows/ci.yaml)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/distribution-auth/auth)
[![built with nix](https://img.shields.io/badge/builtwith-nix-7d81f7?style=flat-square)](https://builtwithnix.org)

**Authentication library implementing the [Distribution Registry Auth specification](https://github.com/distribution/distribution/tree/main/docs/spec/auth).**


## Usage

1. `docker compose up -d`
1. `go run ./cmd/server -addr 0.0.0.0:8080 -debug -realm localhost:8080`
1. `docker login -u user -p password localhost:5000`


## License

The project is licensed under the [MIT License](LICENSE).
