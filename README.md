> # Project moved
> See [](https://github.com/portward/registry-auth/)

# Registry auth

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/registry-auth/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/registry-auth/actions/workflows/ci.yaml)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/mod/github.com/sagikazarmark/registry-auth)
[![built with nix](https://img.shields.io/badge/builtwith-nix-7d81f7?style=flat-square)](https://builtwithnix.org)

**Authentication library implementing the [Docker (Distribution) Registry Auth specification](https://github.com/distribution/distribution/tree/main/docs/spec/auth).**

> [!WARNING]
> **Project is under development. Backwards compatibility is not guaranteed.**

## Development

**For an optimal developer experience, it is recommended to install [Nix](https://nixos.org/download.html) and [direnv](https://direnv.net/docs/installation.html).**

1. `docker compose up -d`
1. `just run`
1. `just login`


## License

The project is licensed under the [MIT License](LICENSE).
