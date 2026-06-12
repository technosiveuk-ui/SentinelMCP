# Contributing to SentinelMCP

Thank you for your interest in contributing to SentinelMCP! This document provides guidelines for contributing.

## Quick Start

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure all tests pass
5. Commit with a sign-off (see DCO below)
6. Push to your fork and open a Pull Request

## Development Setup

```bash
# Prerequisites: Go 1.26+

# Clone and build
git clone https://github.com/technosiveuk-ui/sentinelmcp.git
cd sentinelmcp
go build ./...

# Run all tests with race detector
go test ./... -race -count=1

# Run benchmarks
go test ./adapter/eino/ -bench=. -benchmem
```

## Code Style

- Run `gofmt` before committing — all code must be formatted
- Run `go vet ./...` — no warnings allowed
- All tests must pass with `-race` flag
- Follow existing patterns in the codebase
- New features require tests
- Keep the Anti-Corruption Layer intact: `gateway/` must have zero Eino/MCP imports

## Pull Request Checklist

- [ ] All tests pass: `go test ./... -race -count=1`
- [ ] No vet warnings: `go vet ./...`
- [ ] Code is formatted: `gofmt -w .`
- [ ] New code has tests
- [ ] Commit messages include DCO sign-off
- [ ] No changes to `gateway/` that import Eino or MCP types

## Developer Certificate of Origin (DCO)

Contributors **must** sign off on their commits to certify that they have the right to submit their code under the Apache 2.0 license. This is done by adding a `Signed-off-by` line to each commit message:

```
feat: add new DLP pattern for phone numbers

Signed-off-by: Your Name <your.email@example.com>
```

You can automatically add this with `git commit -s`.

The DCO is based on the [Developer Certificate of Origin](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include Go version, OS, and steps to reproduce
- For security vulnerabilities, please email security@technosive.com instead of opening a public issue

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
