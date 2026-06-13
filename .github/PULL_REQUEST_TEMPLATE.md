## Description

<!-- Brief summary of what this PR does and why. -->

## Motivation

<!-- Link to the issue this resolves, or describe the problem it solves. -->

Closes #

## Changes

<!-- Bullet-point list of key changes. -->

-

## Testing

<!-- How did you verify this works? -->

- [ ] All tests pass: `go test ./... -race -count=1`
- [ ] No vet warnings: `go vet ./...`
- [ ] Benchmarks unaffected (or improved): `go test ./adapter/eino/ -bench=. -benchmem`

## Checklist

- [ ] Code is formatted: `gofmt -w .`
- [ ] New code has tests
- [ ] Commit messages include DCO sign-off (`git commit -s`)
- [ ] No changes to `gateway/` that import Eino or MCP types (Anti-Corruption Layer)
- [ ] Documentation updated (README, config examples, CHANGELOG) if applicable

## Notes for Reviewers

<!-- Anything reviewers should pay extra attention to? -->
