# Run `just` to list recipes.

config := "sesame.toml"

default:
    @just --list

# Build the dist/sesame binary (templates/ and locales/ are embedded, so rebuild after editing them)
build:
    go build -o dist/sesame .

# Build, then run with the given config (copy config.example.toml to sesame.toml first)
run: build
    ./dist/sesame -config {{config}}

# Run the whole test suite, or a subset: `just test TestFullLoginFlow`
test pattern="":
    go test {{ if pattern == "" { "./..." } else { "-run " + pattern + " ." } }}

# Run the tests with the race detector
race:
    go test -race ./...

# Run the tests with a coverage summary
cover:
    go test -cover ./...

# Format all Go files
fmt:
    gofmt -w *.go

# Static checks: gofmt must be clean, go vet must pass
lint:
    @test -z "$(gofmt -l *.go)" || { echo "gofmt needed:"; gofmt -l *.go; exit 1; }
    go vet ./...

# The full local gate (there is no CI): lint + tests
check: lint test

# Remove build artifacts
clean:
    rm -rf dist
