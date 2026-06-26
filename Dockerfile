# AnB-MCP — MCP server front-end for AnB.
#
# This image exists so registries (e.g. Glama) can build the server, start it,
# and exercise MCP introspection (initialize + tools/list) without AnB present:
# the five tools are registered statically and `alice`/`bob` are only invoked at
# tool-CALL time, so the server starts and introspects fine with no AnB backend.
#
# For ACTUAL use the container needs the `alice` binary on PATH plus a configured,
# enrolled AnB identity and a reachable `bob` daemon (see README). Those are
# intentionally not baked in — this is a thin front-end, not the vault.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /anb-mcp .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /anb-mcp /anb-mcp
ENTRYPOINT ["/anb-mcp"]
