# Cross-compiled rather than emulated: the builder always runs on the native
# platform and Go targets TARGETARCH, so a multi-arch build needs no QEMU.
# Digest-pinned because the release workflow signs a provenance attestation:
# an upstream tag move would otherwise be attested as an official build.
# Bump both digests deliberately.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/fly-oidc-discharge ./cmd/fly-oidc-discharge

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# The policy is deployment-specific and is never baked in. Supply it at run
# time as a file at POLICY_FILE, or inline through POLICY_YAML.
ENV POLICY_FILE=/etc/fly-oidc-discharge/policy.yaml
COPY --from=build /out/fly-oidc-discharge /usr/local/bin/fly-oidc-discharge
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fly-oidc-discharge"]
