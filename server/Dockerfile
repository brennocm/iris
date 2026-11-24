# Build: docker build -t iris-verifier server/
# Run:   docker run -p 8080:8080 -e IRIS_PACKAGE_NAME=com.example.app iris-verifier
#
# Base images are pinned by digest; bump the tag and digest together.

FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Static, reproducible binary: no cgo, no VCS stamping, paths trimmed.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/iris-verifier ./cmd/iris-verifier

# distroless/static: CA certificates and tzdata, no shell or package manager; runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/iris-verifier /iris-verifier
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/iris-verifier"]
