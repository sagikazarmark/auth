# Docker registry auth

1. `docker compose up -d`
1. `go run ./cmd/server -addr 0.0.0.0:8080 -debug -issuer localhost:8080 -key private_key.pem -realm localhost:8080`
1. `docker login -u user -p password localhost:5000`

```
docker pull alpine
docker tag alpine localhost:5000/user/alpine
docker push localhost:5000/user/alpine
```
