.PHONY: test test-race fmt vet clean build-caddy

test:
	go test -v ./...

test-race:
	go test -race -v ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f caddy caddy.exe
	rm -f test_users.htdigest

build-caddy:
	xcaddy build --with ./ 