CMDS = zlint zlint-gtld-update
CMD_PREFIX = ./cmd/
GO_ENV = GO111MODULE=on
BUILD = $(GO_ENV) go build -mod=vendor
TEST = $(GO_ENV) GORACE=halt_on_error=1 go test -mod=vendor -race

all: $(CMDS)

zlint:
	$(BUILD) $(CMD_PREFIX)$(@)

zlint-gtld-update:
	$(BUILD) $(CMD_PREFIX)$(@)

clean:
	rm -f $(CMDS)

test:
	$(TEST) ./...

.PHONY: clean zlint zlint-gtld-update test
