PWD := $(shell pwd)
BUILD_DIR := ${PWD}/build

APP_NAME := vaultfile

BUILD_VERSION := $(shell git describe --tags --exact-match 2>/dev/null || git rev-parse --short=8 --verify HEAD)
BUILD_SHA := $(shell git rev-parse --short=8 --verify HEAD)

GO_CMD ?= go
GO_BUILD_TAGS =
GO_BUILD_LDFLAGS ?= -s -w -buildid= -X 'github.com/HallyG/${APP_NAME}/cmd/vaultfile.BuildShortSHA=$(BUILD_SHA)' -X 'github.com/HallyG/${APP_NAME}/cmd/vaultfile.BuildVersion=$(BUILD_VERSION)'

GO_PKGS := $(shell go list -f '{{.Dir}}' ./... )
EXCLUDE_PKGS := github.com/HallyG/vaultfile github.com/HallyG/vaultfile/cmd/vaultfile github.com/HallyG/vaultfile/examples/basic
GO_COVERAGE_PKGS := $(filter-out $(EXCLUDE_PKGS),$(GO_PKGS))
GO_COVERAGE_FILE := $(BUILD_DIR)/cover.out
GO_COVERAGE_TEXT_FILE := $(BUILD_DIR)/cover.txt
GO_COVERAGE_HTML_FILE := $(BUILD_DIR)/cover.html
GOLANGCI_CMD := go tool golangci-lint
GOLANGCI_ARGS ?= --fix --concurrency=4

.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | sort | column -t -s ':' |  sed -e 's/^/ /'

## clean: remove build artifacts and temporary files
.PHONY: clean
clean:
	@rm -f ${BUILD_DIR}/${APP_NAME};
	@rm -f ${GO_COVERAGE_FILE} ${GO_COVERAGE_TEXT_FILE} ${GO_COVERAGE_HTML_FILE}
	@$(GO_CMD) clean

## test: run tests
.PHONY: test
test:
	@$(GO_CMD) test ${GO_BUILD_TAGS} -timeout 30s -race $(if $(VERBOSE),-v) ${GO_COVERAGE_PKGS}

## test/cover: run tests with coverage
.PHONY: test/cover
test/cover:
	@mkdir -p ${BUILD_DIR}
	@rm -f ${GO_COVERAGE_FILE} ${GO_COVERAGE_TEXT_FILE} ${GO_COVERAGE_HTML_FILE}
	@$(GO_CMD) test ${GO_BUILD_TAGS} -timeout 30s -race -coverprofile=${GO_COVERAGE_FILE} ${GO_COVERAGE_PKGS}
	@$(GO_CMD) tool cover -func ${GO_COVERAGE_FILE} -o ${GO_COVERAGE_TEXT_FILE}
	@$(GO_CMD) tool cover -html ${GO_COVERAGE_FILE} -o ${GO_COVERAGE_HTML_FILE}

## lint: run golangci-lint
.PHONY: lint
lint:
	@$(GO_CMD) vet ${GO_PKGS}
	@${GOLANGCI_CMD} run ${GOLANGCI_ARGS} ${GO_PKGS}

## audit: format, vet, and lint Go code
.PHONY: audit
audit: clean lint
	@$(GO_CMD) mod tidy
	@$(GO_CMD) mod verify
	@$(GO_CMD) fmt ${GO_PKGS}

## build: build the application
.PHONY: build
build:
	@$(GO_CMD) build ${GO_BUILD_TAGS} \
		-o ${BUILD_DIR}/${APP_NAME} \
		-trimpath -mod=readonly \
		-ldflags="$(GO_BUILD_LDFLAGS)" .

## run: run the application	
.PHONY: run
run: build
	@${BUILD_DIR}/${APP_NAME} --version

## release/tag: tag latest commit for release
.PHONY: release/tag 
release/tag:
	@echo "Tagging and pushing as v$(NEW_VERSION)"
	@if [ -z "$(NEW_VERSION)" ]; then \
		echo "Error: NEW_VERSION is not set."; \
		exit 1; \
	fi
	@echo -n "Are you sure you want to tag and push v$(NEW_VERSION)? [y/N] " && read ans && [ "$$ans" = "y" ] || exit 1
	@git tag "v$(NEW_VERSION)"
	@git push origin "v$(NEW_VERSION)"
	@echo "Make release from tag v$(NEW_VERSION)"

## release/dry: release (dry-run)
.PHONY: release/dry 
release/dry:
	goreleaser release --clean --snapshot