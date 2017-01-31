.PHONY: help test

IMAGE_NAME ?= erl_tar2

SRC = $(shell find . -name *.erl)

OBJ = $(SRC:%.erl=_build/%.beam)


help:
	@echo "$(IMAGE_NAME):$(VERSION)"
	@perl -nle'print $& if m{^[a-zA-Z_-]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: _build $(OBJ) ## Rebuild

_build:
	mkdir -p _build

_build/%.beam: %.erl
	erlc -o _build erl_tar.erl

shell: ## Shell with erl_tar2 loaded
	erl -pa _build

clean: ## Test
	rm -rf _build
	rm -rf extracted
	rm -f *_tmp.tar
