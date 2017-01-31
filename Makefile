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
	erlc -o _build erl_tar2.erl

clean: ## Test
	rm -rf _build
	rm -rf extracted
	rm -f *_tmp.tar

test: _build ## Test
	rm -f *_tmp.tar
	rm -rf extracted
	erlc -o _build -DTEST erl_tar2.erl
	erl -noshell -pa _build -eval "eunit:test(erl_tar2, [verbose])." -s init stop
