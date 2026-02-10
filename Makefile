#
# See `make help` for a list of all available commands.
#

SOURCEDIR = docs/
BUILDDIR = docs/_build/
.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' | sort

.PHONY: clean
clean: ## Clean build artifacts and generated files
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -delete

.PHONY: docs
docs: ## Build Sphinx HTML documentation
	sphinx-build -M dirhtml "$(SOURCEDIR)" "$(BUILDDIR)"

.PHONY: docs-server
docs-server: ## Run Sphinx build server
	sphinx-autobuild -b dirhtml -a "$(SOURCEDIR)" "$(BUILDDIR)"
.PHONY: docs-ci
docs-ci: ## Generate HTML documentation for publishing to GitHub Pages.
	sphinx-build -M dirhtml "$(SOURCEDIR)" "$(BUILDDIR)" -W --keep-going

.PHONY: docs-pdf
docs-pdf: ## Build Sphinx PDF documentation
	poetry export --dev --without-hashes -f requirements.txt -o docs/requirements.txt
	docker run --rm -v "$(PWD)/docs":/docs sphinxdoc/sphinx-latexpdf:4.3.1 \
			bash -c "pip install -r requirements.txt && sphinx-build -M latexpdf /docs /docs/_build"
	rm docs/requirements.txt

.PHONY: test
test: ## Run tests
	pytest --cov=src/ --cov-report=term-missing


.PHONY: test-ci
test-ci: ## Run tests (with XML coverage report)
	pytest --cov=src/ --cov-report=xml
