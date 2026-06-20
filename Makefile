# SPDX-License-Identifier: Apache-2.0
#
# nest-adapters developer Makefile.
#
# `ci-local` runs the exact 6-command sequence Nanda Town's CONTRIBUTING.md
# mandates as the Definition of Done, in order, hard-failing on the first red
# command. Run it before every push.

.DEFAULT_GOAL := help

.PHONY: help ci-local hooks

help: ## List available targets.
	@echo "nest-adapters developer targets:"
	@echo ""
	@echo "  make ci-local   Run the full CI sequence (sync, ruff check,"
	@echo "                  ruff format --check, mypy, pyright, pytest)."
	@echo "  make help       Show this message."

ci-local: ## Run the exact Nanda Town CI command sequence; hard-fail on first red.
	@echo ">>> [1/6] uv sync"
	uv sync
	@echo ">>> [2/6] uv run ruff check ."
	uv run ruff check .
	@echo ">>> [3/6] uv run ruff format --check ."
	uv run ruff format --check .
	@echo ">>> [4/6] uv run mypy src"
	uv run mypy src
	@echo ">>> [5/6] uv run pyright"
	uv run pyright
	@echo ">>> [6/6] uv run pytest -v"
	uv run pytest -v
	@echo ""
	@echo "ci-local: all 6 checks passed. Safe to push."
