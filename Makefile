# SPDX-License-Identifier: Apache-2.0
#
# nest-adapters developer Makefile.
#
# `ci-local` runs the exact 5-command sequence Nanda Town's CONTRIBUTING.md
# mandates as the Definition of Done, in order, hard-failing on the first red
# command. Run it before every push.

.DEFAULT_GOAL := help

.PHONY: help ci-local hooks

help: ## List available targets.
	@echo "nest-adapters developer targets:"
	@echo ""
	@echo "  make ci-local   Run the full CI sequence (sync, ruff check,"
	@echo "                  ruff format --check, pyright, pytest)."
	@echo "  make help       Show this message."

ci-local: ## Run the exact Nanda Town CI command sequence; hard-fail on first red.
	@echo ">>> [1/5] uv sync"
	uv sync
	@echo ">>> [2/5] uv run ruff check ."
	uv run ruff check .
	@echo ">>> [3/5] uv run ruff format --check ."
	uv run ruff format --check .
	@echo ">>> [4/5] uv run pyright"
	uv run pyright
	@echo ">>> [5/5] uv run pytest -v"
	uv run pytest -v
	@echo ""
	@echo "ci-local: all 5 checks passed. Safe to push."
