# skill2graph shortcuts. `make` or `make help` lists the targets.
#
# Variables (override on the command line):
#   SKILL   skill folder for build/paths targets   e.g. make build SKILL=sample_skills/git-tools
#   SKILLS  root folder for batch targets          (default: sample_skills)
#   OUT     heuristic output folder                (default: out)
#   OUT_LLM LLM output folder                      (default: out_llm)
#   MODEL   Azure deployment for --llm             (default: QLAY_AI_DEPLOYMENT from .env)
#   N       runs per skill for `make stability`    (default: 5)
#   PORT    port for `make serve`                  (default: 8765)

SKILLS  ?= sample_skills
OUT     ?= out
OUT_LLM ?= out_llm
SKILL   ?= sample_skills/send-money
MODEL   ?=
N       ?= 5
PORT    ?= 8765

NAME       := $(notdir $(abspath $(SKILL)))
MODEL_FLAG := $(if $(MODEL),--model $(MODEL),)
RUN        := uv run

.DEFAULT_GOAL := help
.PHONY: help install test build build-llm paths paths-llm batch batch-llm both compare index stability serve clean

help: ## list targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "  e.g. make build SKILL=sample_skills/git-tools    make compare    make serve"

install: ## install dependencies (uv sync)
	uv sync

test: ## run the test suite (never touches the network)
	$(RUN) pytest -q

build: ## one skill, heuristic -> $(OUT)/<skill> (index updated)
	$(RUN) skill2graph build $(SKILL) -o $(OUT)/$(NAME)

build-llm: ## one skill, LLM -> $(OUT_LLM)/<skill> (index updated)
	$(RUN) skill2graph build $(SKILL) --llm $(MODEL_FLAG) -o $(OUT_LLM)/$(NAME)

paths: ## print ranked candidate paths for SKILL (heuristic)
	$(RUN) skill2graph paths $(SKILL)

paths-llm: ## print ranked candidate paths for SKILL (LLM)
	$(RUN) skill2graph paths $(SKILL) --llm $(MODEL_FLAG)

batch: ## every skill in $(SKILLS), heuristic -> $(OUT)/
	$(RUN) skill2graph batch $(SKILLS) -o $(OUT)

batch-llm: ## every skill in $(SKILLS), LLM -> $(OUT_LLM)/
	$(RUN) skill2graph batch $(SKILLS) --llm $(MODEL_FLAG) -o $(OUT_LLM)

both: compare ## alias for compare

compare: ## heuristic + LLM on every skill, time each, store in $(OUT)/ and $(OUT_LLM)/, print comparison
	$(RUN) python tools/compare_extractors.py $(SKILLS) --heuristic-out $(OUT) --llm-out $(OUT_LLM) $(MODEL_FLAG)

index: ## rebuild index.html + summary.csv in $(OUT) and $(OUT_LLM) from the graphs on disk
	$(RUN) skill2graph index $(OUT)
	@if [ -d $(OUT_LLM) ]; then $(RUN) skill2graph index $(OUT_LLM); fi

stability: ## LLM stability check: N runs per skill (N x skills API calls)
	$(RUN) python tools/llm_stability.py $(N)

serve: ## serve the output folders at http://localhost:$(PORT)/ (Ctrl-C to stop)
	@echo "heuristic: http://localhost:$(PORT)/$(OUT)/index.html"
	@echo "llm:       http://localhost:$(PORT)/$(OUT_LLM)/index.html"
	python3 -m http.server $(PORT) --bind 127.0.0.1

clean: ## delete $(OUT)/ and $(OUT_LLM)/
	rm -rf $(OUT) $(OUT_LLM)
