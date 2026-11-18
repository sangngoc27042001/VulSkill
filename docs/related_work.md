# Related work: security of agent skills (and MCP)

## Short comparison (7 most related + ours)

Technique labels: **Rules** (regex/keyword) · **SAST** (AST/static code analysis) · **Graph** (graph across artifacts) ·
**LLM** · **Dynamic** (runs the skill or agent).
Attacker labels: **Skill author** · **Untrusted-source author** (controls content the skill handles at run time) ·
**Agent-app user** · **None** (the developer's own mistake).

| Paper | Problem it solves (main finding) | Technique | Attacker | Mentions untrusted-source author? | Scale |
|---|---|---|---|---|---|
| MalSkills (ASE'26) | Detects malicious skills (400 confirmed in the wild; F1 0.93) | Graph + SAST + LLM | Skill author | No | 150,108 skills |
| Credential leakage (ASE'26) | How skills leak credentials (73.5% via debug logging; 76.3% need both NL and code to detect) | Rules + SAST + Dynamic | None | Yes ("Attack-Induced Leaks": prompt injection in external content the skill consumes; secrets only, 3.1% of cases) | 17,022 skills |
| Agent Skills in the Wild (arXiv) | How common risky patterns are (26.1% of skills have ≥1) | Rules + LLM | Skill author | No | 31,132 skills |
| Malicious Skills in the Wild (USENIX Sec'26) | Detects and characterises malicious skills (157 confirmed, 13 techniques) | Rules + LLM + Dynamic | Skill author | No | 98,380 skills |
| SkillSecurer (arXiv) | Detects and patches prompt-injection risks, injected or latent (17.6% of popular skills flagged) | LLM | Skill author | Yes ("unsafe handling of untrusted input", a latent vulnerability; not in its attacker model) | 954 skills |
| Skill-Inject (NeurIPS'26*) | Measures whether agents obey instructions injected into skills (up to 80% attack success) | Dynamic | Skill author | No | 23 skills, 202 tasks |
| SkillSentry (arXiv) | Finds harmful behaviour that appears only at run time (recall 99.5%) | LLM + Dynamic | Skill author | No | benchmarks |
| **Ours (skill2graph)** | Finds and confirms taint-style vulnerabilities in benign skills | **Graph + SAST + LLM + Dynamic** | **Untrusted-source author** | **Yes (the core threat model)** | planned: sample of registry skills |

\* NeurIPS acceptance taken from the poster listing, not verified.
Indirect prompt injection appears only in the background or related-work sections of Malicious Skills in the Wild,
Skill-Inject and SkillSentry; none of them analyses it, so they are marked "No".

### Gap columns

| Paper | Explains how untrusted data reaches the sink | Follows data through the agent | Confirms with attacker-controlled input | Reports prevalence of untrusted → sink paths |
|---|---|---|---|---|
| MalSkills (ASE'26) | Partly (value-flow subgraph from a sensitive asset to a sink; no untrusted source) | No | No (manual review) | No (prevalence of malicious skills: 400 of 150K) |
| Credential leakage (ASE'26) | Partly (AST check that a credential reaches a sink in code; secrets only) | Partly (secrets reaching the agent's output; no flow beyond it) | Partly (sandbox with one generic injection payload in external content; secrets only) | Partly (237 skills leak only under attack; secrets only) |
| Agent Skills in the Wild (arXiv) | No | No | No | No (26.1% have risky patterns written in the skill itself) |
| Malicious Skills in the Wild (USENIX Sec'26) | No | No | No (dynamic run checks malicious behaviour, not outside input) | No |
| SkillSecurer (arXiv) | No (reports a quoted statement, not a path) | No | Partly (a few incidents triggered by hand) | Partly (17.6% flagged, all latent types mixed, not confirmed) |
| Skill-Inject (NeurIPS'26*) | No | Partly (measures whether the agent obeys instructions in the skill file itself) | No (the attacker's input is the skill itself) | No |
| SkillSentry (arXiv) | Partly (links effects to source and traces; no untrusted source) | Partly (compares runs with and without the skill; no data flow) | No (decoys trigger hidden behaviour, not attacker input) | No |
| **Ours** | **Yes – We extract explicit paths from untrusted sources to sinks across docs, code and the agent, with sanitizers** | **Yes – We model the agent context as a node, with probabilistic edges for its decisions** | **Yes – We run the agent with inputs crafted for each path (file name, web page, issue)** | **Yes – We measure confirmed paths in registry skills, by path type (T1–T7)** |

### Gaps

**General question:** How common are taint-style vulnerabilities in good-faith agent skills, where data controlled by
an outside party reaches a dangerous operation, and can existing tools find them?

Existing work focuses on the skill author as the attacker. Prior studies detect malicious skills (MalSkills, Malicious
Skills in the Wild, SkillSentry), measure risky patterns written in skills (Agent Skills in the Wild), or test whether
agents obey instructions injected into skills (Skill-Inject). Only two works touch content controlled by an outside
party. The credential study shows that 237 skills leak secrets only when processing attacker-controlled content, but it
covers secrets only and uses one generic payload. SkillSecurer flags "unsafe handling of untrusted input" with an LLM,
but gives no path and does not confirm the findings.

This leaves four gaps:
- **How untrusted data reaches the sink.** No work shows the path from an outside-controlled source to a sink, so
  findings can't be checked, classified or explained.
- **Flows through the agent.** No work models data that moves through the agent's context or decisions, e.g. one
  script's output reused by the agent as another script's argument.
- **Confirmation.** No work confirms these paths with attacker-controlled input crafted for each path; existing dynamic
  tests target malicious behaviour or use one generic payload.
- **Prevalence.** No work reports how common confirmed untrusted → sink paths are in real skills, or which shapes they
  take.

Collected 2026-11-09. All papers are in the Zotero collection **Skill Vulnerability Detection** (`FVLR6RZW`).
Venue status comes from the arXiv "Comments" field or the conference program, as noted.

- **Group A**: published at a venue on the target list (ASE, FSE, TOSEM). Only 5 papers qualify.
- **Group B**: not at a listed venue (USENIX Security, NeurIPS, workshops, arXiv). Kept because reviewers will
  expect them to be cited, and two of them (B1, B3) are the closest to this idea.

Short names used below:

| ID | Paper | Venue | Listed? |
|---|---|---|---|
| A1 | MalSkills: Detecting Malicious Skills in the Agentic Supply Chain via Neuro-symbolic Reasoning (Wang et al.) | ASE 2026 | yes |
| A2 | How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study (Chen et al.) | ASE 2026 | yes |
| A3 | Latent Reuse in Agent Skills: Multi-modal Clone Detection at Ecosystem Scale (Zhu et al.) | ASE 2026 | yes |
| A4 | Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions (Hou et al.) | TOSEM, FSE 2026 journal-first | yes (MCP, adjacent) |
| A5 | MCP at First Glance: Studying the Security and Maintainability of MCP Servers (Hasan et al.) | TOSEM per preprint header; final DOI not confirmed | yes (MCP, adjacent) |
| B1 | Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale (Liu et al.), "SkillScan" | arXiv 2601.10338 | no |
| B2 | "Do Not Mention This to the User": Detecting and Understanding Malicious Agent Skills in the Wild (Liu et al.) | USENIX Security 2026 | no |
| B3 | SkillSecurer: Detecting and Patching Prompt-Injection Vulnerabilities in AI Agent Skills (Mecca et al.) | arXiv 2609.14079 | no |
| B4 | Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks (Schmotz et al.) | NeurIPS 2026 poster listing (not verified) | no |
| B5 | SkillJect: Automating Skill-Based Prompt Injection for Skill-Enabled Agents (Jia et al.) | arXiv 2602.14211 | no |
| B6 | SkillSentry: Adaptive Honey Worlds for Dynamic Safety Testing of Agent Skills (Li et al.) | arXiv 2608.03485 | no |
| B7 | ColluSkill: Adversarial Cross-Skill Composition for Evading Agent Skill Scanners (Zeng et al.) | arXiv 2608.09732 | no |
| B8 | Context Matters: Repository-Aware Security Analysis of the Agent Skill Ecosystem (Holzbauer et al.) | AgentSkills '26 workshop @ CAIS (best paper) | no |
| B9 | Towards Secure Agent Skills: Architecture, Threat Taxonomy, and Security Analysis (Li et al.) | arXiv 2604.02837 | no |

Also relevant but not a paper: the ICSE 2027 Industry Challenge *"What Skills Claim and What Skills Do: Detecting
Intent-Behavior Misalignment in Agent Skill Ecosystems"* (solution papers due Nov 13, 2026). ICSE 2027 research-track
acceptances were not public when this was collected; check again before submission.

## Table 1: Problem and threat model

| ID | Problem it solves | Who is the attacker | Victim's flaw | Type of work | Scale / headline result |
|---|---|---|---|---|---|
| A1 | Detect **malicious** skills | Skill **author** (publishes a harmful skill, may evade detection) | Installs a malicious skill | Detector | 150,108 skills from 7 registries; 620 flagged, 400 confirmed; F1 0.93 on 200 skills |
| A2 | How skills **leak credentials** | None needed: a **negligent developer** leaks secrets (logs, output, files) | Accidental secret exposure | Empirical study | 17,022 skills sampled; 520 affected, 1,708 issues, 10 patterns; 73.5% debug logging; 76.3% need both NL and code |
| A3 | Find **clones** across skills (YAML, prose, code) | Not security-first; shows that scanners miss related copies of risky skills | Copied risky skills | Detector + ecosystem study | ~137K skills; 938 security-relevant skills → 16,587 clone links missed by per-skill scanners |
| A4 | Map the MCP **threat landscape** | Malicious developers, external attackers, malicious users, security flaws (4 types) | Many (16 scenarios) | Survey / taxonomy | Lifecycle with 4 phases and 16 activities |
| A5 | **Security and maintainability** of MCP servers | Vulnerable server code; **tool poisoning** | Insecure server code | Empirical study | 1,899 servers; 7.2% with general vulnerabilities, 5.5% with tool poisoning |
| B1 | How common are **"vulnerabilities"** in skills | Malicious authors, supply-chain attackers **and negligent developers**, all in one bucket | Risky patterns in skill content | Empirical study + scanner | 31,132 skills; 26.1% with ≥1 issue; 14 patterns in 4 categories |
| B2 | Detect and characterise **malicious** skills | Skill author / threat actor | Installs a malicious skill | Empirical study | 98,380 skills; 157 malicious, 632 issues, 13 techniques; one actor = 54.1% |
| B3 | Detect and **patch** prompt-injection issues, both **injected** and **latent** | Publishers or compromisers of a skill, **plus negligent developers** ("latent vulnerabilities") | Includes **unsafe handling of untrusted input** (e.g. shell execution of web content) | Detector + repair | 954 skills: 17.6% flagged; 84/100 sampled findings confirmed |
| B4 | **Measure** how agents follow injected skill instructions | Attacker who plants instructions in a skill | Agent obeys the skill | Benchmark | 202 injection-task pairs on 23 skills; up to 80% attack success |
| B5 | **Generate** stealthy skill injections automatically | Attacker publishing a poisoned skill | Agent obeys the skill | Attack | 95.1% attack success on 50 skills |
| B6 | Find behaviour that only shows up **at run time** | Malicious or risky skill that looks benign until certain states occur | Hidden behaviour | Dynamic tester | 99.5% recall, F1 96.3% |
| B7 | **Evade** scanners by splitting a payload across skills | Attacker publishing several skills | Installs several skills that combine | Attack + defense (ChainGuard) | 96.0% evasion → 22.5% with ChainGuard |
| B8 | Reduce **false alarms** with repository context | Malicious skills, hijacked abandoned repos | — | Empirical study | 238,180 skills; scanners flag up to 46.8%, only 0.52% remain suspicious |
| B9 | **Systematise** threats to the skill framework | Many (7 categories, 19 scenarios, 3 layers) | Missing boundary between data and instructions; trust granted once and kept | SoK | 7 incidents mapped |
| **Ours** | Find and confirm **taint-style vulnerabilities in benign skills** | **Third party** controlling run-time input (web page, repo file, issue, file name); author assumed **honest** | Untrusted data reaches a sink with no sanitizer | Empirical study + instrument (SFG) | — |

## Table 2: Technique

| ID | Analyzes docs (SKILL.md) | Analyzes code | Links docs ↔ code | Data flow / taint | Trust labels on sources | Agent as a hop in the flow | LLM role | Dynamic check | Ground truth |
|---|---|---|---|---|---|---|---|---|---|
| A1 | ✓ (LLM + rules) | ✓ (Semgrep, 10 langs) | ✓ operand equivalence (LLM) | ✓ value flow (YASA points-to) | ✗ | ✗ | Extract operations, infer missing flows, judge patterns | ✗ | 200-skill benchmark + manual review |
| A2 | ✓ | ✓ regex + AST | ✓ developer intent vs runtime behaviour | partial (secret → output) | secrets only | partial (secret → LLM context) | Classify intent | ✓ sandbox with mock credentials | Manual + sandbox |
| A3 | ✓ | ✓ | ✓ per-channel similarity | ✗ | ✗ | ✗ | ✗ | ✗ | Labelled clone pairs |
| A4 | — | — | — | — | — | — | — | — | — (survey) |
| A5 | ✗ (tool metadata only) | ✓ general SAST + MCP scanner | ✗ | via SAST tool | ✗ | ✗ | ✗ | ✗ | Tool output + manual |
| B1 | ✓ keywords | ✓ regex (Py/Sh/JS) | ✗ (LLM sees the whole package) | ✗ | ✗ | ✗ | Final verdict (Claude 3.5 Sonnet) | ✗ (listed as limitation) | 200 skills, 2 annotators, κ 0.83 |
| B2 | ✓ | ✓ | partial | ✗ | ✗ | ✗ | Classifier | ✓ behavioural verification | Confirmed malicious |
| B3 | ✓ | ✓ | LLM reasoning only | ✗ (explicitly none) | ✗ | ✗ | Whole detector + patcher | ✗ (patch check is static) | Injected cases + 100 reviewed findings |
| B4 | ✓ | — | — | — | — | ✓ (measures obedience) | Target of the attack | ✓ runs real agents | Attack success |
| B5 | ✓ | ✓ (payload in helper script) | — | — | — | ✓ | Attacker + evaluator | ✓ | Attack success |
| B6 | ✓ | ✓ | ✓ via traces | ✗ | decoy resources | ✓ compares runs with and without the skill | Simulated environment + task generation | ✓ | Benchmarks |
| B7 | ✓ | ✓ | across skills | ✗ | ✗ | ✓ shared context between skills | Attack planner | ✓ | Attack success |
| B8 | ✓ | ✓ | + GitHub repository | ✗ | ✗ | ✗ | — | ✗ | Manual |
| B9 | — | — | — | — | — | — | — | — | — (SoK) |
| **Ours** | ✓ (LLM + heuristic, validated records) | ✓ (Py AST, shell) | ✓ **argument binding** (`<x>` → `argv[i]`, implicit arguments) | ✓ **source → sink, sanitizers** | ✓ **untrusted / trusted / secret** | ✓ **AgentContext node + probabilistic edges** (llm_binding, follow_content, trigger, persists) | Extract instructions only; edges added by fixed rules | planned (confirm candidates) | planned: hand-labelled sample + union of all tools |

## Where this idea stands

**Already covered by others:**
- Malicious skills: A1, B2.
- Injection planted in a skill: B4, B5.
- Credential leaks: A2.
- Scanner evasion: B7.
- Run-time testing: B6.
- Pattern-based prevalence: B1.
- Graphs across docs and code: A1.

**Closest overlap:**
- **B3 (SkillSecurer).** It already names "latent vulnerabilities" in benign skills, including untrusted input reaching a shell. But detection is done entirely by an LLM: no data-flow model, no trust labels, no run-time confirmation. Its 17.6% is a flagging rate, not a confirmed rate.
- **B1.** It includes negligent developers in its threat model but mixes them with malicious authors. Its "vulnerabilities" are content patterns, not source → sink paths.

**What remains open (the contribution):**
1. A threat model that **separates** "third party controls the input" from "the author is malicious". B1 merges them; B3 mixes injected and latent cases.
2. **Explicit taint paths** across docs, code and the agent, with trust labels and sanitizers. No paper models the agent context as a hop in the flow, nor marks which edges depend on an LLM decision.
3. **Confirmed exploitability** of each path by running the agent with crafted inputs. B1 and B3 report flags; A2 and B2 confirm, but only for secrets and malicious skills.
4. A **taxonomy of path shapes** (T1–T7) and how much each shape needs analysis that crosses docs and code, or passes through the LLM. This extends A2's 76.3% from secrets to all sinks.
5. A **detection gap** measured against A1, B1, B3 and code-only SAST on the same confirmed set.

**Risk:** B3 appeared in Sep 2026 and is the closest work. Cite it prominently and compare against it in RQ3.
