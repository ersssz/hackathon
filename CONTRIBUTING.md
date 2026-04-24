# Contributing to ZeroTrust-AI

Thanks for your interest — this project was built during a 6-hour hackathon,
so there are rough edges to sand down and directions to explore.

## Dev setup

```powershell
git clone https://github.com/ersssz/hackathon.git
cd hackathon
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements-dev.txt
copy .env.example .env
# edit .env and paste your API key + base URL
streamlit run app.py
```

## Running tests

```powershell
pytest
```

All tests are **hermetic** — no network calls. If you add a feature that
talks to an LLM, gate it behind a `@pytest.mark.integration` marker and
keep the default test suite fast.

## Adding a new attack

1. Pick the right YAML file in `attacks/` (or create a new one).
2. Give the attack a stable `id` — `<CATEGORY>-<NUMBER>`, e.g. `PI-006`.
3. Fill every field of the `Attack` schema (see `llmsentinel/models.py`).
4. Map `owasp_llm` to the matching OWASP LLM Top 10 code.
5. Run `pytest tests/test_attacks_loader.py` to make sure the file parses.

## Adding a new endpoint preset

1. Edit `ENDPOINT_PRESETS` in `llmsentinel/adapters.py`.
2. Add the provider to the table in `README.md`.

## Adding a new attack category

1. Add the enum value to `AttackCategory` in `llmsentinel/models.py`.
2. Add a mitigation list to `MITIGATIONS` in `llmsentinel/report.py`.
3. Create the corresponding `attacks/<new_category>.yaml` file.

## Code style

- Type-hint everything you touch.
- Prefer small, testable functions.
- Docstrings for every public class/function.
- No emojis in source code unless the user asks.

## Pull requests

- Keep PRs focused — one feature or one fix per PR.
- Run `pytest` locally before pushing.
- Describe what you changed and why.
