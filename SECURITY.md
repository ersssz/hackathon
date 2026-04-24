# Security Policy

## Responsible use

ZeroTrust-AI is a **defensive** security tool. Its attack library is published
so that product teams can audit **their own** chatbots before shipping.

The adversarial prompts in `attacks/*.yaml` are intentionally designed to
trigger unsafe behaviour from LLMs. Do **not**:

- Run ZeroTrust-AI against third-party services you do not own or are not
  explicitly authorised to test.
- Integrate the attack payloads verbatim into a live product.
- Use the tool to generate harmful content for anything other than
  vulnerability assessment under strict sandboxing.

## Reporting a vulnerability

Spotted a bug in ZeroTrust-AI itself — for instance, a code-execution risk
via a crafted attack YAML, a credential-leak in the report renderer, or a
dependency CVE? Please file a GitHub issue tagged `security`.

For sensitive findings, email the team instead of opening a public issue.

## Scope

In scope:

- The Streamlit app (`app.py`) and the `llmsentinel` Python package.
- The Dockerfile.
- The attack YAML schema loader.

Out of scope:

- Vulnerabilities in upstream LLM providers (Fireworks, OpenAI, Groq, etc.).
  Report those to the provider directly.
- Weaknesses in target LLMs discovered *using* ZeroTrust-AI. These belong to
  the model owner's disclosure process.

## Supported versions

Only the latest `main` branch is supported. This is a hackathon submission,
not a production project — but we are happy to review patches.
