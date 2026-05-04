# SentinelAI: Autonomous Cybersecurity Monitoring Agent

SentinelAI is an advanced AI agent developed for the Data Science Applications and AI course (LB3114) at General Sir John Kotelawala Defence University. It demonstrates the practical application of LLM-based autonomous reasoning in the domain of cybersecurity.

---

## Overview

Cybersecurity threats are evolving faster than traditional signature-based systems can address. SentinelAI responds to this challenge by using Large Language Models (LLMs) to perform contextual reasoning on system logs. Rather than simply pattern-matching against known bad strings, the agent understands the intent and technique behind log entries.

**Key Capabilities:**

- **Autonomous Threat Hunting** — Scans logs for indicators of Brute Force attacks, SQL Injection, and Unauthorized Access.
- **Goal-Directed Investigation** — Automatically queries external security databases (IP reputation services, CVE databases) to validate detected threats.
- **Incident Mitigation** — Produces human-readable explanations alongside specific technical remediation steps for each detected issue.
- **Memory Retention** — Tracks recurring suspicious behavior across sessions to identify persistent threat actors.

---

## Technical Architecture

The agent is built using a modular framework:

| Layer | Description |
|---|---|
| **Perception** | Custom Python parsers convert raw SSH and web server logs into structured JSON. |
| **Cognitive Engine** | Powered by LangChain and OpenAI GPT-4o, utilizing a Reasoning and Acting (ReAct) loop. |
| **Action** | Integrated tools for DuckDuckGo search (threat intelligence gathering) and local file updates. |
| **Interface** | A reactive dashboard built with Streamlit. |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- An OpenAI API key (or a locally hosted LLM via Ollama)

### Installation

1. Clone the repository:

    ```bash
    git clone [your-repo-link]
    cd sentinel-ai
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Configure environment variables by creating a `.env` file in the root directory:

    ```env
    GOOGLE_API_KEY=your_api_key_here
    ```

### Running the Agent

```bash
streamlit run src/app.py
```

---

## Repository Structure

```
sentinel-ai/
├── data/               # Mock log files for demonstration
├── src/
│   ├── agent.py        # LangChain agent configuration
│   ├── parser.py       # Log parsing utilities
│   └── app.py          # Streamlit dashboard
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.