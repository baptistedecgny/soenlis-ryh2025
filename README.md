# Soenlis.ai: Intelligent Web Security Scanner

## Ignite Your Vision. Build the Future.

[cite_start]Soenlis.ai is an intelligent web security scanner developed for the **Raise Your Hack 2025** hackathon[cite: 1]. [cite_start]It leverages a cutting-edge multi-agent architecture powered by **Coral Protocol** [cite: 1] [cite_start]and advanced AI models (Llama 3.1, Groq) [cite: 1] to provide comprehensive and precise security audits for web applications. [cite_start]Deployed on **Vultr** infrastructure[cite: 1], Soenlis aims to redefine web security by offering automated, efficient, and ethical vulnerability detection.



## ✨ Key Features

* [cite_start]**AI-Powered Vulnerability Detection:** Utilizes advanced AI models (Llama 3.1, Groq) to identify and analyze web vulnerabilities with high accuracy and speed[cite: 1].

* [cite_start]**Multi-Agent Orchestration (Coral Protocol):** Employs a sophisticated multi-agent architecture where specialized AI agents collaborate seamlessly via Coral Protocol for enhanced scanning and reporting[cite: 1].

* [cite_start]**Blazing Fast Scans (Groq Integration):** Accelerated AI inference with Groq API ensures rapid and efficient security assessments[cite: 1].

* [cite_start]**Automated Reporting:** Generates comprehensive, easy-to-understand HTML reports of identified vulnerabilities and recommendations[cite: 1].

* [cite_start]**Scalable Cloud Deployment (Vultr):** Designed for high availability and scalability, deployed on Vultr's robust cloud infrastructure[cite: 1].

* [cite_start]**CVE Database & Tech Detection:** Integrates with Wappalyzer for technology fingerprinting and cross-references with CVE databases for known vulnerability lookups[cite: 1].

* [cite_start]**Ethical Scanning Mode:** Prioritizes non-intrusiveness, focusing on passive information gathering and non-destructive analysis[cite: 1].

## 🧠 The Soenlis Multi-Agent Architecture

[cite_start]At the heart of Soenlis lies a dynamic, collaborative system of specialized AI agents, orchestrated by Coral Protocol[cite: 1], to deliver unparalleled precision in web security audits. Each agent performs a critical role in the auditing pipeline:

1.  [cite_start]**Orchestrator Agent:** Manages the entire audit workflow, delegates tasks to specialist agents, and synthesizes final results[cite: 1].

2.  [cite_start]**Reconnaissance Agent:** Identifies web technologies, analyzes HTTP headers, and collects initial site data from the target URL[cite: 1].

3.  [cite_start]**CVE Auditor Agent:** Performs detailed CVE (Common Vulnerabilities and Exposures) lookups for identified technologies and their versions[cite: 1].

4.  [cite_start]**Report Generator Agent:** Compiles all findings, including vulnerabilities and recommendations, into a comprehensive and actionable HTML report[cite: 1].

[cite_start]This modular design allows Soenlis to be highly scalable, efficient, and adaptable to new threats and scanning techniques[cite: 1].

## 🚀 Setup Guide

To get Soenlis.ai up and running, you need to set up the Coral Protocol server, the Coral Interface Agent, and then the Soenlis backend (Orchestrator, Recon, CVE agents) and frontend.

### Prerequisites

* **Docker Desktop:** Required for running the Coral Server. [Install Docker Desktop](https://www.docker.com/products/docker-desktop/)

* **Python 3.9+:** Recommended for Soenlis.

* **`uv` (Ultrafast Python package installer and runner):** Replaces `pip` and `venv` for faster dependency management. [Install `uv`]([https://docs.astral.sh/uv/install/](https://docs.astral.sh/uv/install/))

* **Groq API Key:** Obtain one from [Groq Cloud](https://console.groq.com/keys) for AI model inference.

* **VULNERS_API_KEY (Optional but Recommended):** For extended CVE lookup capabilities beyond mock data. Register at [Vulners.com](https://vulners.com/).

### Step 1: Clone the Soenlis Repository

First, clone the Soenlis project repository:

```git clone https://github.com/YourRepo/Soenlis.ai.git # Replace with actual repo URL```
```cd Soenlis.ai```

### Step 2: Set up Soenlis Python Environment and `.env` File

Create and activate a Python virtual environment using `uv`, then install dependencies:

```uv venv```
```source .venv/bin/activate # On Windows: .venv\Scripts\activate```
```uv pip install -r requirements.txt```

Next, create a `.env` file in the root of the `Soenlis.ai` directory and populate it with the following environment variables:

`# Coral Protocol Configuration`
```CORAL_SSE_URL=http://localhost:5555/api/sse # Default Coral Server SSE URL```

```# Soenlis Agent IDs (Must be unique within your Coral setup)```
```# You can choose any unique strings here.```
```CORAL_AGENT_ID=soenlis-orchestrator-agent # This is the Orchestrator's ID```
```RECON_AGENT_ID=soenlis-recon-agent```
```CVE_AGENT_ID=soenlis-cve-agent```
```REPORT_AGENT_ID=soenlis-report-agent # Not directly used in .py but good for consistency```

`# Groq API Key for LLM (Llama 3.1)`
```API_KEY=YOUR_GROQ_API_KEY_HERE```
```MODEL_NAME=llama3-70b-8192 # Recommended model for best performance```

```# Vulners API Key (Optional but recommended for real CVE data)```
```VULNERS_API_KEY=YOUR_VULNERS_API_KEY_HERE # Get from vulners.com```

### Step 3: Run the Coral Server (using Docker)

The Coral Server is the backbone for the Multi-Party Computation (MCP) and agent communication. It runs as a Docker container.

1.  **Pull the Docker image:**
    ```docker pull coralprotocol/coral-server:latest```
2.  **Create a volume for configuration (optional but recommended):**
    If you don't have it already, create a directory for Coral Server's configuration on your host machine.
    * On Linux/macOS: ```mkdir -p ~/coral_server_config```
    * On Windows (PowerShell): ```New-Item -ItemType Directory -Force -Path "C:\coral_server_config"```
3.  **Run the Coral Server:**
    Navigate to the directory where you want to store server data (e.g., your project's `coral-server` folder, or just use a generic path).
    Replace `C:\Users\johnd\Desktop\hackathon_setup\soenlis-ryh2025\coral-server\src\main\resources` with the *actual path* to your config directory from the previous step. **Ensure Docker Desktop is running.**

    `# For Windows (PowerShell, adjust path if necessary):`
    ```docker run -p 5555:5555 -v C:\coral_server_config:/config coralprotocol/coral-server:latest```

    `# For Linux/macOS:`
    ```docker run -p 5555:5555 -v ~/coral_server_config:/config coralprotocol/coral-server:latest```

    The server should start and log messages indicating it's ready on port `5555`

### Step 4: Run the Coral Interface Agent

The Coral Interface Agent is a separate project that provides the `send_message`, `create_thread`, `wait_for_mentions` tools that Soenlis agents use.

1.  **Clone the Coral Interface Agent repository:**
    ```cd .. # Go up to the parent directory if you're inside Soenlis.ai```
    ```git clone https://github.com/Coral-Protocol/Coral-Interface-Agent.git```
    ```cd Coral-Interface-Agent```
2.  **Set up its Python environment and dependencies:**
    ```uv venv```
    ```source .venv/bin/activate # On Windows: .venv\Scripts\activate```
    ```uv pip install -r requirements.txt```
3.  **Create a `.env` file** in `Coral-Interface-Agent` with the following:
    `# Coral Interface Agent Configuration`
    `CORAL_AGENT_ID=coral-interface-agent # This agent's ID`
    `CORAL_SSE_URL=http://localhost:5555/api/sse`
4.  **Run the Interface Agent:**
    `./run_agent.sh src/interface_agent.py`
    You should see logs indicating the agent connecting to Coral and listening.

### Step 5: Run Soenlis Agents (Recon & CVE)

These are the specialist agents for Soenlis that will listen for tasks from the Orchestrator. Each should be run in a **separate terminal window**.

Navigate back to your `Soenlis.ai` project directory:

```cd ../Soenlis.ai # Go back to your Soenlis.ai project directory```
```source .venv/bin/activate # Activate Soenlis's virtual environment```

**Terminal 1: Run Reconnaissance Agent**
```python recon_agent.py```

**Terminal 2: Run CVE Agent**
```python cve_agent.py```
You should see logs indicating these agents are "connected" and "listening for tasks."

### Step 6: Run the Soenlis Backend (Flask App)

This is the Flask server that powers the web interface and acts as the main Orchestrator for the audit workflow.

Navigate back to your `Soenlis.ai` project directory if you aren't there, and ensure the virtual environment is active.

**Terminal 3: Run Soenlis Flask Backend**
```python app.py```
The Flask server will start, typically on `http://127.0.0.1:5000/` or `http://localhost:5000/`. It will also attempt to initialize its connection to Coral.

## 🌐 Usage

1.  **Open your web browser** and navigate to `http://localhost:5000/`.
2.  **Enter the URL** of the website you wish to scan in the input field.
3.  **Click "Start Scan"**.

The Orchestrator agent will delegate tasks to the Reconnaissance and CVE agents, process the results, and generate a comprehensive security audit report. The scan status will update on the page, and a download button for the HTML report will appear upon completion.



The audit report will be generated as an HTML file, providing a detailed overview of detected technologies, vulnerabilities, and recommendations.



## 🧑‍💻 Who We Are

Soenlis is the result of the collaborative work of **Baptiste Decagny** and his colleague **Uramix**. We are a team passionate about web development, artificial intelligence, and cybersecurity. Baptiste Decagny, an 18-year-old student, is the initial creator of Soenlis. Uramix brings complementary expertise and vision to strengthen the project. Together, we push the boundaries of innovation to build next-generation security solutions for Raise Your Hack 2025.

## 🤝 Contribution

Contributions are welcome! If you have ideas for improvements, bug fixes, or new features, feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
