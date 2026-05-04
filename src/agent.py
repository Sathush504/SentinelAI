import os
import subprocess
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import create_agent
from langchain_core.messages import SystemMessage
from langchain.tools import tool

load_dotenv()

# --- Custom Tools ---

@tool
def security_policy_lookup(query: str) -> str:
    """Useful for looking up corporate security policies regarding specific threats."""
    policies = {
        "brute force": "Policy: Block IP after 5 failed attempts. Notify admin.",
        "sql injection": "Policy: Immediately quarantine web server and audit database logs.",
        "unauthorized access": "Policy: Revoke user credentials and force password reset."
    }
    for key in policies:
        if key in query.lower():
            return policies[key]
    return "No specific policy found. Escalating to standard SOP."

@tool
def execute_terminal_command(command: str) -> str:
    """Run a safe terminal command (e.g., ping, whois, ls, netstat) to investigate the local system or network.
    Do not run destructive commands."""
    allowed_base_commands = ["ping", "whois", "nslookup", "netstat", "ifconfig", "ls", "echo", "pwd", "date"]
    base_cmd = command.split()[0] if command else ""
    if base_cmd not in allowed_base_commands:
        return f"Command '{base_cmd}' is not allowed for security reasons. Allowed: {', '.join(allowed_base_commands)}"
    
    try:
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Error executing command: {str(e)}"

class SentinelAgent:
    def __init__(self):
        # Use Gemini Flash (Free tier friendly)
        self.llm = ChatGoogleGenerativeAI(model="gemini-3.1-flash-lite-preview", temperature=0)
        self.tools = [security_policy_lookup, execute_terminal_command]
        
        system_prompt = (
            "You are SentinelAI, an expert autonomous cybersecurity analyst. "
            "Your goal is to analyze system logs, identify threats, suggest mitigation, and answer user queries. "
            "You have access to a terminal to run commands like 'ping' or 'whois' to investigate IPs. "
            "When you identify an attack type, lookup the relevant security policy."
        )
        
        # Using the modern LangChain 1.2 Agent Factory
        self.agent = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt
        )

    def analyze_threat(self, threat_context: str):
        """Analyze a specific set of logs or a detected event."""
        input_text = f"Analyze the following log data and provide a detailed threat report and mitigation steps:\n\n{threat_context}"
        return self.chat(input_text)

    def chat(self, user_input: str):
        """Interactive chat method for the agent."""
        try:
            response = self.agent.invoke({"messages": [("human", user_input)]})
            # Standard LangGraph agent output
            content = response["messages"][-1].content
            if isinstance(content, list) and len(content) > 0 and 'text' in content[0]:
                return content[0]['text']
            elif isinstance(content, str):
                return content
            else:
                return str(content)
        except Exception as e:
            return f"Agent is currently unavailable (API Error): {str(e)}"
