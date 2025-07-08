import logging
from colorama import Fore, Style, init

# Initialize colorama to work everywhere
init(autoreset=True)

# Configure a basic logger that writes to a file for debugging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='soenlis_audit.log',
                    filemode='w')

# Our "modern" display function
def log_event(agent_name: str, message: str, status: str = "INFO"):
    """Displays a formatted and colored message in the console, and logs it to a file."""
    
    # Dictionary of styles for the console
    status_styles = {
        "INFO": Fore.BLUE + "[i]",
        "ACTION": Fore.MAGENTA + "[>]",
        "SUCCESS": Fore.GREEN + Style.BRIGHT + "[✓]",
        "ERROR": Fore.RED + Style.BRIGHT + "[✗]",
        "WAITING": Fore.YELLOW + "[...]",
    }

    prefix = status_styles.get(status.upper(), status_styles["INFO"])
    
    # Choose color based on agent name
    agent_color = Fore.CYAN if "Orchestrator" in agent_name else Fore.YELLOW if "Recon" in agent_name else Fore.LIGHTBLUE_EX
    
    console_message = f"{agent_color}{Style.BRIGHT}[{agent_name}]{Style.RESET_ALL} {prefix} {message}"
    print(console_message)
    
    # Also write a clean log to the file, without colors
    logging.info(f"[{agent_name}] [{status}] {message}")