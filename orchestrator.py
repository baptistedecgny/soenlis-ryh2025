import os
import json
import asyncio
import re
import base64
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from langchain_mcp_adapters.client import MultiServerMCPClient
import logging
import urllib.parse
import traceback
import xml.etree.ElementTree as ET
import time

# --- Soenlis module imports ---
from console_ui import log_event
from soenlis_tools import tool_enrich_technologies, tool_generate_final_summary
from audit import audit as generate_professional_audit_html

# --- Global Configuration ---
logging.basicConfig(level=logging.INFO, filename='orchestrator.log', filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
console = Console()
load_dotenv()

# --- Constants ---
RECON_TIMEOUT_MS = 59000
CVE_TIMEOUT_MS = 45000
POLL_INTERVAL_S = 2

# --- Coral Initialization (MOVED OUTSIDE ORCHESTRATOR'S GLOBAL SCOPE) ---
# These variables will now be passed as arguments to functions that need them.

# ############################################################################
# NEW: SECTION FOR PROFESSIONAL HTML REPORT GENERATION
# ############################################################################

def consolidate_and_generate_report(url: str, report_data: dict) -> str:
    # Gathers all findings, formats them, and generates the HTML report.
    # Returns the Base64 encoded HTML content of the report.
    log_event("Orchestrator", "Consolidating findings and generating professional HTML audit report...", status="ACTION")
    
    findings_for_html = []
    
    for finding in report_data.get('consolidated_findings', []):
        findings_for_html.append({
            "title": finding.get('title', 'Untitled Finding'),
            "severity": finding.get('severity', 'INFORMATIONAL').upper(),
            "technology": finding.get('technology', 'N/A'),
            "description": finding.get('meaning', 'No detailed explanation provided.') + 
                           (f"\n\n**Business Impact:** {finding.get('business_impact')}" if finding.get('business_impact') else ""),
            "recommendation": "\n".join(finding.get('remediation_steps', ["No specific recommendations provided."]))
        })

    header_analysis = report_data.get('detailed_header_analysis', {})
    for header_type, headers_list in header_analysis.items():
        for header in headers_list:
            severity = "GOOD" if header_type == "good_headers" else "MEDIUM"
            findings_for_html.append({
                "title": f"Security Header: {header.get('header', 'Unknown')}",
                "severity": severity,
                "technology": "HTTP Headers",
                "description": header.get('meaning', 'No detailed explanation provided.') + 
                               (f"\n\n**Business Impact:** {header.get('business_impact')}" if header.get('business_impact') else ""),
                "recommendation": "\n".join(header.get('remediation_steps', ["No specific recommendations provided."]))
            })
            
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "GOOD"]
    sorted_findings = sorted(findings_for_html, key=lambda x: severity_order.index(x.get("severity", "INFORMATIONAL")))

    domain = urllib.parse.urlparse(url).netloc.replace('.', '_')
    filename = f"Soenlis_Audit_{domain}_{datetime.now():%Y%m%d%H%M%S}.html"
    
    html_content = generate_professional_audit_html(
        url=url,
        score=report_data.get('final_security_score', 0),
        executive_summary=report_data.get('executive_summary', {}).get('overall_assessment', "No summary available."),
        findings=sorted_findings,
        filename=filename
    )
    
    log_event("Orchestrator", f"Professional HTML audit report generated: audits/{filename}", status="SUCCESS")
    
    return base64.b64encode(html_content.encode('utf-8')).decode('utf-8')


# ############################################################################
# SECTION: CORAL COMMUNICATION TOOLS (MODIFIED TO RECEIVE CLIENT AND TOOLS)
# ############################################################################
async def create_coral_thread_util(coral_mcp_tools: dict, participant_ids: list, thread_name: str) -> str:
    tool = coral_mcp_tools.get("create_thread")
    if not tool: raise ValueError("Coral tool 'create_thread' not found.")
    try:
        args = {"participantIds": participant_ids, "threadName": thread_name}
        raw_result = await tool.ainvoke(args)
        match = re.search(r"ID: ([0-9a-fA-F-]+)", str(raw_result))
        if not match: raise ValueError(f"Could not extract thread ID from result: {raw_result}")
        conversation_id = match.group(1).strip()
        log_event("Orchestrator", f"Created Coral Thread: {conversation_id}", status="SUCCESS")
        return conversation_id
    except Exception as e:
        log_event("Orchestrator", f"Error in create_coral_thread_util: {e}", status="ERROR"); return f"ERROR: {e}"

async def send_coral_message_util(coral_mcp_tools: dict, conversation_id: str, content: str, receiver_id: str, mentions: list = None) -> str:
    tool = coral_mcp_tools.get("send_message")
    if not tool: raise ValueError("Coral tool 'send_message' not found.")
    try:
        args = {"senderId": os.getenv("CORAL_AGENT_ID"), "receiverId": receiver_id, "content": content, "conversationId": conversation_id, "threadId": conversation_id, "isAgentMessage": True, "mentions": mentions or [receiver_id]}
        result = await tool.ainvoke(args)
        if "error" in str(result).lower(): return f"ERROR: {result}"
        log_event("Orchestrator", "Message sent successfully.", status="SUCCESS")
        return "Message sent successfully."
    except Exception as e:
        log_event("Orchestrator", f"Error in send_coral_message_util: {e}", status="ERROR"); return f"ERROR: {e}"

async def wait_for_filtered_mention(coral_mcp_tools: dict, conversation_id: str, agent_id: str, timeout_s: int) -> str:
    tool = coral_mcp_tools.get("wait_for_mentions")
    if not tool: raise ValueError("Coral tool 'wait_for_mentions' not found.")
    start_time = time.time()
    log_event("Orchestrator", f"Listening on thread {conversation_id} for {timeout_s}s...", status="WAITING")
    while time.time() - start_time < timeout_s:
        try:
            raw_result = await tool.ainvoke({"agentId": agent_id, "conversationId": conversation_id, "timeoutMs": POLL_INTERVAL_S * 1000})
            if isinstance(raw_result, str) and "No new messages" in raw_result:
                await asyncio.sleep(POLL_INTERVAL_S)
                continue
            cleaned_xml_content = raw_result.replace("<ArrayList>", "").replace("</ArrayList>", "").strip()
            if not cleaned_xml_content: continue
            root = ET.fromstring(f"<root>{cleaned_xml_content}</root>")
            for msg_elem in root.findall('ResolvedMessage'):
                if msg_elem.get("threadId") == conversation_id:
                    log_event("Orchestrator", f"Received valid message from thread {conversation_id}", status="SUCCESS")
                    message_content = {"conversation_id": conversation_id, "sender_id": msg_elem.get("senderId"), "content": msg_elem.get("content")}
                    return json.dumps([message_content])
        except Exception as e:
            log_event("Orchestrator", f"Minor error during listen poll: {e}", status="ERROR")
            await asyncio.sleep(POLL_INTERVAL_S)
    return "No new messages received within timeout."

# ############################################################################
# SECTION: WORKFLOW ORCHESTRATION LOGIC (MODIFIED TO RECEIVE CLIENT AND TOOLS)
# ############################################################################
async def run_full_audit_workflow(url: str, coral_client_instance: MultiServerMCPClient, coral_mcp_tools_dict: dict) -> dict:
    # Orchestrates the full audit workflow and returns the enriched JSON report.
    orchestrator_agent_id, recon_agent_id, cve_agent_id = os.getenv("CORAL_AGENT_ID"), os.getenv("RECON_AGENT_ID"), os.getenv("CVE_AGENT_ID")
    context = {}
    log_event("Orchestrator", f"PIPELINE STARTED for {url}", status="ACTION")
    try:
        log_event("Orchestrator", f"Step [1/4] Delegating initial recon to {recon_agent_id}...", status="WAITING")
        recon_conv_id = await create_coral_thread_util(coral_mcp_tools_dict, [recon_agent_id, orchestrator_agent_id], f"recon-audit-{urllib.parse.urlparse(url).netloc}")
        await send_coral_message_util(coral_mcp_tools_dict, recon_conv_id, url, recon_agent_id)
        recon_response_str = await wait_for_filtered_mention(coral_mcp_tools_dict, recon_conv_id, orchestrator_agent_id, int(RECON_TIMEOUT_MS / 1000))
        if "No new messages" in recon_response_str: raise Exception("Recon Agent timeout or no response.")
        context = json.loads(json.loads(recon_response_str)[0].get("content")).get("result")
        
        log_event("Orchestrator", "Step [2/4] Performing AI-powered technology enrichment...", status="ACTION")
        enriched_data = await asyncio.to_thread(tool_enrich_technologies, context)
        context['technologies_identified'] = enriched_data.get('technologies_identified', context.get('technologies_identified', []))
        
        techs_with_version = [t for t in context.get("technologies_identified", []) if isinstance(t, dict) and t.get("version", "Unknown") != "Unknown"]
        if techs_with_version:
            log_event("Orchestrator", f"Step [3/4] Delegating {len(techs_with_version)} CVE lookups...", status="WAITING")
            cve_conv_id = await create_coral_thread_util(coral_mcp_tools_dict, [cve_agent_id, orchestrator_agent_id], f"cve-audit-{urllib.parse.urlparse(url).netloc}")
            cve_results = []
            for tech in techs_with_version:
                await send_coral_message_util(coral_mcp_tools_dict, cve_conv_id, json.dumps(tech), cve_agent_id)
                cve_response_str = await wait_for_filtered_mention(coral_mcp_tools_dict, cve_conv_id, orchestrator_agent_id, int(CVE_TIMEOUT_MS / 1000))
                if "No new messages" not in cve_response_str:
                    cve_results.append(json.loads(json.loads(cve_response_str)[0].get("content")).get("result"))
            tech_map = {f"{t.get('name')}-{t.get('version')}": t for t in context["technologies_identified"] if isinstance(t, dict)}
            for res in cve_results:
                if res and res.get('product'):
                    key = f"{res.get('product')}-{res.get('version')}"
                    if key in tech_map: tech_map[key]['known_vulnerabilities'] = res.get('vulnerabilities', [])
        
        log_event("Orchestrator", "Step [4/4] Performing final AI analysis and summary generation...", status="ACTION")
        summary_report = await asyncio.to_thread(tool_generate_final_summary, context)
        if "error" in summary_report: raise Exception(f"AI Summary failed: {summary_report.get('details')}")
        
        html_report_base64 = consolidate_and_generate_report(url, summary_report)
        
        summary_report['html_report_base64'] = html_report_base64
        
        log_event("Orchestrator", "PIPELINE COMPLETE.", status="SUCCESS")
        return summary_report

    except Exception as e:
        log_event("Orchestrator", f"PIPELINE FAILED: {e}", status="ERROR")
        logger.error(traceback.format_exc())
        return {"error": "The audit pipeline failed.", "details": str(e)}

# ############################################################################
# SECTION: MAIN ENTRY POINT (MODIFIED TO BE A DIRECT SERVER)
# ############################################################################
async def main_cli(): 
    # Main CLI function that initializes the connection and starts the interaction loop.
    # These objects are now local to main_cli, no longer global
    coral_client_instance: MultiServerMCPClient = None 
    coral_mcp_tools_dict: dict = {}

    console.print(Panel("[bold cyan]Soenlis Orchestrator V1.0 - 'Professional Edition'[/bold cyan]", expand=False))
    orchestrator_agent_id = os.getenv("CORAL_AGENT_ID")
    os.environ["ORCHESTRATOR_AGENT_ID"] = orchestrator_agent_id
    coral_sse_url = os.getenv("CORAL_SSE_URL")
    coral_params = {"agentId": orchestrator_agent_id, "agentDescription": "The main Orchestrator for Soenlis."}
    coral_server_url = f"{coral_sse_url}?{urllib.parse.urlencode(coral_params)}"
    log_event("Orchestrator", "Connecting to Coral Server...", status="WAITING")
    try:
        coral_client_instance = MultiServerMCPClient(connections={"coral": {"transport": "sse", "url": coral_server_url, "timeout": 600, "sse_read_timeout": 600}})
        coral_mcp_tools_dict.update({tool.name: tool for tool in await coral_client_instance.get_tools(server_name="coral")})
        log_event("Orchestrator", "Connection Established.", status="SUCCESS")
    except Exception as e:
        log_event("Orchestrator", f"Connection to Coral Server failed: {e}", status="ERROR"); return
    
    while True:
        try:
            user_input = await asyncio.to_thread(console.input, "\n[bold]SOENLIS >[/bold] Enter a URL to scan (or 'exit'): ")
            if user_input.lower() in ['exit', 'quit']: break
            if not re.search(r'https?://[^\s]+', user_input): console.print("[red]Invalid URL format.[/red]"); continue
            
            # Pass client and tools instances
            final_report = await run_full_audit_workflow(user_input, coral_client_instance, coral_mcp_tools_dict)
            
            if "error" in final_report:
                console.print(Panel(f"[bold red]Audit Failed:[/bold red]\n\n{final_report.get('details')}", title="[bold]Audit Result[/bold]", border_style="red"))
            else:
                console.print(Panel(f"[bold green]Audit Success![/bold green] Full JSON and HTML reports generated.", title="[bold]Audit Result[/bold]", border_style="green"))

        except (KeyboardInterrupt, asyncio.CancelledError):
            break
        except Exception as e:
            log_event("Orchestrator", f"A critical error occurred in main loop: {e}", status="ERROR"); logger.error(traceback.format_exc())
    console.print("\n[bold cyan]Soenlis Orchestrator shutting down. Goodbye.[/bold cyan]\n")

if __name__ == "__main__":
    try:
        asyncio.run(main_cli()) # Call the renamed CLI function
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutdown requested by user.[/bold yellow]")