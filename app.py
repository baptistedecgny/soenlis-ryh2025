from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import asyncio
import os
import sys
import logging
import urllib.parse
import traceback

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import only run_full_audit_workflow from the orchestrator.
# coral_client and coral_mcp_tools are no longer imported as they are managed locally in app.py
from orchestrator import run_full_audit_workflow 
from langchain_mcp_adapters.client import MultiServerMCPClient # Import here for type declaration

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app) 

# Declare global variables for app.py
orchestrator_is_ready = False
coral_client: MultiServerMCPClient = None
coral_mcp_tools: dict = {}

async def initialize_soenlis_orchestrator_coral_connection():
    global orchestrator_is_ready, coral_client, coral_mcp_tools
    if orchestrator_is_ready:
        return
    logger.info("Initializing Soenlis Orchestrator and Coral client connection.")
    try:
        orchestrator_agent_id = os.getenv("CORAL_AGENT_ID")
        coral_sse_url = os.getenv("CORAL_SSE_URL")
        if not all([orchestrator_agent_id, coral_sse_url]):
            raise ValueError("CORAL_AGENT_ID or CORAL_SSE_URL not set.")
        
        # Initialization here
        coral_params = {"agentId": orchestrator_agent_id, "agentDescription": "The main Orchestrator for Soenlis."}
        coral_server_url = f"{coral_sse_url}?{urllib.parse.urlencode(coral_params)}"
        
        coral_client = MultiServerMCPClient(connections={"coral": {"transport": "sse", "url": coral_server_url, "timeout": 600, "sse_read_timeout": 600}})
        coral_mcp_tools.update({tool.name: tool for tool in await coral_client.get_tools(server_name="coral")})
        
        orchestrator_is_ready = True
        logger.info("Soenlis Orchestrator (Coral client) initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Soenlis Orchestrator: {e}\n{traceback.format_exc()}")
        raise RuntimeError(f"Soenlis Orchestrator initialization failed: {e}")

@app.route('/api/scan', methods=['POST'])
async def scan_url():
    global orchestrator_is_ready, coral_client, coral_mcp_tools # Ensure these globals are accessible
    if not orchestrator_is_ready:
        try:
            await initialize_soenlis_orchestrator_coral_connection()
        except RuntimeError as e:
            return jsonify({"error": "Backend initialization failed", "details": str(e)}), 500

    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    logger.info(f"Received scan request for URL: {url}")
    try:
        # Pass client and tools instances to the orchestrator function
        audit_report = await run_full_audit_workflow(url, coral_client, coral_mcp_tools)
        if "error" in audit_report:
            logger.error(f"Audit workflow returned an error for {url}: {audit_report.get('details')}")
            return jsonify({"error": "Audit workflow failed", "details": audit_report.get("details")}), 500
        return jsonify(audit_report), 200
    except Exception as e:
        logger.error(f"Unhandled error during audit for {url}: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal server error during audit", "details": str(e)}), 500

@app.route('/api/download-audit', methods=['GET'])
def download_audit():
    # Serves the HTML audit file for download.
    try:
        path_to_file = "audit_report.html" 
        
        # TEMPORARY SOLUTION: Try to find the latest audit file if the exact name is not known
        audit_dir = "audits"
        if os.path.exists(audit_dir):
            list_of_files = [os.path.join(audit_dir, f) for f in os.listdir(audit_dir) if f.startswith("Soenlis_Audit_") and f.endswith(".html")]
            if list_of_files:
                latest_file = max(list_of_files, key=os.path.getctime)
                return send_file(latest_file, as_attachment=True)
        
        return jsonify({"error": "Audit report not found. Please run a scan first."}), 404
    except Exception as e:
        logger.error(f"Error serving the audit report: {e}")
        return jsonify({"error": "Could not serve the audit report."}), 500

@app.route('/')
def index_route():
    return send_file('index.html')

if __name__ == '__main__':
    # Flask now handles the asyncio loop via `Flask[async]`
    app.run(host='0.0.0.0', port=5000, debug=True)