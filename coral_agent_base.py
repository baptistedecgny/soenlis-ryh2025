import os
import asyncio
import json
import logging
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.tools import Tool
import urllib.parse

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CoralAgentBase:
    def __init__(self, agent_id: str, agent_description: str):
        self.agent_id = agent_id
        self.agent_description = agent_description
        self.client: MultiServerMCPClient = None
        self.coral_mcp_tools: dict = {} # Dictionary to store MCP tools retrieved by this agent

    async def connect_to_coral(self):
        coral_sse_url = os.getenv("CORAL_SSE_URL")
        if not coral_sse_url:
            logger.error("CORAL_SSE_URL not found in .env file. Cannot connect to Coral Server.")
            raise ValueError("CORAL_SSE_URL not configured.")

        coral_params = {
            "agentId": self.agent_id,
            "agentDescription": self.agent_description
        }
        query_string = urllib.parse.urlencode(coral_params)
        coral_server_url_with_params = f"{coral_sse_url}?{query_string}"

        self.client = MultiServerMCPClient(
            connections={
                "coral": {
                    "transport": "sse",
                    "url": coral_server_url_with_params,
                    "timeout": 600,
                    "sse_read_timeout": 600,
                }
            }
        )
        logger.info(f"Agent '{self.agent_id}' initialized client for Coral Server: {coral_server_url_with_params}")

    async def retrieve_coral_mcp_tools(self):
        # Retrieves and stores the MCP tools provided by the Coral Server.
        try:
            raw_coral_tools = await self.client.get_tools(server_name="coral")
            for tool in raw_coral_tools:
                self.coral_mcp_tools[tool.name] = tool
            logger.info(f"Agent '{self.agent_id}' retrieved {len(self.coral_mcp_tools)} Coral MCP tools from server.")
        except Exception as e:
            logger.error(f"Agent '{self.agent_id}' failed to retrieve Coral MCP tools: {e}")
            raise

    async def run(self):
        raise NotImplementedError("The 'run' method must be implemented by derived classes.")