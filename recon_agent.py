import os
import json
import asyncio
from dotenv import load_dotenv
import logging
from console_ui import log_event
# Import the specialized tool using an alias for simplicity
from soenlis_tools import tool_run_reconnaissance_only as tool_run_reconnaissance
from coral_agent_base import CoralAgentBase
import traceback
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

class ReconAgent(CoralAgentBase):
    def __init__(self):
        agent_id = os.getenv("RECON_AGENT_ID")
        super().__init__(
            agent_id=agent_id,
            agent_description="A specialist agent for web reconnaissance and technology fingerprinting."
        )
        if not self.agent_id:
            log_event("Recon Agent", "RECON_AGENT_ID not found in .env file. Shutting down.", status="ERROR")
            raise ValueError("RECON_AGENT_ID not configured.")

    async def process_incoming_task(self, message_data: dict):
        try:
            url_to_scan = message_data.get("content")
            sender_id = message_data.get("sender_id")
            conversation_id = message_data.get("conversation_id")

            if not all([url_to_scan, sender_id, conversation_id]):
                log_event("Recon Agent", "Received a malformed task. Ignoring.", status="ERROR")
                return

            log_event("Recon Agent", f"Task received from '{sender_id}': Analyze URL '{url_to_scan}'", status="ACTION")

            # Call the specialized tool that only performs reconnaissance
            report_dict = await asyncio.to_thread(tool_run_reconnaissance, url_to_scan)
            
            response_payload = {
                "tool_name": "run_reconnaissance", # The tool name can remain for semantic purposes
                "result": report_dict
            }
            response_str = json.dumps(response_payload)

            send_tool = self.coral_mcp_tools.get("send_message")
            if not send_tool:
                raise ValueError("Coral tool 'send_message' not found.")

            await send_tool.ainvoke({
                "senderId": self.agent_id,
                "receiverId": sender_id,
                "content": response_str,
                "conversationId": conversation_id,
                "threadId": conversation_id,
                "isAgentMessage": True,
                "mentions": [sender_id]
            })

            log_event("Recon Agent", f"Reconnaissance complete. Report sent to '{sender_id}'.", status="SUCCESS")

        except Exception as e:
            log_event("Recon Agent", f"Error processing task: {e}", status="ERROR")
            logger.error(traceback.format_exc())
            # Optional: send an error response
            # ...

    async def run(self):
        log_event("Recon Agent", f"Agent '{self.agent_id}' started. Connecting...", status="WAITING")
        try:
            await self.connect_to_coral()
            await self.retrieve_coral_mcp_tools()
        except Exception as e:
            logger.error(f"Recon Agent connection failed: {e}\n{traceback.format_exc()}")
            return

        log_event("Recon Agent", f"Agent connected. Listening for tasks...", status="SUCCESS")
        
        while True:
            try:
                wait_tool = self.coral_mcp_tools.get("wait_for_mentions")
                if not wait_tool:
                    log_event("Recon Agent", "Tool 'wait_for_mentions' not found.", status="ERROR")
                    await asyncio.sleep(60)
                    continue

                # The agent passively waits to be mentioned
                messages_xml_str = await wait_tool.ainvoke({"agentId": self.agent_id, "timeoutMs": 5000})
                
                if "No new messages" in messages_xml_str or "ERROR:" in messages_xml_str:
                    await asyncio.sleep(1)
                    continue

                # XML parsing logic to process received messages
                xml_to_parse = f"<root>{messages_xml_str.replace('<ArrayList>', '').replace('</ArrayList>', '')}</root>"
                root = ET.fromstring(xml_to_parse)
                
                for msg_elem in root.findall('ResolvedMessage'):
                    # Ensure the message is indeed from the orchestrator to avoid loops
                    if msg_elem.get("senderId") == os.getenv("ORCHESTRATOR_AGENT_ID"):
                        message_data = {
                            "conversation_id": msg_elem.get("threadId"),
                            "sender_id": msg_elem.get("senderId"),
                            "content": msg_elem.get("content"),
                        }
                        await self.process_incoming_task(message_data)

            except ET.ParseError:
                # Handle case where the response is not valid XML as expected
                log_event("Recon Agent", f"Received non-XML or malformed message, ignoring. Raw: {messages_xml_str}", status="INFO")
                await asyncio.sleep(1)
            except Exception as e:
                log_event("Recon Agent", f"Critical error in main loop: {e}", status="ERROR")
                logger.error(traceback.format_exc())
                await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(ReconAgent().run())