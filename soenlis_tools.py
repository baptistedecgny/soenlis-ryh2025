import os
import json
import requests
import re
import asyncio
import urllib.parse
from datetime import datetime
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from bs4 import BeautifulSoup
import logging
import time
from typing import List, Optional, Dict, Any, Union
import warnings
import traceback
from typing import List
from pydantic import BaseModel, Field, ValidationError, RootModel

# Filter pkg_resources warning (Wappalyzer)
warnings.filterwarnings("ignore", category=UserWarning, module='Wappalyzer')
# Filter SyntaxWarning for backslashes (which might come from prompts if not handled)
warnings.filterwarnings("ignore", category=SyntaxWarning, message="invalid escape sequence")

from langchain_core.messages import HumanMessage, SystemMessage

from Wappalyzer import Wappalyzer, WebPage 

from console_ui import log_event

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - SoenlisTools - %(message)s', datefmt='%H:%M:%S')
load_dotenv()
HTTP_HEADERS = {'User-Agent': 'SoenlisSecurityScanner/5.0 Final - The Ultimate'}

# --- Pydantic Schemas for Maximum Robustness ---
class TechInfo(BaseModel):
    name: str
    version: str
    source: str
    categories: Optional[List[str]] = Field(default=[])
    known_vulnerabilities: Optional[List[dict]] = Field(default=[])

class EnrichedTechInfo(RootModel[List[TechInfo]]):
    pass

class DetailedFinding(BaseModel):
    title: str = Field(description="Concise title of the vulnerability or misconfiguration.")
    severity: str = Field(description="Severity of the finding (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, GOOD).")
    technology: Optional[str] = Field(default="N/A", description="The specific technology associated with this finding, if applicable.")
    meaning: str = Field(description="Clear and concise explanation of the finding for a non-technical audience.")
    business_impact: str = Field(description="Description of the potential business impact (financial, reputational, operational).")
    remediation_steps: List[str] = Field(description="List of clear, ordered technical steps to fix the vulnerability, including code if relevant.")

class HeaderDetail(BaseModel):
    header: str
    assessment: str
    recommendation: str
    meaning: str = Field(description="Explanation of this header and why it is good/bad.")
    business_impact: str = Field(description="Impact of this header's configuration on security.")
    remediation_steps: List[str] = Field(description="Steps to fix/implement the header, with code examples if possible.")

class DetailedHeaderAnalysisContent(BaseModel):
    good_headers: List[HeaderDetail] = Field(default=[])
    bad_headers: List[HeaderDetail] = Field(default=[])

class ExecutiveSummaryContent(BaseModel):
    key_technologies: List[str]
    unknown_versions: List[str]
    critical_vulnerabilities: List[dict]
    overall_assessment: str
    security_score: int

class FinalReport(BaseModel):
    executive_summary: ExecutiveSummaryContent
    technologies_identified: List[TechInfo]
    detailed_header_analysis: DetailedHeaderAnalysisContent
    final_security_score: int
    consolidated_findings: List[DetailedFinding] = Field(default=[])

class SoenlisScanner:
    def __init__(self):
        self.llm_version_enrichment = ChatGroq(model_name=os.getenv("MODEL_NAME", "llama3-70b-8192"), api_key=os.getenv("API_KEY"), temperature=0.1, model_kwargs={"seed": 42})
        self.llm_summary_generation = ChatGroq(model_name=os.getenv("MODEL_NAME", "llama3-70b-8192"), api_key=os.getenv("API_KEY"), temperature=0.0, model_kwargs={"seed": 42})
        self.wappalyzer = Wappalyzer.latest()
        self.raw_data = {}

    def _fetch_data(self, url: str) -> bool:
        log_event("SoenlisTools", f"Pipeline [1/X] Fetching data from {url}", status="ACTION")
        try:
            with requests.Session() as session:
                session.headers.update(HTTP_HEADERS)
                main_response = session.get(url, timeout=20, allow_redirects=True)
                main_response.raise_for_status() 
                
                self.raw_data.update({
                    'final_url': main_response.url,
                    'headers': dict(main_response.headers),
                    'html': main_response.text,
                    'status_code': main_response.status_code
                })
                
                robots_url = urllib.parse.urljoin(self.raw_data['final_url'], '/robots.txt')
                robots_response = session.get(robots_url, timeout=10)
                self.raw_data['robots_txt'] = robots_response.text if robots_response.status_code == 200 else "Not found."

            log_event("SoenlisTools", "Data fetching complete.", status="SUCCESS")
            return True
        except requests.exceptions.RequestError as e:
            log_event("SoenlisTools", f"Network error during data fetching: {e}", status="ERROR")
            return False
        except Exception as e:
            log_event("SoenlisTools", f"An unexpected error occurred during data fetching: {e}", status="ERROR")
            return False

    def _fingerprint_technologies(self) -> list:
        log_event("SoenlisTools", "Pipeline [2/X] Fingerprinting with Wappalyzer...", status="WAITING")
        try:
            webpage = WebPage(self.raw_data['final_url'], self.raw_data['html'], self.raw_data['headers'])
            
            tech_report_raw = self.wappalyzer.analyze_with_versions(webpage)
            
            all_detected_techs = []

            for tech_name, tech_data in tech_report_raw.items():
                version = "Unknown"
                categories = []
                if tech_data:
                    if tech_data.get("versions"):
                        version = ", ".join(str(v) for v in tech_data["versions"])
                    if tech_data.get("categories"):
                        categories = [cat.get('name') for cat in tech_data['categories'] if cat.get('name')]
                
                all_detected_techs.append({
                    "name": tech_name,
                    "version": version,
                    "source": "Wappalyzer",
                    "categories": categories
                })
            
            log_event("SoenlisTools", f"Wappalyzer found {len(all_detected_techs)} technologies, with {sum(1 for t in all_detected_techs if t['version'] != 'Unknown')} versions identified.", status="SUCCESS")
            return all_detected_techs
        except Exception as e:
            log_event("SoenlisTools", f"Wappalyzer analysis failed: {e}", status="ERROR")
            return []

    def _run_tech_enrichment_ai(self, context_data: dict) -> dict:
        log_event("SoenlisTools", "Pipeline [3/X] Starting AI Technology Enrichment (Deep Analysis)...", status="ACTION")
        
        initial_technologies = [TechInfo(**t) for t in context_data.get('technologies_identified', [])]
        
        soup = BeautifulSoup(context_data.get('html', ''), 'html.parser')
        
        head_html = (str(soup.head) if soup.head else "")[:3300]
        all_scripts = ("\n".join([str(tag) for tag in soup.find_all('script')]))[:3300]
        all_links = ("\n".join([str(tag) for tag in soup.find_all('link')]))[:3300]
        body_start_html = (str(soup.body.prettify()) if soup.body else "")[:3000]
        
        enriched_ai_context = {
            "http_headers": context_data.get('http_headers', {}),
            "full_head_html": head_html,
            "all_script_tags_content": all_scripts,
            "all_link_tags_content": all_links,
            "body_start_html_snippet": body_start_html,
            "robots_txt_content": context_data.get('robots_txt', "Not found.")
        }

        ai_prompt = f"""MISSION: You are Soenlis, an extremely powerful, meticulous, and expert AI specialized in web technology fingerprinting. Your sole purpose is to find precise version numbers for technologies listed as 'Unknown' within the 'TECHNOLOGIES TO ENRICH' list. You will leverage ALL provided raw data. Your goal is 100000% accuracy.

**PRIORITIES FOR VERSION EXTRACTION (in order of reliability, search exhaustively):**
1.  **HTTP Headers (`http_headers`):** Look for `X-Generator`, `Server`, `X-Powered-By`, `Via`, `Content-Type`, `Set-Cookie` or any other header that might contain a version (e.g., `Server: Apache/2.4.52 (Ubuntu)` -> Apache 2.4.52, `X-Powered-By: PHP/8.1.10` -> PHP 8.1.10).
2.  **Full Head HTML (`full_head_html`):** Examine the entire <head> section. Many frameworks and CMS declare versions here:
    * `<meta name="generator" content="Drupal 10 (https://www.drupal.org)" />`
    * `<meta name="framework" content="Vue.js 3.2.0">`
    * `<link rel="stylesheet" href="/assets/css/bootstrap.min.css?v=5.3.0">`
3.  **All Script Tags Content (`all_script_tags_content`):** Scan for patterns within script tags, including inline scripts:
    * `jQuery v3.6.1`
    * `var Vue = {{version: "2.6.14"}}`
    * `/*! Bootstrap v5.2.3 ...*/`
    * `src="/js/some-library.min.js?v=1.2.3"`
4.  **All Link Tags Content (`all_link_tags_content`):** Check CSS and other linked resources for version numbers in their URLs or comments.
5.  **Body Start HTML Snippet (`body_start_html_snippet`):** Search for version comments, inline data attributes (`data-version`), or other subtle hints at the beginning of the page body. E.g., ``.
6.  **Robots.txt Content (`robots_txt_content`):** Sometimes reveals CMS paths (e.g., `Disallow: /wp-admin/` hints at WordPress). While not direct version, it's a strong indicator.

**CRITICAL RULES FOR YOUR JSON OUTPUT:**
-   You MUST return ONLY a JSON array (list) of objects. No conversational text, no explanations, just the JSON.
-   Each object in the array MUST STRICTLY conform to the `TechInfo` schema: `{{ "name": "string", "version": "string", "source": "string", "categories": ["list of strings"], "known_vulnerabilities": [] }}`.
-   The 'source' field should be 'AI analysis' if you successfully find a version or refine an 'Unknown' version. If Wappalyzer already provided a specific version, keep 'Wappalyzer' as the source.
-   Include ALL technologies from the original 'TECHNOLOGIES TO ENRICH' list and any new ones you confidently identify with a version.
-   If you cannot find a version after EXHAUSTIVE search across ALL provided data, leave it as 'Unknown'. Do NOT guess or hallucinate versions.
-   If multiple versions are found for a single technology, list them comma-separated (e.g., "3.5.1, 3.6.0").
-   Ensure that if a technology was originally 'Unknown' but you find a version, you update its 'source' to 'AI analysis'.

RAW DATA FOR YOUR HYPER-DETAILED ANALYSIS:
{json.dumps(enriched_ai_context, indent=2, ensure_ascii=False)}

TECHNOLOGIES TO ENRICH (You MUST include ALL of these in your final output, with updated versions if found):
{json.dumps([t.dict() for t in initial_technologies], indent=2, ensure_ascii=False)}

YOUR JSON ARRAY OUTPUT:
"""
        try:
            system_prompt = "You are an AI with unparalleled precision in web data extraction. Your ENTIRE output must be a single, valid, minified JSON array of TechInfo objects. NO other text, NO preamble, NO explanation. Just the JSON."
            messages = [SystemMessage(content=system_prompt), HumanMessage(content=ai_prompt)]
            response = self.llm_version_enrichment.invoke(messages)
            
            json_data = None
            try:
                json_string = str(response.content).strip()
                if json_string.startswith("```json"):
                    json_string = json_string[7:].strip()
                if json_string.endswith("```"):
                    json_string = json_string[:-3].strip()
                json_data = json.loads(json_string)
            except json.JSONDecodeError as e:
                log_event("SoenlisTools", f"JSONDecodeError: Raw AI response was not valid JSON string during tech enrichment. Error: {e}. Content: {response.content}", status="ERROR")
                match = re.search(r'\[\s*{[^\]]*}\s*\]', json_string, re.DOTALL)
                if match:
                    try:
                        json_data = json.loads(match.group(0))
                        log_event("SoenlisTools", "Successfully extracted JSON from malformed AI response.", status="INFO")
                    except json.JSONDecodeError:
                        log_event("SoenlisTools", "Could not extract valid JSON from malformed AI response. Proceeding with original technologies.", status="ERROR")
                        return {"technologies_identified": [t.dict() for t in initial_technologies]}
                elif isinstance(response.content, (list, dict)): 
                    json_data = response.content
                else:
                    raise ValueError(f"AI response is neither a valid JSON string nor a list/dict: {type(response.content)}") from e
            except Exception as e:
                log_event("SoenlisTools", f"Unexpected error during JSON parsing attempt in tech enrichment: {e}. Content: {response.content}", status="ERROR")
                raise

            if json_data is None:
                    raise ValueError("AI response content could not be converted to a valid JSON object or list.")
            
            validated_tech_list = EnrichedTechInfo(root=json_data).root

            original_tech_map = {t.name.lower(): t for t in initial_technologies}
            
            for enriched_tech in validated_tech_list:
                tech_name_lower = enriched_tech.name.lower()
                
                if tech_name_lower in original_tech_map:
                    current_tech_info = original_tech_map[tech_name_lower]
                    
                    if (enriched_tech.version.lower() != 'unknown' and 
                        (current_tech_info.version.lower() == 'unknown' or
                           (enriched_tech.version != current_tech_info.version and 
                           len(enriched_tech.version) > len(current_tech_info.version)))
                    ):
                        current_tech_info.version = enriched_tech.version
                        if current_tech_info.source.lower() == 'wappalyzer' or current_tech_info.version.lower() == 'unknown':
                            current_tech_info.source = 'AI analysis'
                    
                    if not current_tech_info.categories and enriched_tech.categories:
                        current_tech_info.categories = enriched_tech.categories
                    
                    if enriched_tech.known_vulnerabilities:
                        existing_cve_ids = {cve.get('id') for cve in current_tech_info.known_vulnerabilities}
                        for new_cve in enriched_tech.known_vulnerabilities:
                            if new_cve.get('id') and new_cve.get('id') not in existing_cve_ids:
                                current_tech_info.known_vulnerabilities.append(new_cve)
                                existing_cve_ids.add(new_cve.get('id'))
                else:
                    if enriched_tech.version.lower() != 'unknown': 
                        enriched_tech.source = 'AI analysis'
                        original_tech_map[tech_name_lower] = enriched_tech
            
            final_enriched_list_dicts = [t.dict() for t in original_tech_map.values()]
            
            log_event("SoenlisTools", f"AI Enrichment complete. Total technologies: {len(final_enriched_list_dicts)}", status="SUCCESS")
            return {"technologies_identified": final_enriched_list_dicts}
        except ValidationError as e:
            log_event("SoenlisTools", f"AI Enrichment response validation failed: {e}. Raw AI response: {response.content}", status="ERROR")
            return {"error": "Failed to validate AI enriched data", "details": str(e), "raw_ai_response": response.content.strip()}
        except Exception as e:
            log_event("SoenlisTools", f"AI Enrichment failed: {e}. Traceback: {traceback.format_exc()}", status="ERROR")
            return {"error": "AI Enrichment process failed.", "details": str(e)}

    def _get_all_cves(self, product: str, version: str) -> list:
        if not version or version.lower() == 'unknown': return []
        log_event("SoenlisTools", f"Pipeline [X/X] Aggregating CVEs for {product} v{version}...", status="WAITING")
        
        mock_cves = []
        
        product_lower = product.lower()
        version_lower = version.lower()

        if "drupal" in product_lower:
            if "10" in version_lower:
                mock_cves.append({"id": "CVE-2012-2084", "title": "Drupal 10 - XSS in core (Mock)", "cvss_score": 4.3, "description": "Cross-site scripting vulnerability in Drupal core.", "severity": "MEDIUM"})
                mock_cves.append({"id": "CVE-2023-XXXX-DRUPAL", "title": "Drupal 10 - Critical RCE in contributed module (Mock)", "cvss_score": 9.8, "description": "A highly critical remote code execution vulnerability.", "severity": "CRITICAL"})
            elif "9" in version_lower:
                mock_cves.append({"id": "CVE-2021-32693", "title": "Drupal 9 - Access Bypass (Mock)", "cvss_score": 7.5, "description": "Access bypass vulnerability due to insufficient validation.", "severity": "HIGH"})
        
        if "jquery" in product_lower:
            if "3.6.0" in version_lower:
                mock_cves.append({"id": "CVE-2020-11022", "title": "jQuery 3.6.0 - XSS (htmlPrefilter) (Mock)", "cvss_score": 6.1, "description": "Cross-site scripting vulnerability in jQuery prior to 3.5.0.", "severity": "MEDIUM"})
            elif any(v in version_lower for v in ["2.", "1."]):
                mock_cves.append({"id": "CVE-2015-9251", "title": "jQuery (older) - XSS (Hashchange) (Mock)", "cvss_score": 4.8, "description": "XSS in jQuery 1.0.0-3.0.0.", "severity": "LOW"})

        if "php" in product_lower:
            if "8.1.10" in version_lower:
                    mock_cves.append({"id": "CVE-2017-6381", "title": "PHP 8.1.10 - Deserialization RCE (Mock)", "cvss_score": 8.1, "description": "Remote Code Execution via deserialization vulnerability in PHP (mock).", "severity": "HIGH"})
            elif "8.2" in version_lower:
                mock_cves.append({"id": "CVE-202X-PHP8.2", "title": "PHP 8.2 - Recent vulnerability (Mock)", "cvss_score": 8.0, "description": "A high-severity vulnerability specific to PHP 8.2 installations.", "severity": "HIGH"})
            else:
                mock_cves.append({"id": "CVE-202X-PHP-GENERIC", "title": "PHP Potential Vulnerability (Generic)", "cvss_score": 7.5, "description": "General potential vulnerability related to PHP installations.", "severity": "HIGH"})
        
        if "bootstrap" in product_lower:
            if "5.2.3" in version_lower:
                mock_cves.append({"id": "CVE-2021-39148", "title": "Bootstrap 5.2.3 - XSS (Modal Component) (Mock)", "cvss_score": 5.4, "description": "XSS vulnerability in Bootstrap 5 modal component.", "severity": "MEDIUM"})
            elif "4" in version_lower:
                mock_cves.append({"id": "CVE-2019-8331", "title": "Bootstrap 4 - XSS (Tooltip/Popovers) (Mock)", "cvss_score": 6.1, "description": "XSS in Bootstrap 4 due to improper sanitization.", "severity": "MEDIUM"})
        
        if "apache" in product_lower:
            if "2.4.54" in version_lower:
                mock_cves.append({"id": "CVE-2022-31813", "title": "Apache HTTP Server 2.4.54 - Path Traversal (Mock)", "cvss_score": 9.8, "description": "Path traversal vulnerability affecting Apache HTTP Server 2.4.54. (mock).", "severity": "CRITICAL"})
                mock_cves.append({"id": "CVE-2022-28615", "title": "Apache HTTP Server 2.4.54 - Null Pointer Dereference (Mock)", "cvss_score": 9.1, "description": "Null Pointer Dereference in Apache HTTP Server 2.4.54. (mock).", "severity": "CRITICAL"})
                mock_cves.append({"id": "CVE-2022-26377", "title": "Apache HTTP Server 2.4.54 - Race Condition (Mock)", "cvss_score": 7.5, "description": "Race condition in Apache HTTP Server 2.4.54. (mock).", "severity": "HIGH"})
                mock_cves.append({"id": "CVE-2022-30556", "title": "Apache HTTP Server 2.4.54 - DoS (Mock)", "cvss_score": 7.5, "description": "Denial of Service in Apache HTTP Server 2.4.54. (mock).", "severity": "HIGH"})


        api_key = os.getenv("VULNERS_API_KEY")
        if api_key and version and version.lower() != 'unknown':
            api_url = "https://vulners.com/api/v3/search/lucene/"
            query_parts = [f"type:cve AND \"{product_lower}\""]
            if re.match(r'^[\d.]+$', version):
                query_parts.append(f"affectedSoftware.version:\"{version}\"")
            else:
                log_event("SoenlisTools", f"Version '{version}' is complex, performing generic CVE search for '{product}' on Vulners.", status="INFO")

            query = " AND ".join(query_parts)
            request_body = {"query": query, "size": 10, "sort": "cvss.score", "sort_order": "desc"}
            try:
                response = requests.post(api_url, params={"apiKey": api_key}, json=request_body, timeout=20)
                response.raise_for_status()
                data = response.json()
                if data.get("result") == "OK" and data.get("data", {}).get("search"):
                    for item in data["data"]["search"]:
                        source = item["_source"]
                        if not re.match(r'^[\d.]+$', version) and version.lower() not in str(source.get("affectedSoftware", [])).lower():
                            continue

                        vuln_info = {
                            "id": source.get("id"),
                            "title": source.get("title"),
                            "cvss_score": source.get("cvss", {}).get("score", 0.0),
                            "description": source.get("description", "No description available."),
                            "severity": source.get("cvss", {}).get("severity", "UNKNOWN")
                        }
                        if not any(v['id'] == vuln_info['id'] for v in mock_cves):
                            mock_cves.append(vuln_info)
                else:
                    log_event("SoenlisTools", f"No specific CVEs found via Vulners API for {product} v{version} or API error: {data.get('result', 'No result')}", status="INFO")

            except requests.exceptions.RequestException as e:
                log_event("SoenlisTools", f"Vulners API request failed for {product} v{version}: {e}", status="WARNING")
            except Exception as e:
                log_event("SoenlisTools", f"Error processing Vulners API response for {product} v{version}: {e}", status="WARNING")

        log_event("SoenlisTools", f"Final CVEs found for {product} v{version}: {len(mock_cves)} (including mocks)", status="SUCCESS")
        return mock_cves

    def _run_summary_generation_ai(self, final_context: dict) -> dict:
        log_event("SoenlisTools", "Pipeline [X/X] Starting AI Final Summary Generation...", status="ACTION")
        
        score = 100
        
        unknown_versions_count = sum(1 for tech in final_context.get('technologies_identified', []) if tech.get('version', 'Unknown').lower() == 'unknown')
        score -= (unknown_versions_count * 10)

        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
        vulnerabilities_summary_for_ai = [] 
        
        vulnerabilities_for_ai_detail = []

        for tech in final_context.get('technologies_identified', []):
            for vul in tech.get('known_vulnerabilities', []):
                cvss = vul.get('cvss_score', 0)
                vul_severity = vul.get('severity', 'UNKNOWN').upper()

                if vul_severity not in severity_counts:
                    vul_severity = "UNKNOWN" 
                
                severity_counts[vul_severity] += 1
                
                vulnerabilities_for_ai_detail.append({
                    "id": vul.get('id'),
                    "title": vul.get('title'),
                    "cvss_score": cvss,
                    "impact": vul_severity,
                    "technology": tech.get('name'),
                    "version": tech.get('version'),
                    "description": vul.get('description')
                })

        score -= (severity_counts["CRITICAL"] * 25)
        score -= (severity_counts["HIGH"] * 15)
        score -= (severity_counts["MEDIUM"] * 7)
        score -= (severity_counts["LOW"] * 3)
        score -= (severity_counts["UNKNOWN"] * 5)

        final_context['final_security_score'] = max(0, min(100, score))
        
        exec_summary_for_ai = {
            "key_technologies": list(set([t['name'] for t in final_context.get('technologies_identified', [])])),
            "unknown_versions": [t['name'] for t in final_context.get('technologies_identified', []) if t.get('version', 'Unknown').lower() == 'unknown'],
            "critical_vulnerabilities": vulnerabilities_summary_for_ai,
            "overall_assessment": "",
            "security_score": final_context['final_security_score']
        }

        header_analysis_raw_headers = final_context.get('http_headers', {})

        system_prompt = "You are a top-tier cybersecurity consultant. Your task is to generate a concise, professional, and impactful security audit report in strict JSON format. You will ONLY output the JSON object, with absolutely no conversational text, preambles, or explanations outside of it. Ensure the JSON is well-formed and directly usable."
        human_prompt = f"""TASK: Based on the provided data, generate the final audit report components.
You MUST follow this exact JSON structure for your output. Fill in the details based on the provided context.

JSON STRUCTURE TO ADHERE TO:
{{
  "executive_summary": {{
    "key_technologies": ["list of technology names"],
    "unknown_versions": ["list of technology names with unknown versions"],
    "critical_vulnerabilities": [
      {{ "id": "CVE-XXXX-YYYY", "title": "CVE Title", "cvss_score": 7.5, "impact": "HIGH" }}
    ],
    "overall_assessment": "Concise overall security posture assessment based on findings, highlighting main risks (unknown versions, critical CVEs) and suggesting general improvements. Max 3-4 sentences.",
    "security_score": 0 
  }},
  "detailed_header_analysis": {{
    "good_headers": [
      {{ 
        "header": "Header-Name", 
        "assessment": "Brief assessment", 
        "recommendation": "Brief recommendation",
        "meaning": "Explanation of this header's purpose and security value.",
        "business_impact": "Impact if not configured correctly.",
        "remediation_steps": ["Step 1", "Step 2", "Code example if relevant"] 
      }}
    ],
    "bad_headers": [
      {{ 
        "header": "Header-Name", 
        "assessment": "Brief assessment (e.g., 'Missing', 'Misconfigured')", 
        "recommendation": "Brief, actionable recommendation (e.g., 'Implement Strict-Transport-Security', 'Set X-Content-Type-Options to nosniff')",
        "meaning": "Explanation of this header's purpose and security implications.",
        "business_impact": "Impact if not configured correctly or missing.",
        "remediation_steps": ["Step 1", "Step 2", "Code example if relevant"] 
      }}
    ]
  }},
  "consolidated_findings": [
    {{
      "title": "Concise title for the finding (e.g., 'XSS Vulnerability in jQuery')",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|GOOD",
      "technology": "Technology name (e.g., 'jQuery 3.6.0')",
      "meaning": "Detailed, non-technical explanation of the vulnerability or misconfiguration.",
      "business_impact": "How this finding could negatively affect the business (e.g., 'Data breach, reputational damage, financial loss').",
      "remediation_steps": [
        "Step 1: Specific action, e.g., 'Update jQuery to version 3.7.1 or higher.'",
        "Step 2: Another specific action, e.g., 'Sanitize all user-supplied input before rendering it on the page.'",
        "Code example (if applicable, use markdown for code blocks, e.g., ```html\\n<p>test</p>```)"
      ]
    }}
  ],
  "final_security_score": 0 
}}

DATA FOR YOUR ANALYSIS:
- Technologies Identified: {json.dumps(final_context.get('technologies_identified', []), indent=2, ensure_ascii=False)}
- HTTP Headers (for detailed_header_analysis - Analyze EACH header and determine if it's 'good' or 'bad' for security, provide assessment, recommendation, meaning, business_impact, and detailed remediation_steps with code examples if possible): {json.dumps(header_analysis_raw_headers, indent=2, ensure_ascii=False)}
    * **Good Headers (Examples to look for and assess):** Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy (if well-configured), Referrer-Policy, Permissions-Policy, X-DNS-Prefetch-Control.
    * **Bad/Missing Headers (Examples to look for and assess):** X-Powered-By (if too verbose), Server (if too verbose), missing Strict-Transport-Security, missing X-Content-Type-Options, missing X-Frame-Options, Missing/Weak Content-Security-Policy, Missing Referrer-Policy, Missing Feature-Policy/Permissions-Policy.
- Vulnerabilities Details (use these to populate 'consolidated_findings' for CVEs. Generate meaning, business_impact, and remediation_steps for EACH of these based on common knowledge): {json.dumps(vulnerabilities_for_ai_detail, indent=2, ensure_ascii=False)}
- Pre-calculated Final Security Score: {final_context['final_security_score']}

GENERATE THE JSON OUTPUT ACCORDING TO THE SPECIFIED STRUCTURE:
"""
        try:
            messages = [SystemMessage(content=system_prompt), HumanMessage(content=human_prompt)]
            response = self.llm_summary_generation.invoke(messages)
            
            json_data = None
            try:
                json_string = str(response.content).strip()
                if json_string.startswith("```json"):
                    json_string = json_string[7:].strip()
                if json_string.endswith("```"):
                    json_string = json_string[:-3].strip()
                json_data = json.loads(json_string)
            except json.JSONDecodeError as e:
                log_event("SoenlisTools", f"JSONDecodeError: Raw AI response was not valid JSON string during summary generation. Error: {e}. Content: {response.content}", status="ERROR")
                if isinstance(response.content, dict):
                    json_data = response.content
                else:
                    raise ValueError(f"AI response for final summary is neither a valid JSON string nor a dictionary: {type(response.content)}") from e
            except Exception as e:
                log_event("SoenlisTools", f"Unexpected error during JSON parsing attempt in summary generation: {e}. Content: {response.content}", status="ERROR")
                raise

            if json_data is None:
                    raise ValueError("AI response content for final summary could not be converted to a valid JSON object or dict.")
            
            json_data['technologies_identified'] = final_context.get('technologies_identified', [])
            
            json_data['final_security_score'] = final_context['final_security_score']
            if 'executive_summary' in json_data and isinstance(json_data['executive_summary'], dict):
                json_data['executive_summary']['security_score'] = final_context['final_security_score']

            if 'consolidated_findings' not in json_data or not isinstance(json_data['consolidated_findings'], list):
                log_event("SoenlisTools", "AI did not return 'consolidated_findings' list as expected. Initializing empty list.", status="WARNING")
                json_data['consolidated_findings'] = []

            validated_findings = []
            for f in json_data.get('consolidated_findings', []):
                try:
                    if isinstance(f.get('severity'), list) and f['severity']:
                        f['severity'] = str(f['severity'][0]).upper()
                    elif isinstance(f.get('severity'), str):
                        f['severity'] = f['severity'].upper()
                    
                    validated_findings.append(DetailedFinding.parse_obj(f).dict())
                except ValidationError as ve:
                    log_event("SoenlisTools", f"Validation error for a consolidated finding: {ve}. Skipping invalid finding: {f}", status="ERROR")
            json_data['consolidated_findings'] = validated_findings

            for header_type in ['good_headers', 'bad_headers']:
                if header_type in json_data.get('detailed_header_analysis', {}):
                    validated_headers = []
                    for h in json_data['detailed_header_analysis'][header_type]:
                        try:
                            validated_headers.append(HeaderDetail.parse_obj(h).dict())
                        except ValidationError as ve:
                            log_event("SoenlisTools", f"Validation error for a header detail: {ve}. Skipping invalid header: {h}", status="ERROR")
                    json_data['detailed_header_analysis'][header_type] = validated_headers

            validated_data = FinalReport.parse_obj(json_data)
            
            summary_data = validated_data.dict()
            log_event("SoenlisTools", "AI Summary Generation complete.", status="SUCCESS")
            return summary_data
        except ValidationError as e:
            log_event("SoenlisTools", f"AI Summary response validation failed: {e}. Raw AI response: {response.content}", status="ERROR")
            return {"error": "Failed to generate AI summary due to validation error.", "details": str(e), "raw_ai_response": response.content}
        except json.JSONDecodeError as e:
            log_event("SoenlisTools", f"AI Summary response is not valid JSON after all attempts: {e}. Raw AI response: {response.content}", status="ERROR")
            return {"error": "AI response was not valid JSON after all attempts.", "details": str(e), "raw_ai_response": response.content}
        except Exception as e:
            log_event("SoenlisTools", f"The AI summary generation encountered an unexpected error: {e}. Traceback: {traceback.format_exc()}", status="ERROR")
            return {"error": "The AI summary generation encountered an unexpected error.", "details": str(e)}

def tool_run_reconnaissance_only(url: str) -> dict:
    scanner = SoenlisScanner()
    if not scanner._fetch_data(url):
        return {"error": "Failed to fetch critical data from target URL."}
    
    technologies_from_wappalyzer = scanner._fingerprint_technologies()
    
    soup = BeautifulSoup(scanner.raw_data.get('html', ''), 'html.parser')
    extracted_script_src = [tag['src'] for tag in soup.find_all('script', src=True) if tag['src']]
    extracted_link_href = [tag['href'] for tag in soup.find_all('link', href=True) if tag['href']]
    extracted_meta_content_raw = [{'name': tag.get('name'), 'content': tag.get('content')} for tag in soup.find_all('meta') if tag.get('name') and tag.get('content')]
    
    head_html = str(soup.head) if soup.head else ""
    all_scripts_tags = "\n".join([str(tag) for tag in soup.find_all('script')])
    all_links_tags = "\n".join([str(tag) for tag in soup.find_all('link')])
    body_start_html = str(soup.body.prettify())[:3000] if soup.body else ""

    initial_context = {
        "technologies_identified": technologies_from_wappalyzer,
        "http_headers": scanner.raw_data.get('headers', {}),
        "extracted_script_srcs": extracted_script_src,
        "extracted_link_hrefs": extracted_link_href,
        "extracted_meta_contents": extracted_meta_content_raw,
        "html": scanner.raw_data.get('html', ''),
        "head_section_html": head_html,
        "all_script_tags_content": all_scripts_tags,
        "all_link_tags_content": all_links_tags,
        "body_start_html_snippet": body_start_html,
        "robots_txt": scanner.raw_data.get('robots_txt', "Not found.")
    }
    return initial_context

def tool_enrich_technologies(context_data: dict) -> dict:
    scanner = SoenlisScanner()
    return scanner._run_tech_enrichment_ai(context_data)

def tool_run_cve_lookup(payload_str: str) -> dict:
    try:
        payload = json.loads(payload_str)
        product = payload.get("name")
        version = payload.get("version")
        if not product: return {"error": "'name' is required in payload."}
        
        scanner = SoenlisScanner()
        vulnerabilities = scanner._get_all_cves(product, version)
        return {"product": product, "version": version, "vulnerabilities": vulnerabilities}
    except Exception as e:
        return {"error": f"An error occurred in CVE tool: {e}. Payload was: {payload_str}. Traceback: {traceback.format_exc()}"}

def tool_generate_final_summary(final_context: dict) -> dict:
    scanner = SoenlisScanner()
    return scanner._run_summary_generation_ai(final_context)