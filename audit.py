import os
from datetime import datetime
from typing import List, Dict, Any
import re 

SEVERITY_STYLES = {
    "CRITICAL": {"icon": "🔥", "color": "text-red-400", "bg_color": "bg-red-900/50", "border_color": "border-red-500"},
    "HIGH": {"icon": "🚨", "color": "text-orange-400", "bg_color": "bg-orange-900/50", "border_color": "border-orange-500"},
    "MEDIUM": {"icon": "⚠️", "color": "text-yellow-400", "bg_color": "bg-yellow-900/50", "border_color": "border-yellow-500"},
    "LOW": {"icon": "ℹ️", "color": "text-blue-400", "bg_color": "bg-blue-900/50", "border_color": "border-blue-600"},
    "INFORMATIONAL": {"icon": "💡", "color": "text-gray-400", "bg_color": "bg-gray-800/50", "border_color": "border-gray-700"},
    "GOOD": {"icon": "✅", "color": "text-green-400", "bg_color": "bg-green-900/50", "border_color": "border-green-600"},
}

def escape_html(text: Any) -> str:
    # Escapes HTML characters for secure display.
    if not isinstance(text, str):
        text = str(text)
    
    # Step 1: Replace triple backticks with <pre><code> and </code></pre>
    # This assumes the AI *always* uses ``` for code blocks.
    temp_text = text.replace("```python\n", "<pre class=\"code-block language-python\"><code>")
    temp_text = temp_text.replace("```html\n", "<pre class=\"code-block language-html\"><code>")
    temp_text = temp_text.replace("```js\n", "<pre class=\"code-block language-javascript\"><code>")
    temp_text = temp_text.replace("```\n", "<pre class=\"code-block\"><code>") # Generic code block
    temp_text = temp_text.replace("```", "</code></pre>") # Closing tag

    # Step 2: Escape HTML characters in the rest of the text, but *not* inside <pre><code> blocks
    parts = re.split(r'(<pre.*?<code>.*?<\/code><\/pre>)', temp_text, flags=re.DOTALL)
    final_parts = []
    for part in parts:
        if part.startswith('<pre') and part.endswith('</pre>'):
            final_parts.append(part) # Keep code blocks as is (they are already structured)
        else:
            # Escape HTML characters and convert newlines to <br> for plain text
            escaped_part = part.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
            final_parts.append(escaped_part.replace('\n', '<br>'))
            
    # Also handle bold (**) and italic (*) for very basic formatting if needed
    result = "".join(final_parts)
    result = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', result)
    result = re.sub(r'\*(.*?)\*', r'<em>\1</em>', result)
    
    return result

def generate_finding_card(finding: Dict[str, Any]) -> str:
    # Generates an HTML card for a vulnerability or observation.
    severity = finding.get("severity", "INFORMATIONAL").upper()
    style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["INFORMATIONAL"])
    
    technology_html = ""
    if finding.get('technology') and finding['technology'] != 'N/A':
        technology_html = f"""
        <div class="mb-2">
            <h4 class="font-semibold text-gray-300 mb-1">Affected Technology</h4>
            <p class="text-gray-400 text-sm">{escape_html(finding['technology'])}</p>
        </div>
        """

    # Use escape_html for descriptions and recommendations, which will handle newlines
    description_html = escape_html(finding.get('description', 'No detailed description provided.'))
    remediation_html = escape_html(finding.get('remediation_steps', 'No remediation steps provided.'))

    return f"""
    <div class="mb-6 break-inside-avoid border {style['border_color']} rounded-xl shadow-lg overflow-hidden {style['bg_color']}">
        <div class="p-6">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold {style['color']} flex-grow pr-4">{escape_html(finding['title'])}</h3>
                <span class="text-2xl">{style['icon']}</span>
            </div>
            <div class="space-y-4">
                {technology_html}
                <div>
                    <h4 class="font-semibold text-gray-300 mb-1">Detailed Description & Impact</h4>
                    <div class="text-gray-400 text-sm">
                        {description_html}
                    </div>
                </div>
                <div>
                    <h4 class="font-semibold text-gray-300 mb-1">Recommendations & Remediation</h4>
                    <div class="text-gray-400 text-sm">
                        {remediation_html}
                    </div>
                </div>
            </div>
        </div>
    </div>
    """

def audit(
    url: str,
    score: int,
    executive_summary: str,
    findings: List[Dict[str, Any]],
    filename: str = "audit.html"
) -> str:
    # Generates a comprehensive and professional HTML security audit report.
    # Returns the HTML content as a string.
    start_time = datetime.now()
    
    # --- Vulnerability count for the chart ---
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "GOOD"]
    vuln_counts = {s: 0 for s in severity_order}
    for f in findings:
        sev = f.get("severity", "INFORMATIONAL").upper()
        if sev in vuln_counts:
            vuln_counts[sev] += 1

    # --- Generation of vulnerability cards ---
    findings_html = "\n".join(generate_finding_card(f) for f in findings)
    if not findings_html:
        findings_html = "<p class='text-gray-400'>No significant vulnerabilities or misconfigurations were identified during this scan.</p>"

    # --- Score and summary ---
    score_color = "text-green-400" if score >= 75 else "text-yellow-400" if score >= 50 else "text-red-400"

    html_template = f"""
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - {escape_html(url)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        .font-mono {{ font-family: 'Roboto Mono', monospace; }}
        .break-inside-avoid {{ break-inside: avoid; }}
        /* Styles for simple code blocks if the AI generates newlines */
        .code-block {{
            background-color: #1f2937; /* bg-gray-800 */
            color: #e5e7eb; /* text-gray-200 */
            padding: 0.75em;
            border-radius: 0.5em;
            overflow-x: auto;
            margin-top: 0.8em;
            margin-bottom: 0.8em;
            font-family: 'Roboto Mono', monospace;
            font-size: 0.875em; /* text-sm */
            white-space: pre-wrap; /* For text to wrap if too long */
            word-wrap: break-word;
        }}
        .code-block code {{
            display: block; /* Ensures code takes full width */
            padding: 0; /* Resets internal code padding */
            background: none; /* Resets internal code background */
            color: inherit; /* Uses parent color */
        }}
        /* Generic styles for basic formatting of raw texts */
        .text-gray-400 strong {{
            color: #fff;
            font-weight: 600;
        }}
        .text-gray-400 em {{
            font-style: italic;
        }}
        .text-gray-400 a {{
            color: #8b5cf6; /* purple-400 */
            text-decoration: underline;
        }}
        /* Pygments styles if we decide to add them later, but not used without markdown lib */
    </style>
</head>
<body class="bg-gray-900 text-gray-200">
    <div class="max-w-5xl mx-auto p-4 sm:p-8 md:p-12">
        <header class="border-b-2 border-purple-700 pb-6 mb-12">
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-4xl md:text-5xl font-black text-white">Security Audit Report</h1>
                    <p class="text-purple-400 font-mono text-lg mt-2">{escape_html(url)}</p>
                </div>
                <div class="text-right">
                    <p class="text-2xl font-bold text-purple-300">Soenlis<span class="text-white">.ai</span></p>
                    <p class="text-xs text-gray-500 font-mono mt-1">Generated on: {start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </header>

        <section id="summary" class="mb-16">
            <h2 class="text-3xl font-bold text-purple-300 border-l-4 border-purple-300 pl-4 mb-6">Executive Summary</h2>
            <div class="grid md:grid-cols-3 gap-8">
                <div class="md:col-span-2 bg-gray-800/50 p-6 rounded-xl border border-gray-700">
                    <p class="text-gray-300 leading-relaxed">{escape_html(executive_summary)}</p>
                </div>
                <div class="text-center bg-gray-800/50 p-6 rounded-xl border border-gray-700 flex flex-col justify-center">
                    <p class="text-sm font-bold text-gray-400 uppercase tracking-wider">Security Score</p>
                    <p class="font-black text-7xl {score_color} my-2">{score}</p>
                    <p class="text-sm text-gray-500">out of 100</p>
                </div>
            </div>
        </section>

        <section id="distribution" class="mb-16">
            <h2 class="text-3xl font-bold text-purple-300 border-l-4 border-purple-300 pl-4 mb-6">Findings Distribution</h2>
            <div class="bg-gray-800/50 p-6 rounded-xl border border-gray-700">
                <canvas id="vulnChart" height="120"></canvas>
            </div>
        </section>

        <section id="findings">
            <h2 class="text-3xl font-bold text-purple-300 border-l-4 border-purple-300 pl-4 mb-8">Detailed Findings</h2>
            <div class="md:columns-2 gap-8">
                {findings_html}
            </div>
        </section>

        <footer class="text-center mt-16 pt-8 border-t border-gray-800">
            <p class="text-sm text-gray-600">Confidential report generated by Soenlis.ai for the Raise Your Hack 2025.</p>
        </footer>
    </div>

    <script>
        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Good'],
                datasets: [{{
                    label: 'Number of Findings',
                    data: [{vuln_counts["CRITICAL"]}, {vuln_counts["HIGH"]}, {vuln_counts["MEDIUM"]}, {vuln_counts["LOW"]}, {vuln_counts["INFORMATIONAL"]}, {vuln_counts["GOOD"]}],
                    backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#6b7280', '#22c55e'],
                    borderColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#6b7280', '#22c55e'],
                    borderWidth: 1,
                    borderRadius: 4,
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{ display: false }},
                    tooltip: {{
                        backgroundColor: '#1f2937',
                        titleColor: '#e5e7eb',
                        bodyColor: '#d1d5db',
                        padding: 10,
                        cornerRadius: 4,
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ 
                            color: '#9ca3af',
                            stepSize: 1
                        }},
                        grid: {{ color: 'rgba(156, 163, 175, 0.1)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#9ca3af' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
    </script>
    <script>
        // Function to highlight code if Pygments or another library is included later
        // For now, it's just a visual placeholder
        document.addEventListener('DOMContentLoaded', () => {{
            document.querySelectorAll('pre.code-block code').forEach((block) => {{
                // Simulate very basic coloring if desired
                let content = block.innerHTML;
                content = content.replace(/&lt;(\/?\w+)&gt;/g, '<span style="color:#81A1C1;">&lt;$1&gt;</span>'); // HTML tags
                content = content.replace(/\b(function|var|const|let|class|if|else|for|while|return)\b/g, '<span style="color:#C67979;">$1</span>'); // JS/Python keywords
                content = content.replace(/"(.*?)"/g, '<span style="color:#A4CC9E;">"$1"</span>'); // Strings
                block.innerHTML = content;
            }});
        }});
    </script>
</body>
</html>
    """
    
    # Writes the HTML file to an "audits" subfolder
    output_dir = "audits"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_template)
        
    return html_template