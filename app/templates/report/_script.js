/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
function showSection(sectionId, clickedLinkElement = null) {
    document.querySelectorAll('.content-section').forEach(section => {
        section.style.display = 'none';
    });
    const targetSection = document.getElementById(sectionId + '-section');
    if (targetSection) {
        targetSection.style.display = 'block';
    }
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    const targetNavLink = document.querySelector(`.sidebar .nav-link[href='#${sectionId}']`);
    if (targetNavLink) {
         targetNavLink.classList.add('active');
    }
    if (history.pushState) {
        history.pushState(null, null, '#' + sectionId);
    } else {
        window.location.hash = sectionId;
    }
}

document.addEventListener("DOMContentLoaded", function() {
    const hash = window.location.hash.substring(1);
    if (hash && document.getElementById(hash + '-section')) {
        showSection(hash);
    } else {
        showSection('overview');
    }
});

function toggleSubSection(btn) {
    const container = btn.nextElementSibling;
    if (container) {
        if (container.style.display === "none") {
            container.style.display = "block";
            btn.textContent = "Hide Details";
        } else {
            container.style.display = "none";
            btn.textContent = "View Details";
        }
    }
}

// --- UPDATED: generateAiSummary now includes the new Gemini sparkle theme ---
async function generateAiSummary() {
    const btn = document.getElementById("summaryBtn");
    const container = document.getElementById("ai-summary-container");
    const content = document.getElementById("ai-summary-content");

    btn.disabled = true;
    btn.textContent = "Generating...";

    // Apply the new vibrant blue theme and show the container
    container.classList.add('gemini-summary-card');
    container.style.display = "block";

    // Inject the HTML for the new sparkle loader
    const geminiLoaderHtml = `
        <div class="gemini-loader-container">
            <div class="gemini-loader">
                <span class="sparkle"></span><span class="sparkle"></span>
                <span class="sparkle"></span><span class="sparkle"></span>
            </div>
            <p>Generating summary with Gemini...</p>
        </div>`;
    content.innerHTML = geminiLoaderHtml;

    try {
        const response = await fetch('/api/get-summary', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope_id: {{ scope_id|tojson }}, job_id: {{ job_id|tojson }} }) 
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Network response was not ok');
        }
        const data = await response.json();
        content.innerHTML = renderMarkdown(data.summary);
        btn.textContent = "Summary Generated";
    } catch (error) {
        container.classList.remove('gemini-summary-card');
        content.innerHTML = `<p style='color:var(--error-color);'><strong>Failed to generate summary:</strong> ${error.message}</p>`;
        btn.textContent = "Error - Retry?";
        btn.disabled = false;
    }
}

// --- The rest of the functions are unchanged ---
let allInsightsData = [];
let currentPage = 1;
const rowsPerPage = 10;

function renderTablePage(page) {
    currentPage = page;
    const placeholder = document.getElementById('insights-placeholder');
    if (!placeholder || allInsightsData.length === 0) return;
    const startIndex = (page - 1) * rowsPerPage;
    const endIndex = startIndex + rowsPerPage;
    const pageData = allInsightsData.slice(startIndex, endIndex);
    let tableRowsHtml = '';
    pageData.forEach(insight => {
        tableRowsHtml += `<tr><td>${insight.check}</td><td>${insight.project}</td><td>${insight.resource}</td><td>${insight.details}</td></tr>`;
    });
    const tableHtml = `<h3>Detailed Insights</h3><table class="styled-table"><thead><tr><th>Check</th><th>Project</th><th>Resource</th><th>Details</th></tr></thead><tbody>${tableRowsHtml}</tbody></table>`;
    const totalPages = Math.ceil(allInsightsData.length / rowsPerPage);
    let paginationHtml = '';
    if (totalPages > 1) {
        paginationHtml = '<div class="pagination-controls">';
        paginationHtml += `<button onclick="renderTablePage(${page - 1})" ${page === 1 ? 'disabled' : ''}>&laquo; Previous</button>`;
        paginationHtml += `<span> Page ${page} of ${totalPages} </span>`;
        paginationHtml += `<button onclick="renderTablePage(${page + 1})" ${page === totalPages ? 'disabled' : ''}>Next &raquo;</button>`;
        paginationHtml += '</div>';
    }
    placeholder.innerHTML = tableHtml + paginationHtml;
}

async function fetchInsights(btn) {
    const placeholder = document.getElementById('insights-placeholder');
    const introText = document.querySelector('.insights-intro');
    const loader = btn.querySelector('.loader');
    btn.disabled = true;
    loader.style.display = 'inline-block';
    placeholder.innerHTML = "";
    try {
        const response = await fetch('/api/get-insights', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope: {{ scope|tojson }}, scope_id: {{ scope_id|tojson }} })
        });
        if (!response.ok) { throw new Error('Network response was not ok'); }
        allInsightsData = await response.json();
        if (allInsightsData.length === 0) {
            placeholder.innerHTML = "<p>No detailed insights found.</p>";
        } else {
            if (introText) { introText.style.display = 'none'; }
            renderTablePage(1);
        }
        btn.style.display = 'none';
    } catch (error) {
        placeholder.innerHTML = "<p style='color:var(--error-color);'>Failed to load insights. Check logs.</p>";
        btn.textContent = "Error - Retry?";
        btn.disabled = false;
        loader.style.display = 'none';
    }
}

function renderMarkdown(text) {
    text = text.replace(/\*\*([^\*]+)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/^\*\s(.*)$/gm, '<li>$1</li>');
    text = text.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    text = text.replace(/\n/g, '<br>');
    return text;
}

async function getGeminiSuggestions() {
    const btn = event.target;
    btn.disabled = true;
    const findingsToFix = [];
    const placeholders = document.querySelectorAll(".remediation-placeholder");

    placeholders.forEach((placeholder) => {
        const listItem = placeholder.closest('li');
        const detailsDiv = listItem.querySelector('.details');
        const table = detailsDiv.querySelector('table.details-table');
        const index = placeholder.id.split('-')[1];

        let findingText = '';
        let projectId = '';

        if (table) {
            // Case 1: Handle structured table data
            const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
            const projectIndex = headers.indexOf('Project');
            // Look for multiple possible column names for the recommendation
            const recommendationIndex = ['Recommendation', 'Issue', 'Role', 'Tier'].find(h => headers.includes(h)) ? headers.findIndex(h => ['Recommendation', 'Issue', 'Role', 'Tier'].includes(h)) : -1;

            if (recommendationIndex !== -1) {
                const rows = table.querySelectorAll('tbody tr');
                const recommendations = [];
                rows.forEach((row, i) => {
                    const cells = row.querySelectorAll('td');
                    const currentProject = (projectIndex !== -1) ? cells[projectIndex].textContent.trim() : '';
                    const recommendation = cells[recommendationIndex].textContent.trim();

                    if (i === 0) { projectId = currentProject; } // Use first project for the batch context

                    // Combine all relevant cell data into a clear, readable string for the LLM
                    let fullRecommendationText = headers.map((h, idx) => `${h}: ${cells[idx].textContent.trim()}`).join(', ');
                    recommendations.push(fullRecommendationText);
                });
                findingText = recommendations.join('\n'); // Use newline to separate multiple findings
            } else {
                findingText = detailsDiv.innerText.trim(); // Fallback if no recommendation column
            }
        } else {
            // Case 2: Handle simple text data (no table)
            findingText = detailsDiv.innerText.trim();
        }

        // Extract project ID with regex as a final fallback if not found in table
        if (!projectId) {
            const projectIdMatch = findingText.match(/Project `([^`]+)`/);
            if (projectIdMatch) { projectId = projectIdMatch[1]; }
        }

        if (findingText) {
            findingsToFix.push({ index: index, finding_text: findingText, project_id: projectId });
        }
    });

    if (findingsToFix.length === 0) {
        btn.textContent = "No Actionable Findings";
        return;
    }

    const BATCH_SIZE = 5;
    for (let i = 0; i < findingsToFix.length; i += BATCH_SIZE) {
        const batch = findingsToFix.slice(i, i + BATCH_SIZE);
        btn.textContent = `Getting Fixes (${i + batch.length}/${findingsToFix.length})...`;
        try {
            const response = await fetch('/api/get-suggestions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ findings: batch })
            });
            if (!response.ok) { throw new Error(`API returned status ${response.status}`); }
            const suggestions = await response.json();
            for (const [key, suggestion] of Object.entries(suggestions)) {
                 const originalIndex = key.split('-')[1];
                 if (suggestion) {
                    const placeholder = document.getElementById(`fix-${originalIndex}`);
                    if (placeholder) {
                        const preNode = document.createElement("pre");
                        preNode.style.cssText = 'background-color: #f1f3f4; padding: 10px; border-radius: 4px; margin-top: 10px; white-space: pre-wrap; word-break: break-all;';
                        preNode.textContent = suggestion;
                        placeholder.innerHTML = `<strong>Suggested Fix:</strong>`;
                        placeholder.appendChild(preNode);
                    }
                }
            }
        } catch (e) {
            console.error("Failed to get Gemini suggestions:", e);
            btn.textContent = "Error - Check Logs";
            return;
        }
    }
    btn.textContent = "Suggestions Loaded";
}
