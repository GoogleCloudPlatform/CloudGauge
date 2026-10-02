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
    // The filter box acts on the checks of the page shown; the Overview has none, so it is hidden there.
    const toolbar = document.querySelector('.report-toolbar');
    if (toolbar) {
        toolbar.classList.toggle('no-filter', !(targetSection && targetSection.querySelector('.checks-list')));
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
    // Large tables: click a column header to sort (see "Layout for large organizations" in app/reporting/context.py).
    document.querySelectorAll('table.details-table th').forEach(th => {
        th.title = 'Sort by this column';
        th.addEventListener('click', () => sortTable(th));
    });
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

// --- Large tables: paging, sorting, and filtering (all client-side, no requests) ---
const ROWS_PER_PAGE = {{ rows_per_page|tojson }};
// Rows of one check sent to Gemini for a remediation suggestion; the rest are summarized.
const MAX_ROWS_FOR_FIX = 25;

function tableRows(table) {
    return Array.from(table.tBodies[0].rows);
}

function tableOf(element) {
    return element.closest('.check-content').querySelector('table.details-table');
}

// Shows the first `count` rows of a table and hides the rest; keeps the "Showing N of M rows" line current.
function setShownRows(table, count) {
    const rows = tableRows(table);
    const shown = Math.min(count, rows.length);
    rows.forEach((row, i) => { row.hidden = i >= shown; });
    table.dataset.shown = shown;
    const controls = table.closest('.check-content').querySelector('.table-controls');
    if (controls) {
        controls.querySelector('.shown-count').textContent = shown.toLocaleString();
        controls.querySelectorAll('button').forEach(button => { button.disabled = shown >= rows.length; });
    }
}

function shownRows(table) {
    return parseInt(table.dataset.shown, 10) || ROWS_PER_PAGE;
}

function showMoreRows(btn) {
    const table = tableOf(btn);
    setShownRows(table, shownRows(table) + ROWS_PER_PAGE);
}

function showAllRows(btn) {
    const table = tableOf(btn);
    setShownRows(table, tableRows(table).length);
}

function sortTable(th) {
    const table = th.closest('table');
    const index = Array.from(th.parentNode.children).indexOf(th);
    const ascending = th.getAttribute('aria-sort') !== 'ascending';
    const rows = tableRows(table);
    const valueOf = row => row.cells[index] ? row.cells[index].textContent.trim() : '';
    const numeric = rows.every(row => valueOf(row) === '' || !isNaN(parseFloat(valueOf(row))));
    rows.sort((a, b) => {
        const x = valueOf(a), y = valueOf(b);
        const order = numeric ? (parseFloat(x) || 0) - (parseFloat(y) || 0)
                              : x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
        return ascending ? order : -order;
    });
    const body = table.tBodies[0];
    rows.forEach(row => body.appendChild(row));
    table.querySelectorAll('th[aria-sort]').forEach(header => header.removeAttribute('aria-sort'));
    th.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
    if (currentFilter()) {
        applyRowFilter();
    } else {
        setShownRows(table, shownRows(table));
    }
}

let filterTimer = null;

function scheduleRowFilter() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(applyRowFilter, 150);
}

function currentFilter() {
    const input = document.getElementById('row-filter');
    return input ? input.value.trim().toLowerCase() : '';
}

// Hides the rows (and the checks) that don't contain the filter text; an empty filter restores the paging.
// A page whose checks are all hidden shows its .filter-empty note instead of going blank.
function applyRowFilter() {
    const term = currentFilter();
    let matchedChecks = 0, totalChecks = 0, matchedRows = 0;
    const matchedOnPage = new Map();
    document.querySelectorAll('.checks-list > li').forEach(item => {
        totalChecks++;
        const table = item.querySelector('table.details-table');
        const nameMatches = item.querySelector('strong').textContent.toLowerCase().includes(term);
        let visible = true;
        if (!term) {
            if (table) { setShownRows(table, shownRows(table)); }
        } else if (table) {
            let matches = 0;
            tableRows(table).forEach(row => {
                const hit = row.textContent.toLowerCase().includes(term);
                row.hidden = !hit;
                if (hit) { matches++; }
            });
            matchedRows += matches;
            visible = matches > 0 || nameMatches;
            const controls = item.querySelector('.table-controls');
            if (controls) {
                controls.querySelector('.shown-count').textContent = matches.toLocaleString();
                controls.querySelectorAll('button').forEach(button => { button.disabled = true; });
            }
        } else {
            visible = item.textContent.toLowerCase().includes(term);
        }
        item.hidden = !visible;
        if (visible) {
            matchedChecks++;
            const page = item.closest('.content-section');
            matchedOnPage.set(page, (matchedOnPage.get(page) || 0) + 1);
        }
    });
    const input = document.getElementById('row-filter');
    const shownTerm = input ? input.value.trim() : term;
    document.querySelectorAll('.filter-empty').forEach(note => {
        const matchedHere = matchedOnPage.get(note.closest('.content-section')) || 0;
        const elsewhere = matchedChecks - matchedHere;
        note.hidden = !term || matchedHere > 0;
        note.textContent = note.hidden ? '' : `No checks in this category match \u201C${shownTerm}\u201D.`
            + (elsewhere ? ` ${elsewhere} matching ${elsewhere === 1 ? 'check is' : 'checks are'} on other pages.` : '');
    });
    const status = document.getElementById('filter-status');
    if (status) {
        status.textContent = term ? `${matchedChecks} of ${totalChecks} checks match (${matchedRows.toLocaleString()} rows)` : '';
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
                    if (i >= MAX_ROWS_FOR_FIX) { return; }  // a sample is enough for one gcloud command
                    const cells = row.querySelectorAll('td');
                    const currentProject = (projectIndex !== -1) ? cells[projectIndex].textContent.trim() : '';
                    const recommendation = cells[recommendationIndex].textContent.trim();

                    if (i === 0) { projectId = currentProject; } // Use first project for the batch context

                    // Combine all relevant cell data into a clear, readable string for the LLM
                    let fullRecommendationText = headers.map((h, idx) => `${h}: ${cells[idx].textContent.trim()}`).join(', ');
                    recommendations.push(fullRecommendationText);
                });
                if (rows.length > MAX_ROWS_FOR_FIX) {
                    recommendations.push(`... and ${rows.length - MAX_ROWS_FOR_FIX} more rows like these`);
                }
                findingText = recommendations.join('\n'); // Use newline to separate multiple findings
            } else {
                findingText = detailsDiv.innerText.trim().slice(0, 4000); // Fallback if no recommendation column
            }
        } else {
            // Case 2: Handle simple text data (no table)
            findingText = detailsDiv.innerText.trim().slice(0, 4000);
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
