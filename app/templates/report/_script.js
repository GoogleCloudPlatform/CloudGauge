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
        settleClamps(targetSection);
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

// --- Accordions (one <details class="check"> per check, see _macros.html) ---
// Items that need a human open on load, the rest are collapsed; "Expand all" / "Collapse all" act on the page
// shown, the filter opens every item it matches (and restores the default when cleared), printing opens all,
// and a #<section id>-<check slug> link opens that one check.
function checkDetails(root) {
    return Array.from((root || document).querySelectorAll('details.check'));
}

function currentSection() {
    return Array.from(document.querySelectorAll('.content-section')).find(section => section.style.display !== 'none');
}

function setAllChecks(open) {
    checkDetails(currentSection()).forEach(details => { details.open = open; });
    if (open) { settleClamps(currentSection()); }
}

function openCheckFromHash(hash) {
    const item = hash && document.getElementById(hash);
    if (!item || !item.matches('.checks-list > li')) { return false; }
    showSection(item.closest('.content-section').id.replace(/-section$/, ''));
    const details = item.querySelector('details.check');
    if (details) { details.open = true; }
    history.replaceState(null, null, '#' + hash);
    item.scrollIntoView({ block: 'start' });
    return true;
}

document.addEventListener("DOMContentLoaded", function() {
    clampLongCells();
    checkDetails().forEach(details => { details.dataset.defaultOpen = details.open ? 'true' : 'false'; });
    const hash = window.location.hash.substring(1);
    if (hash && document.getElementById(hash + '-section')) {
        showSection(hash);
    } else if (!openCheckFromHash(hash)) {
        showSection('overview');
    }
    // Large tables: click a column header to sort (see "Layout for large organizations" in app/reporting/context.py).
    document.querySelectorAll('table.details-table th').forEach(th => {
        th.title = 'Sort by this column';
        th.addEventListener('click', () => sortTable(th));
    });
    // Opening a collapsed item lays its clamped cells out for the first time.
    document.querySelectorAll('details.check').forEach(details => {
        details.addEventListener('toggle', () => { if (details.open) { settleClamps(details); } });
    });
});

let closedForPrint = [];
window.addEventListener('beforeprint', () => {
    closedForPrint = checkDetails().filter(details => !details.open);
    closedForPrint.forEach(details => { details.open = true; });
});
window.addEventListener('afterprint', () => {
    closedForPrint.forEach(details => { details.open = false; });
    closedForPrint = [];
});

// --- Long cells (see app/reporting/layouts.py) ---
// A plain cell longer than CLAMP_MIN_CHARS is clamped to three lines with a "Show more" toggle; the briefings'
// message cells come clamped from the template. The toggle's label is CSS-generated (data-more / data-less), so it
// is not part of the row's text for sorting, filtering, or the Gemini prompt. Once a cell is visible, a toggle whose
// text fits in three lines anyway is removed (settleClamps); hidden rows keep theirs until they are shown.
const CLAMP_MIN_CHARS = 200;

function clampLongCells() {
    document.querySelectorAll('table.details-table td').forEach(td => {
        if (td.childElementCount > 0 || td.textContent.length <= CLAMP_MIN_CHARS) { return; }
        const box = document.createElement('div');
        box.className = 'clamp';
        box.textContent = td.textContent;
        td.textContent = '';
        td.appendChild(box);
        const toggle = document.createElement('button');
        toggle.className = 'link-btn clamp-toggle';
        toggle.type = 'button';
        toggle.dataset.more = 'Show more';
        toggle.dataset.less = 'Show less';
        toggle.setAttribute('aria-expanded', 'false');
        toggle.addEventListener('click', () => toggleClamp(toggle));
        td.appendChild(toggle);
    });
}

function toggleClamp(toggle) {
    const box = toggle.previousElementSibling;
    const open = box.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
}

function settleClamps(root) {
    (root || document).querySelectorAll('.clamp:not(.open)').forEach(box => {
        const toggle = box.nextElementSibling;
        if (toggle && toggle.classList.contains('clamp-toggle') && box.clientHeight > 0 && box.scrollHeight <= box.clientHeight + 1) {
            toggle.remove();
            box.classList.add('open');
        }
    });
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
        const details = item.querySelector('details.check');
        if (details) {
            // A matching item opens so its rows can be seen; clearing the filter puts the default state back.
            details.open = term ? visible : details.dataset.defaultOpen === 'true';
        }
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

// --- Gemini (the two actions on the Overview card, see report.html) ---
// "Get AI summary" writes the executive summary into the card under the actions. "Get remediation suggestions" asks
// Gemini for a gcloud command for every failing finding that does not already show a Fix and writes each one into
// the finding's remediation placeholder on its category page; the status line under the actions says what happened,
// because the fixes land on pages other than the one the button is on. Gemini's text is escaped before it is marked
// up (renderMarkdown), so nothing quoted from a finding becomes HTML.
const GEMINI_FOOTNOTE = "Written by Gemini from this report's findings. Check the details before acting on them.";

function pendingHtml(text) {
    return `<div class="pending"><span class="spinner"></span><span>${text}</span></div>`;
}

async function generateAiSummary() {
    const btn = document.getElementById("summaryBtn");
    const container = document.getElementById("ai-summary-container");
    const content = document.getElementById("ai-summary-content");
    const copyBtn = document.getElementById("copy-summary-btn");

    btn.disabled = true;
    btn.textContent = "Writing summary…";
    container.hidden = false;
    if (copyBtn) { copyBtn.hidden = true; }
    content.innerHTML = pendingHtml("Gemini is reading the report and writing the summary…");

    try {
        const response = await fetch('/api/get-summary', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope_id: {{ scope_id|tojson }}, job_id: {{ job_id|tojson }} })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `The server answered ${response.status}.`);
        }
        const data = await response.json();
        // Gemini tends to open with the heading the card already has.
        const body = renderMarkdown(data.summary || '').replace(/^<h3>\s*executive summary\s*<\/h3>/i, '');
        content.innerHTML = `<div class="prose-block">${body}</div><p class="footnote">${GEMINI_FOOTNOTE}</p>`;
        btn.textContent = "Summary ready";
        if (copyBtn) { copyBtn.hidden = false; }
    } catch (error) {
        content.innerHTML = `<div class="notice notice-rose"><strong>Couldn't write the summary.</strong> ${escapeHtml(error.message)}</div>`;
        btn.textContent = "Retry summary";
        btn.disabled = false;
    }
}

async function copySummary(btn) {
    const content = document.getElementById("ai-summary-content").querySelector('.prose-block');
    try {
        await navigator.clipboard.writeText((content || {}).innerText || '');
        btn.textContent = "Copied";
    } catch (error) {
        btn.textContent = "Couldn't copy";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 2000);
}

// --- Cost insights (the Cost Optimization footer's "Get detailed insights", see _macros.html) ---
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
        tableRowsHtml += `<tr><td class="prose">${escapeHtml(insight.check)}</td><td class="code nowrap"><code class="chip">${escapeHtml(insight.project)}</code></td><td class="code"><code class="chip">${escapeHtml(insight.resource)}</code></td><td class="prose">${escapeHtml(insight.details)}</td></tr>`;
    });
    const count = allInsightsData.length;
    const tableHtml = `<div class="card-title-row"><h3>Detailed insights</h3><span class="muted"><span class="mono">${count}</span> recommendation${count === 1 ? '' : 's'}</span></div>`
        + `<table class="data-table"><thead><tr><th>Check</th><th>Project</th><th>Resource</th><th>Details</th></tr></thead><tbody>${tableRowsHtml}</tbody></table>`;
    const totalPages = Math.ceil(count / rowsPerPage);
    let paginationHtml = '';
    if (totalPages > 1) {
        paginationHtml = '<div class="pagination-controls">';
        paginationHtml += `<button class="btn btn-outline btn-sm" onclick="renderTablePage(${page - 1})" ${page === 1 ? 'disabled' : ''}>Previous</button>`;
        paginationHtml += `<span>Page <span class="mono">${page}</span> of <span class="mono">${totalPages}</span></span>`;
        paginationHtml += `<button class="btn btn-outline btn-sm" onclick="renderTablePage(${page + 1})" ${page === totalPages ? 'disabled' : ''}>Next</button>`;
        paginationHtml += '</div>';
    }
    placeholder.innerHTML = tableHtml + paginationHtml;
}

async function fetchInsights(btn) {
    const placeholder = document.getElementById('insights-placeholder');
    const introText = document.querySelector('.insights-intro');
    btn.disabled = true;
    btn.textContent = "Loading insights…";
    placeholder.innerHTML = pendingHtml("Querying the Recommender API for every project in scope — this can take a minute…");
    try {
        const response = await fetch('/api/get-insights', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope: {{ scope|tojson }}, scope_id: {{ scope_id|tojson }} })
        });
        if (!response.ok) { throw new Error(`The server answered ${response.status}.`); }
        allInsightsData = await response.json();
        if (allInsightsData.length === 0) {
            placeholder.innerHTML = '<div class="empty-state"><span class="dot dot-compliant"></span>The Recommender API has no cost recommendations for this scope.</div>';
        } else {
            if (introText) { introText.hidden = true; }
            renderTablePage(1);
        }
        btn.hidden = true;
    } catch (error) {
        placeholder.innerHTML = `<div class="notice notice-rose"><strong>Couldn't load the insights.</strong> ${escapeHtml(error.message)} The server logs have the detail.</div>`;
        btn.textContent = "Try again";
        btn.disabled = false;
    }
}

function escapeHtml(text) {
    return String(text == null ? '' : text).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function renderInline(text) {
    return escapeHtml(text)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s.,;:)]|$)/g, '$1<em>$2</em>');
}

// The summary prompt asks for GitHub-flavored Markdown: headings, paragraphs, bulleted and numbered lists, bold,
// italics and inline code are rendered; everything is escaped first, so nothing quoted from a finding becomes HTML.
function renderMarkdown(text) {
    const html = [];
    let list = null;
    let paragraph = [];
    const closeList = () => { if (list) { html.push(`</${list}>`); list = null; } };
    const flushParagraph = () => { if (paragraph.length) { html.push(`<p>${renderInline(paragraph.join(' '))}</p>`); paragraph = []; } };
    const item = (kind, body) => { flushParagraph(); if (list !== kind) { closeList(); list = kind; html.push(`<${kind}>`); } html.push(`<li>${renderInline(body)}</li>`); };
    String(text == null ? '' : text).replace(/\r\n?/g, '\n').split('\n').forEach(raw => {
        const line = raw.trim();
        let m;
        if (!line) { flushParagraph(); closeList(); }
        else if ((m = line.match(/^#+\s+(.*)$/))) { flushParagraph(); closeList(); html.push(`<h3>${renderInline(m[1])}</h3>`); }
        else if ((m = line.match(/^[-*+\u2022]\s+(.*)$/))) { item('ul', m[1]); }
        else if ((m = line.match(/^\d+[.)]\s+(.*)$/))) { item('ol', m[1]); }
        else if (list && /^\s{2,}\S/.test(raw) && html.length) { html[html.length - 1] = html[html.length - 1].replace(/<\/li>$/, ` ${renderInline(line)}</li>`); }
        else { paragraph.push(line); }
    });
    flushParagraph();
    closeList();
    return html.join('');
}

// The status line under the Gemini actions: pending (with the spinner), done, or an error notice.
function setGeminiStatus(html, state) {
    const status = document.getElementById('gemini-status');
    if (!status) { return; }
    status.hidden = false;
    status.className = `gemini-status is-${state}`;
    if (state === 'error') {
        status.innerHTML = `<div class="notice notice-rose">${html}</div>`;
    } else {
        status.innerHTML = `${state === 'pending' ? '<span class="spinner"></span>' : ''}<span>${html}</span>`;
    }
}

// "Suggested fixes added to 12 findings: Security & Identity (5) · Cost Optimization (7)." with links to the pages.
// Counted from the page, so a retry after an error reports every fix added so far.
function fixesSummary(declined) {
    const perSection = new Map();
    document.querySelectorAll('.remediation-placeholder.fix-block').forEach(placeholder => {
        const section = placeholder.closest('.content-section');
        if (section) { perSection.set(section, (perSection.get(section) || 0) + 1); }
    });
    const drafted = Array.from(perSection.values()).reduce((sum, count) => sum + count, 0);
    const parts = Array.from(perSection, ([section, count]) => {
        const id = section.id.replace(/-section$/, '');
        const title = (section.querySelector('.section-header h2') || {}).textContent || id;
        return `<a href="#${id}" onclick="showSection('${id}')">${escapeHtml(title)}</a> (<span class="mono">${count}</span>)`;
    });
    const findings = n => `${n} finding${n === 1 ? '' : 's'}`;
    let text = drafted
        ? `Suggested fixes added to ${findings(drafted)}: ${parts.join(' · ')}.`
        : `Gemini couldn't draft a command for ${declined === 1 ? 'the finding' : `any of the ${findings(declined)}`}.`;
    if (drafted && declined) { text += ` Gemini couldn't draft a command for ${declined} of them.`; }
    return text;
}

function suggestedFixHtml() {
    return '<strong>Suggested fix</strong> <span class="pill pill-sky">AI-generated</span>';
}

async function getGeminiSuggestions(btn) {
    btn = btn || document.getElementById('suggestionsBtn');
    btn.disabled = true;
    const findingsToFix = [];
    let alreadyFixed = 0;
    const placeholders = document.querySelectorAll(".remediation-placeholder");

    placeholders.forEach((placeholder) => {
        const listItem = placeholder.closest('li');
        // A check that knows its fix shows it (the fix-block); only the others are asked of Gemini.
        if (listItem.querySelector('.fix-block')) { alreadyFixed++; return; }
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
        btn.textContent = alreadyFixed ? "Every finding already shows its fix" : "No failing findings";
        setGeminiStatus(alreadyFixed ? "Every failing finding already shows its fix, so there is nothing to ask Gemini for." : "There are no failing findings to draft fixes for.", 'done');
        return;
    }

    // Each finding shows that its fix is on the way; the status line says where the fixes will appear.
    findingsToFix.forEach(finding => {
        const placeholder = document.getElementById(`fix-${finding.index}`);
        if (placeholder) { placeholder.innerHTML = pendingHtml("Gemini is drafting a fix…"); }
    });
    setGeminiStatus(`Drafting fixes for ${findingsToFix.length} finding${findingsToFix.length === 1 ? '' : 's'} — each appears under its finding, on the category pages, as it arrives.`, 'pending');

    let drafted = 0;
    let declined = 0;
    const BATCH_SIZE = 5;
    for (let i = 0; i < findingsToFix.length; i += BATCH_SIZE) {
        const batch = findingsToFix.slice(i, i + BATCH_SIZE);
        btn.textContent = `Drafting fixes (${Math.min(i + batch.length, findingsToFix.length)} of ${findingsToFix.length})…`;
        try {
            const response = await fetch('/api/get-suggestions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ findings: batch })
            });
            if (!response.ok) { throw new Error(`The server answered ${response.status}.`); }
            const suggestions = await response.json();
            batch.forEach(finding => {
                const placeholder = document.getElementById(`fix-${finding.index}`);
                if (!placeholder) { return; }
                const suggestion = String(suggestions[`finding-${finding.index}`] || '').trim();
                // The service answers with a gcloud command, or with a sentence saying why it could not.
                if (suggestion.startsWith('gcloud')) {
                    drafted++;
                    placeholder.className = 'remediation-placeholder fix-block';
                    placeholder.innerHTML = suggestedFixHtml();
                    const preNode = document.createElement("pre");
                    preNode.textContent = suggestion;
                    placeholder.appendChild(preNode);
                } else {
                    declined++;
                    placeholder.className = 'remediation-placeholder';
                    placeholder.innerHTML = '<p class="remediation-note">Gemini couldn\u2019t draft a command for this finding.</p>';
                }
            });
        } catch (error) {
            console.error("Failed to get Gemini suggestions:", error);
            findingsToFix.slice(i).forEach(finding => {
                const placeholder = document.getElementById(`fix-${finding.index}`);
                if (placeholder && placeholder.querySelector('.pending')) { placeholder.innerHTML = ''; }
            });
            const before = drafted ? ` ${drafted} fix${drafted === 1 ? ' was' : 'es were'} added before the error; "Try again" asks only for the rest.` : '';
            setGeminiStatus(`<strong>Couldn't get fixes from Gemini.</strong> ${escapeHtml(error.message)}${before}`, 'error');
            btn.textContent = "Try again";
            btn.disabled = false;
            return;
        }
    }
    btn.textContent = "Fixes added";
    setGeminiStatus(fixesSummary(declined), 'done');
}
