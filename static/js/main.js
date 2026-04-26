/* AtomicLoop — main.js */
'use strict';

const _API_KEY = document.querySelector('meta[name="al-api-key"]')?.content || '';

// ── Globals ───────────────────────────────────────────────────────────────────

let _allTechniques = [];
let _selectedTech  = null;
let _selectedTest  = null;
let _lastRunResult = null;

// ── Bootstrap ─────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Only run browser logic on the index page
    if (!document.getElementById('techniqueList')) return;
    loadTechniques();
    updateRunButtonState();
    document.getElementById('dryRunToggle').addEventListener('change', updateRunButtonState);
    document.getElementById('confirmCheck') && document.getElementById('confirmCheck').addEventListener('change', updateRunButtonState);
});

// ── Technique loading ─────────────────────────────────────────────────────────

async function loadTechniques() {
    try {
        const resp = await fetch('/api/atomics');
        const data = await resp.json();
        _allTechniques = data.techniques || [];
        renderTechniqueList(_allTechniques);
    } catch (err) {
        const list = document.getElementById('techniqueList');
        if (list) list.innerHTML = `<div style="padding:16px;color:var(--accent-red)">Failed to load techniques: ${esc(err.message)}</div>`;
    }
}

function filterTechniques(query) {
    if (!_allTechniques.length) return;
    const q = (query || '').toLowerCase();
    const filtered = q
        ? _allTechniques.filter(t =>
            t.technique_id.toLowerCase().includes(q) ||
            t.technique_name.toLowerCase().includes(q) ||
            t.tactic.toLowerCase().includes(q))
        : _allTechniques;
    renderTechniqueList(filtered);
}

function renderTechniqueList(techniques) {
    const list    = document.getElementById('techniqueList');
    const counter = document.getElementById('techCount');
    if (!list) return;

    counter.textContent = `${techniques.length} technique${techniques.length !== 1 ? 's' : ''}`;

    if (!techniques.length) {
        list.innerHTML = '<div class="loading-placeholder">No techniques match the search.</div>';
        return;
    }

    // Group by tactic
    const byTactic = {};
    techniques.forEach(t => {
        const tac = t.tactic || 'Other';
        (byTactic[tac] = byTactic[tac] || []).push(t);
    });

    const tacticOrder = ['Initial Access','Execution','Persistence','Privilege Escalation',
        'Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection',
        'Command and Control','Exfiltration','Impact','Other'];

    let html = '';
    const orderedTactics = tacticOrder.filter(t => byTactic[t]);
    Object.keys(byTactic).filter(t => !tacticOrder.includes(t)).forEach(t => orderedTactics.push(t));

    orderedTactics.forEach(tactic => {
        if (!byTactic[tactic]) return;
        html += `<div class="tactic-group-label">${esc(tactic)}</div>`;
        byTactic[tactic].forEach(t => {
            const activeClass = _selectedTech && _selectedTech.technique_id === t.technique_id ? ' active' : '';
            html += `<div class="technique-card${activeClass}" onclick="selectTechnique('${esc(t.technique_id)}')">
                <div class="tc-id">${esc(t.technique_id)}</div>
                <div class="tc-name">${esc(t.technique_name)}</div>
                <div class="tc-tests">${t.test_count} test${t.test_count !== 1 ? 's' : ''}</div>
            </div>`;
        });
    });

    list.innerHTML = html;
}

// ── Technique selection ───────────────────────────────────────────────────────

async function selectTechnique(techniqueId) {
    try {
        const resp = await fetch(`/api/atomics/${encodeURIComponent(techniqueId)}`);
        const data = await resp.json();
        if (!data.success) return;

        _selectedTech = data;
        _selectedTest = data.tests && data.tests[0] ? data.tests[0] : null;

        // Update active card in list
        document.querySelectorAll('.technique-card').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.technique-card').forEach(el => {
            if (el.querySelector('.tc-id')?.textContent === techniqueId) el.classList.add('active');
        });

        // Show detail
        document.getElementById('detailEmpty').classList.add('hidden');
        document.getElementById('detailContent').classList.remove('hidden');

        // Populate header
        setText('detailTechId', techniqueId);
        setText('detailTactic', data.tactic || '');
        setText('detailTechName', data.technique_name || '');
        setText('detailTechDesc', data.description || '');
        const mitreLink = document.getElementById('detailMitreUrl');
        if (mitreLink) mitreLink.href = data.mitre_url || '#';

        // Build test tabs
        renderTestTabs(data.tests || []);
        if (_selectedTest) selectTest(_selectedTest);

        // Reset run result
        _lastRunResult = null;
        const rp = document.getElementById('runResultPanel');
        if (rp) rp.classList.add('hidden');
        const vp = document.getElementById('validationPanel');
        if (vp) vp.classList.add('hidden');

    } catch (err) {
        console.error('selectTechnique error:', err);
    }
}

// ── Test selection ────────────────────────────────────────────────────────────

function renderTestTabs(tests) {
    const container = document.getElementById('testTabs');
    if (!container) return;
    container.innerHTML = tests.map(t =>
        `<button class="test-tab-btn${t === _selectedTest ? ' active' : ''}"
            onclick="selectTestByNumber(${t.test_number})" id="testTab-${t.test_number}">
            #${t.test_number} ${esc(t.test_name)}
        </button>`
    ).join('');
}

function selectTestByNumber(testNumber) {
    if (!_selectedTech) return;
    const test = (_selectedTech.tests || []).find(t => t.test_number === testNumber);
    if (!test) return;
    _selectedTest = test;
    document.querySelectorAll('.test-tab-btn').forEach(b => b.classList.remove('active'));
    const tab = document.getElementById(`testTab-${testNumber}`);
    if (tab) tab.classList.add('active');
    selectTest(test);
}

function selectTest(test) {
    if (!test) return;
    _selectedTest = test;

    // Meta badges
    const execBadge = document.getElementById('testExecutorBadge');
    const permBadge = document.getElementById('testPermBadge');
    if (execBadge) { execBadge.textContent = test.executor_type; execBadge.className = 'test-meta-badge executor-badge'; }
    if (permBadge) {
        permBadge.textContent = test.required_permissions || 'user';
        permBadge.className = 'test-meta-badge perm-badge' + (test.required_permissions === 'administrator' ? ' admin-perm' : '');
    }

    setText('testDesc', test.description || '');

    // Command / cleanup
    const cmdEl = document.getElementById('testCommand');
    if (cmdEl) cmdEl.textContent = test.command || '';
    const cleanupEl = document.getElementById('testCleanup');
    if (cleanupEl) cleanupEl.textContent = test.cleanup_command || '(no cleanup command)';

    // Artifacts
    const artsEl = document.getElementById('testArtifacts');
    if (artsEl) {
        const eids  = test.expected_event_ids || [];
        const srcs  = test.expected_log_sources || [];
        let html = '';
        eids.forEach(e => {
            html += `<div class="artifact-item"><span class="artifact-eid">${esc(String(e))}</span><span class="artifact-label">${eidLabel(e)}</span></div>`;
        });
        srcs.forEach(s => {
            html += `<div class="artifact-item"><span class="artifact-eid" style="color:var(--accent-blue);width:auto;padding-right:8px">${esc(s)}</span></div>`;
        });
        artsEl.innerHTML = html || '<div style="color:var(--text-muted);font-size:12px">No artifact metadata defined.</div>';
    }

    // Input arguments
    const argsCard = document.getElementById('inputArgsCard');
    const argsFields = document.getElementById('inputArgsFields');
    const inputArgs = test.input_arguments || {};
    if (argsCard && argsFields) {
        const keys = Object.keys(inputArgs);
        if (keys.length) {
            argsCard.classList.remove('hidden');
            argsFields.innerHTML = keys.map(k => {
                const def = inputArgs[k];
                return `<div class="arg-field">
                    <label class="arg-label">#{${esc(k)}}</label>
                    <input class="arg-input" id="arg-${esc(k)}" type="text"
                        value="${esc(def.default || '')}"
                        placeholder="${esc(def.default || '')}">
                    <div class="arg-hint">${esc(def.description || '')}</div>
                </div>`;
            }).join('');
        } else {
            argsCard.classList.add('hidden');
        }
    }

    showCmdTab('command');
    updateRunButtonState();
}

// ── Command tab switching ─────────────────────────────────────────────────────

function showCmdTab(name) {
    ['command', 'cleanup', 'artifacts'].forEach(n => {
        const panel = document.getElementById(`cmdPanel-${n}`);
        const btn   = document.querySelector(`.cmd-tab[onclick="showCmdTab('${n}')"]`);
        if (panel) panel.classList.toggle('hidden', n !== name);
        if (btn)   btn.classList.toggle('active', n === name);
    });
}

// ── Run controls ──────────────────────────────────────────────────────────────

function updateRunButtonState() {
    const dryRun  = document.getElementById('dryRunToggle')?.checked;
    const confirm = document.getElementById('confirmCheck')?.checked;
    const btn     = document.getElementById('runBtn');
    const confirmRow = document.getElementById('confirmRow');

    if (confirmRow) confirmRow.classList.toggle('hidden', !!dryRun);

    if (!btn) return;
    if (dryRun) {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">👁</span> Dry Run Preview';
    } else if (confirm) {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">▶</span> Execute Test';
    } else {
        btn.disabled = true;
        btn.innerHTML = '<span class="btn-icon">🔒</span> Confirm Required';
    }
}

// ── Run test ──────────────────────────────────────────────────────────────────

async function runTest() {
    if (!_selectedTech || !_selectedTest) {
        alert('Select a technique and test first.');
        return;
    }

    const dryRun         = document.getElementById('dryRunToggle')?.checked ?? true;
    const confirm        = document.getElementById('confirmCheck')?.checked ?? false;
    const captureEvents  = document.getElementById('captureEventsToggle')?.checked ?? true;
    const normalize      = document.getElementById('normalizeToggle')?.checked ?? true;
    const timeout        = parseInt(document.getElementById('timeoutInput')?.value || '30', 10);

    // Collect input arguments
    const inputArguments = {};
    const inputArgs = _selectedTest.input_arguments || {};
    Object.keys(inputArgs).forEach(k => {
        const el = document.getElementById(`arg-${k}`);
        if (el) inputArguments[k] = el.value;
    });

    const runBtn    = document.getElementById('runBtn');
    const runStatus = document.getElementById('runStatus');
    if (runBtn)    runBtn.disabled = true;
    if (runStatus) runStatus.classList.remove('hidden');

    try {
        const resp = await fetch('/api/run', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': _API_KEY },
            body:    JSON.stringify({
                technique_id:    _selectedTech.technique_id,
                test_number:     _selectedTest.test_number,
                confirm,
                dry_run:         dryRun,
                capture_events:  captureEvents,
                normalize,
                timeout,
                input_arguments: inputArguments,
            }),
        });

        const data = await resp.json();
        if (!data.success && !data.dry_run) {
            alert(`Run failed: ${data.error || 'Unknown error'}`);
            return;
        }
        _lastRunResult = data;
        renderRunResult(data);

    } catch (err) {
        alert(`Request failed: ${err.message}`);
    } finally {
        if (runBtn) {
            runBtn.disabled = false;
            updateRunButtonState();
        }
        if (runStatus) runStatus.classList.add('hidden');
    }
}

function renderRunResult(data) {
    const panel = document.getElementById('runResultPanel');
    if (!panel) return;

    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    setText('resExitCode',   data.exit_code !== null && data.exit_code !== undefined ? String(data.exit_code) : '—');
    setText('resDuration',   `${data.duration_ms || 0}ms`);
    setText('resEventCount', String(data.event_count || 0));
    setText('resRunId',      data.run_id || data.id || '—');

    const viewLink = document.getElementById('resultViewLink');
    if (viewLink && (data.id || data.run_id)) {
        viewLink.href = `/run/${data.id || data.run_id}`;
        viewLink.classList.remove('hidden');
    }

    const outputEl = document.getElementById('resOutput');
    if (outputEl) outputEl.textContent = (data.raw_output || '').trim() || '(no output)';

    const stderrEl    = document.getElementById('resStderr');
    const stderrLabel = document.getElementById('stderrLabel');
    if (stderrEl && stderrLabel) {
        const stderr = (data.stderr || '').trim();
        if (stderr) {
            stderrEl.textContent = stderr;
            stderrEl.classList.remove('hidden');
            stderrLabel.classList.remove('hidden');
        } else {
            stderrEl.classList.add('hidden');
            stderrLabel.classList.add('hidden');
        }
    }

    // Color exit code
    const exitEl = document.getElementById('resExitCode');
    if (exitEl && data.exit_code !== null && data.exit_code !== undefined) {
        exitEl.style.color = data.exit_code === 0 ? 'var(--accent-green)' : 'var(--accent-red)';
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

function openValidationPanel() {
    const vp = document.getElementById('validationPanel');
    if (vp) {
        vp.classList.remove('hidden');
        vp.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

async function validateDetection() {
    const sigma = document.getElementById('sigmaRuleInput')?.value?.trim();
    const runId = _lastRunResult?.id || _lastRunResult?.run_id;

    if (!runId && !sigma) {
        alert('Run a test first, then paste a Sigma rule to validate.');
        return;
    }

    const validateBtn    = document.getElementById('validateBtn');
    const validateStatus = document.getElementById('validateStatus');
    if (validateBtn)    validateBtn.disabled = true;
    if (validateStatus) validateStatus.classList.remove('hidden');

    try {
        const body = {};
        if (runId)  body.run_id = runId;
        if (sigma)  body.sigma_rule = sigma;
        // Also pass events from last run if available
        if (_lastRunResult?.events?.length) {
            body.events = _lastRunResult.events;
        }

        const resp = await fetch('/api/validate', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
        const data = await resp.json();
        if (!data.success) {
            alert(`Validation error: ${data.error || 'Unknown error'}`);
            return;
        }
        renderValidationResult(data);

    } catch (err) {
        alert(`Validation request failed: ${err.message}`);
    } finally {
        if (validateBtn)    validateBtn.disabled = false;
        if (validateStatus) validateStatus.classList.add('hidden');
    }
}

function renderValidationResult(data) {
    const resultEl = document.getElementById('valResult');
    if (!resultEl) return;
    resultEl.classList.remove('hidden');

    const fired = data.detection_fired;
    const verdictEl = document.getElementById('valVerdict');
    if (verdictEl) {
        if (fired === true) {
            verdictEl.textContent = '✓ Detection FIRED';
            verdictEl.className = 'val-verdict val-fired';
        } else if (fired === false) {
            verdictEl.textContent = '✗ Detection DID NOT fire';
            verdictEl.className = 'val-verdict val-miss';
        } else {
            verdictEl.textContent = '— Not evaluated (no Sigma rule)';
            verdictEl.className = 'val-verdict val-pending';
        }
    }

    setText('valGap', data.gap_analysis || '');

    const matchedLabel  = document.getElementById('valMatchedLabel');
    const matchedEvents = document.getElementById('valMatchedEvents');
    const matched = data.matched_events || [];

    if (matchedEvents && matched.length) {
        if (matchedLabel) matchedLabel.classList.remove('hidden');
        matchedEvents.innerHTML = matched.slice(0, 5).map(e =>
            `<pre class="cmd-pre" style="margin-bottom:6px">${esc(JSON.stringify(e, null, 2))}</pre>`
        ).join('');
        if (matched.length > 5) {
            matchedEvents.innerHTML += `<div style="color:var(--text-muted);font-size:12px">… ${matched.length - 5} more matched events</div>`;
        }
    } else if (matchedEvents) {
        if (matchedLabel) matchedLabel.classList.add('hidden');
        matchedEvents.innerHTML = '';
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function eidLabel(eid) {
    const labels = {
        4624: 'Logon Success',       4625: 'Logon Failure',
        4688: 'Process Created',     4698: 'Scheduled Task Created',
        4657: 'Registry Modified',   4104: 'PowerShell Script Block',
        5156: 'Network Connection',  5140: 'Network Share Accessed',
        1102: 'Audit Log Cleared',   1:    'Sysmon: Process Create',
        3:    'Sysmon: Network Conn',10:   'Sysmon: Process Access',
        11:   'Sysmon: File Created',12:   'Sysmon: Reg Create',
        13:   'Sysmon: Reg Set',     7045: 'New Service',
        5001: 'Defender Disabled',   4776: 'NTLM Auth Attempt',
    };
    return labels[eid] || '';
}
