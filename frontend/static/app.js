const fileSelect = document.querySelector('#log-file');
const form = document.querySelector('#analyze-form');
const analyzeButton = document.querySelector('#analyze-button');
const notice = document.querySelector('#notice');
const incidentList = document.querySelector('#incident-list');
const detailPanel = document.querySelector('#detail-panel');
let activeReport = null;
let selectedService = null;
let activeInvestigation = null;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = !message;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function setMetric(id, value) { document.querySelector(id).textContent = value; }

async function loadFiles() {
  const result = await api('/files');
  fileSelect.replaceChildren();
  for (const name of result.files) {
    const option = node('option', '', name);
    option.value = name;
    fileSelect.append(option);
  }
  if (!result.files.length) {
    fileSelect.append(new Option('No .log files found', ''));
    analyzeButton.disabled = true;
    showNotice('Add a UTF-8 .log file to the project data folder to get started.');
  }
}

function updateMetrics(report) {
  setMetric('#metric-lines', report.total_lines_analyzed ?? 0);
  setMetric('#metric-incidents', report.incident_count ?? 0);
  setMetric('#metric-malformed', report.malformed_line_count ?? 0);
  setMetric('#metric-high', report.incidents.filter(item => item.severity === 'HIGH').length);
  document.querySelector('#incident-total').textContent = report.incident_count;
}

function renderIncidents(report) {
  incidentList.replaceChildren();
  if (!report.incidents.length) {
    const empty = node('div', 'empty-state');
    empty.append(node('span', 'empty-icon', '✓'), node('strong', '', 'No incidents found'));
    empty.append(node('p', '', 'This log has no parsed ERROR or CRITICAL entries.'));
    incidentList.append(empty);
    detailPanel.innerHTML = '<div class="detail-empty"><div class="empty-icon large">✓</div><h2>All clear</h2><p>No incidents were detected in this log.</p></div>';
    return;
  }
  for (const incident of report.incidents) {
    const button = node('button', `incident-item${incident.service === selectedService ? ' selected' : ''}`);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(incident.service === selectedService));
    const top = node('span', 'item-top');
    top.append(node('span', 'service-name', incident.service));
    top.append(node('span', `severity ${incident.severity.toLowerCase()}`, incident.severity));
    const bottom = node('span', 'item-bottom');
    bottom.append(node('span', '', `${incident.error_count} error${incident.error_count === 1 ? '' : 's'}`));
    bottom.append(node('span', 'cause-snippet', incident.possible_root_cause));
    button.append(top, bottom);
    button.addEventListener('click', () => { selectedService = incident.service; activeInvestigation = null; renderIncidents(report); renderDetail(incident); });
    incidentList.append(button);
  }
  const chosen = report.incidents.find(item => item.service === selectedService) || report.incidents[0];
  selectedService = chosen.service;
  renderDetail(chosen);
}

function renderDetail(incident) {
  detailPanel.replaceChildren();
  const content = node('div', 'detail-content');
  const title = node('div', 'detail-title-row');
  const heading = node('div');
  heading.append(node('h2', '', incident.service), node('div', 'detail-sub', `${incident.error_count} error event(s) · heuristic assessment`));
  title.append(heading, node('span', `severity ${incident.severity.toLowerCase()}`, incident.severity));
  content.append(title);
  content.append(node('p', 'section-label', 'SUSPECTED CAUSES · HYPOTHESES'));
  for (const cause of incident.possible_causes || []) {
    const card = node('article', 'cause-card');
    card.append(node('div', 'cause-title', cause.cause), node('p', 'cause-basis', cause.basis));
    for (const item of cause.evidence || []) {
      const evidence = node('div', 'evidence');
      evidence.append(node('time', '', item.timestamp), document.createTextNode(item.message));
      card.append(evidence);
    }
    card.append(node('p', 'recommendation', cause.recommendation));
    content.append(card);
  }
  content.append(node('p', 'section-label', 'SEVERITY RULE'));
  content.append(node('div', 'severity-note', incident.severity_basis || 'Severity is a rule-based heuristic, not a production assessment.'));
  content.append(node('p', 'section-label', 'ERROR LOG EVIDENCE'));
  for (const error of incident.errors) {
    const row = node('div', 'log-row');
    row.append(node('time', '', error.timestamp), node('span', 'level', error.level), node('p', '', error.message));
    content.append(row);
  }
  const agent = activeInvestigation;
  if (agent && agent.service === incident.service) renderInvestigation(content, agent);
  else {
    const start = node('button', 'button outline-button', 'Ask the local investigation agent');
    start.type = 'button';
    start.addEventListener('click', () => beginInvestigation(incident));
    content.append(node('p', 'section-label', 'HUMAN-REVIEWED INVESTIGATION'));
    content.append(start);
    content.append(node('p', 'decision-note', 'Deterministic local fallback. Suggested steps await your review; no actions are executed.'));
  }
  detailPanel.append(content);
}

function renderInvestigation(content, record) {
  content.append(node('p', 'section-label', 'INVESTIGATION PLAN'));
  const card = node('section', 'agent-card');
  const head = node('div', 'agent-header');
  head.append(node('strong', '', 'Local agent proposal'), node('span', 'agent-chip', record.proposal.provider));
  card.append(head);
  card.append(node('p', 'recommendation', record.proposal.summary));
  card.append(node('p', 'section-label', 'OBSERVED FACTS'));
  const facts = node('ul');
  for (const fact of record.proposal.facts) facts.append(node('li', '', fact));
  card.append(facts);
  if (record.messages?.length) {
    card.append(node('p', 'section-label', 'HUMAN CONTEXT'));
    const messages = node('ul');
    for (const message of record.messages) messages.append(node('li', '', message.content));
    card.append(messages);
  }
  card.append(node('p', 'section-label', 'PROPOSED CHECKS'));
  const steps = node('ul');
  for (const step of record.proposal.proposed_steps) steps.append(node('li', '', step));
  card.append(steps);
  const context = document.createElement('div');
  context.className = 'context-row';
  const input = document.createElement('input');
  input.placeholder = 'Add human context or a follow-up…';
  input.maxLength = 4000;
  const send = node('button', 'button outline-button', 'Send context');
  send.type = 'button';
  send.addEventListener('click', () => sendContext(record, input));
  context.append(input, send);
  card.append(context);
  const actions = node('div', 'agent-actions');
  const approve = node('button', 'button primary', 'Approve plan');
  approve.addEventListener('click', () => submitDecision(record, 'approved'));
  const reject = node('button', 'button danger-button', 'Reject');
  reject.addEventListener('click', () => submitDecision(record, 'rejected'));
  const modify = node('button', 'button outline-button', 'Edit steps');
  modify.addEventListener('click', () => editPlan(record));
  actions.append(approve, reject, modify);
  card.append(actions);
  card.append(node('p', 'decision-note', `Human decision: ${record.decision.status}${record.decision.note ? ` · ${record.decision.note}` : ''}`));
  card.append(node('p', 'decision-note', `Switch handoff: ${record.switch_handoff.adapter}; live integration: ${record.switch_handoff.live_switch_integration ? 'yes' : 'no'}.`));
  content.append(card);
}

async function beginInvestigation(incident) {
  try {
    activeInvestigation = await api('/investigations', { method: 'POST', body: JSON.stringify({ filename: fileSelect.value, service: incident.service }) });
    renderDetail(incident);
  } catch (error) { showNotice(error.message); }
}

async function sendContext(record, input) {
  if (!input.value.trim()) { input.focus(); return; }
  try {
    activeInvestigation = await api(`/investigations/${record.id}/messages`, { method: 'POST', body: JSON.stringify({ message: input.value }) });
    renderDetail(activeReport.incidents.find(item => item.service === record.service));
  } catch (error) { showNotice(error.message); }
}

async function submitDecision(record, decision, modifiedSteps) {
  try {
    activeInvestigation = await api(`/investigations/${record.id}/decision`, { method: 'POST', body: JSON.stringify({ decision, note: '', modified_steps: modifiedSteps }) });
    renderDetail(activeReport.incidents.find(item => item.service === record.service));
  } catch (error) { showNotice(error.message); }
}

function editPlan(record) {
  const replacement = window.prompt('Edit the proposed checks. Enter one step per line.', record.proposal.proposed_steps.join('\n'));
  if (replacement === null) return;
  const steps = replacement.split('\n').map(step => step.trim()).filter(Boolean);
  if (!steps.length) { showNotice('Keep at least one proposed step.'); return; }
  submitDecision(record, 'modified', steps);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!fileSelect.value) return;
  showNotice('');
  analyzeButton.disabled = true;
  analyzeButton.textContent = 'Analyzing…';
  try {
    const result = await api('/analyze', { method: 'POST', body: JSON.stringify({ filename: fileSelect.value }) });
    activeReport = result.report;
    selectedService = null;
    activeInvestigation = null;
    updateMetrics(activeReport);
    renderIncidents(activeReport);
    if (activeReport.malformed_line_count) showNotice(`${activeReport.malformed_line_count} nonblank line(s) could not be parsed. Review them below.`);
    if (activeReport.malformed_lines?.length) {
      const section = node('section', 'panel detail-content');
      section.append(node('p', 'section-label', 'MALFORMED LOG ENTRIES'));
      const list = node('div', 'malformed-list');
      for (const item of activeReport.malformed_lines) list.append(node('div', '', `Line ${item.line_number}: ${item.content}`));
      section.append(list);
      detailPanel.append(section);
    }
  } catch (error) { showNotice(error.message); }
  finally { analyzeButton.disabled = false; analyzeButton.innerHTML = 'Analyze logs <span>↗</span>'; }
});

loadFiles().catch(error => showNotice(error.message));
