'use strict';

let selectedUUID = null;

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const resp = await fetch('/admin' + path, opts);
  if (!resp.ok) {
    const msg = await resp.text();
    throw new Error(msg || resp.statusText);
  }
  const ct = resp.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) return resp.json();
  const text = await resp.text();
  return text || null;
}

function showStatus(msg, isError) {
  const el = document.getElementById('status-msg');
  el.textContent = msg;
  el.className = 'status ' + (isError ? 'error' : 'ok');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.className = 'status hidden', 4000);
}

async function loadDevices() {
  const list = document.getElementById('device-list');
  list.innerHTML = '<p class="muted">Loading...</p>';
  try {
    const raw = await api('GET', '/device');
    const uuids = (raw || '').split('\n').map(s => s.trim()).filter(Boolean);
    if (uuids.length === 0) {
      list.innerHTML = '<p class="muted" style="padding:10px 14px">No devices registered.</p>';
      return;
    }
    list.innerHTML = '';
    for (const uuid of uuids) {
      const el = document.createElement('div');
      el.className = 'device-item' + (uuid === selectedUUID ? ' active' : '');
      el.textContent = uuid;
      el.onclick = () => selectDevice(uuid);
      list.appendChild(el);
    }
  } catch (e) {
    list.innerHTML = `<p class="muted" style="padding:10px 14px">Error: ${e.message}</p>`;
  }
}

async function selectDevice(uuid) {
  selectedUUID = uuid;
  document.getElementById('detail-uuid').textContent = uuid;
  document.getElementById('device-detail').classList.remove('hidden');
  document.querySelectorAll('.device-item').forEach(el => {
    el.classList.toggle('active', el.textContent === uuid);
  });
  await loadEventLogState();
}

async function loadEventLogState() {
  const container = document.getElementById('eventlog-state');
  container.innerHTML = '<p class="muted">Loading...</p>';
  try {
    const state = await api('GET', `/device/${selectedUUID}/eventlog`);
    const badgeClass = state.state === 'active' ? 'state-active'
                     : state.state === 'inactive' ? 'state-inactive'
                     : 'state-unknown';
    container.innerHTML = `
      <span class="state-badge ${badgeClass}">${state.state}</span>
      <div class="state-meta">
        <span><strong>Baseline:</strong> ${state.baselineFile}</span>
        <span><strong>Hash:</strong> ${state.logHash}</span>
        <span><strong>Created:</strong> ${new Date(state.createdAt).toLocaleString()}</span>
      </div>`;
    document.getElementById('activate-btn').disabled = state.state === 'active';
  } catch (e) {
    container.innerHTML = `<p class="muted">No baseline found.</p>`;
    document.getElementById('activate-btn').disabled = true;
  }
}

async function activateEventLog() {
  try {
    await api('PUT', `/device/${selectedUUID}/eventlog/activate`);
    showStatus('Event log baseline activated.');
    await loadEventLogState();
  } catch (e) {
    showStatus('Failed to activate: ' + e.message, true);
  }
}

async function setSSHKey() {
  const key = document.getElementById('ssh-key-input').value.trim();
  if (!key) { showStatus('SSH key cannot be empty.', true); return; }
  try {
    await api('PUT', `/device/${selectedUUID}/ssh`, { publicKey: key });
    showStatus('SSH key set. EVE will pick it up on next config poll.');
    document.getElementById('ssh-key-input').value = '';
  } catch (e) {
    showStatus('Failed to set SSH key: ' + e.message, true);
  }
}

loadDevices();
