'use strict';

let selectedUUID = null;
let selectedImageID = null;
let allImages = [];

// --- Tab navigation ---

function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.remove('hidden');
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.textContent.toLowerCase() === name) btn.classList.add('active');
  });
  if (name === 'images' && document.getElementById('image-list').children.length <= 1) loadImages();
}

// --- API helper ---

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
  el._timer = setTimeout(() => el.className = 'status hidden', 5000);
}

// --- Devices ---

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
  await Promise.all([loadEventLogState(), loadUpgradeImageList(), loadUpgradeStatus()]);
}

// --- Event log ---

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
    container.innerHTML = '<p class="muted">No baseline found.</p>';
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

// --- SSH ---

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

// --- Upgrade ---

async function loadUpgradeImageList() {
  const container = document.getElementById('upgrade-image-list');
  selectedImageID = null;
  document.getElementById('upgrade-btn').disabled = true;

  try {
    allImages = await api('GET', '/images') || [];
  } catch (e) {
    allImages = [];
  }

  if (allImages.length === 0) {
    container.innerHTML = '<p class="muted">No images available. Upload one in the Images tab.</p>';
    return;
  }

  container.innerHTML = '';
  for (const img of allImages) {
    const el = document.createElement('div');
    el.className = 'upgrade-item';
    el.dataset.id = img.id;
    el.innerHTML = `<strong>${img.name}</strong> <span class="version-badge">${img.version}</span>
      <span class="img-meta">${formatBytes(img.sizeBytes)} &bull; ${new Date(img.uploadedAt).toLocaleDateString()}</span>`;
    el.onclick = () => selectUpgradeImage(img.id);
    container.appendChild(el);
  }
}

function selectUpgradeImage(id) {
  selectedImageID = id;
  document.querySelectorAll('.upgrade-item').forEach(el => {
    el.classList.toggle('active', el.dataset.id === id);
  });
  document.getElementById('upgrade-btn').disabled = false;
}

async function triggerUpgrade() {
  if (!selectedImageID) return;
  if (!confirm('Trigger EVE OS upgrade? EVE will download and install the image on the next config poll.')) return;
  try {
    await api('POST', `/device/${selectedUUID}/upgrade`, { imageId: selectedImageID });
    showStatus('Upgrade scheduled. EVE will install the image on the next config poll.');
    await loadUpgradeStatus();
  } catch (e) {
    showStatus('Upgrade failed: ' + e.message, true);
  }
}

async function loadUpgradeStatus() {
  if (!selectedUUID) return;
  const banner = document.getElementById('upgrade-status-banner');
  try {
    const status = await api('GET', `/device/${selectedUUID}/upgrade`);
    if (status && status.active) {
      const img = allImages.find(i => i.id === status.imageId);
      const label = img ? `${img.name} ${img.version}` : status.version;
      banner.innerHTML = `<span class="state-badge state-active">Upgrade in progress</span>
        <span class="state-meta-inline">Version: <strong>${label || status.version}</strong></span>
        <button class="btn-danger btn-small" onclick="cancelUpgrade()">Cancel</button>`;
      banner.classList.remove('hidden');
      document.getElementById('upgrade-btn').disabled = true;
    } else {
      banner.classList.add('hidden');
      banner.innerHTML = '';
    }
  } catch (e) {
    banner.classList.add('hidden');
  }
}

async function cancelUpgrade() {
  if (!confirm('Cancel the pending upgrade? EVE will stop downloading on the next config poll.')) return;
  try {
    await api('DELETE', `/device/${selectedUUID}/upgrade`);
    showStatus('Upgrade cancelled.');
    await Promise.all([loadUpgradeStatus(), loadUpgradeImageList()]);
  } catch (e) {
    showStatus('Failed to cancel upgrade: ' + e.message, true);
  }
}

// --- Images ---

async function loadImages() {
  const list = document.getElementById('image-list');
  list.innerHTML = '<p class="muted">Loading...</p>';
  try {
    const images = await api('GET', '/images') || [];
    if (images.length === 0) {
      list.innerHTML = '<p class="muted">No images uploaded yet.</p>';
      return;
    }
    list.innerHTML = '';
    for (const img of images) {
      const el = document.createElement('div');
      el.className = 'image-row';
      el.innerHTML = `
        <div class="image-info">
          <strong>${img.name}</strong>
          <span class="version-badge">${img.version}</span>
          <span class="img-meta">${formatBytes(img.sizeBytes)} &bull; SHA256: ${img.sha256.slice(0,16)}... &bull; ${new Date(img.uploadedAt).toLocaleString()}</span>
        </div>
        <button class="btn-danger" onclick="deleteImage('${img.id}', this)">Delete</button>`;
      list.appendChild(el);
    }
  } catch (e) {
    list.innerHTML = `<p class="muted">Error: ${e.message}</p>`;
  }
}

async function deleteImage(id, btn) {
  if (!confirm('Delete this image?')) return;
  btn.disabled = true;
  try {
    const resp = await fetch('/admin/images/' + id, { method: 'DELETE' });
    if (!resp.ok) throw new Error(await resp.text());
    await loadImages();
  } catch (e) {
    showUploadStatus('Delete failed: ' + e.message, true);
    btn.disabled = false;
  }
}

function updateFileLabel(input) {
  document.getElementById('file-label-text').textContent =
    input.files.length ? input.files[0].name : 'Choose rootfs.img...';
}

async function uploadImage() {
  const name = document.getElementById('img-name').value.trim();
  const version = document.getElementById('img-version').value.trim();
  const fileInput = document.getElementById('img-file');

  if (!name || !version) { showUploadStatus('Name and version are required.', true); return; }
  if (!fileInput.files.length) { showUploadStatus('Select a file first.', true); return; }

  const form = new FormData();
  form.append('name', name);
  form.append('version', version);
  form.append('file', fileInput.files[0]);

  const progress = document.getElementById('upload-progress');
  const fill = document.getElementById('progress-fill');
  const progressText = document.getElementById('progress-text');
  progress.classList.remove('hidden');
  fill.style.width = '0%';

  try {
    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/admin/images');
      xhr.upload.onprogress = e => {
        if (e.lengthComputable) {
          const pct = Math.round(e.loaded / e.total * 100);
          fill.style.width = pct + '%';
          progressText.textContent = pct + '%';
        }
      };
      xhr.onload = () => xhr.status === 201 ? resolve() : reject(new Error(xhr.responseText || xhr.statusText));
      xhr.onerror = () => reject(new Error('Network error'));
      xhr.send(form);
    });

    showUploadStatus('Image uploaded successfully.');
    document.getElementById('img-name').value = '';
    document.getElementById('img-version').value = '';
    fileInput.value = '';
    document.getElementById('file-label-text').textContent = 'Choose rootfs.img...';
    await loadImages();
  } catch (e) {
    showUploadStatus('Upload failed: ' + e.message, true);
  } finally {
    progress.classList.add('hidden');
  }
}

function showUploadStatus(msg, isError) {
  const el = document.getElementById('upload-status');
  el.textContent = msg;
  el.className = 'status ' + (isError ? 'error' : 'ok');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.className = 'status hidden', 5000);
}

function formatBytes(bytes) {
  if (bytes >= 1 << 30) return (bytes / (1 << 30)).toFixed(1) + ' GB';
  if (bytes >= 1 << 20) return (bytes / (1 << 20)).toFixed(1) + ' MB';
  return (bytes / (1 << 10)).toFixed(1) + ' KB';
}

// Auto-refresh: poll devices every 10s, event log every 15s, images every 30s.
loadDevices();
setInterval(loadDevices, 10000);
setInterval(() => { if (selectedUUID) loadEventLogState(); }, 15000);
setInterval(() => { if (selectedUUID) loadUpgradeStatus(); }, 10000);
setInterval(() => {
  loadImages();
  if (selectedUUID) loadUpgradeImageList();
}, 30000);
