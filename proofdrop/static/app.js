const form = document.querySelector('#uploadForm');
const fileInput = document.querySelector('#fileInput');
const dropzone = document.querySelector('#dropzone');
const fileName = document.querySelector('#fileName');
const fileSize = document.querySelector('#fileSize');
const button = document.querySelector('#sendButton');
const pauseButton = document.querySelector('#pauseButton');
const message = document.querySelector('#formMessage');
const rows = document.querySelector('#traceRows');

let currentJobId = null;
let currentStatus = 'idle';
let cursor = 0;
let pollTimer = null;

function formatBytes(value) {
  if (value === null || value === undefined) return '-';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
}

function setFile(file) {
  if (!file) return;
  fileName.textContent = file.name;
  fileSize.textContent = `${formatBytes(file.size)} ready to send`;
}

fileInput.addEventListener('change', () => setFile(fileInput.files[0]));
dropzone.addEventListener('dragover', event => {
  event.preventDefault();
  dropzone.classList.add('dragging');
});
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragging'));
dropzone.addEventListener('drop', event => {
  event.preventDefault();
  dropzone.classList.remove('dragging');
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const transfer = new DataTransfer();
  transfer.items.add(file);
  fileInput.files = transfer.files;
  setFile(file);
});

function clearTrace() {
  rows.replaceChildren();
  cursor = 0;
  document.querySelector('#uploadId').textContent = 'Upload ID appears here';
  document.querySelector('#ackValue').textContent = '0 / 0';
  document.querySelector('#ackHint').textContent = 'Application progress';
  document.querySelector('#rttValue').textContent = '-';
  document.querySelector('#throughputValue').textContent = '-';
  document.querySelector('#progressFill').style.width = '0%';
  document.querySelector('#percentValue').textContent = '0%';
  document.querySelector('#progressChunks').textContent = '0 chunks acknowledged';
  document.querySelector('#detailTitle').textContent = 'Select a trace row';
  document.querySelector('#detailIntro').textContent = 'Inspect direction, chunk sequence, application size, and framed bytes. Payload content stays encrypted.';
  document.querySelector('#detailLayer').textContent = '-';
  document.querySelector('#detailDirection').textContent = '-';
  document.querySelector('#detailSequence').textContent = '-';
  document.querySelector('#detailHash').textContent = '-';
  document.querySelector('#detailChunkBytes').textContent = '-';
  document.querySelector('#detailAppBytes').textContent = '-';
  document.querySelector('#detailFrameBytes').textContent = '-';
  document.querySelector('#detailOverhead').textContent = '-';
  document.querySelector('#detailEncrypted').textContent = '-';
}

function setControls() {
  const busy = ['sending to dashboard', 'queued', 'connecting', 'transferring', 'pausing', 'verifying file'].includes(currentStatus);
  const paused = currentStatus === 'paused';
  const settingsLocked = busy || paused;
  fileInput.disabled = busy;
  document.querySelectorAll('#chunkSize, #windowSize, #demoRtt').forEach(control => {
    control.disabled = settingsLocked;
  });
  dropzone.classList.toggle('locked', busy);

  if (currentStatus === 'paused') {
    button.disabled = false;
    button.innerHTML = 'Start / resume selected file <span aria-hidden="true">-&gt;</span>';
  } else if (currentStatus === 'complete') {
    button.disabled = false;
    button.innerHTML = 'Start another transfer <span aria-hidden="true">-&gt;</span>';
  } else if (currentStatus === 'failed') {
    button.disabled = false;
    button.innerHTML = 'Try this upload again <span aria-hidden="true">-&gt;</span>';
  } else if (busy) {
    button.disabled = true;
    button.textContent = currentStatus === 'pausing' ? 'Pausing at chunk boundary...' : 'Transfer running...';
  } else {
    button.disabled = false;
    button.innerHTML = 'Start TCP upload <span aria-hidden="true">-&gt;</span>';
  }

  const canPause = ['connecting', 'transferring'].includes(currentStatus);
  pauseButton.hidden = !canPause;
  pauseButton.disabled = currentStatus === 'pausing';
  pauseButton.textContent = currentStatus === 'pausing' ? 'Interrupting...' : 'Interrupt transfer';
}

function selectEvent(event, row) {
  document.querySelectorAll('tr.trace-row.selected').forEach(node => node.classList.remove('selected'));
  row.classList.add('selected');
  document.querySelector('#detailTitle').textContent = event.message || 'Protocol event';
  document.querySelector('#detailIntro').textContent = `Frame ${event.id} at ${event.time}`;
  document.querySelector('#detailLayer').textContent = event.layer || '-';
  document.querySelector('#detailDirection').textContent = event.direction || '-';
  document.querySelector('#detailSequence').textContent = event.sequence === null || event.sequence === undefined ? '-' : event.sequence;
  document.querySelector('#detailHash').textContent = event.sha256_prefix || '-';
  document.querySelector('#detailChunkBytes').textContent = formatBytes(event.chunk_bytes);
  document.querySelector('#detailAppBytes').textContent = formatBytes(event.application_bytes);
  document.querySelector('#detailFrameBytes').textContent = formatBytes(event.frame_bytes);
  document.querySelector('#detailOverhead').textContent = event.frame_bytes === null || event.frame_bytes === undefined || event.application_bytes === null || event.application_bytes === undefined
    ? '-'
    : formatBytes(event.frame_bytes - event.application_bytes);
  const security = event.layer === 'Dashboard HTTP'
    ? 'HTTP to local dashboard'
    : (event.message === 'client_hello' || event.message === 'server_hello')
      ? 'Signed key exchange'
      : event.encrypted ? 'Yes - AES-GCM' : 'No';
  document.querySelector('#detailEncrypted').textContent = security;
}

function appendEvent(event) {
  const empty = rows.querySelector('.empty-row');
  if (empty) empty.remove();
  const row = document.createElement('tr');
  row.className = 'trace-row';
  const values = [
    event.id,
    event.time,
    event.layer === 'Dashboard HTTP' ? 'HTTP / WEB' : event.layer === 'Dashboard control' ? 'WEB / CONTROL' : 'APP / TCP',
    event.direction,
    event.message,
    event.sequence === null || event.sequence === undefined ? '-' : event.sequence,
    formatBytes(event.application_bytes),
    formatBytes(event.frame_bytes),
    event.encrypted ? 'AES-GCM' : 'clear',
  ];
  values.forEach((value, index) => {
    const cell = document.createElement('td');
    cell.textContent = value ?? '-';
    if (index === 2) cell.className = 'layer-tag';
    if (index === 3) cell.className = 'direction-cell';
    if (index === 4) cell.className = 'message-cell';
    if (index === 8) cell.className = event.encrypted ? 'security-on' : 'security-off';
    row.appendChild(cell);
  });
  row.addEventListener('click', () => selectEvent(event, row));
  rows.appendChild(row);
  const scroller = document.querySelector('.trace-scroll');
  if (scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80) {
    scroller.scrollTop = scroller.scrollHeight;
  }
}

function updateJob(job) {
  currentStatus = job.status;
  document.querySelector('#statusValue').textContent = job.status;
  document.querySelector('#fileValue').textContent = `${job.filename} / ${formatBytes(job.size)}`;
  document.querySelector('#progressLabel').textContent = job.status === 'complete' ? 'File accepted and verified' : job.status;
  const percent = Math.round((job.progress || 0) * 100);
  document.querySelector('#progressFill').style.width = `${percent}%`;
  document.querySelector('#percentValue').textContent = `${percent}%`;
  document.querySelector('#ackValue').textContent = `${job.completed_chunks} / ${job.total_chunks}`;
  document.querySelector('#progressChunks').textContent = `${job.completed_chunks} of ${job.total_chunks} chunks stored`;
  if (job.receipt) document.querySelector('#uploadId').textContent = `ID ${job.receipt.upload_id}`;
  if (job.summary) {
    document.querySelector('#rttValue').textContent = job.summary.mean_ack_ms === null ? '-' : `${job.summary.mean_ack_ms.toFixed(1)} ms`;
    document.querySelector('#throughputValue').textContent = `${job.summary.throughput_mib_s.toFixed(2)} MiB/s`;
    document.querySelector('#ackHint').textContent = `${job.summary.already_stored_chunks} already stored before this run`;
  }
  if (job.status === 'failed') {
    message.textContent = job.error || 'Upload failed.';
    message.classList.add('error');
  } else if (job.status === 'complete') {
    message.textContent = 'Receipt signature verified. The server accepted the file.';
    message.classList.remove('error');
  } else if (job.status === 'paused') {
    message.textContent = 'Upload paused. Start the same unchanged file to resume its stored chunks, or choose another file for a separate transfer.';
    message.classList.remove('error');
  } else if (job.status === 'pausing') {
    message.textContent = 'Finishing the current acknowledgement batch, then the transfer will stop.';
    message.classList.remove('error');
  } else if (job.status === 'connecting') {
    message.textContent = 'Connecting to the TCP server and checking which chunks it already has.';
    message.classList.remove('error');
  } else if (job.status === 'transferring') {
    message.textContent = 'Transfer is active. Pause waits for the current chunk acknowledgement batch to finish.';
    message.classList.remove('error');
  } else if (job.status === 'verifying file') {
    message.textContent = 'All chunks are stored. The server is checking the reconstructed file and preparing its receipt.';
    message.classList.remove('error');
  } else {
    message.classList.remove('error');
  }
  document.querySelector('#traceState').textContent = job.status;
  setControls();
}

async function pollJob() {
  if (!currentJobId) return;
  try {
    const response = await fetch(`/api/job?id=${encodeURIComponent(currentJobId)}&after=${cursor}`, { cache: 'no-store' });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || 'Could not read upload status');
    job.events.forEach(appendEvent);
    cursor = job.cursor;
    updateJob(job);
    if (['complete', 'failed', 'paused'].includes(job.status)) {
      clearTimeout(pollTimer);
      pollTimer = null;
      return;
    }
  } catch (error) {
    message.textContent = error.message;
    message.classList.add('error');
  }
  pollTimer = setTimeout(pollJob, 500);
}

pauseButton.addEventListener('click', async () => {
  if (!currentJobId || !['connecting', 'transferring'].includes(currentStatus)) return;
  pauseButton.disabled = true;
  currentStatus = 'pausing';
  setControls();
  message.textContent = 'Interrupting after the current chunk acknowledgement batch.';
  try {
    const response = await fetch(`/api/pause?id=${encodeURIComponent(currentJobId)}`, { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not pause this upload');
  } catch (error) {
    message.textContent = error.message;
    message.classList.add('error');
    if (pollTimer === null) pollTimer = setTimeout(pollJob, 0);
  }
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  const file = fileInput.files[0];
  if (!file) return;
  if (pollTimer) clearTimeout(pollTimer);
  currentJobId = null;
  currentStatus = 'sending to dashboard';
  clearTrace();
  document.querySelector('#statusValue').textContent = 'Sending to dashboard';
  document.querySelector('#fileValue').textContent = `${file.name} / ${formatBytes(file.size)}`;
  document.querySelector('#progressLabel').textContent = 'Browser -> dashboard -> TCP server';
  document.querySelector('#traceState').textContent = 'Starting';
  setControls();
  button.textContent = 'Sending file to dashboard...';
  message.classList.remove('error');
  message.textContent = 'The browser is sending the file to the local dashboard. The ProofDrop TCP transfer starts next.';

  const query = new URLSearchParams({
    chunk_size: document.querySelector('#chunkSize').value,
    window_size: document.querySelector('#windowSize').value,
    demo_rtt_ms: document.querySelector('#demoRtt').value,
  });
  try {
    const response = await fetch(`/api/upload?${query}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-File-Name': encodeURIComponent(file.name) },
      body: file,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not start upload');
    currentJobId = result.job_id;
    document.querySelector('#uploadId').textContent = `Job ${currentJobId}`;
    currentStatus = 'connecting';
    setControls();
    pollJob();
  } catch (error) {
    message.textContent = error.message;
    message.classList.add('error');
    currentStatus = 'failed';
    document.querySelector('#statusValue').textContent = 'Error';
    document.querySelector('#traceState').textContent = 'Error';
    setControls();
  }
});

async function checkDashboard() {
  const dot = document.querySelector('#connectionDot');
  const label = document.querySelector('#connectionText');
  try {
    const response = await fetch('/api/health', { cache: 'no-store' });
    const health = await response.json();
    if (!response.ok) throw new Error('Dashboard unavailable');
    dot.classList.add('online');
    label.textContent = `TCP target ${health.tcp_host}:${health.tcp_port}`;
  } catch {
    label.textContent = 'Dashboard connection unavailable';
  }
}

checkDashboard();
