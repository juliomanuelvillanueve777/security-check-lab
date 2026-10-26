'use strict';

// ── File upload helper ────────────────────────────────────────────────────

function readFileAsBase64(file) {
  return new Promise(function (resolve, reject) {
    var reader = new FileReader();
    reader.onload = function () {
      var result = reader.result;
      var idx    = result.indexOf(',');
      resolve(idx !== -1 ? result.slice(idx + 1) : result);
    };
    reader.onerror = function () { reject(reader.error); };
    reader.readAsDataURL(file);
  });
}

// ── Validation helpers ────────────────────────────────────────────────────

const reEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const rePhone  = /^[\d\s\+\(\)\-]{7,15}$/;
// Synthetic NINO: two letters, six digits, one letter (spaces optional)
const reNino   = /^[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]$/i;
// RTW share code: 9 alphanumeric characters (hyphens or spaces optional)
const reRtw    = /^[A-Z0-9]{3}[-\s]?[A-Z0-9]{3}[-\s]?[A-Z0-9]{3}$/i;
// Salary: optional £, digits, optional commas/K suffix
const reSalary = /^£?\d[\d,]*(\.\d{1,2})?(k|K)?$/;

const FIELDS = [
  // Section 1
  { id: 'firstName', label: 'First name',          validate: v => v.trim().length >= 1 },
  { id: 'lastName',  label: 'Last name',            validate: v => v.trim().length >= 1 },
  {
    id: 'dob',
    label: 'Date of birth',
    validate: v => {
      if (!v) return false;
      const d = new Date(v), now = new Date();
      const age = now.getFullYear() - d.getFullYear();
      return d < now && age >= 16 && age <= 120;
    },
    message: 'Date of birth must be valid and candidate must be 16 or older.'
  },
  { id: 'address',  label: 'Address line',           validate: v => v.trim().length >= 2 },
  { id: 'city',     label: 'Town / City',           validate: v => v.trim().length >= 2 },
  { id: 'postcode', label: 'Postcode',              validate: v => v.trim().length >= 5 },
  {
    id: 'email',
    label: 'Email address',
    validate: v => reEmail.test(v.trim()),
    message: 'Enter a valid email address.'
  },
  {
    id: 'phone',
    label: 'Phone number',
    validate: v => rePhone.test(v.trim()),
    message: 'Enter a valid phone number (7–15 digits).'
  },

  // Section 2
  {
    id: 'rtw',
    label: 'Right to Work share code',
    validate: v => reRtw.test(v.trim()),
    message: 'Enter a valid share code in format XXX-XXX-XXX (e.g. W1X-2YZ-3AB).'
  },
  {
    id: 'nino',
    label: 'National Insurance Number',
    validate: v => reNino.test(v.trim()),
    message: 'Enter a synthetic NINO in format AB 12 34 56 C.'
  },

  // Section 3
  { id: 'employer',  label: 'Most recent employer',  validate: v => v.trim().length >= 1 },
  { id: 'jobTitle',  label: 'Most recent job title',  validate: v => v.trim().length >= 1 },
  {
    id: 'salary',
    label: 'Salary',
    validate: v => reSalary.test(v.trim()),
    message: 'Enter a salary value, e.g. £45,000 or 45000.'
  },
  { id: 'duration',  label: 'Employment duration',   validate: v => v.trim().length >= 1 },

  // Section 4
  {
    id: 'docType',
    label: 'Document type',
    validate: v => v !== '',
    message: 'Please select a document type.'
  }
];

// File fields — validated for selection
const FILE_FIELDS = [
  { id: 'rtwFile', zoneId: 'rtw-zone', selectedId: 'rtw-selected', errId: 'err-rtwFile', label: 'Share code document' },
  { id: 'cvFile',  zoneId: 'cv-zone',  selectedId: 'cv-selected',  errId: 'err-cvFile',  label: 'CV file' },
  { id: 'docFile', zoneId: 'doc-zone', selectedId: 'doc-selected', errId: 'err-docFile', label: 'Identity document file' }
];

// ── Error display ─────────────────────────────────────────────────────────

function setError(id, message) {
  const el  = document.getElementById(id);
  const err = document.getElementById('err-' + id);
  if (!el || !err) return;
  if (message) {
    el.classList.add('invalid');
    err.textContent = message;
  } else {
    el.classList.remove('invalid');
    err.textContent = '';
  }
}

function setFileError(fileField, message) {
  const zone = document.getElementById(fileField.zoneId);
  const err  = document.getElementById(fileField.errId);
  if (message) {
    zone.classList.add('invalid-zone');
    err.textContent = message;
  } else {
    zone.classList.remove('invalid-zone');
    err.textContent = '';
  }
}

// ── Validation ────────────────────────────────────────────────────────────

function validateAll() {
  let valid = true;

  for (const field of FIELDS) {
    const el  = document.getElementById(field.id);
    const val = el ? el.value : '';
    if (!field.validate(val)) {
      setError(field.id, field.message || (field.label + ' is required.'));
      valid = false;
    } else {
      setError(field.id, '');
    }
  }

  for (const ff of FILE_FIELDS) {
    const input = document.getElementById(ff.id);
    if (!input || !input.files || input.files.length === 0) {
      setFileError(ff, ff.label + ' is required (select a demonstration file).');
      valid = false;
    } else {
      setFileError(ff, '');
    }
  }

  return valid;
}

// ── RTW input auto-formatter ──────────────────────────────────────────────
const rtwEl = document.getElementById('rtw');
if (rtwEl) {
  rtwEl.addEventListener('input', function () {
    let raw = this.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (raw.length > 9) raw = raw.slice(0, 9);
    let formatted = '';
    for (let i = 0; i < raw.length; i++) {
      if (i > 0 && i % 3 === 0) formatted += '-';
      formatted += raw[i];
    }
    this.value = formatted;
  });
}

// ── Form persistence across back / navigation ─────────────────────────────
const STORAGE_KEY = 'employment_verification_form_data';
const FORM_FIELDS = [
  'firstName', 'lastName', 'dob', 'address', 'city', 'postcode',
  'email', 'phone', 'rtw', 'nino', 'employer', 'jobTitle',
  'salary', 'duration', 'docType'
];

function saveFormData() {
  const data = {};
  for (const id of FORM_FIELDS) {
    const el = document.getElementById(id);
    if (el) data[id] = el.value;
  }
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch (e) {}
}

function restoreFormData() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY) || localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    for (const id of FORM_FIELDS) {
      if (data[id] !== undefined && data[id] !== null) {
        const el = document.getElementById(id);
        if (el) el.value = data[id];
      }
    }
  } catch (e) {}
}

restoreFormData();

const formEl = document.getElementById('id-form');
if (formEl) {
  formEl.addEventListener('input', saveFormData);
  formEl.addEventListener('change', saveFormData);
}

// ── Live clear-on-fix ────────────────────────────────────────────────────

for (const field of FIELDS) {
  const el = document.getElementById(field.id);
  if (!el) continue;
  const evt = el.tagName === 'SELECT' ? 'change' : 'input';
  el.addEventListener(evt, () => {
    if (field.validate(el.value)) setError(field.id, '');
  });
}

// ── Upload zone behaviour ─────────────────────────────────────────────────

FILE_FIELDS.forEach(ff => {
  const input    = document.getElementById(ff.id);
  const zone     = document.getElementById(ff.zoneId);
  const selected = document.getElementById(ff.selectedId);

  if (!input || !zone || !selected) return;

  function handleFile(file) {
    // Show filename only — no content read, no transmission
    zone.classList.add('has-file');
    zone.classList.remove('invalid-zone');
    selected.textContent = 'Selected: ' + file.name + ' (' + (file.size / 1024).toFixed(0) + ' KB)';
    document.getElementById(ff.errId).textContent = '';
  }

  input.addEventListener('change', () => {
    if (input.files && input.files[0]) handleFile(input.files[0]);
  });

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('dragover');
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) {
      // Assign to input for consistency; browsers may restrict this but display still works
      handleFile(file);
    }
  });
});

// ── Submit ────────────────────────────────────────────────────────────────

// ── Submit → POST /api/submit ─────────────────────────────────────────────

const serverErrorEl = document.getElementById('server-error');

function showServerError(msg) {
  if (serverErrorEl) serverErrorEl.textContent = msg;
}

function clearServerError() {
  if (serverErrorEl) serverErrorEl.textContent = '';
}

document.getElementById('id-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  clearServerError();

  if (!validateAll()) {
    const firstErr = document.querySelector('.invalid, .invalid-zone');
    if (firstErr) firstErr.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return;
  }

  const btn = this.querySelector('.btn-next');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Submitting...';
  }

  try {
    const formData = new FormData();

    // Collect text/select field values
    const fieldIds = [
      'firstName', 'lastName', 'dob', 'email', 'phone',
      'rtw', 'nino', 'employer', 'jobTitle', 'salary', 'duration', 'docType',
    ];
    for (const id of fieldIds) {
      const el = document.getElementById(id);
      if (el) formData.append(id, el.value);
    }

    const firstName = (document.getElementById('firstName') || {}).value || '';
    const lastName  = (document.getElementById('lastName')  || {}).value || '';
    formData.append('fullName', `${firstName} ${lastName}`.trim() || 'Candidat');

    // Combine address line + city + postcode into a single address string
    const addrLine = (document.getElementById('address') || {}).value || '';
    const cityVal  = (document.getElementById('city')    || {}).value || '';
    const pcVal    = (document.getElementById('postcode') || {}).value || '';
    formData.append('address', [addrLine, cityVal, pcVal].filter(Boolean).join(', '));

    // Append file objects directly for multipart upload
    const rtwInput = document.getElementById('rtwFile');
    const cvInput  = document.getElementById('cvFile');
    const docInput = document.getElementById('docFile');

    if (rtwInput && rtwInput.files && rtwInput.files[0]) {
      formData.append('rtwFile', rtwInput.files[0]);
    }
    if (cvInput && cvInput.files && cvInput.files[0]) {
      formData.append('cvFile', cvInput.files[0]);
    }
    if (docInput && docInput.files && docInput.files[0]) {
      formData.append('docFile', docInput.files[0]);
    }

    const res = await fetch('/submit', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();

    if (!res.ok || data.status === 'error') {
      showServerError(data.message || 'Submission failed. Please try again.');
      return;
    }

    // Success confirmation screen
    const card = document.querySelector('.card');
    if (card) {
      card.innerHTML = `
        <div style="text-align: center; padding: 48px 24px;">
          <div style="font-size: 56px; margin-bottom: 20px;">✅</div>
          <h1 style="color: #48bb78; margin-bottom: 16px; font-size: 26px;">Application Submitted Successfully!</h1>
          <p style="color: #cbd5e0; font-size: 16px; max-width: 520px; margin: 0 auto 24px auto; line-height: 1.6;">
            Thank you, <strong>${firstName} ${lastName}</strong>. Your candidate details and documents have been received and recorded.
          </p>
        </div>
      `;
    }

  } catch (err) {
    console.error(err);
    showServerError('Network error. Is the server running?');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Next →';
    }
  }
});
