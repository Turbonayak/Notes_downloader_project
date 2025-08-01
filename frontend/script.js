// app.js
const BACKEND_URL = "http://localhost:3000";
const CLIENT_ID = "7587e8c3-4899-4940-aaa8-3292e53fc544";
const DISCOVERY_URL = "https://jp-osa.appid.cloud.ibm.com/oauth/v4/ba920c0d-1f13-4528-8aa6-dda3b2b043c9/.well-known/openid-configuration ";

let appID;
let token = localStorage.getItem('token');

async function initAppID() {
  appID = new AppID();
  await appID.init({ clientId: CLIENT_ID, discoveryEndpoint: DISCOVERY_URL });
}

async function login() {
  try {
    const tokens = await appID.signin();
    token = tokens.idToken;
    localStorage.setItem('token', token);
    await checkAdminAccess();
  } catch (err) {
    alert('Login failed');
    console.error(err);
  }
}

async function checkAdminAccess() {
  await initAppID();

  if (!token) {
    document.getElementById('loginBtn').classList.remove('hidden');
    document.getElementById('adminSection').classList.add('hidden');
    return;
  }

  const userInfo = parseJwt(token);
  if (userInfo.email && userInfo.email !== '' && userInfo.email) {
    // Show admin section
    document.getElementById('loginBtn').classList.add('hidden');
    document.getElementById('adminSection').classList.remove('hidden');
    await loadNotes();
  } else {
    alert('Access denied: Admins only');
    localStorage.removeItem('token');
  }
}

async function loadNotes() {
  try {
    const res = await fetch(`${BACKEND_URL}/notes`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Unauthorized or error fetching notes');
    const notes = await res.json();
    const list = document.getElementById('notesList');
    list.innerHTML = notes.map(n => `<li><a href="${BACKEND_URL}/download/${n}" target="_blank">${n}</a></li>`).join('');
  } catch (err) {
    alert('Failed to load notes');
    console.error(err);
  }
}

document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('fileUpload').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(`${BACKEND_URL}/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: formData
    });
    if (!res.ok) throw new Error('Upload failed');
    alert('File uploaded successfully');
    await loadNotes();
  } catch (err) {
    alert('Upload failed');
    console.error(err);
  }
});

// Utility function to parse JWT token payload
function parseJwt(token) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(atob(base64).split('').map(c =>
    '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
  ).join(''));
  return JSON.parse(jsonPayload);
}

// On page load, check admin access
window.onload = checkAdminAccess;
