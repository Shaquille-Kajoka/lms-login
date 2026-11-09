const $ = (id) => document.getElementById(id);
const loginForm = $('loginForm'), forgotForm = $('forgotForm');

// Show / hide password
$('togglePw').addEventListener('click', (e) => {
  const pw = $('password'), show = pw.type === 'password';
  pw.type = show ? 'text' : 'password';
  e.target.textContent = show ? 'Hide' : 'Show';
  e.target.setAttribute('aria-pressed', show);
  e.target.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
});

// Switch between sign-in and forgot-password
const swap = (toForgot) => { loginForm.hidden = toForgot; forgotForm.hidden = !toForgot; };
$('showForgot').addEventListener('click', (e) => { e.preventDefault(); swap(true); });
$('showLogin').addEventListener('click', (e) => { e.preventDefault(); swap(false); });

function say(el, text, ok) { el.textContent = text; el.classList.toggle('ok', !!ok); el.hidden = false; }
async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin', body: JSON.stringify(body) });
  return { res, data: await res.json().catch(() => ({})) };
}
const busy = (btn, on) => { btn.disabled = on; btn.classList.toggle('loading', on); };

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('username').value.trim(), password = $('password').value, btn = $('loginBtn');
  if (!username || !password) return say($('loginMsg'), 'Please enter your username and password.');
  $('loginMsg').hidden = true; busy(btn, true);
  try {
    const { res, data } = await post('/api/auth/login', { username, password, remember: $('remember').checked });
    if (res.ok) return (window.location.href = data.redirect || '/dashboard');
    say($('loginMsg'), data.error || 'Sign in failed. Please try again.');
  } catch { say($('loginMsg'), 'Cannot reach the server. Check your connection.'); }
  busy(btn, false);
});

forgotForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('femail').value.trim(), btn = $('forgotBtn');
  if (!/^\S+@\S+\.\S+$/.test(email)) return say($('forgotMsg'), 'Please enter a valid email address.');
  busy(btn, true);
  try {
    const { data } = await post('/api/auth/forgot', { email });
    say($('forgotMsg'), data.message || 'If that email exists, a reset link has been sent.', true);
  } catch { say($('forgotMsg'), 'Cannot reach the server. Try again.'); }
  busy(btn, false);
});
