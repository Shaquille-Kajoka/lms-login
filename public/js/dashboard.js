fetch('/api/auth/me').then(r => r.json()).then(u => { document.getElementById('hi').textContent = 'Welcome, ' + u.username; });
document.getElementById('out').addEventListener('submit', async (e) => {
  e.preventDefault(); await fetch('/api/auth/logout', { method: 'POST' }); location.href = '/login.html';
});
