const status = document.getElementById('status');
const code = new URL(window.location.href).searchParams.get('code');

if (!code) {
  if (status) status.textContent = 'This pairing link is invalid.';
} else {
  chrome.runtime.sendMessage({ type: 'marcellus-pair', code }, (result) => {
    if (!status) return;
    if (chrome.runtime.lastError || !result?.success) {
      status.textContent = result?.detail || 'Pairing failed. Start pairing again from Marcellus.';
      return;
    }
    status.textContent = 'Browser companion paired. Keep a signed-in ChatGPT, Claude, or Gemini tab open, then return to Marcellus.';
  });
}
