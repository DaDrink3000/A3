
document.addEventListener('DOMContentLoaded', () => {
  const ack = document.getElementById('ack');
  const submitBtn = document.getElementById('submitBtn');
  if (ack && submitBtn) {
    ack.addEventListener('change', () => { submitBtn.disabled = !ack.checked; });
  }
});
