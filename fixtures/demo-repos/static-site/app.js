// Demo fixture: computes a tip in the browser. No network access.
const bill = document.getElementById('bill');
const pct = document.getElementById('pct');
const result = document.getElementById('result');
function update() {
  const b = Number(bill.value) || 0;
  const p = Number(pct.value) || 0;
  result.textContent = `Tip: ${(b * p / 100).toFixed(2)} · Total: ${(b * (1 + p / 100)).toFixed(2)}`;
  document.body.dataset.ready = 'true';
}
bill.addEventListener('input', update);
pct.addEventListener('input', update);
update();
