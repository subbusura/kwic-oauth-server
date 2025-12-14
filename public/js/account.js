(() => {
  const phoneList = document.getElementById('phone-list');
  if (!phoneList) return;

  const template = document.getElementById('phone-template');

  function syncHidden(row) {
    const country = row.querySelector('.phone-code');
    const number = row.querySelector('.phone-number');
    const label = row.querySelector('.phone-label');
    const hiddenCountry = row.querySelector('input[type="hidden"][name="phone_country_code[]"]');
    const hiddenNumber = row.querySelector('input[type="hidden"][name="phone_number[]"]');
    const hiddenLabel = row.querySelector('input[type="hidden"][name="phone_label[]"]');
    if (country && hiddenCountry) hiddenCountry.value = country.value;
    if (number && hiddenNumber) hiddenNumber.value = number.value;
    if (label && hiddenLabel) hiddenLabel.value = label.value;
    const display = row.querySelector('.phone-display');
    if (display) {
      const codeText = country && country.value ? country.value : hiddenCountry?.value || '';
      const numText = number && number.value ? number.value : hiddenNumber?.value || '';
      const labelText = label && label.value ? ` (${label.value})` : hiddenLabel?.value ? ` (${hiddenLabel.value})` : '';
      display.textContent = `${codeText} ${numText}${labelText}`.trim();
    }
  }

  phoneList.addEventListener('click', (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;

    if (target.classList.contains('phone-edit')) {
      const row = target.closest('.phone-row');
      if (row) row.classList.add('editing');
      return;
    }

    if (target.classList.contains('phone-done')) {
      const row = target.closest('.phone-row');
      if (row) {
        syncHidden(row);
        row.classList.remove('editing');
      }
      return;
    }

    if (target.classList.contains('phone-remove')) {
      const row = target.closest('.phone-row');
      if (row && row.parentElement === phoneList) {
        row.remove();
      }
      return;
    }

    if (target.classList.contains('add-phone')) {
      e.preventDefault();
      if (!template) return;
      const clone = template.content.firstElementChild.cloneNode(true);
      phoneList.insertBefore(clone, target);
      clone.classList.add('editing');
      const input = clone.querySelector('.phone-number');
      if (input) input.focus();
    }
  });

  phoneList.addEventListener('change', (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const row = target.closest('.phone-row');
    if (row) syncHidden(row);
  });

  // initialize display text for existing rows
  phoneList.querySelectorAll('.phone-row').forEach((row) => syncHidden(row));

  // ensure all edits are synced before submit
  const form = document.getElementById('profileForm');
  if (form) {
    form.addEventListener('submit', () => {
      phoneList.querySelectorAll('.phone-row').forEach((row) => syncHidden(row));
    });
  }
})();
