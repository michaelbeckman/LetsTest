'use strict';

const form        = document.getElementById('search-form');
const zipInput    = document.getElementById('zip');
const resultsSection = document.getElementById('results-section');
const resultsHeading = document.getElementById('results-heading');
const resultsList    = document.getElementById('results-list');
const errorSection   = document.getElementById('error-section');
const errorMessage   = document.getElementById('error-message');
const loader         = document.getElementById('loader');

function showLoader() {
  loader.hidden = false;
  resultsSection.hidden = true;
  errorSection.hidden = true;
}

function hideLoader() {
  loader.hidden = true;
}

function showError(msg) {
  hideLoader();
  errorMessage.textContent = msg;
  errorSection.hidden = false;
  resultsSection.hidden = true;
}

function renderStars(rating) {
  const full  = Math.floor(rating);
  const half  = rating % 1 >= 0.5 ? 1 : 0;
  const empty = 5 - full - half;
  return '★'.repeat(full) + (half ? '½' : '') + '☆'.repeat(empty);
}

function renderResults(businesses, zip) {
  hideLoader();
  errorSection.hidden = true;

  if (!businesses.length) {
    showError(`No barbershops found near ${zip}. Try a different zip code.`);
    return;
  }

  resultsHeading.textContent = `Barbershops near ${zip} — sorted by rating`;
  resultsList.innerHTML = '';

  businesses.forEach((shop) => {
    const li = document.createElement('li');
    li.className = 'card';

    const imgEl = shop.image_url
      ? `<img class="card-img" src="${escapeHtml(shop.image_url)}" alt="${escapeHtml(shop.name)}" loading="lazy" />`
      : `<div class="card-img-placeholder">✂️</div>`;

    const closedBadge = shop.is_closed
      ? `<span class="badge-closed">CLOSED</span>`
      : '';

    li.innerHTML = `
      ${imgEl}
      <div class="card-body">
        <a class="card-name" href="${escapeHtml(shop.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(shop.name)}</a>
        <div class="card-rating">
          <span class="stars" title="${shop.rating} stars">${renderStars(shop.rating)}</span>
          <strong>${shop.rating}</strong>
          <span class="review-count">(${shop.review_count} reviews)</span>
          ${closedBadge}
        </div>
        ${shop.address ? `<p class="card-address">📍 ${escapeHtml(shop.address)}</p>` : ''}
        ${shop.phone   ? `<p class="card-phone">📞 ${escapeHtml(shop.phone)}</p>`   : ''}
      </div>`;

    resultsList.appendChild(li);
  });

  resultsSection.hidden = false;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const zip = zipInput.value.trim();

  if (!/^\d{5}$/.test(zip)) {
    showError('Please enter a valid 5-digit US zip code.');
    return;
  }

  showLoader();

  try {
    const response = await fetch(`/api/barbershops?zip=${encodeURIComponent(zip)}`);
    const data = await response.json();

    if (!response.ok) {
      showError(data.error || 'Something went wrong. Please try again.');
      return;
    }

    renderResults(data.businesses, zip);
  } catch {
    showError('Network error. Please check your connection and try again.');
  }
});

// Allow only numeric input in zip field
zipInput.addEventListener('input', () => {
  zipInput.value = zipInput.value.replace(/\D/g, '').slice(0, 5);
});
