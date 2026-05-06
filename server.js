require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const YELP_API_KEY = process.env.YELP_API_KEY;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/barbershops', async (req, res) => {
  const { zip } = req.query;

  if (!zip || !/^\d{5}$/.test(zip)) {
    return res.status(400).json({ error: 'Please provide a valid 5-digit US zip code.' });
  }

  if (!YELP_API_KEY) {
    return res.status(500).json({ error: 'Yelp API key is not configured on the server.' });
  }

  try {
    const response = await axios.get('https://api.yelp.com/v3/businesses/search', {
      headers: {
        Authorization: `Bearer ${YELP_API_KEY}`,
      },
      params: {
        term: 'barbershop',
        location: zip,
        sort_by: 'rating',
        limit: 20,
      },
    });

    const businesses = response.data.businesses.map((b) => ({
      id: b.id,
      name: b.name,
      rating: b.rating,
      review_count: b.review_count,
      phone: b.display_phone,
      address: b.location.display_address.join(', '),
      image_url: b.image_url,
      url: b.url,
      is_closed: b.is_closed,
    }));

    // Yelp's sort_by=rating is not always perfectly sorted; ensure descending order.
    businesses.sort((a, b) => b.rating - a.rating);

    res.json({ businesses });
  } catch (err) {
    if (err.response && err.response.status === 400) {
      return res.status(400).json({ error: 'Location not found. Please check the zip code and try again.' });
    }
    console.error('Yelp API error:', err.message);
    res.status(502).json({ error: 'Unable to reach the Yelp API. Please try again later.' });
  }
});

// Only start listening when run directly (not when required by tests)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Barbershop Finder running at http://localhost:${PORT}`);
  });
}

module.exports = app;
