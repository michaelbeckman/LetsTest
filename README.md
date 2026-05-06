# Barbershop Finder ✂️

Find top-rated barbershops near you by zip code, powered by the [Yelp Fusion API](https://docs.developer.yelp.com/docs/fusion-intro).

## Features

- Enter a 5-digit US zip code to search for nearby barbershops
- Results ordered by Yelp rating (highest first)
- Shows name, star rating, review count, address, phone number, and photo for each shop
- Indicates temporarily-closed shops

## Tech Stack

- **Backend**: Node.js + Express
- **Frontend**: Vanilla HTML / CSS / JavaScript
- **Data**: Yelp Fusion API (`/v3/businesses/search`)

## Setup

### 1. Get a Yelp API Key

Create a free app at <https://www.yelp.com/developers/v3/manage_app> and copy your **API Key**.

### 2. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env and paste your Yelp API key
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Run the App

```bash
npm start
# → Barbershop Finder running at http://localhost:3000
```

Open <http://localhost:3000> in your browser, type a zip code, and click **Search**.

## Running Tests

```bash
npm test
```

Tests use Node.js's built-in `node:test` runner — no extra test framework needed.
