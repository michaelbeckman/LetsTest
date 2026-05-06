'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the /api/barbershops endpoint.
 * Uses the built-in Node.js test runner (node:test) — no extra deps needed.
 *
 * Because the real Yelp API requires a live key, these tests validate:
 *   - Input validation (missing zip, non-numeric, wrong length)
 *   - Server response shape when the API key is absent
 */

const request = require('../tests/helpers/request');

describe('GET /api/barbershops', () => {
  test('returns 400 when zip query param is missing', async () => {
    const { status, body } = await request('/api/barbershops');
    assert.equal(status, 400);
    assert.ok(body.error, 'should have an error message');
  });

  test('returns 400 when zip is not 5 digits', async () => {
    const { status, body } = await request('/api/barbershops?zip=123');
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  test('returns 400 when zip contains letters', async () => {
    const { status, body } = await request('/api/barbershops?zip=abcde');
    assert.equal(status, 400);
    assert.ok(body.error);
  });

  test('returns 500 when YELP_API_KEY is not set', async () => {
    // The test server is started without a YELP_API_KEY so this should fire.
    const { status, body } = await request('/api/barbershops?zip=90210');
    assert.equal(status, 500);
    assert.ok(body.error);
  });
});
