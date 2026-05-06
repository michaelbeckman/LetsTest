'use strict';

/**
 * Minimal HTTP helper that starts the Express app on an ephemeral port,
 * makes a single GET request, and returns { status, body }.
 * The server is closed automatically after the request.
 */

const http = require('node:http');

const app = require('../../server');

function request(path) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      const url = `http://127.0.0.1:${port}${path}`;

      http.get(url, (res) => {
        let raw = '';
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => {
          server.close(() => {
            try {
              resolve({ status: res.statusCode, body: JSON.parse(raw) });
            } catch {
              resolve({ status: res.statusCode, body: {} });
            }
          });
        });
      }).on('error', (err) => {
        server.close(() => reject(err));
      });
    });
  });
}

module.exports = request;
