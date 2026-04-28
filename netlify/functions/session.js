const crypto = require('crypto');

// Temporary in-memory store for valid tokens.
// Fine for a class project — resets when the function goes cold.
const validTokens = new Set();

exports.handler = async (event) => {
  const method = event.httpMethod;

  // --- GET: Issue a session cookie + CSRF token ---
  if (method === 'GET') {
    // Generate a cryptographically random token
    const csrfToken = crypto.randomBytes(32).toString('hex');

    // Save it so we can validate it later
    validTokens.add(csrfToken);

    return {
      statusCode: 200,
      headers: {
        // HttpOnly: JS cannot access this cookie
        // Secure: only sent over HTTPS
        // SameSite=Strict: only sent from your own site (extra CSRF protection)
        'Set-Cookie': `session=active; HttpOnly; Secure; SameSite=Strict; Path=/`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ csrfToken }),
    };
  }

  // --- POST: Validate the CSRF token before doing anything ---
  if (method === 'POST') {
    let body;

    try {
      body = JSON.parse(event.body);
    } catch {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid request body.' }),
      };
    }

    const { csrfToken } = body;

    // Reject if token is missing or not one we issued
    if (!csrfToken || !validTokens.has(csrfToken)) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Invalid or missing CSRF token.' }),
      };
    }

    // One-time use — delete after validation
    validTokens.delete(csrfToken);

    // Token is valid — handle your form data here
    // e.g. const { name, email } = body;

    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Form submitted successfully!' }),
    };
  }

  // Any other method (PUT, DELETE, etc.) is not allowed
  return {
    statusCode: 405,
    body: JSON.stringify({ error: 'Method not allowed.' }),
  };
};