// Vercel serverless entry point.
// Vercel treats any (req, res) => void export in /api as a function handler,
// and an Express app instance is itself callable as (req, res) — so we can
// reuse the exact same app/routes defined in server/src/index.ts unchanged.
import app from '../server/src/index';

export default app;
