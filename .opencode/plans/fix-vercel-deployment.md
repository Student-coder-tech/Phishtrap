# Fix Vercel Deployment Issue

## Problem
Build fails on Vercel. The build works locally but the deployment pipeline has issues with the 3-step copy process between Vite output and Vercel's expected output directory.

## Changes

### 1. `client/vite.config.ts` — Build directly to root `dist/`
Add `build.outDir: '../dist'` and `emptyOutDir: true` so Vite outputs directly to Vercel's `outputDirectory`, eliminating the copy step.

### 2. `vercel.json` — Simplify build command
Remove the copy step. Add proper Node.js function runtime config.

### 3. `server/package.json` — Move `esbuild` to devDependencies

### 4. Delete `scripts/copy-dist.mjs` — No longer needed

### 5. Clean up `package.json` — Remove `build:vercel` script (no longer needed)

### 6. Verify build succeeds locally
