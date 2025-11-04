// src/auth.ts
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as readline from 'readline/promises';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import { fileURLToPath } from 'url';

// --- Calculate paths relative to this script file (ESM way) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRootDir = path.resolve(__dirname, '..');

const TOKEN_PATH = path.join(projectRootDir, 'token.json');
const CREDENTIALS_PATH = path.join(projectRootDir, 'credentials.json');
// --- End of path calculation ---

const SCOPES = [
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/drive' // Full Drive access for listing, searching, and document discovery
];

async function loadSavedCredentialsIfExist(): Promise<OAuth2Client | null> {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content.toString());
    const { client_secret, client_id, redirect_uris } = await loadClientSecrets();
    const client = new google.auth.OAuth2(client_id, client_secret, redirect_uris?.[0]);
    client.setCredentials(credentials);
    return client;
  } catch (err) {
    return null;
  }
}

async function loadClientSecrets() {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content.toString());
  const key = keys.installed || keys.web;
   if (!key) throw new Error("Could not find client secrets in credentials.json.");
  return {
      client_id: key.client_id,
      client_secret: key.client_secret,
      redirect_uris: key.redirect_uris || ['http://localhost:3000/'], // Default for web clients
      client_type: keys.web ? 'web' : 'installed'
  };
}

async function saveCredentials(client: OAuth2Client): Promise<void> {
  const { client_secret, client_id } = await loadClientSecrets();
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: client_id,
    client_secret: client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
  console.error('Token stored to', TOKEN_PATH);
}

async function authenticate(): Promise<OAuth2Client> {
  const { client_secret, client_id, redirect_uris, client_type } = await loadClientSecrets();
  console.error(`DEBUG: Client type: ${client_type}`);
  if (client_type === 'installed') {
    return authenticateWithLoopback(client_id, client_secret);
  }

  const redirectUri = redirect_uris[0];
  console.error(`DEBUG: Using redirect URI: ${redirectUri}`);
  return authenticateWithManualCode(client_id, client_secret, redirectUri);
}

async function authenticateWithManualCode(clientId: string, clientSecret: string, redirectUri: string): Promise<OAuth2Client> {
  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
  });

  console.error('DEBUG: Generated auth URL:', authorizeUrl);
  console.error('Authorize this app by visiting this url:', authorizeUrl);
  const code = await rl.question('Enter the code from that page here: ');
  rl.close();

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    if (tokens.refresh_token) {
      await saveCredentials(oAuth2Client);
    } else {
      console.error('Did not receive refresh token. Token might expire.');
    }
    console.error('Authentication successful!');
    return oAuth2Client;
  } catch (err) {
    console.error('Error retrieving access token', err);
    throw new Error('Authentication failed');
  }
}

async function authenticateWithLoopback(clientId: string, clientSecret: string): Promise<OAuth2Client> {
  let redirectUri = '';
  let serverClosed = false;
  let resolveCode!: (code: string) => void;
  let rejectCode!: (reason?: unknown) => void;

  const server = createServer((req, res) => {
    if (!req.url || !redirectUri) {
      res.statusCode = 500;
      res.end('OAuth handler not ready.');
      return;
    }

    const requestUrl = new URL(req.url, redirectUri);
    const code = requestUrl.searchParams.get('code');
    const error = requestUrl.searchParams.get('error');

    res.setHeader('Content-Type', 'text/html');

    if (error) {
      res.statusCode = 400;
      res.end(`<html><body><h1>Authentication failed</h1><p>${error}</p></body></html>`);
      rejectCode(new Error(`OAuth Error: ${error}`));
      return;
    }

    if (!code) {
      res.statusCode = 400;
      res.end('<html><body><h1>Authentication failed</h1><p>Missing authorization code.</p></body></html>');
      rejectCode(new Error('Missing authorization code.'));
      return;
    }

    res.end('<html><body><h1>Authentication complete</h1><p>You may close this window.</p></body></html>');
    resolveCode(code);
  });

  const codePromise = new Promise<string>((resolve, reject) => {
    resolveCode = (code: string) => {
      if (!serverClosed) {
        serverClosed = true;
        server.close();
      }
      resolve(code);
    };
    rejectCode = (reason?: unknown) => {
      if (!serverClosed) {
        serverClosed = true;
        server.close();
      }
      reject(reason);
    };
  });

  server.on('error', rejectCode);

  await new Promise<void>((resolve, reject) => {
    server.listen(0, () => resolve());
    server.on('error', reject);
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    rejectCode(new Error('Failed to determine local server address.'));
    throw new Error('Authentication failed');
  }

  const { port } = address as AddressInfo;
  redirectUri = `http://127.0.0.1:${port}/oauth2callback`;

  console.error(`DEBUG: Using redirect URI: ${redirectUri}`);
  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);

  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    redirect_uri: redirectUri,
    prompt: 'consent',
  });

  console.error('DEBUG: Generated auth URL:', authorizeUrl);
  console.error('Authorize this app by visiting this url:', authorizeUrl);

  let code: string;
  try {
    code = await codePromise;
  } catch (err) {
    console.error('Authentication flow was interrupted', err);
    throw new Error('Authentication failed');
  }

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    if (tokens.refresh_token) {
      await saveCredentials(oAuth2Client);
    } else {
      console.error('Did not receive refresh token. Token might expire.');
    }
    console.error('Authentication successful!');
    return oAuth2Client;
  } catch (err) {
    console.error('Error retrieving access token', err);
    throw new Error('Authentication failed');
  }
}

export async function authorize(): Promise<OAuth2Client> {
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    // Optional: Add token refresh logic here if needed, though library often handles it.
    console.error('Using saved credentials.');
    return client;
  }
  console.error('Starting authentication flow...');
  client = await authenticate();
  return client;
}
