#!/usr/bin/env node
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PHRASES = [
  'Hakika confirm my line',
  'My voice opens this SIM',
  'Register this number now',
];
const users = new Map();
const challenges = new Map();
const phrases = new Map();
const STORE = path.join(ROOT, 'data', 'users.json');

function loadUsers(){
  try {
    const rows = JSON.parse(fs.readFileSync(STORE, 'utf8'));
    rows.forEach(function(row){
      row.credentials.forEach(function(c){
        c.credId = Buffer.from(c.credId, 'base64url');
        c.publicKey = Buffer.from(c.publicKey, 'base64url');
      });
      users.set(row.id, row);
    });
  } catch(err) {}
}
function saveUsers(){
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
  const rows = Array.from(users.values()).map(function(user){
    return {
      id: user.id,
      credentials: user.credentials.map(function(c){
        return {
          credId: Buffer.from(c.credId).toString('base64url'),
          publicKey: Buffer.from(c.publicKey).toString('base64url'),
          counter: c.counter,
          transports: c.transports || [],
        };
      }),
    };
  });
  fs.writeFileSync(STORE, JSON.stringify(rows));
}
loadUsers();

function argsPort(){
  const i = process.argv.indexOf('--port');
  return i >= 0 ? process.argv[i + 1] : '';
}
const PORT = Number(process.env.PORT || argsPort() || 10000);

function b64url(bytes){
  return Buffer.from(bytes).toString('base64url');
}
function readBody(req){
  return new Promise(function(resolve, reject){
    const chunks = [];
    req.on('data', function(c){ chunks.push(c); });
    req.on('end', function(){
      const raw = Buffer.concat(chunks).toString('utf8');
      if(!raw){ resolve({}); return; }
      try { resolve(JSON.parse(raw)); }
      catch(err){ reject(err); }
    });
    req.on('error', reject);
  });
}
function send(res, code, obj){
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}
function originOf(req){
  const host = (req.headers.host || 'localhost').split(',')[0].trim();
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  return { host: host.replace(/:\d+$/, ''), origin: proto + '://' + host };
}
function userOf(name){
  const key = name || 'subscriber@hakika';
  if(!users.has(key)){
    users.set(key, { id: key, credentials: [] });
  }
  return users.get(key);
}

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res){
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if(urlPath === '/') urlPath = '/index.html';
  const file = path.normalize(path.join(ROOT, urlPath));
  if(!file.startsWith(ROOT)){
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(file, function(err, data){
    if(err){
      res.writeHead(404); res.end('Not found'); return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async function(req, res){
  try {
    const url = req.url.split('?')[0];
    if(req.method === 'POST' && url === '/api/webauthn/register/options'){
      const body = await readBody(req);
      const { host, origin } = originOf(req);
      const user = userOf(body.username);
      const options = await generateRegistrationOptions({
        rpName: 'Hakika',
        rpID: host,
        userID: user.id,
        userName: user.id,
        attestationType: 'none',
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        excludeCredentials: user.credentials.map(function(c){
          return { id: c.credId, type: 'public-key', transports: c.transports };
        }),
      });
      const sid = b64url(crypto.getRandomValues(new Uint8Array(16)));
      challenges.set(sid, { challenge: options.challenge, user: user.id, kind: 'reg', origin: origin, host: host });
      send(res, 200, { sid: sid, options: options });
      return;
    }
    if(req.method === 'POST' && url === '/api/webauthn/register/verify'){
      const body = await readBody(req);
      const pending = challenges.get(body.sid);
      if(!pending || pending.kind !== 'reg'){ send(res, 400, { ok: false, error: 'Challenge expired.' }); return; }
      challenges.delete(body.sid);
      const user = userOf(pending.user);
      const checked = await verifyRegistrationResponse({
        response: body.response,
        expectedChallenge: pending.challenge,
        expectedOrigin: pending.origin,
        expectedRPID: pending.host,
        requireUserVerification: true,
      });
      if(!checked.verified){ send(res, 400, { ok: false, error: 'Fingerprint registration was rejected.' }); return; }
      const info = checked.registrationInfo;
      user.credentials.push({
        credId: info.credentialID,
        publicKey: info.credentialPublicKey,
        counter: info.counter,
        transports: body.response.response.transports || [],
      });
      saveUsers();
      send(res, 200, { ok: true, credentialId: Buffer.from(info.credentialID).toString('base64url') });
      return;
    }
    if(req.method === 'POST' && url === '/api/webauthn/login/options'){
      const body = await readBody(req);
      const { host, origin } = originOf(req);
      const user = userOf(body.username);
      if(!user.credentials.length){ send(res, 404, { ok: false, error: 'No fingerprint is enrolled on this server.' }); return; }
      const options = await generateAuthenticationOptions({
        rpID: host,
        userVerification: 'required',
        allowCredentials: user.credentials.map(function(c){
          return { id: c.credId, type: 'public-key', transports: c.transports };
        }),
      });
      const sid = b64url(crypto.getRandomValues(new Uint8Array(16)));
      challenges.set(sid, { challenge: options.challenge, user: user.id, kind: 'auth', origin: origin, host: host });
      send(res, 200, { sid: sid, options: options });
      return;
    }
    if(req.method === 'POST' && url === '/api/webauthn/login/verify'){
      const body = await readBody(req);
      const pending = challenges.get(body.sid);
      if(!pending || pending.kind !== 'auth'){ send(res, 400, { ok: false, error: 'Challenge expired.' }); return; }
      challenges.delete(body.sid);
      const user = userOf(pending.user);
      const cred = user.credentials.find(function(c){
        return Buffer.from(c.credId).toString('base64url') === body.response.id;
      });
      if(!cred){ send(res, 400, { ok: false, error: 'Unknown credential.' }); return; }
      const checked = await verifyAuthenticationResponse({
        response: body.response,
        expectedChallenge: pending.challenge,
        expectedOrigin: pending.origin,
        expectedRPID: pending.host,
        authenticator: {
          credentialID: cred.credId,
          credentialPublicKey: cred.publicKey,
          counter: cred.counter,
        },
        requireUserVerification: true,
      });
      if(!checked.verified){ send(res, 400, { ok: false, error: 'Fingerprint check failed.' }); return; }
      cred.counter = checked.authenticationInfo.newCounter;
      saveUsers();
      send(res, 200, { ok: true });
      return;
    }
    if(req.method === 'POST' && url === '/api/voice/phrase'){
      const id = b64url(crypto.getRandomValues(new Uint8Array(12)));
      const phrase = PHRASES[Math.floor(Math.random() * PHRASES.length)];
      phrases.set(id, { phrase: phrase, at: Date.now() });
      send(res, 200, { id: id, phrase: phrase });
      return;
    }
    if(req.method === 'POST' && url === '/api/voice/verify'){
      const body = await readBody(req);
      const pending = phrases.get(body.id);
      phrases.delete(body.id);
      const audio = String(body.audioBase64 || '');
      const peak = Number(body.peak) || 0;
      const seconds = Number(body.seconds) || 0;
      if(!pending || pending.phrase !== body.phrase){
        send(res, 400, { ok: false, error: 'That phrase was not issued.' }); return;
      }
      if(seconds < 3 || seconds > 6){
        send(res, 400, { ok: false, error: 'The sample must be between 3 and 5 seconds.' }); return;
      }
      if(peak < 14){
        send(res, 400, { ok: false, error: 'The room was too quiet. Speak the phrase clearly.' }); return;
      }
      if(audio.length < 1500){
        send(res, 400, { ok: false, error: 'The recording was empty.' }); return;
      }
      send(res, 200, { ok: true, bytes: Math.floor(audio.length * 0.75) });
      return;
    }
    if(req.method === 'GET'){ serveStatic(req, res); return; }
    send(res, 404, { ok: false, error: 'Not found' });
  } catch(err){
    send(res, 500, { ok: false, error: err && err.message ? err.message : 'Server error' });
  }
});

server.listen(PORT, '0.0.0.0', function(){
  console.log('Hakika listening on ' + PORT);
});
