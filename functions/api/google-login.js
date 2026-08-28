// Cloudflare Pages Function — verifica no SERVIDOR o access_token do Google
// Identity Services antes do login confiar no e-mail retornado, e emite um
// custom token do Firebase pra esse e-mail já verificado poder autenticar
// no Firestore de verdade (não é Firebase Admin SDK, que não roda no
// runtime de Cloudflare Workers — assinatura manual do JWT via Web Crypto).
//
// O cliente (index.html) usa google.accounts.oauth2.initTokenClient
// (escopo "openid email profile") pra obter um access_token, e manda esse
// token pra cá via POST. Esta function consulta o próprio Google pra
// confirmar que o token é válido, pega o e-mail JÁ VERIFICADO, e assina um
// custom token do Firebase com esse e-mail como uid e como custom claim
// `email` (é esse claim que vira request.auth.token.email nas regras do
// Firestore). O casamento desse e-mail contra D.professionals pra decidir
// nível de acesso continua no cliente — esta function só garante "quem é",
// nunca decide "quem pode". Autorização por clínica é uma leitura ao vivo
// nas regras do Firestore (exists() no documento do profissional), não um
// dado congelado neste token.

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json().catch(() => null);
    const accessToken = body && body.access_token;
    if (!accessToken || typeof accessToken !== 'string') {
      return json({ error: 'access_token ausente.' }, 400);
    }

    const resp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!resp.ok) {
      return json({ error: 'Token do Google inválido ou expirado.' }, 401);
    }
    const info = await resp.json().catch(() => null);
    if (!info || !info.email || info.email_verified !== true) {
      return json({ error: 'Conta Google sem e-mail verificado.' }, 401);
    }

    const email = String(info.email).toLowerCase().trim();

    if (!env.FIREBASE_CLIENT_EMAIL || !env.FIREBASE_PRIVATE_KEY) {
      return json({ error: 'Backend sem credenciais do Firebase configuradas.' }, 500);
    }
    const firebaseToken = await mintFirebaseCustomToken(
      env.FIREBASE_CLIENT_EMAIL,
      env.FIREBASE_PRIVATE_KEY,
      email
    );

    return json({ email, nome: info.name || '', firebaseToken });
  } catch (err) {
    return json({ error: 'Erro interno na function.', detail: String(err && err.message || err) }, 500);
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

/* ── Custom token do Firebase, assinado manualmente (Web Crypto, RS256) ──
   Formato exigido pelo Firebase Auth pra signInWithCustomToken: JWT RS256
   assinado pela chave privada de uma conta de serviço do próprio projeto,
   com iss/sub = client_email dessa conta, aud fixo do Identity Toolkit,
   uid = identificador único do usuário, e claims = custom claims que o
   Firebase propaga pro ID token final (é assim que request.auth.token.email
   chega até as regras do Firestore). exp curto (1h, o máximo permitido). */
async function mintFirebaseCustomToken(clientEmail, privateKeyPem, email) {
  const agora = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: clientEmail,
    sub: clientEmail,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: agora,
    exp: agora + 3600,
    uid: email,
    claims: { email }
  };
  const semAssinar = b64urlStr(JSON.stringify(header)) + '.' + b64urlStr(JSON.stringify(claims));
  const chave = await crypto.subtle.importKey(
    'pkcs8', pemParaArrayBuffer(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  );
  const assinatura = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', chave, new TextEncoder().encode(semAssinar));
  return semAssinar + '.' + b64url(assinatura);
}

function b64url(bytes) {
  let bin = '';
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlStr(str) { return b64url(new TextEncoder().encode(str)); }
function pemParaArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\\n/g, '')
    .replace(/\s+/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
