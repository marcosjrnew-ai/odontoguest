// Cloudflare Pages Function — verifica no SERVIDOR o access_token do Google
// Identity Services antes do login confiar no e-mail retornado.
//
// O cliente (index.html) usa google.accounts.oauth2.initTokenClient
// (escopo "openid email profile") pra obter um access_token, e manda esse
// token pra cá via POST. Esta function consulta o próprio Google pra
// confirmar que o token é válido e devolve o e-mail JÁ VERIFICADO — o
// casamento desse e-mail contra D.professionals continua no cliente
// (mesmo nível de confiança do resto do app, que não tem backend de dado).
// Esta function só garante "quem é", nunca decide "quem pode".
//
// Não precisa de chave nem de segredo: só confirma junto ao próprio Google
// que o token é válido.

export async function onRequestPost(context) {
  try {
    const { request } = context;
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

    return json({ email: String(info.email).toLowerCase().trim(), nome: info.name || '' });
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
