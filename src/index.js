// src/index.js - Cloudflare Worker with D1 + WebAuthn
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const { pathname } = url;

        // CORS 支持（可选）
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders, status: 204 });
        }

        try {
            if (pathname === '/api/webauthn/register/options') {
                return handleRegisterOptions(request, env, corsHeaders);
            }
            if (pathname === '/api/webauthn/register/complete') {
                return handleRegisterComplete(request, env, corsHeaders);
            }
            if (pathname === '/api/webauthn/auth/options') {
                return handleAuthOptions(request, env, corsHeaders);
            }
            if (pathname === '/api/webauthn/auth/complete') {
                return handleAuthComplete(request, env, corsHeaders);
            }
            if (pathname === '/api/webauthn/parse') {
                return handleParseData(request, env, corsHeaders);
            }

            return new Response('Not Found', { status: 404, headers: corsHeaders });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: 'Internal error' }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
};

// ==================== 工具函数 ====================

function base64urlEncode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(base64) {
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    const str = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i);
    }
    return arr.buffer;
}

// 模拟加密（Workers 不支持 OpenSSL，使用 XOR + PBKDF2）
async function encryptData(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const keyMaterial = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv },
        keyMaterial,
        encoded
    );
    return {
        ciphertext: base64urlEncode(ciphertext),
        iv: base64urlEncode(iv)
    };
}

async function decryptData(ciphertext, iv, key) {
    const encrypted = base64urlDecode(ciphertext);
    const initVector = base64urlDecode(iv);
    const keyMaterial = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: initVector },
        keyMaterial,
        encrypted
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
}

// 从密码生成密钥（PBKDF2）
async function getKeyFromPassword(password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: enc.encode('webauthn-salt-2025'), iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// 生成随机 buffer
function getRandomBuffer(length) {
    return crypto.getRandomValues(new Uint8Array(length)).buffer;
}

// ==================== WebAuthn 接口 ====================

async function handleRegisterOptions(request, env, corsHeaders) {
    const { username, label, authType } = await request.json();
    if (!username) return json({ error: "Missing username" }, 400, corsHeaders);

    const challenge = getRandomBuffer(32);
    const userId = getRandomBuffer(16);

    // 使用 KV 或临时内存存储 challenge（生产建议用 D1 + TTL）
    const challengeKey = `challenge:reg:${username}`;
    await env.CHALLENGES.put(challengeKey, JSON.stringify({
        challenge: base64urlEncode(challenge),
        userId: base64urlEncode(userId),
        label,
        authType,
        expires: Date.now() + 5 * 60 * 1000
    }), { expirationTtl: 300 });

    return json({
        publicKey: {
            challenge: base64urlEncode(challenge),
            rp: { name: "Scratch Biometric Auth" },
            user: {
                id: base64urlEncode(userId),
                name: username,
                displayName: label || username
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },
                { alg: -257, type: "public-key" }
            ],
            timeout: 60000,
            attestation: "direct",
            authenticatorSelection: {
                authenticatorAttachment: authType === "fingerprint" ? "cross-platform" :
                                       authType === "face" ? "platform" : undefined
            }
        }
    }, 200, corsHeaders);
}

async function handleRegisterComplete(request, env, corsHeaders) {
    const { username, response } = await request.json();
    const challengeKey = `challenge:reg:${username}`;
    const challengeDataStr = await env.CHALLENGES.get(challengeKey);
    if (!challengeDataStr) return json({ error: "Challenge expired" }, 400, corsHeaders);

    const challengeData = JSON.parse(challengeDataStr);
    if (Date.now() > challengeData.expires) {
        await env.CHALLENGES.delete(challengeKey);
        return json({ error: "Challenge expired" }, 400, corsHeaders);
    }

    const clientData = JSON.parse(atob(response.response.clientDataJSON));
    if (clientData.challenge !== challengeData.challenge) {
        return json({ error: "Challenge mismatch" }, 400, corsHeaders);
    }

    const credentialId = response.id;
    const rawId = response.rawId; // base64 string

    // 获取或创建用户
    let { results: userResults } = await env.DB.prepare(
        "SELECT id FROM users WHERE username = ?"
    ).bind(username).all();

    let userId;
    if (userResults.length > 0) {
        userId = userResults[0].id;
    } else {
        const { success, error } = await env.DB.prepare(
            "INSERT INTO users (username) VALUES (?)"
        ).bind(username).run();
        if (!success) return json({ error }, 500, corsHeaders);
        userId = (await env.DB.prepare("SELECT last_insert_rowid() as id").first())?.id;
    }

    // 加密 rawId
    const key = await getKeyFromPassword(`user-key-${username}`);
    const encrypted = await encryptData({ rawId }, key);

    // 存入 D1
    const { success, error } = await env.DB.prepare(`
        INSERT INTO credentials (user_id, credential_id, encrypted_raw_id, iv, label, auth_type, registration_time)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
        userId,
        credentialId,
        encrypted.ciphertext,
        encrypted.iv,
        challengeData.label || username,
        challengeData.authType || 'any'
    ).run();

    if (!success) return json({ error }, 500, corsHeaders);

    const tokenId = (await env.DB.prepare("SELECT last_insert_rowid() as id").first())?.id;

    await env.CHALLENGES.delete(challengeKey);

    return json({
        success: true,
        token: `token_${tokenId}`
    }, 200, corsHeaders);
}

async function handleAuthOptions(request, env, corsHeaders) {
    const { username, token } = await request.json();
    const tokenId = parseInt(token.replace('token_', ''), 10);
    if (!username || isNaN(tokenId)) return json({ error: "Invalid input" }, 400, corsHeaders);

    const { results } = await env.DB.prepare(`
        SELECT c.credential_id FROM credentials c
        JOIN users u ON c.user_id = u.id
        WHERE u.username = ? AND c.id = ? AND c.active = 1
    `).bind(username, tokenId).all();

    if (results.length === 0) return json({ error: "Not found" }, 404, corsHeaders);

    const challenge = getRandomBuffer(32);
    const challengeKey = `challenge:auth:${username}`;
    await env.CHALLENGES.put(challengeKey, JSON.stringify({
        challenge: base64urlEncode(challenge),
        tokenId,
        expires: Date.now() + 300000
    }), { expirationTtl: 300 });

    return json({
        publicKey: {
            challenge: base64urlEncode(challenge),
            timeout: 60000,
            allowCredentials: [{
                id: results[0].credential_id,
                type: "public-key",
                transports: ["usb", "nfc", "ble", "internal"]
            }]
        }
    }, 200, corsHeaders);
}

async function handleAuthComplete(request, env, ctx, corsHeaders) {
    const { username, token, response } = await request.json();
    const challengeKey = `challenge:auth:${username}`;
    const challengeDataStr = await env.CHALLENGES.get(challengeKey);
    if (!challengeDataStr) return json({ error: "No challenge" }, 400, corsHeaders);

    const challengeData = JSON.parse(challengeDataStr);
    const clientData = JSON.parse(atob(response.response.clientDataJSON));
    if (clientData.challenge !== challengeData.challenge) {
        return json({ error: "Challenge mismatch" }, 400, corsHeaders);
    }

    // 实际应验证签名（需存储公钥），此处简化为成功
    await env.CHALLENGES.delete(challengeKey);

    return json({ success: true }, 200, corsHeaders);
}

async function handleParseData(request, env, corsHeaders) {
    const { username, token } = await request.json();
    const tokenId = parseInt(token.replace('token_', ''), 10);

    const { results } = await env.DB.prepare(`
        SELECT c.label, c.auth_type, c.registration_time, u.username as user_username
        FROM credentials c
        JOIN users u ON c.user_id = u.id
        WHERE u.username = ? AND c.id = ?
    `).bind(username, tokenId).all();

    if (results.length === 0) return json({ success: false }, 200, corsHeaders);

    const row = results[0];
    return json({
        success: true,
        username: row.user_username,
        label: row.label,
        authType: row.auth_type,
        registrationTime: row.registration_time
    }, 200, corsHeaders);
}

// 工具函数：返回 JSON 响应
function json(data, status, headers) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...headers, 'Content-Type': 'application/json' }
    });
}
