
const json = (data, status = 200, extraHeaders = {}) =>
    Response.json(data, {
        status,
        headers: {
            "Cache-Control": "no-store",
            ...extraHeaders
        }
    });

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;

    let result = 0;

    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }

    return result === 0;
}

async function verifyPassword(password, storedHash) {
    try {
        const parts = storedHash.split("$");

        if (
            parts.length !== 4 ||
            parts[0] !== "pbkdf2" ||
            parts[1] !== "100000"
        ) {
            return false;
        }

        const salt = base64ToBytes(parts[2]);
        const expected = base64ToBytes(parts[3]);

        if (salt.length !== 16 || expected.length !== 32) {
            return false;
        }

        const key = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const derived = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt,
                iterations: 310000,
                hash: "SHA-256"
            },
            key,
            256
        );

        return constantTimeEqual(
            new Uint8Array(derived),
            expected
        );

    } catch {
        return false;
    }
}

async function sha256(value) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
    );

    return bytesToHex(new Uint8Array(digest));
}

export async function onRequestPost({ request, env }) {
    try {
        if (!env.DB) {
            return json({
                success: false,
                message: "Database unavailable."
            }, 500);
        }

        if (
            !request.headers.get("content-type")
                ?.includes("application/json")
        ) {
            return json({
                success: false,
                message: "JSON request required."
            }, 415);
        }

        const data = await request.json();

        const email = String(data.email || "")
            .trim()
            .toLowerCase();

        const password = data.password;

        if (
            !email ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            typeof password !== "string" ||
            password.length === 0 ||
            password.length > 1024
        ) {
            return json({
                success: false,
                message: "Invalid email or password."
            }, 400);
        }

        const user = await env.DB.prepare(`
            SELECT
                id,
                full_name,
                email,
                category,
                password_hash,
                email_verified,
                status,
                role
            FROM users
            WHERE email = ?
            LIMIT 1
        `).bind(email).first();

        if (!user || !user.password_hash) {
            return json({
                success: false,
                message: "Invalid email or password."
            }, 401);
        }

        const passwordValid = await verifyPassword(
            password,
            user.password_hash
        );

        if (!passwordValid) {
            return json({
                success: false,
                message: "Invalid email or password."
            }, 401);
        }

        if (user.email_verified !== 1) {
            return json({
                success: false,
                message: "Please verify your email before logging in.",
                requiresVerification: true
            }, 403);
        }

        if (user.status !== "ACTIVE") {
            return json({
                success: false,
                message: "Your account is currently suspended."
            }, 403);
        }

        // Generate a cryptographically secure session token.
        const randomBytes = crypto.getRandomValues(
            new Uint8Array(32)
        );

        const sessionToken = bytesToHex(randomBytes);

        // Store only the SHA-256 hash in D1.
        const tokenHash = await sha256(sessionToken);

        // Seven-day persistent session.
        const expiresAt = new Date(
            Date.now() + 7 * 24 * 60 * 60 * 1000
        ).toISOString();

        // Remove expired sessions for this user.
        await env.DB.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
              AND datetime(expires_at) <= datetime('now')
        `).bind(user.id).run();

        await env.DB.prepare(`
            INSERT INTO sessions (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (?, ?, ?)
        `).bind(
            user.id,
            tokenHash,
            expiresAt
        ).run();

        const cookie =
            `ssa_session=${sessionToken}; ` +
            `HttpOnly; Secure; SameSite=Lax; ` +
            `Path=/; Max-Age=604800`;

        return json({
            success: true,
            message: "Login successful.",
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email,
                category: user.category,
                role: user.role
            },
            expiresInSeconds: 604800
        }, 200, {
            "Set-Cookie": cookie
        });

    } catch (error) {
        return json({
            success: false,
            message: "Unable to process login. Please try again."
        }, 500);
    }
}
