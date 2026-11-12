
const PBKDF2_ITERATIONS = 100000;

const json = (data, status = 200) =>
    Response.json(data, {
        status,
        headers: { "Cache-Control": "no-store" }
    });

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const derived = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        key,
        256
    );

    return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToBase64(
        new Uint8Array(salt)
    )}$${bytesToBase64(new Uint8Array(derived))}`;
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

        if (!request.headers.get("content-type")?.includes("application/json")) {
            return json({
                success: false,
                message: "JSON request required."
            }, 415);
        }

        const data = await request.json();

        const email = String(data.email || "")
            .trim()
            .toLowerCase();

        const resetToken = String(data.resetToken || "").trim();
        const newPassword = data.newPassword;

        if (
            !email ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            !/^[a-f0-9]{64}$/i.test(resetToken) ||
            typeof newPassword !== "string" ||
            newPassword.length < 12 ||
            newPassword.length > 128
        ) {
            return json({
                success: false,
                message: "Invalid reset details. Password must contain 12 to 128 characters."
            }, 400);
        }

        const user = await env.DB.prepare(`
            SELECT id
            FROM users
            WHERE email = ?
              AND email_verified = 1
              AND status = 'ACTIVE'
            LIMIT 1
        `).bind(email).first();

        if (!user) {
            return json({
                success: false,
                message: "Invalid or expired password-reset session."
            }, 400);
        }

        const tokenHash = await sha256(resetToken);

        const challenge = await env.DB.prepare(`
            SELECT id
            FROM password_reset_challenges
            WHERE user_id = ?
              AND reset_token_hash = ?
              AND reset_token_expires_at IS NOT NULL
              AND datetime(reset_token_expires_at) > datetime('now')
              AND verified_at IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
        `).bind(user.id, tokenHash).first();

        if (!challenge) {
            return json({
                success: false,
                message: "Invalid or expired password-reset session. Request a new OTP."
            }, 400);
        }

        // Generate the new password hash.
        const newPasswordHash = await hashPassword(newPassword);

        // Consume the temporary token before changing the password.
        const consumed = await env.DB.prepare(`
            UPDATE password_reset_challenges
            SET reset_token_hash = NULL
            WHERE id = ?
              AND user_id = ?
              AND reset_token_hash = ?
              AND datetime(reset_token_expires_at) > datetime('now')
        `).bind(
            challenge.id,
            user.id,
            tokenHash
        ).run();

        if (consumed.meta.changes !== 1) {
            return json({
                success: false,
                message: "This password-reset token has already been used or has expired."
            }, 400);
        }

        // Update the user's password.
        await env.DB.prepare(`
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
        `).bind(
            newPasswordHash,
            user.id
        ).run();

        // Invalidate all active sessions for this user.
        await env.DB.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
        `).bind(user.id).run();

        // Remove the completed password-reset challenge.
        await env.DB.prepare(`
            DELETE FROM password_reset_challenges
            WHERE id = ?
        `).bind(challenge.id).run();

        return json({
            success: true,
            message: "Password reset successfully. Please log in using your new password."
        });

    } catch (error) {
        console.error("PASSWORD RESET FAILURE:", error.message);

        return json({
            success: false,
            message: "Password reset could not be completed. Please try again."
        }, 500);
    }
}
