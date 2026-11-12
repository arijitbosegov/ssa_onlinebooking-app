
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

async function hashOTP(userId, otp, secret) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(`${userId}:${otp}`)
    );

    return bytesToHex(new Uint8Array(signature));
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;

    let result = 0;

    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
}

export async function onRequestPost({ request, env }) {
    try {
        if (!env.DB || !env.OTP_HMAC_SECRET) {
            return json({
                success: false,
                message: "Verification service unavailable."
            }, 500);
        }

        const data = await request.json();

        const email = String(data.email || "").trim().toLowerCase();
        const otp = String(data.otp || "").trim();

        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            !/^\d{6}$/.test(otp)
        ) {
            return json({
                success: false,
                message: "Enter a valid email address and six-digit OTP."
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
                message: "Invalid or expired OTP."
            }, 400);
        }

        const challenge = await env.DB.prepare(`
            SELECT id, otp_hash, expires_at, attempts, verified_at
            FROM password_reset_challenges
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
        `).bind(user.id).first();

        if (
            !challenge ||
            challenge.verified_at ||
            challenge.attempts >= 5 ||
            new Date(challenge.expires_at).getTime() <= Date.now()
        ) {
            return json({
                success: false,
                message: "Invalid or expired OTP. Request a new code."
            }, 400);
        }

        const submittedHash = await hashOTP(
            user.id,
            otp,
            env.OTP_HMAC_SECRET
        );

        if (!constantTimeEqual(submittedHash, challenge.otp_hash)) {
            await env.DB.prepare(`
                UPDATE password_reset_challenges
                SET attempts = attempts + 1
                WHERE id = ?
                  AND attempts < 5
            `).bind(challenge.id).run();

            return json({
                success: false,
                message: "Incorrect OTP. Please try again."
            }, 400);
        }

        // Mark OTP as verified. The password-reset endpoint
        // will require this verification before changing a password.
        await env.DB.prepare(`
            UPDATE password_reset_challenges
            SET verified_at = ?
            WHERE id = ?
              AND verified_at IS NULL
              AND attempts < 5
        `).bind(
            new Date().toISOString(),
            challenge.id
        ).run();

        return json({
            success: true,
            message: "OTP verified successfully. You may now reset your password."
        });

    } catch (error) {
        console.error("RESET OTP VERIFICATION FAILURE:", error.message);

        return json({
            success: false,
            message: "OTP verification could not be completed."
        }, 500);
    }
}
