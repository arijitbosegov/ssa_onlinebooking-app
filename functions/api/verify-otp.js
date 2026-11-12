
const json = (data, status = 200) =>
    Response.json(data, {
        status,
        headers: { "Cache-Control": "no-store" }
    });

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

    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function constantTimeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
        return false;
    }

    let diff = a.length ^ b.length;
    const length = Math.max(a.length, b.length);

    for (let i = 0; i < length; i++) {
        diff |= (a.charCodeAt(i) || 0) ^
                (b.charCodeAt(i) || 0);
    }

    return diff === 0;
}

export async function onRequestPost({ request, env }) {
    try {
        if (!env.DB || !env.OTP_HMAC_SECRET) {
            return json({
                success: false,
                message: "Server configuration incomplete."
            }, 500);
        }

        if (!request.headers.get("content-type")?.includes("application/json")) {
            return json({
                success: false,
                message: "JSON request required."
            }, 415);
        }

        const data = await request.json();

        const userId = Number(data.userId);
        const otp = String(data.otp || "").trim();

        if (
            !Number.isSafeInteger(userId) ||
            userId <= 0 ||
            !/^\d{6}$/.test(otp)
        ) {
            return json({
                success: false,
                message: "Invalid verification details."
            }, 400);
        }

        const user = await env.DB.prepare(`
            SELECT id, email_verified
            FROM users
            WHERE id = ?
        `).bind(userId).first();

        if (!user) {
            return json({
                success: false,
                message: "Invalid verification details."
            }, 400);
        }

        if (user.email_verified === 1) {
            return json({
                success: true,
                message: "Email already verified."
            });
        }

        const challenge = await env.DB.prepare(`
            SELECT id, otp_hash, expires_at, attempts
            FROM verification_challenges
            WHERE user_id = ?
              AND channel = 'EMAIL'
              AND verified_at IS NULL
            ORDER BY id DESC
            LIMIT 1
        `).bind(userId).first();

        if (!challenge) {
            return json({
                success: false,
                message: "No active verification request. Request a new OTP."
            }, 400);
        }

        if (challenge.attempts >= 5) {
            return json({
                success: false,
                message: "Maximum verification attempts reached. Request a new OTP."
            }, 429);
        }

        if (Date.parse(challenge.expires_at) <= Date.now()) {
            return json({
                success: false,
                message: "OTP expired. Request a new OTP."
            }, 400);
        }

        const suppliedHash = await hashOTP(
            userId,
            otp,
            env.OTP_HMAC_SECRET
        );

        // Increment attempts atomically before checking the OTP.
        const attemptResult = await env.DB.prepare(`
            UPDATE verification_challenges
            SET attempts = attempts + 1
            WHERE id = ?
              AND attempts < 5
              AND verified_at IS NULL
        `).bind(challenge.id).run();

        if (attemptResult.meta.changes !== 1) {
            return json({
                success: false,
                message: "Verification request is no longer active."
            }, 409);
        }

        if (!constantTimeEqual(suppliedHash, challenge.otp_hash)) {
            return json({
                success: false,
                message: "Incorrect OTP.",
                attemptsRemaining: Math.max(0, 4 - challenge.attempts)
            }, 400);
        }

        // Complete verification only if this challenge is still unused.
        const results = await env.DB.batch([
            env.DB.prepare(`
                UPDATE verification_challenges
                SET verified_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND verified_at IS NULL
                  AND attempts <= 5
            `).bind(challenge.id),

            env.DB.prepare(`
                UPDATE users
                SET email_verified = 1
                WHERE id = ?
                  AND EXISTS (
                      SELECT 1
                      FROM verification_challenges
                      WHERE id = ?
                        AND verified_at IS NOT NULL
                  )
            `).bind(userId, challenge.id)
        ]);

        if (
            results[0].meta.changes !== 1 ||
            results[1].meta.changes !== 1
        ) {
            return json({
                success: false,
                message: "Verification could not be completed. Please try again."
            }, 409);
        }

        return json({
            success: true,
            message: "Email verified successfully. You can now log in."
        });

    } catch (error) {
        return json({
            success: false,
            message: "Verification could not be completed."
        }, 500);
    }
}
