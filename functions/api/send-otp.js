
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

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, c => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[c]);
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

export async function onRequestPost({ request, env }) {
    try {
        if (!env.DB || !env.RESEND_API_KEY || !env.OTP_HMAC_SECRET) {
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

        if (!Number.isSafeInteger(userId) || userId <= 0) {
            return json({
                success: false,
                message: "Invalid request."
            }, 400);
        }

        const user = await env.DB.prepare(`
            SELECT id, full_name, email, email_verified
            FROM users
            WHERE id = ?
        `).bind(userId).first();

        if (!user || user.email_verified === 1) {
            return json({
                success: false,
                message: "Verification request cannot be processed."
            }, 400);
        }

        // Check the most recent OTP request.
        const latest = await env.DB.prepare(`
            SELECT created_at
            FROM verification_challenges
            WHERE user_id = ?
              AND channel = 'EMAIL'
            ORDER BY id DESC
            LIMIT 1
        `).bind(userId).first();

        if (latest) {
            const cooldown = await env.DB.prepare(`
                SELECT CASE
                    WHEN datetime(?) > datetime('now', '-60 seconds')
                    THEN 1 ELSE 0
                END AS active
            `).bind(latest.created_at).first();

            if (cooldown?.active === 1) {
                return json({
                    success: false,
                    message: "Please wait 60 seconds before requesting another OTP."
                }, 429);
            }
        }

        // Maximum five OTP requests in one hour.
        const count = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM verification_challenges
            WHERE user_id = ?
              AND channel = 'EMAIL'
              AND datetime(created_at) >= datetime('now', '-1 hour')
        `).bind(userId).first();

        if (count.total >= 5) {
            return json({
                success: false,
                message: "OTP request limit reached. Please try again later."
            }, 429);
        }

        const otp = String(
            crypto.getRandomValues(new Uint32Array(1))[0] % 1000000
        ).padStart(6, "0");

        const otpHash = await hashOTP(
            userId,
            otp,
            env.OTP_HMAC_SECRET
        );

        const expiresAt = new Date(
            Date.now() + 5 * 60 * 1000
        ).toISOString();

        // Expire previous challenges and create the new one.
        const results = await env.DB.batch([
            env.DB.prepare(`
                UPDATE verification_challenges
                SET expires_at = '2000-01-01T00:00:00.000Z'
                WHERE user_id = ?
                  AND channel = 'EMAIL'
                  AND verified_at IS NULL
            `).bind(userId),

            env.DB.prepare(`
                INSERT INTO verification_challenges (
                    user_id, channel, otp_hash, expires_at
                )
                VALUES (?, 'EMAIL', ?, ?)
            `).bind(userId, otpHash, expiresAt)
        ]);

        const challengeId = results[1]?.meta?.last_row_id;

        if (!challengeId) {
            throw new Error("Could not create verification challenge.");
        }

        const safeName = escapeHTML(user.full_name);

        const emailResponse = await fetch(
            "https://api.resend.com/emails",
            {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${env.RESEND_API_KEY}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    from: "SAPTA SHAKTI AUDITORIUM <onboarding@resend.dev>",
                    to: [user.email],
                    subject: "Your new SAPTA SHAKTI AUDITORIUM OTP",
                    html: `
                        <div style="font-family:Arial,sans-serif;padding:25px">
                            <h2>SAPTA SHAKTI AUDITORIUM</h2>
                            <p>Dear ${safeName},</p>
                            <p>Your new email verification code is:</p>
                            <h1 style="letter-spacing:8px">${otp}</h1>
                            <p>This OTP expires in 5 minutes.</p>
                            <p>Your previous OTP is no longer valid.</p>
                        </div>
                    `,
                    text: `Dear ${user.full_name}, your new verification OTP is ${otp}. It expires in 5 minutes.`
                })
            }
        );

        if (!emailResponse.ok) {
            await env.DB.prepare(`
                DELETE FROM verification_challenges
                WHERE id = ?
            `).bind(challengeId).run();

            throw new Error("Email delivery failed.");
        }

        return json({
            success: true,
            message: "A new verification code has been sent to your email.",
            expiresInSeconds: 300,
            resendCooldownSeconds: 60
        });

    } catch (error) {
        return json({
            success: false,
            message: "Unable to resend OTP. Please try again later."
        }, 500);
    }
}
