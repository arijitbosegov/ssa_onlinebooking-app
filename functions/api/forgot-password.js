
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

function generateOTP() {
    const limit = Math.floor(0x100000000 / 1000000) * 1000000;
    let value;

    do {
        value = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (value >= limit);

    return String(value % 1000000).padStart(6, "0");
}

export async function onRequestPost({ request, env }) {
    try {
        if (!env.DB || !env.RESEND_API_KEY || !env.OTP_HMAC_SECRET) {
            return json({
                success: false,
                message: "Password reset service is temporarily unavailable."
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

        if (
            !email ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        ) {
            return json({
                success: false,
                message: "Enter a valid email address."
            }, 400);
        }

        const user = await env.DB.prepare(`
            SELECT id, full_name
            FROM users
            WHERE email = ?
              AND email_verified = 1
              AND status = 'ACTIVE'
            LIMIT 1
        `).bind(email).first();

        // Return the same response whether the account exists or not.
        if (!user) {
            return json({
                success: true,
                message: "If an eligible account exists, a password-reset OTP will be sent to its registered email address."
            });
        }

        // Remove previous unused reset challenges for this user.
        await env.DB.prepare(`
            DELETE FROM password_reset_challenges
            WHERE user_id = ?
        `).bind(user.id).run();

        const otp = generateOTP();

        const otpHash = await hashOTP(
            user.id,
            otp,
            env.OTP_HMAC_SECRET
        );

        const expiresAt = new Date(
            Date.now() + 5 * 60 * 1000
        ).toISOString();

        await env.DB.prepare(`
            INSERT INTO password_reset_challenges (
                user_id,
                otp_hash,
                expires_at
            )
            VALUES (?, ?, ?)
        `).bind(
            user.id,
            otpHash,
            expiresAt
        ).run();

        const safeName = String(user.full_name).replace(
            /[&<>"']/g,
            char => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            })[char]
        );

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
                    to: [email],
                    subject: "SAPTA SHAKTI AUDITORIUM - Password Reset OTP",
                    html: `
                        <div style="font-family:Arial,sans-serif;padding:25px">
                            <h2>SAPTA SHAKTI AUDITORIUM</h2>
                            <p>Dear ${safeName},</p>
                            <p>Your password-reset verification code is:</p>
                            <h1 style="letter-spacing:8px">${otp}</h1>
                            <p>This OTP expires in 5 minutes.</p>
                            <p>If you did not request a password reset, please ignore this email.</p>
                        </div>
                    `,
                    text: `Dear ${user.full_name}, your SAPTA SHAKTI AUDITORIUM password reset OTP is ${otp}. It expires in 5 minutes.`
                })
            }
        );

        if (!emailResponse.ok) {
            const errorText = await emailResponse.text();

            console.error("PASSWORD RESET EMAIL ERROR:", {
                status: emailResponse.status,
                response: errorText
            });

            await env.DB.prepare(`
                DELETE FROM password_reset_challenges
                WHERE user_id = ?
            `).bind(user.id).run();

            return json({
                success: false,
                message: "Unable to send the password-reset email. Please try again later."
            }, 502);
        }

        return json({
            success: true,
            message: "If an eligible account exists, a password-reset OTP will be sent to its registered email address.",
            expiresInSeconds: 300
        });

    } catch (error) {
        console.error("FORGOT PASSWORD FAILURE:", error.message);

        return json({
            success: false,
            message: "Password reset could not be initiated. Please try again."
        }, 500);
    }
}
