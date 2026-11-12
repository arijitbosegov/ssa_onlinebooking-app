
const json = (data, status = 200) =>
    Response.json(data, {
        status,
        headers: { "Cache-Control": "no-store" }
    });

function normaliseMobile(value) {
    return String(value || "").replace(/[\s()-]/g, "");
}

function validEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
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
            iterations: 310000,
            hash: "SHA-256"
        },
        key,
        256
    );

    return `pbkdf2$310000$${bytesToBase64(salt)}$${bytesToBase64(new Uint8Array(derived))}`;
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

    let userId = null;
    let stage = "configuration";

    try {

        // 1. Check Cloudflare bindings and secrets
        if (!env.DB || !env.RESEND_API_KEY || !env.OTP_HMAC_SECRET) {

            console.error("Missing server configuration:", {
                DB: !!env.DB,
                RESEND_API_KEY: !!env.RESEND_API_KEY,
                OTP_HMAC_SECRET: !!env.OTP_HMAC_SECRET
            });

            return json({
                success: false,
                message: "Server configuration incomplete."
            }, 500);
        }

        // 2. Validate request content type
        stage = "request_validation";

        if (!request.headers.get("content-type")?.includes("application/json")) {
            return json({
                success: false,
                message: "JSON request required."
            }, 415);
        }

        const data = await request.json();

        // 3. Read and normalise registration details
        stage = "input_validation";

        const fullName = String(data.fullName || "").trim();
        const mobile = normaliseMobile(data.mobile);
        const email = String(data.email || "").trim().toLowerCase();
        const category = String(data.category || "").toUpperCase();
        const password = String(data.password || "");

        const allowedCategories = [
            "OFFICER",
            "JCO",
            "OR",
            "DEPENDANT",
            "GUEST"
        ];

        if (!fullName || fullName.length > 100) {
            return json({
                success: false,
                message: "Enter a valid full name."
            }, 400);
        }

        if (!/^\+?[1-9]\d{9,14}$/.test(mobile)) {
            return json({
                success: false,
                message: "Enter a valid mobile number."
            }, 400);
        }

        if (!validEmail(email) || email.length > 254) {
            return json({
                success: false,
                message: "Enter a valid email address."
            }, 400);
        }

        if (!allowedCategories.includes(category)) {
            return json({
                success: false,
                message: "Invalid user category."
            }, 400);
        }

        if (password.length < 12 || password.length > 128) {
            return json({
                success: false,
                message: "Password must contain 12 to 128 characters."
            }, 400);
        }

        // 4. Check for an existing account
        stage = "database_lookup";

        const existing = await env.DB.prepare(
            "SELECT id FROM users WHERE email = ? OR mobile = ? LIMIT 1"
        ).bind(email, mobile).first();

        if (existing) {
            return json({
                success: false,
                message: "An account with these details already exists or registration is pending."
            }, 409);
        }

        // 5. Hash password
        stage = "password_hashing";

        const passwordHash = await hashPassword(password);

        // 6. Create user record
        stage = "user_insertion";

        const userResult = await env.DB.prepare(`
            INSERT INTO users (
                full_name,
                mobile,
                email,
                password_hash,
                category,
                mobile_verified,
                email_verified,
                status
            )
            VALUES (?, ?, ?, ?, ?, 0, 0, 'ACTIVE')
        `).bind(
            fullName,
            mobile,
            email,
            passwordHash,
            category
        ).run();

        userId = userResult.meta.last_row_id;

        if (!userId) {
            throw new Error("User creation failed.");
        }

        console.log("Registration user record created.");

        // 7. Generate secure email OTP
        stage = "otp_generation";

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

        // 8. Store OTP challenge
        stage = "otp_storage";

        await env.DB.prepare(`
            INSERT INTO verification_challenges (
                user_id,
                channel,
                otp_hash,
                expires_at
            )
            VALUES (?, 'EMAIL', ?, ?)
        `).bind(
            userId,
            otpHash,
            expiresAt
        ).run();

        console.log("Email OTP challenge stored.");

        // 9. Send OTP using Resend
        stage = "resend_email";

        const safeName = escapeHTML(fullName);

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

                    subject: "Your SAPTA SHAKTI AUDITORIUM verification code",

                    html: `
                        <div style="font-family:Arial,sans-serif;padding:25px">
                            <h2>SAPTA SHAKTI AUDITORIUM</h2>
                            <p>Dear ${safeName},</p>
                            <p>Your email verification OTP is:</p>
                            <h1 style="letter-spacing:8px">${otp}</h1>
                            <p>This code expires in 5 minutes.</p>
                            <p>If you did not request this code, please ignore this email.</p>
                        </div>
                    `,

                    text: `Dear ${fullName}, your SAPTA SHAKTI AUDITORIUM verification OTP is ${otp}. It expires in 5 minutes.`
                })
            }
        );

        if (!emailResponse.ok) {

            const resendError = await emailResponse.text();

            console.error("RESEND DELIVERY ERROR:", {
                status: emailResponse.status,
                response: resendError
            });

            throw new Error(
                `Resend rejected the request. HTTP ${emailResponse.status}`
            );
        }

        console.log("Resend accepted the OTP email request.");

        // 10. Registration successful
        return json({
            success: true,
            message: "Registration initiated. Check your email for the verification code.",
            userId,
            expiresInSeconds: 300
        }, 201);

    } catch (error) {

        // 11. Log the actual failure stage
        console.error("REGISTRATION FAILURE:", {
            stage,
            error: error?.message || String(error)
        });

        // 12. Clean up incomplete registration
        if (userId && env.DB) {

            try {

                await env.DB.batch([
                    env.DB.prepare(
                        "DELETE FROM verification_challenges WHERE user_id = ?"
                    ).bind(userId),

                    env.DB.prepare(
                        "DELETE FROM users WHERE id = ? AND email_verified = 0"
                    ).bind(userId)
                ]);

                console.log("Incomplete registration cleaned up.");

            } catch (cleanupError) {

                console.error("REGISTRATION CLEANUP FAILURE:", {
                    error: cleanupError?.message || String(cleanupError)
                });
            }
        }

        return json({
            success: false,
            message: "Registration could not be completed. Please try again."
        }, 500);
    }
}
