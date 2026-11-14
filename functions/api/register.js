
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
            iterations: 100000,
            hash: "SHA-256"
        },
        key,
        256
    );

    return `pbkdf2$100000$${bytesToBase64(salt)}$${bytesToBase64(new Uint8Array(derived))}`;
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

async function sendMailjetEmail(env, recipient, recipientName, otp) {
    const authentication = btoa(
        `${env.MAILJET_API_KEY}:${env.MAILJET_SECRET_KEY}`
    );

    const response = await fetch(
        "https://api.mailjet.com/v3.1/send",
        {
            method: "POST",
            headers: {
                "Authorization": `Basic ${authentication}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                Messages: [
                    {
                        From: {
                            Email: env.MAILJET_FROM_EMAIL,
                            Name: "SAPTA SHAKTI AUDITORIUM"
                        },
                        To: [
                            {
                                Email: recipient,
                                Name: recipientName
                            }
                        ],
                        Subject: "Your SAPTA SHAKTI AUDITORIUM verification code",
                        HTMLPart: `
                            <div style="font-family:Arial,sans-serif;padding:25px">
                                <h2>SAPTA SHAKTI AUDITORIUM</h2>
                                <p>Dear ${escapeHTML(recipientName)},</p>
                                <p>Your email verification OTP is:</p>
                                <h1 style="letter-spacing:8px">${otp}</h1>
                                <p>This code expires in 5 minutes.</p>
                                <p>If you did not request this code, please ignore this email.</p>
                            </div>
                        `,
                        TextPart: `Dear ${recipientName}, your SAPTA SHAKTI AUDITORIUM verification OTP is ${otp}. It expires in 5 minutes.`
                    }
                ]
            })
        }
    );

    const responseText = await response.text();

    let result;

    try {
        result = JSON.parse(responseText);
    } catch {
        result = null;
    }

    if (!response.ok) {
        console.error("MAILJET HTTP ERROR:", {
            status: response.status,
            response: responseText
        });

        throw new Error(
            `Mailjet rejected the request. HTTP ${response.status}`
        );
    }

    const messageResult = result?.Messages?.[0];

    if (!messageResult || messageResult.Status !== "success") {
        console.error("MAILJET DELIVERY ERROR:", {
            status: messageResult?.Status || "Unknown",
            response: responseText
        });

        throw new Error("Mailjet did not accept the email.");
    }

    return true;
}

export async function onRequestPost({ request, env }) {
    let userId = null;
    let stage = "configuration";

    try {
        if (
            !env.DB ||
            !env.MAILJET_API_KEY ||
            !env.MAILJET_SECRET_KEY ||
            !env.MAILJET_FROM_EMAIL ||
            !env.OTP_HMAC_SECRET
        ) {
            console.error("Missing server configuration:", {
                DB: !!env.DB,
                MAILJET_API_KEY: !!env.MAILJET_API_KEY,
                MAILJET_SECRET_KEY: !!env.MAILJET_SECRET_KEY,
                MAILJET_FROM_EMAIL: !!env.MAILJET_FROM_EMAIL,
                OTP_HMAC_SECRET: !!env.OTP_HMAC_SECRET
            });

            return json({
                success: false,
                message: "Server configuration incomplete."
            }, 500);
        }

        stage = "request_validation";

        if (!request.headers.get("content-type")?.includes("application/json")) {
            return json({
                success: false,
                message: "JSON request required."
            }, 415);
        }

        const data = await request.json();

        stage = "input_validation";

        const fullName = String(data.fullName || "").trim();
        const mobile = normaliseMobile(data.mobile);
        const email = String(data.email || "").trim().toLowerCase();
        const selectedCategory = String(data.category || "").toUpperCase();
        const password = String(data.password || "");

        const categoryMapping = {
            OFFICER: {
                category: "OFFICER",
                serviceCategory: "SERVING"
            },
            JCO: {
                category: "JCO",
                serviceCategory: "SERVING"
            },
            OR: {
                category: "OR",
                serviceCategory: "SERVING"
            },
            EX_SERVICEMAN_OFFICER: {
                category: "OFFICER",
                serviceCategory: "EX_SERVICEMAN"
            },
            EX_SERVICEMAN_JCO: {
                category: "JCO",
                serviceCategory: "EX_SERVICEMAN"
            },
            EX_SERVICEMAN_OR: {
                category: "OR",
                serviceCategory: "EX_SERVICEMAN"
            },
            GUEST: {
                category: "GUEST",
                serviceCategory: null
            }
        };

        const selectedMapping = categoryMapping[selectedCategory];

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

        if (!selectedMapping) {
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

        stage = "password_hashing";

        const passwordHash = await hashPassword(password);

        stage = "user_insertion";

        const userResult = await env.DB.prepare(`
            INSERT INTO users (
                full_name,
                mobile,
                email,
                password_hash,
                category,
                service_category,
                mobile_verified,
                email_verified,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, 0, 'ACTIVE')
        `).bind(
            fullName,
            mobile,
            email,
            passwordHash,
            selectedMapping.category,
            selectedMapping.serviceCategory
        ).run();

        userId = userResult.meta.last_row_id;

        if (!userId) {
            throw new Error("User creation failed.");
        }

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

        stage = "otp_storage";

        await env.DB.prepare(`
            INSERT INTO verification_challenges (
                user_id, channel, otp_hash, expires_at
            )
            VALUES (?, 'EMAIL', ?, ?)
        `).bind(
            userId,
            otpHash,
            expiresAt
        ).run();

        stage = "mailjet_email";

        await sendMailjetEmail(
            env,
            email,
            fullName,
            otp
        );

        console.log("Registration and Mailjet OTP email request successful.");

        return json({
            success: true,
            message: "Registration initiated. Check your email for the verification code.",
            userId,
            expiresInSeconds: 300
        }, 201);

    } catch (error) {
        console.error("REGISTRATION FAILURE:", {
            stage,
            error: error?.message || String(error)
        });

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
            } catch (cleanupError) {
                console.error(
                    "REGISTRATION CLEANUP FAILURE:",
                    cleanupError.message
                );
            }
        }

        return json({
            success: false,
            message: "Registration could not be completed. Please try again."
        }, 500);
    }
}
