
async function sha256(value) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function json(data, status = 200) {
    return Response.json(data, {
        status,
        headers: {
            "Cache-Control": "no-store",
            "Pragma": "no-cache"
        }
    });
}

export async function onRequestGet({ request, env }) {

    try {

        const cookie = request.headers.get("Cookie") || "";

        const match = cookie.match(
            /(?:^|;\s*)ssa_session=([a-f0-9]{64})(?:;|$)/
        );

        if (!match) {

            return json({
                success: false,
                authenticated: false,
                message: "Please log in."
            }, 401);

        }

        const tokenHash = await sha256(match[1]);

        const session = await env.DB.prepare(`
            SELECT
                s.id AS session_id,
                s.expires_at,
                u.id,
                u.full_name,
                u.email,
                u.category,
                u.role,
                u.status,
                u.email_verified
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND datetime(s.expires_at) > datetime('now')
            LIMIT 1
        `).bind(tokenHash).first();

        if (
            !session ||
            session.status !== "ACTIVE" ||
            session.email_verified !== 1
        ) {

            return json({
                success: false,
                authenticated: false,
                message: "Session expired. Please log in again."
            }, 401);

        }

        const role = session.role || "USER";

        const isSuperAdmin = role === "SUPER_ADMIN";

        const isAdmin = [
            "SUPER_ADMIN",
            "ADMIN"
        ].includes(role);

        return json({

            success: true,

            authenticated: true,

            user: {
                id: session.id,
                fullName: session.full_name,
                email: session.email,
                category: session.category,
                role: role,

                permissions: {
                    isAdmin: isAdmin,
                    isSuperAdmin: isSuperAdmin
                }
            },

            expiresAt: session.expires_at

        });

    } catch (error) {

        console.error("SESSION VALIDATION ERROR:", error);

        return json({
            success: false,
            authenticated: false,
            message: "Unable to validate session."
        }, 500);

    }
}
