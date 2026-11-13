
async function sha256(value) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

export function jsonResponse(data, status = 200) {
    return Response.json(data, {
        status,
        headers: {
            "Cache-Control": "no-store",
            "Pragma": "no-cache"
        }
    });
}

export async function getAuthenticatedUser(request, env) {

    const cookie = request.headers.get("Cookie") || "";

    const match = cookie.match(
        /(?:^|;\s*)ssa_session=([a-f0-9]{64})(?:;|$)/
    );

    if (!match) {
        return null;
    }

    const tokenHash = await sha256(match[1]);

    const user = await env.DB.prepare(`
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
        !user ||
        user.status !== "ACTIVE" ||
        user.email_verified !== 1
    ) {
        return null;
    }

    return {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        category: user.category,
        role: user.role || "USER",
        sessionId: user.session_id,
        expiresAt: user.expires_at
    };
}

export async function requireRole(request, env, allowedRoles) {

    try {

        const user = await getAuthenticatedUser(request, env);

        if (!user) {
            return {
                authorized: false,
                response: jsonResponse({
                    success: false,
                    message: "Authentication required. Please log in."
                }, 401)
            };
        }

        if (!allowedRoles.includes(user.role)) {
            return {
                authorized: false,
                response: jsonResponse({
                    success: false,
                    message: "You are not authorised to access this resource."
                }, 403)
            };
        }

        return {
            authorized: true,
            user
        };

    } catch (error) {

        console.error("AUTHORIZATION ERROR:", error);

        return {
            authorized: false,
            response: jsonResponse({
                success: false,
                message: "Unable to verify access permissions."
            }, 500)
        };

    }
}

export async function requireSuperAdmin(request, env) {

    return requireRole(
        request,
        env,
        ["SUPER_ADMIN"]
    );

}

export async function requireAdmin(request, env) {

    return requireRole(
        request,
        env,
        ["SUPER_ADMIN", "ADMIN"]
    );

}
