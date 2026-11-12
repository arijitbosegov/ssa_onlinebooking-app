
async function sha256(value) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

export async function onRequestPost({ request, env }) {
    try {
        const cookie = request.headers.get("Cookie") || "";

        const match = cookie.match(
            /(?:^|;\s*)ssa_session=([a-f0-9]{64})(?:;|$)/
        );

        if (match) {
            const tokenHash = await sha256(match[1]);

            await env.DB.prepare(`
                DELETE FROM sessions
                WHERE token_hash = ?
            `).bind(tokenHash).run();
        }

        return Response.json({
            success: true,
            message: "You have been logged out successfully."
        }, {
            status: 200,
            headers: {
                "Cache-Control": "no-store",
                "Set-Cookie": "ssa_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
            }
        });

    } catch (error) {
        return Response.json({
            success: false,
            message: "Unable to complete logout."
        }, {
            status: 500,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }
}
