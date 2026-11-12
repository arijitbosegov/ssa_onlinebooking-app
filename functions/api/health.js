
export async function onRequestGet({ env }) {
    try {
        const result = await env.DB
            .prepare("SELECT 1 AS connected")
            .first();

        return Response.json({
            status: "success",
            database: result?.connected === 1
                ? "connected"
                : "error",
            application: "SAPTA SHAKTI AUDITORIUM",
            message: "Database connection successful"
        });

    } catch (error) {
        return Response.json({
            status: "error",
            database: "disconnected",
            message: error.message
        }, { status: 500 });
    }
}
