import {
    requireSuperAdmin,
    jsonResponse
} from "../_auth.js";

function validateMovie(data) {

    if (!data || typeof data !== "object" || Array.isArray(data)) {
        return "Invalid movie information.";
    }

    const title = typeof data.title === "string"
        ? data.title.trim()
        : "";

    const description = typeof data.description === "string"
        ? data.description.trim()
        : "";

    const language = typeof data.language === "string"
        ? data.language.trim()
        : "";

    const certification = typeof data.certification === "string"
        ? data.certification.trim().toUpperCase()
        : "";

    const duration = Number(data.duration_minutes);

    if (title.length < 2 || title.length > 150) {
        return "Movie title must contain 2 to 150 characters.";
    }

    if (description.length > 3000) {
        return "Description cannot exceed 3000 characters.";
    }

    if (!language || language.length > 50) {
        return "Please enter a valid movie language.";
    }

    if (
        !Number.isInteger(duration) ||
        duration < 1 ||
        duration > 500
    ) {
        return "Duration must be between 1 and 500 minutes.";
    }

    if (!certification || certification.length > 10) {
        return "Please enter a valid movie certification.";
    }

    const posterUrl = typeof data.poster_url === "string"
        ? data.poster_url.trim()
        : "";

    if (posterUrl) {
        try {
            const parsedUrl = new URL(posterUrl);

            if (parsedUrl.protocol !== "https:") {
                return "Poster URL must use HTTPS.";
            }

        } catch {
            return "Please enter a valid poster URL.";
        }
    }

    const releaseDate = data.release_date || null;

    if (releaseDate !== null) {

        if (
            typeof releaseDate !== "string" ||
            !/^\d{4}-\d{2}-\d{2}$/.test(releaseDate)
        ) {
            return "Release date must use YYYY-MM-DD format.";
        }

        const parsedDate = new Date(releaseDate + "T00:00:00Z");

        if (
            Number.isNaN(parsedDate.getTime()) ||
            parsedDate.toISOString().slice(0, 10) !== releaseDate
        ) {
            return "Please enter a valid release date.";
        }
    }

    const status = data.status || "ACTIVE";

    if (!["ACTIVE", "INACTIVE"].includes(status)) {
        return "Movie status must be ACTIVE or INACTIVE.";
    }

    return null;
}

export async function onRequestGet({ request, env }) {

    try {

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const result = await env.DB.prepare(`
            SELECT
                id,
                title,
                description,
                language,
                duration_minutes,
                certification,
                poster_url,
                release_date,
                status,
                created_at
            FROM movies
            ORDER BY created_at DESC, id DESC
        `).all();

        return jsonResponse({
            success: true,
            movies: result.results || [],
            count: (result.results || []).length
        });

    } catch (error) {

        console.error("ADMIN MOVIE LIST ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to retrieve movies."
        }, 500);

    }
}

export async function onRequestPost({ request, env }) {

    try {

        const requestOrigin = request.headers.get("Origin");
        const applicationOrigin = new URL(request.url).origin;

        if (requestOrigin !== applicationOrigin) {
            return jsonResponse({
                success: false,
                message: "Request origin could not be verified."
            }, 403);
        }

        const contentType = request.headers.get("Content-Type") || "";

        if (!contentType.toLowerCase().startsWith("application/json")) {
            return jsonResponse({
                success: false,
                message: "Content-Type must be application/json."
            }, 415);
        }

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const data = await request.json();

        const validationError = validateMovie(data);

        if (validationError) {
            return jsonResponse({
                success: false,
                message: validationError
            }, 400);
        }

        const title = data.title.trim();
        const description = (data.description || "").trim();
        const language = data.language.trim();
        const duration = Number(data.duration_minutes);
        const certification = data.certification.trim().toUpperCase();
        const posterUrl = (data.poster_url || "").trim() || null;
        const releaseDate = data.release_date || null;
        const status = data.status || "ACTIVE";

        const result = await env.DB.prepare(`
            INSERT INTO movies (
                title,
                description,
                language,
                duration_minutes,
                certification,
                poster_url,
                release_date,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            title,
            description,
            language,
            duration,
            certification,
            posterUrl,
            releaseDate,
            status
        ).run();

        return jsonResponse({
            success: true,
            message: "Movie added successfully.",
            movieId: result.meta.last_row_id
        }, 201);

    } catch (error) {

        console.error("ADMIN ADD MOVIE ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to add movie."
        }, 500);

    }
}

export async function onRequestDelete({ request, env }) {

    try {

        const requestOrigin = request.headers.get("Origin");
        const applicationOrigin = new URL(request.url).origin;

        if (requestOrigin !== applicationOrigin) {
            return jsonResponse({
                success: false,
                message: "Request origin could not be verified."
            }, 403);
        }

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const url = new URL(request.url);
        const movieId = Number(url.searchParams.get("id"));

        if (
            !Number.isSafeInteger(movieId) ||
            movieId < 1
        ) {
            return jsonResponse({
                success: false,
                message: "A valid movie ID is required."
            }, 400);
        }

        const movie = await env.DB.prepare(`
            SELECT id, title
            FROM movies
            WHERE id = ?
            LIMIT 1
        `).bind(movieId).first();

        if (!movie) {
            return jsonResponse({
                success: false,
                message: "Movie not found."
            }, 404);
        }

        const linkedShow = await env.DB.prepare(`
            SELECT id
            FROM shows
            WHERE movie_id = ?
            LIMIT 1
        `).bind(movieId).first();

        if (linkedShow) {
            return jsonResponse({
                success: false,
                message: "This movie is linked to an existing show and cannot be deleted. Change its status to INACTIVE instead."
            }, 409);
        }

        await env.DB.prepare(`
            DELETE FROM movies
            WHERE id = ?
        `).bind(movieId).run();

        return jsonResponse({
            success: true,
            message: "Movie '" + movie.title + "' deleted successfully."
        });

    } catch (error) {

        console.error("ADMIN DELETE MOVIE ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to delete movie. It may be linked to other records."
        }, 500);

    }
}
