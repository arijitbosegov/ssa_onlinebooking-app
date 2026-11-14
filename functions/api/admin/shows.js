
import {
    requireSuperAdmin,
    jsonResponse
} from "../_auth.js";

/*
 * SAPTA SHAKTI AUDITORIUM
 * Super Admin - Show Management API
 *
 * Show types:
 * MATINEE
 * EVENING
 *
 * Internal show_time values are stored as MATINEE / EVENING
 * to preserve the existing database UNIQUE constraint:
 * UNIQUE (show_date, show_time)
 *
 * Booking remains closed until seat inventory is configured.
 */

function verifySameOrigin(request) {
    const requestOrigin = request.headers.get("Origin");
    const applicationOrigin = new URL(request.url).origin;

    return requestOrigin === applicationOrigin;
}

function verifyJsonContentType(request) {
    const contentType = request.headers.get("Content-Type") || "";

    return contentType.toLowerCase().startsWith("application/json");
}

async function readJson(request) {
    try {
        return await request.json();
    } catch {
        return null;
    }
}

function validateShow(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
        return "Invalid show information.";
    }

    const movieId = Number(data.movie_id);

    if (!Number.isSafeInteger(movieId) || movieId < 1) {
        return "Please select a valid movie.";
    }

    const showDate = typeof data.show_date === "string"
        ? data.show_date.trim()
        : "";

    if (!/^\d{4}-\d{2}-\d{2}$/.test(showDate)) {
        return "Show date must use YYYY-MM-DD format.";
    }

    const parsedDate = new Date(showDate + "T00:00:00Z");

    if (
        Number.isNaN(parsedDate.getTime()) ||
        parsedDate.toISOString().slice(0, 10) !== showDate
    ) {
        return "Please enter a valid show date.";
    }

    const showType = typeof data.show_type === "string"
        ? data.show_type.trim().toUpperCase()
        : "";

    if (!["MATINEE", "EVENING"].includes(showType)) {
        return "Show type must be MATINEE or EVENING.";
    }

    return null;
}

function getShowValues(data) {
    const showType = data.show_type.trim().toUpperCase();

    return {
        movieId: Number(data.movie_id),
        showDate: data.show_date.trim(),
        showType,
        showTime: showType
    };
}

function getShowId(request) {
    const url = new URL(request.url);
    const showId = Number(url.searchParams.get("id"));

    if (!Number.isSafeInteger(showId) || showId < 1) {
        return null;
    }

    return showId;
}

async function getActiveMovie(env, movieId) {
    return env.DB.prepare(`
        SELECT id, title
        FROM movies
        WHERE id = ?
          AND status = 'ACTIVE'
        LIMIT 1
    `).bind(movieId).first();
}

async function hasBookings(env, showId) {
    const result = await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM bookings
        WHERE show_id = ?
    `).bind(showId).first();

    return Number(result?.total || 0);
}

function isUniqueConstraintError(error) {
    return String(error?.message || "")
        .toLowerCase()
        .includes("unique constraint");
}

export async function onRequestGet({ request, env }) {
    try {
        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const result = await env.DB.prepare(`
            SELECT
                s.id,
                s.movie_id,
                m.title AS movie_title,
                m.language,
                m.certification,
                m.poster_url,
                s.show_date,
                s.show_type,
                s.booking_open,
                s.status,
                s.created_at,

                (
                    SELECT COUNT(*)
                    FROM seats st
                    WHERE st.is_active = 1
                ) AS configured_seats,

                (
                    SELECT COUNT(*)
                    FROM show_seats ss
                    WHERE ss.show_id = s.id
                ) AS show_seat_count

            FROM shows s
            LEFT JOIN movies m ON m.id = s.movie_id
            ORDER BY
                s.show_date DESC,
                CASE s.show_type
                    WHEN 'MATINEE' THEN 1
                    WHEN 'EVENING' THEN 2
                    ELSE 3
                END,
                s.id DESC
        `).all();

        return jsonResponse({
            success: true,
            shows: result.results || [],
            count: (result.results || []).length
        });

    } catch (error) {
        console.error("ADMIN SHOW LIST ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to retrieve shows."
        }, 500);
    }
}

export async function onRequestPost({ request, env }) {
    try {
        if (!verifySameOrigin(request)) {
            return jsonResponse({
                success: false,
                message: "Request origin could not be verified."
            }, 403);
        }

        if (!verifyJsonContentType(request)) {
            return jsonResponse({
                success: false,
                message: "Content-Type must be application/json."
            }, 415);
        }

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const data = await readJson(request);

        if (!data) {
            return jsonResponse({
                success: false,
                message: "Invalid JSON request."
            }, 400);
        }

        const validationError = validateShow(data);

        if (validationError) {
            return jsonResponse({
                success: false,
                message: validationError
            }, 400);
        }

        const show = getShowValues(data);

        const movie = await getActiveMovie(env, show.movieId);

        if (!movie) {
            return jsonResponse({
                success: false,
                message: "Selected movie was not found or is inactive."
            }, 404);
        }

        const duplicate = await env.DB.prepare(`
            SELECT id
            FROM shows
            WHERE show_date = ?
              AND show_time = ?
            LIMIT 1
        `).bind(
            show.showDate,
            show.showTime
        ).first();

        if (duplicate) {
            return jsonResponse({
                success: false,
                message:
                    "A " + show.showType +
                    " show already exists on this date."
            }, 409);
        }

        const result = await env.DB.prepare(`
            INSERT INTO shows (
                movie_id,
                show_date,
                show_time,
                show_type,
                ticket_price,
                booking_open,
                status
            )
            VALUES (?, ?, ?, ?, 0, 0, 'SCHEDULED')
        `).bind(
            show.movieId,
            show.showDate,
            show.showTime,
            show.showType
        ).run();

        return jsonResponse({
            success: true,
            message:
                show.showType +
                " show created successfully. Booking remains closed until seating is configured.",
            showId: result.meta.last_row_id,
            bookingOpen: false
        }, 201);

    } catch (error) {
        console.error("ADMIN ADD SHOW ERROR:", error);

        if (isUniqueConstraintError(error)) {
            return jsonResponse({
                success: false,
                message: "A show of this type already exists on this date."
            }, 409);
        }

        return jsonResponse({
            success: false,
            message: "Unable to create show."
        }, 500);
    }
}

export async function onRequestPut({ request, env }) {
    try {
        if (!verifySameOrigin(request)) {
            return jsonResponse({
                success: false,
                message: "Request origin could not be verified."
            }, 403);
        }

        if (!verifyJsonContentType(request)) {
            return jsonResponse({
                success: false,
                message: "Content-Type must be application/json."
            }, 415);
        }

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const showId = getShowId(request);

        if (!showId) {
            return jsonResponse({
                success: false,
                message: "A valid show ID is required."
            }, 400);
        }

        const existingShow = await env.DB.prepare(`
            SELECT id, status
            FROM shows
            WHERE id = ?
            LIMIT 1
        `).bind(showId).first();

        if (!existingShow) {
            return jsonResponse({
                success: false,
                message: "Show not found."
            }, 404);
        }

        if (existingShow.status !== "SCHEDULED") {
            return jsonResponse({
                success: false,
                message: "Only scheduled shows can be edited."
            }, 409);
        }

        const bookingCount = await hasBookings(env, showId);

        if (bookingCount > 0) {
            return jsonResponse({
                success: false,
                message: "This show has booking records and cannot be edited."
            }, 409);
        }

        const data = await readJson(request);

        if (!data) {
            return jsonResponse({
                success: false,
                message: "Invalid JSON request."
            }, 400);
        }

        const validationError = validateShow(data);

        if (validationError) {
            return jsonResponse({
                success: false,
                message: validationError
            }, 400);
        }

        const show = getShowValues(data);

        const movie = await getActiveMovie(env, show.movieId);

        if (!movie) {
            return jsonResponse({
                success: false,
                message: "Selected movie was not found or is inactive."
            }, 404);
        }

        const duplicate = await env.DB.prepare(`
            SELECT id
            FROM shows
            WHERE show_date = ?
              AND show_time = ?
              AND id != ?
            LIMIT 1
        `).bind(
            show.showDate,
            show.showTime,
            showId
        ).first();

        if (duplicate) {
            return jsonResponse({
                success: false,
                message:
                    "A " + show.showType +
                    " show already exists on this date."
            }, 409);
        }

        await env.DB.prepare(`
            UPDATE shows
            SET
                movie_id = ?,
                show_date = ?,
                show_time = ?,
                show_type = ?,
                ticket_price = 0,
                booking_open = 0
            WHERE id = ?
        `).bind(
            show.movieId,
            show.showDate,
            show.showTime,
            show.showType,
            showId
        ).run();

        return jsonResponse({
            success: true,
            message: "Show updated successfully. Booking remains closed.",
            showId,
            bookingOpen: false
        });

    } catch (error) {
        console.error("ADMIN UPDATE SHOW ERROR:", error);

        if (isUniqueConstraintError(error)) {
            return jsonResponse({
                success: false,
                message: "A show of this type already exists on this date."
            }, 409);
        }

        return jsonResponse({
            success: false,
            message: "Unable to update show."
        }, 500);
    }
}

export async function onRequestDelete({ request, env }) {
    try {
        if (!verifySameOrigin(request)) {
            return jsonResponse({
                success: false,
                message: "Request origin could not be verified."
            }, 403);
        }

        const auth = await requireSuperAdmin(request, env);

        if (!auth.authorized) {
            return auth.response;
        }

        const showId = getShowId(request);

        if (!showId) {
            return jsonResponse({
                success: false,
                message: "A valid show ID is required."
            }, 400);
        }

        const show = await env.DB.prepare(`
            SELECT id, status, show_type
            FROM shows
            WHERE id = ?
            LIMIT 1
        `).bind(showId).first();

        if (!show) {
            return jsonResponse({
                success: false,
                message: "Show not found."
            }, 404);
        }

        if (show.status === "COMPLETED") {
            return jsonResponse({
                success: false,
                message: "A completed show cannot be cancelled."
            }, 409);
        }

        if (show.status === "CANCELLED") {
            return jsonResponse({
                success: true,
                message: "This show is already cancelled."
            });
        }

        await env.DB.prepare(`
            UPDATE shows
            SET
                status = 'CANCELLED',
                booking_open = 0
            WHERE id = ?
        `).bind(showId).run();

        return jsonResponse({
            success: true,
            message: show.show_type + " show cancelled successfully.",
            showId
        });

    } catch (error) {
        console.error("ADMIN CANCEL SHOW ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to cancel show."
        }, 500);
    }
}
