
import {
    requireSuperAdmin,
    jsonResponse
} from "../_auth.js";

/*
 * SAPTA SHAKTI AUDITORIUM
 * Super Admin - Master Seating Management API
 *
 * Sections:
 * GROUND_FLOOR: planned capacity 512
 * BALCONY: planned capacity 89
 *
 * Actual seat numbers will be configured from
 * the auditorium seating layout when available.
 */

const SECTION_CAPACITY = {
    GROUND_FLOOR: 512,
    BALCONY: 89
};

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

function getSeatId(request) {
    const url = new URL(request.url);
    const seatId = Number(url.searchParams.get("id"));

    if (!Number.isSafeInteger(seatId) || seatId < 1) {
        return null;
    }

    return seatId;
}

function validateSeat(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
        return "Invalid seat information.";
    }

    const seatNumber = typeof data.seat_number === "string"
        ? data.seat_number.trim()
        : "";

    const seatRow = typeof data.seat_row === "string"
        ? data.seat_row.trim()
        : "";

    const seatPosition = Number(data.seat_position);

    const seatSection = typeof data.seat_section === "string"
        ? data.seat_section.trim().toUpperCase()
        : "";

    const seatCategory = typeof data.seat_category === "string"
        ? data.seat_category.trim().toUpperCase()
        : "STANDARD";

    if (!seatNumber || seatNumber.length > 30) {
        return "Seat number must contain 1 to 30 characters.";
    }

    if (!seatRow || seatRow.length > 20) {
        return "Seat row must contain 1 to 20 characters.";
    }

    if (
        !Number.isSafeInteger(seatPosition) ||
        seatPosition < 1 ||
        seatPosition > 1000
    ) {
        return "Seat position must be a number between 1 and 1000.";
    }

    if (!Object.prototype.hasOwnProperty.call(
        SECTION_CAPACITY,
        seatSection
    )) {
        return "Seat section must be GROUND_FLOOR or BALCONY.";
    }

    if (!seatCategory || seatCategory.length > 30) {
        return "Please enter a valid seat category.";
    }

    if (
        data.is_active !== undefined &&
        ![0, 1, true, false].includes(data.is_active)
    ) {
        return "Seat active status must be true or false.";
    }

    return null;
}

function getSeatValues(data) {
    return {
        seatNumber: data.seat_number.trim(),
        seatRow: data.seat_row.trim(),
        seatPosition: Number(data.seat_position),
        seatSection: data.seat_section.trim().toUpperCase(),
        seatCategory: (
            typeof data.seat_category === "string"
                ? data.seat_category.trim().toUpperCase()
                : "STANDARD"
        ),
        isActive: data.is_active === undefined
            ? 1
            : (data.is_active === true || data.is_active === 1 ? 1 : 0)
    };
}

function isUniqueConstraintError(error) {
    return String(error?.message || "")
        .toLowerCase()
        .includes("unique constraint");
}

async function getSeatUsage(env, seatId) {
    const result = await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM show_seats
        WHERE seat_id = ?
    `).bind(seatId).first();

    return Number(result?.total || 0);
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
                s.seat_number,
                s.seat_row,
                s.seat_position,
                s.seat_category,
                s.seat_section,
                s.is_active,

                (
                    SELECT COUNT(*)
                    FROM show_seats ss
                    WHERE ss.seat_id = s.id
                ) AS show_assignments

            FROM seats s
            ORDER BY
                CASE s.seat_section
                    WHEN 'GROUND_FLOOR' THEN 1
                    WHEN 'BALCONY' THEN 2
                    ELSE 3
                END,
                s.seat_row,
                s.seat_position,
                s.id
        `).all();

        const seats = result.results || [];

        const summary = {};

        for (const section of Object.keys(SECTION_CAPACITY)) {
            const sectionSeats = seats.filter(
                seat => seat.seat_section === section
            );

            summary[section] = {
                plannedCapacity: SECTION_CAPACITY[section],
                configuredSeats: sectionSeats.length,
                activeSeats: sectionSeats.filter(
                    seat => seat.is_active === 1
                ).length,
                inactiveSeats: sectionSeats.filter(
                    seat => seat.is_active !== 1
                ).length
            };
        }

        return jsonResponse({
            success: true,
            seats,
            count: seats.length,
            totalPlannedCapacity: 601,
            summary
        });

    } catch (error) {
        console.error("ADMIN SEAT LIST ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to retrieve seating information."
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

        const validationError = validateSeat(data);

        if (validationError) {
            return jsonResponse({
                success: false,
                message: validationError
            }, 400);
        }

        const seat = getSeatValues(data);

        const sectionCount = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM seats
            WHERE seat_section = ?
        `).bind(seat.seatSection).first();

        if (
            Number(sectionCount?.total || 0) >=
            SECTION_CAPACITY[seat.seatSection]
        ) {
            return jsonResponse({
                success: false,
                message:
                    "The planned capacity for " +
                    seat.seatSection +
                    " has been reached."
            }, 409);
        }

        const result = await env.DB.prepare(`
            INSERT INTO seats (
                seat_number,
                seat_row,
                seat_position,
                seat_category,
                is_active,
                seat_section
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
            seat.seatNumber,
            seat.seatRow,
            seat.seatPosition,
            seat.seatCategory,
            seat.isActive,
            seat.seatSection
        ).run();

        return jsonResponse({
            success: true,
            message: "Seat added successfully.",
            seatId: result.meta.last_row_id
        }, 201);

    } catch (error) {
        console.error("ADMIN ADD SEAT ERROR:", error);

        if (isUniqueConstraintError(error)) {
            return jsonResponse({
                success: false,
                message: "This seat number already exists."
            }, 409);
        }

        return jsonResponse({
            success: false,
            message: "Unable to add seat."
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

        const seatId = getSeatId(request);

        if (!seatId) {
            return jsonResponse({
                success: false,
                message: "A valid seat ID is required."
            }, 400);
        }

        const existingSeat = await env.DB.prepare(`
            SELECT id
            FROM seats
            WHERE id = ?
            LIMIT 1
        `).bind(seatId).first();

        if (!existingSeat) {
            return jsonResponse({
                success: false,
                message: "Seat not found."
            }, 404);
        }

        const usageCount = await getSeatUsage(env, seatId);

        if (usageCount > 0) {
            return jsonResponse({
                success: false,
                message:
                    "This seat is already assigned to one or more shows. " +
                    "Its details cannot be modified."
            }, 409);
        }

        const data = await readJson(request);

        if (!data) {
            return jsonResponse({
                success: false,
                message: "Invalid JSON request."
            }, 400);
        }

        const validationError = validateSeat(data);

        if (validationError) {
            return jsonResponse({
                success: false,
                message: validationError
            }, 400);
        }

        const seat = getSeatValues(data);

        const sectionCount = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM seats
            WHERE seat_section = ?
              AND id != ?
        `).bind(
            seat.seatSection,
            seatId
        ).first();

        if (
            Number(sectionCount?.total || 0) >=
            SECTION_CAPACITY[seat.seatSection]
        ) {
            return jsonResponse({
                success: false,
                message:
                    "The planned capacity for " +
                    seat.seatSection +
                    " has been reached."
            }, 409);
        }

        await env.DB.prepare(`
            UPDATE seats
            SET
                seat_number = ?,
                seat_row = ?,
                seat_position = ?,
                seat_category = ?,
                seat_section = ?,
                is_active = ?
            WHERE id = ?
        `).bind(
            seat.seatNumber,
            seat.seatRow,
            seat.seatPosition,
            seat.seatCategory,
            seat.seatSection,
            seat.isActive,
            seatId
        ).run();

        return jsonResponse({
            success: true,
            message: "Seat updated successfully.",
            seatId
        });

    } catch (error) {
        console.error("ADMIN UPDATE SEAT ERROR:", error);

        if (isUniqueConstraintError(error)) {
            return jsonResponse({
                success: false,
                message: "This seat number already exists."
            }, 409);
        }

        return jsonResponse({
            success: false,
            message: "Unable to update seat."
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

        const seatId = getSeatId(request);

        if (!seatId) {
            return jsonResponse({
                success: false,
                message: "A valid seat ID is required."
            }, 400);
        }

        const existingSeat = await env.DB.prepare(`
            SELECT id, seat_number
            FROM seats
            WHERE id = ?
            LIMIT 1
        `).bind(seatId).first();

        if (!existingSeat) {
            return jsonResponse({
                success: false,
                message: "Seat not found."
            }, 404);
        }

        const usageCount = await getSeatUsage(env, seatId);

        if (usageCount > 0) {
            return jsonResponse({
                success: false,
                message:
                    "This seat is assigned to a show and cannot be " +
                    "deactivated. Preserve its existing show inventory."
            }, 409);
        }

        await env.DB.prepare(`
            UPDATE seats
            SET is_active = 0
            WHERE id = ?
        `).bind(seatId).run();

        return jsonResponse({
            success: true,
            message:
                "Seat " + existingSeat.seat_number +
                " has been deactivated.",
            seatId
        });

    } catch (error) {
        console.error("ADMIN DEACTIVATE SEAT ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to deactivate seat."
        }, 500);
    }
}
