
import {
    requireSuperAdmin,
    jsonResponse
} from "../_auth.js";

const ALLOWED_CATEGORIES = [
    "OFFICER",
    "JCO",
    "OR",
    "DEPENDANT",
    "GUEST"
];

const ALLOWED_SERVICE_CATEGORIES = [
    "SERVING",
    "EX_SERVICEMAN"
];

const ALLOWED_STATUSES = [
    "ACTIVE",
    "SUSPENDED"
];

function isSameOrigin(request) {
    const requestUrl = new URL(request.url);
    const origin = request.headers.get("Origin");
    const fetchSite = request.headers.get("Sec-Fetch-Site");

    if (fetchSite && fetchSite === "cross-site") {
        return false;
    }

    if (origin && origin !== requestUrl.origin) {
        return false;
    }

    return true;
}

function isJsonRequest(request) {
    const contentType = request.headers.get("Content-Type") || "";
    return contentType.toLowerCase().includes("application/json");
}

function escapeLike(value) {
    return value.replace(/[\\%_]/g, "\\$&");
}

export async function onRequestGet({ request, env }) {
    const auth = await requireSuperAdmin(request, env);

    if (!auth.authorized) {
        return auth.response;
    }

    try {
        const url = new URL(request.url);

        const search = (url.searchParams.get("search") || "").trim().slice(0, 100);
        const category = (url.searchParams.get("category") || "").trim().toUpperCase();
        const serviceCategory = (url.searchParams.get("service_category") || "")
            .trim()
            .toUpperCase();
        const status = (url.searchParams.get("status") || "").trim().toUpperCase();

        const requestedPage = Number.parseInt(url.searchParams.get("page") || "1", 10);
        const requestedLimit = Number.parseInt(url.searchParams.get("limit") || "20", 10);

        const page = Number.isInteger(requestedPage) && requestedPage > 0
            ? requestedPage
            : 1;
        const limit = Number.isInteger(requestedLimit)
            ? Math.min(Math.max(requestedLimit, 1), 100)
            : 20;
        const offset = (page - 1) * limit;

        if (category && !ALLOWED_CATEGORIES.includes(category)) {
            return jsonResponse({
                success: false,
                message: "Invalid user category filter."
            }, 400);
        }

        if (
            serviceCategory &&
            !ALLOWED_SERVICE_CATEGORIES.includes(serviceCategory)
        ) {
            return jsonResponse({
                success: false,
                message: "Invalid service category filter."
            }, 400);
        }

        if (status && !ALLOWED_STATUSES.includes(status)) {
            return jsonResponse({
                success: false,
                message: "Invalid account status filter."
            }, 400);
        }

        const conditions = [];
        const bindings = [];

        if (search) {
            const term = `%${escapeLike(search)}%`;
            conditions.push(`(
                full_name LIKE ? ESCAPE '\\'
                OR email LIKE ? ESCAPE '\\'
                OR mobile LIKE ? ESCAPE '\\'
                OR CAST(id AS TEXT) LIKE ? ESCAPE '\\'
            )`);
            bindings.push(term, term, term, term);
        }

        if (category) {
            conditions.push("category = ?");
            bindings.push(category);
        }

        if (serviceCategory) {
            conditions.push("service_category = ?");
            bindings.push(serviceCategory);
        }

        if (status) {
            conditions.push("status = ?");
            bindings.push(status);
        }

        const whereClause = conditions.length
            ? `WHERE ${conditions.join(" AND ")}`
            : "";

        const countResult = await env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM users
            ${whereClause}
        `).bind(...bindings).first();

        const total = Number(countResult?.total || 0);
        const totalPages = Math.ceil(total / limit);

        const usersResult = await env.DB.prepare(`
            SELECT
                id,
                full_name,
                mobile,
                email,
                category,
                service_category,
                role,
                status,
                email_verified,
                mobile_verified,
                created_at
            FROM users
            ${whereClause}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
        `).bind(...bindings, limit, offset).all();

        const users = (usersResult.results || []).map(user => ({
            id: user.id,
            fullName: user.full_name,
            mobile: user.mobile,
            email: user.email,
            category: user.category,
            serviceCategory: user.service_category,
            role: user.role || "USER",
            status: user.status,
            emailVerified: Number(user.email_verified) === 1,
            mobileVerified: Number(user.mobile_verified) === 1,
            createdAt: user.created_at
        }));

        return jsonResponse({
            success: true,
            users,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasPreviousPage: page > 1,
                hasNextPage: page < totalPages
            },
            filters: {
                search,
                category: category || null,
                serviceCategory: serviceCategory || null,
                status: status || null
            }
        });

    } catch (error) {
        console.error("ADMIN USERS GET ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to load user records."
        }, 500);
    }
}

export async function onRequestPut({ request, env }) {
    const auth = await requireSuperAdmin(request, env);

    if (!auth.authorized) {
        return auth.response;
    }

    if (!isSameOrigin(request)) {
        return jsonResponse({
            success: false,
            message: "Cross-origin requests are not permitted."
        }, 403);
    }

    if (!isJsonRequest(request)) {
        return jsonResponse({
            success: false,
            message: "Content-Type must be application/json."
        }, 415);
    }

    try {
        const body = await request.json();

        const userId = Number(body.user_id);
        const newStatus = String(body.status || "").trim().toUpperCase();

        if (!Number.isSafeInteger(userId) || userId <= 0) {
            return jsonResponse({
                success: false,
                message: "A valid user ID is required."
            }, 400);
        }

        if (!ALLOWED_STATUSES.includes(newStatus)) {
            return jsonResponse({
                success: false,
                message: "Status must be ACTIVE or SUSPENDED."
            }, 400);
        }

        if (userId === auth.user.id) {
            return jsonResponse({
                success: false,
                message: "You cannot change your own account status."
            }, 403);
        }

        const targetUser = await env.DB.prepare(`
            SELECT id, full_name, role, status
            FROM users
            WHERE id = ?
            LIMIT 1
        `).bind(userId).first();

        if (!targetUser) {
            return jsonResponse({
                success: false,
                message: "User account not found."
            }, 404);
        }

        if (targetUser.role === "SUPER_ADMIN") {
            return jsonResponse({
                success: false,
                message: "Super Admin accounts cannot be suspended or changed through User Management."
            }, 403);
        }

        if (targetUser.status === newStatus) {
            return jsonResponse({
                success: true,
                message: `Account is already ${newStatus.toLowerCase()}.`,
                userId,
                status: newStatus
            });
        }

        await env.DB.prepare(`
            UPDATE users
            SET status = ?
            WHERE id = ?
        `).bind(newStatus, userId).run();

        return jsonResponse({
            success: true,
            message: newStatus === "SUSPENDED"
                ? "User account suspended successfully."
                : "User account reactivated successfully.",
            userId,
            fullName: targetUser.full_name,
            status: newStatus
        });

    } catch (error) {
        console.error("ADMIN USERS PUT ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to update the user account."
        }, 500);
    }
}

export async function onRequestPost({ request }) {
    return jsonResponse({
        success: false,
        message: "Use GET to view users and PUT to update account status."
    }, 405);
}

export async function onRequestDelete({ request }) {
    return jsonResponse({
        success: false,
        message: "Permanent deletion of user accounts is not supported."
    }, 405);
}
