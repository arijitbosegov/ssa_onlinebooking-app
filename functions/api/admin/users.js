
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

    if (fetchSite === "cross-site") return false;
    if (origin && origin !== requestUrl.origin) return false;

    return true;
}

function isJsonRequest(request) {
    const contentType = request.headers.get("Content-Type") || "";
    return contentType.toLowerCase().includes("application/json");
}

function escapeLike(value) {
    return value.replace(/[\\%_]/g, "\\$&");
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validMobile(mobile) {
    return /^\d{10,15}$/.test(mobile);
}

export async function onRequestGet({ request, env }) {
    const auth = await requireSuperAdmin(request, env);

    if (!auth.authorized) return auth.response;

    try {
        const url = new URL(request.url);

        const search = (url.searchParams.get("search") || "").trim().slice(0, 100);
        const category = (url.searchParams.get("category") || "").trim().toUpperCase();
        const serviceCategory = (url.searchParams.get("service_category") || "")
            .trim().toUpperCase();
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

        if (serviceCategory && !ALLOWED_SERVICE_CATEGORIES.includes(serviceCategory)) {
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
                u.id,
                u.full_name,
                u.mobile,
                u.email,
                u.category,
                u.service_category,
                u.role,
                u.status,
                u.email_verified,
                u.mobile_verified,
                u.created_at,
                (
                    SELECT c.proposed_value
                    FROM user_contact_change_requests c
                    WHERE c.user_id = u.id
                      AND c.contact_type = 'EMAIL'
                      AND c.status = 'PENDING'
                    ORDER BY c.created_at DESC, c.id DESC
                    LIMIT 1
                ) AS pending_email
            FROM users u
            ${whereClause ? whereClause.replace(/\b(full_name|email|mobile|category|service_category|status)\b/g, "u.$1") : ""}
            ORDER BY u.created_at DESC, u.id DESC
            LIMIT ? OFFSET ?
        `).bind(...bindings, limit, offset).all();

        const users = (usersResult.results || []).map(user => ({
            id: user.id,
            fullName: user.full_name,
            mobile: user.mobile,
            email: user.email,
            pendingEmail: user.pending_email || null,
            emailChangePending: Boolean(user.pending_email),
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

    if (!auth.authorized) return auth.response;

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

        if (!Number.isSafeInteger(userId) || userId <= 0) {
            return jsonResponse({
                success: false,
                message: "A valid user ID is required."
            }, 400);
        }

        const targetUser = await env.DB.prepare(`
            SELECT id, full_name, mobile, email, category,
                   service_category, role, status
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
                message: "Super Admin accounts are protected from editing through User Management."
            }, 403);
        }

        // Account status update
        if (Object.prototype.hasOwnProperty.call(body, "status")) {
            const newStatus = String(body.status || "").trim().toUpperCase();

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
        }

        // Profile update
        const fullName = String(body.full_name || "").trim();
        const mobile = String(body.mobile || "").replace(/\D/g, "");
        const email = String(body.email || "").trim().toLowerCase();
        const category = String(body.category || "").trim().toUpperCase();
        const serviceCategory = body.service_category
            ? String(body.service_category).trim().toUpperCase()
            : null;

        if (!fullName || fullName.length > 150) {
            return jsonResponse({
                success: false,
                message: "Enter a valid full name (maximum 150 characters)."
            }, 400);
        }

        if (!validMobile(mobile)) {
            return jsonResponse({
                success: false,
                message: "Enter a valid mobile number containing 10 to 15 digits."
            }, 400);
        }

        if (!validEmail(email) || email.length > 254) {
            return jsonResponse({
                success: false,
                message: "Enter a valid email address."
            }, 400);
        }

        if (!ALLOWED_CATEGORIES.includes(category)) {
            return jsonResponse({
                success: false,
                message: "Invalid user category."
            }, 400);
        }

        if (
            serviceCategory &&
            !ALLOWED_SERVICE_CATEGORIES.includes(serviceCategory)
        ) {
            return jsonResponse({
                success: false,
                message: "Invalid service classification."
            }, 400);
        }

        if (category === "GUEST" && serviceCategory) {
            return jsonResponse({
                success: false,
                message: "Guest accounts cannot have a service classification."
            }, 400);
        }

        const mobileOwner = await env.DB.prepare(`
            SELECT id FROM users
            WHERE mobile = ? AND id != ?
            LIMIT 1
        `).bind(mobile, userId).first();

        if (mobileOwner) {
            return jsonResponse({
                success: false,
                message: "This mobile number is already registered to another account."
            }, 409);
        }

        const emailChanged = email !== String(targetUser.email).toLowerCase();

        if (emailChanged) {
            const emailOwner = await env.DB.prepare(`
                SELECT id FROM users
                WHERE LOWER(email) = LOWER(?) AND id != ?
                LIMIT 1
            `).bind(email, userId).first();

            if (emailOwner) {
                return jsonResponse({
                    success: false,
                    message: "This email address is already registered to another account."
                }, 409);
            }

            const pendingOwner = await env.DB.prepare(`
                SELECT user_id
                FROM user_contact_change_requests
                WHERE contact_type = 'EMAIL'
                  AND status = 'PENDING'
                  AND LOWER(proposed_value) = LOWER(?)
                  AND user_id != ?
                LIMIT 1
            `).bind(email, userId).first();

            if (pendingOwner) {
                return jsonResponse({
                    success: false,
                    message: "This email address is already pending verification for another account."
                }, 409);
            }
        }

        const statements = [
            env.DB.prepare(`
                UPDATE users
                SET full_name = ?,
                    mobile = ?,
                    category = ?,
                    service_category = ?
                WHERE id = ?
            `).bind(
                fullName,
                mobile,
                category,
                serviceCategory,
                userId
            )
        ];

        if (emailChanged) {
            statements.push(
                env.DB.prepare(`
                    UPDATE user_contact_change_requests
                    SET status = 'CANCELLED'
                    WHERE user_id = ?
                      AND contact_type = 'EMAIL'
                      AND status = 'PENDING'
                `).bind(userId)
            );

            statements.push(
                env.DB.prepare(`
                    INSERT INTO user_contact_change_requests (
                        user_id,
                        contact_type,
                        proposed_value,
                        status,
                        created_by_admin_id
                    )
                    VALUES (?, 'EMAIL', ?, 'PENDING', ?)
                `).bind(userId, email, auth.user.id)
            );
        }

        await env.DB.batch(statements);

        return jsonResponse({
            success: true,
            message: emailChanged
                ? "User profile updated. The new email is pending verification by the individual user."
                : "User profile updated successfully.",
            userId,
            emailChangePending: emailChanged,
            pendingEmail: emailChanged ? email : null
        });

    } catch (error) {
        console.error("ADMIN USERS PUT ERROR:", error);

        return jsonResponse({
            success: false,
            message: "Unable to update the user profile."
        }, 500);
    }
}

export async function onRequestPost() {
    return jsonResponse({
        success: false,
        message: "Use GET to view users and PUT to update user records."
    }, 405);
}

export async function onRequestDelete() {
    return jsonResponse({
        success: false,
        message: "Permanent deletion of user accounts is not supported."
    }, 405);
}
