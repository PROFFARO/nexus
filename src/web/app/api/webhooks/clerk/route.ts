import { Webhook } from "svix";
import { headers } from "next/headers";
import { WebhookEvent } from "@clerk/nextjs/server";
import { connectToDatabase } from "@/lib/db/mongodb";
import { User, defaultPermissions } from "@/lib/db/models";
import { NextResponse } from "next/server";

export async function POST(req: Request) {
    // Get the Clerk webhook secret from environment
    const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET;

    if (!WEBHOOK_SECRET) {
        console.error("Missing CLERK_WEBHOOK_SECRET");
        return new NextResponse("Missing webhook secret", { status: 500 });
    }

    // Get the headers
    const headerPayload = await headers();
    const svix_id = headerPayload.get("svix-id");
    const svix_timestamp = headerPayload.get("svix-timestamp");
    const svix_signature = headerPayload.get("svix-signature");

    // If there are no headers, error out
    if (!svix_id || !svix_timestamp || !svix_signature) {
        return new NextResponse("Missing svix headers", { status: 400 });
    }

    // Get the body
    const payload = await req.json();
    const body = JSON.stringify(payload);

    // Create a new Svix instance with your secret
    const wh = new Webhook(WEBHOOK_SECRET);

    let evt: WebhookEvent;

    // Verify the payload with the headers
    try {
        evt = wh.verify(body, {
            "svix-id": svix_id,
            "svix-timestamp": svix_timestamp,
            "svix-signature": svix_signature,
        }) as WebhookEvent;
    } catch (err) {
        console.error("Error verifying webhook:", err);
        return new NextResponse("Error verifying webhook", { status: 400 });
    }

    // Connect to database
    await connectToDatabase();

    const eventType = evt.type;

    // Handle different webhook events
    switch (eventType) {
        case "user.created": {
            const { id, email_addresses, first_name, last_name } = evt.data;
            const primaryEmail = email_addresses?.[0]?.email_address;

            if (!primaryEmail) {
                console.error("No email found for user:", id);
                return new NextResponse("No email found", { status: 400 });
            }

            // Check if this is the first user - make them admin
            const userCount = await User.countDocuments();
            const role = userCount === 0 ? "admin" : "viewer";

            try {
                await User.create({
                    clerkId: id,
                    email: primaryEmail,
                    firstName: first_name || undefined,
                    lastName: last_name || undefined,
                    role,
                    permissions: defaultPermissions[role],
                    isActive: true,
                });
                console.log(`Created user ${primaryEmail} with role ${role}`);
            } catch (error) {
                console.error("Error creating user:", error);
                return new NextResponse("Error creating user", { status: 500 });
            }
            break;
        }

        case "user.updated": {
            const { id, email_addresses, first_name, last_name } = evt.data;
            const primaryEmail = email_addresses?.[0]?.email_address;

            try {
                await User.findOneAndUpdate(
                    { clerkId: id },
                    {
                        email: primaryEmail,
                        firstName: first_name || undefined,
                        lastName: last_name || undefined,
                    }
                );
                console.log(`Updated user ${id}`);
            } catch (error) {
                console.error("Error updating user:", error);
            }
            break;
        }

        case "user.deleted": {
            const { id } = evt.data;

            try {
                // Soft delete - just deactivate the user
                await User.findOneAndUpdate({ clerkId: id }, { isActive: false });
                console.log(`Deactivated user ${id}`);
            } catch (error) {
                console.error("Error deactivating user:", error);
            }
            break;
        }

        case "session.created": {
            const { user_id } = evt.data;

            try {
                await User.findOneAndUpdate(
                    { clerkId: user_id },
                    { lastLoginAt: new Date() }
                );
            } catch (error) {
                console.error("Error updating last login:", error);
            }
            break;
        }

        default:
            console.log(`Unhandled webhook event: ${eventType}`);
    }

    return new NextResponse("Webhook processed", { status: 200 });
}
