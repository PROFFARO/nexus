import type { Metadata } from "next";

export const metadata: Metadata = {
    title: "Sign In - NEXUS",
    description: "Sign in to your NEXUS account",
};

export default function SignInLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return <>{children}</>;
}
