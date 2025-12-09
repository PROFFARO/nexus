import type { Metadata } from "next";

export const metadata: Metadata = {
    title: "Sign Up - NEXUS",
    description: "Create your free NEXUS account",
};

export default function SignUpLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return <>{children}</>;
}
