import { SignUp } from "@clerk/nextjs";

export default function SignUpPage() {
    return (
        <div className="flex min-h-screen items-center justify-center bg-[#0a0a0f]">
            <SignUp
                appearance={{
                    elements: {
                        formButtonPrimary: "bg-teal-500 hover:bg-teal-600",
                    },
                }}
                fallbackRedirectUrl="/"
                signInUrl="/sign-in"
            />
        </div>
    );
}
