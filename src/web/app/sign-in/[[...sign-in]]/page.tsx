import { SignIn } from "@clerk/nextjs";

export default function SignInPage() {
    return (
        <div className="flex min-h-screen items-center justify-center bg-[#0a0a0f]">
            <SignIn
                appearance={{
                    elements: {
                        formButtonPrimary: "bg-teal-500 hover:bg-teal-600",
                    },
                }}
                fallbackRedirectUrl="/"
                signUpUrl="/sign-up"
            />
        </div>
    );
}
