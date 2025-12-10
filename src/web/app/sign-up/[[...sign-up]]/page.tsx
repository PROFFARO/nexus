"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { useSignUp, useAuth } from "@clerk/nextjs";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import Image from "next/image";
import {
    Mail,
    Eye,
    EyeOff,
    ArrowRight,
    User,
    Loader2,
    Lock,
    Shield,
    CheckCircle2,
    Server,
    Globe2,
    Sparkles
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button as StatefulButton } from "@/components/ui/stateful-button";
import { AnimatedAuthInput, AnimatedAuthInputRef } from "@/components/ui/animated-auth-input";
import { InputOTP, InputOTPGroup, InputOTPSlot, InputOTPSeparator } from "@/components/ui/input-otp";
import { AuthLoadingOverlay } from "@/components/ui/auth-loading-overlay";
import { signUpSchema, verificationSchema, validateField, validateForm } from "@/lib/validations/auth";


// OAuth Button Component
function OAuthButton({
    icon,
    label,
    onClick,
    delay,
}: {
    icon: React.ReactNode;
    label: string;
    onClick: () => void;
    delay: number;
}) {
    return (
        <motion.button
            type="button"
            onClick={onClick}
            initial={{ opacity: 0, y: 20 }}
            animate={{
                opacity: 1,
                y: 0,
                transition: { delay, duration: 0.4 }
            }}
            whileHover={{
                scale: 1.02,
                backgroundColor: "var(--secondary)",
                borderColor: "var(--primary)",
                transition: { duration: 0.2, delay: 0 }
            }}
            whileTap={{
                scale: 0.98,
                transition: { duration: 0.1 }
            }}
            className="flex items-center justify-center gap-3 w-full py-3.5 px-4 rounded-none border-2 border-[var(--border)] bg-[var(--card)] text-[var(--foreground)] font-medium transition-colors cursor-pointer"
        >
            {icon}
            <span>{label}</span>
        </motion.button>
    );
}

// Benefit Item for Showcase
function BenefitItem({
    icon: Icon,
    title,
    description,
    delay,
    color,
}: {
    icon: React.ElementType;
    title: string;
    description: string;
    delay: number;
    color: string;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay, duration: 0.5 }}
            whileHover={{ x: 5 }}
            className="group flex items-start gap-4 p-6 rounded-2xl bg-white/5 backdrop-blur-md border border-white/10 hover:bg-white/10 hover:border-white/20 transition-all duration-300 shadow-lg shadow-black/5 cursor-default relative overflow-hidden"
        >
            <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/5 to-white/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000" />
            <motion.div
                className={`p-3 rounded-xl ${color}`}
                whileHover={{ rotate: [0, -10, 10, 0], scale: 1.1 }}
                transition={{ duration: 0.4 }}
            >
                <Icon className="h-6 w-6" />
            </motion.div>
            <div>
                <h3 className="font-semibold text-white text-lg">{title}</h3>
                <p className="text-slate-400 mt-1 text-sm">{description}</p>
            </div>
        </motion.div>
    );
}

export default function SignUpPage() {
    const { isLoaded, signUp, setActive } = useSignUp();
    const { isSignedIn, isLoaded: authLoaded } = useAuth();
    const [firstName, setFirstName] = useState("");
    const [lastName, setLastName] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [pendingVerification, setPendingVerification] = useState(false);
    const [code, setCode] = useState("");
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [touched, setTouched] = useState<Record<string, boolean>>({});
    const [submitError, setSubmitError] = useState("");
    const [verifyError, setVerifyError] = useState("");
    const router = useRouter();

    // Refs for vanish effect
    const firstNameInputRef = useRef<AnimatedAuthInputRef>(null);
    const lastNameInputRef = useRef<AnimatedAuthInputRef>(null);
    const emailInputRef = useRef<AnimatedAuthInputRef>(null);
    const passwordInputRef = useRef<AnimatedAuthInputRef>(null);

    // Redirect if already signed in
    useEffect(() => {
        if (authLoaded && isSignedIn) {
            router.push("/");
        }
    }, [authLoaded, isSignedIn, router]);

    // Show loading while checking auth or redirecting
    if (!authLoaded || isSignedIn) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-[var(--background)]">
                <Loader2 className="h-8 w-8 animate-spin text-[var(--primary)]" />
            </div>
        );
    }

    // Validate single field immediately
    const validateSingleField = (field: "firstName" | "lastName" | "email" | "password", value: string) => {
        const error = validateField(signUpSchema, field, value);
        setErrors(prev => ({ ...prev, [field]: error || "" }));
    };

    // Handle field changes with immediate validation
    const handleFieldChange = (field: "firstName" | "lastName" | "email" | "password", value: string) => {
        switch (field) {
            case "firstName": setFirstName(value); break;
            case "lastName": setLastName(value); break;
            case "email": setEmail(value); break;
            case "password": setPassword(value); break;
        }
        setTouched(prev => ({ ...prev, [field]: true }));
        validateSingleField(field, value);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!isLoaded) return;

        // Validate all fields
        const formErrors = validateForm(signUpSchema, { firstName, lastName, email, password });
        setErrors(formErrors);
        setTouched({ firstName: true, lastName: true, email: true, password: true });

        if (Object.keys(formErrors).length > 0) {
            return;
        }

        // Trigger vanish effect on all inputs
        firstNameInputRef.current?.triggerVanish();
        lastNameInputRef.current?.triggerVanish();
        emailInputRef.current?.triggerVanish();
        passwordInputRef.current?.triggerVanish();

        setIsLoading(true);
        setSubmitError("");

        try {
            await signUp.create({
                firstName,
                lastName,
                emailAddress: email,
                password,
            });

            await signUp.prepareEmailAddressVerification({ strategy: "email_code" });
            setPendingVerification(true);
        } catch (err: unknown) {
            console.error("Sign up error:", err);
            if (err && typeof err === 'object' && 'errors' in err) {
                const clerkError = (err as { errors: Array<{ message: string }> }).errors[0];
                setSubmitError(clerkError?.message || "Something went wrong. Please try again.");
            } else {
                setSubmitError("Something went wrong. Please try again.");
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!isLoaded) return;

        // Validate verification code
        const codeError = validateField(verificationSchema, "code", code);
        if (codeError) {
            setVerifyError(codeError);
            return;
        }

        setIsLoading(true);
        setVerifyError("");

        try {
            const result = await signUp.attemptEmailAddressVerification({ code });
            if (result.status === "complete") {
                await setActive({ session: result.createdSessionId });
                router.push("/");
            }
        } catch (err: unknown) {
            console.error("Verification error:", err);
            if (err && typeof err === 'object' && 'errors' in err) {
                const clerkError = (err as { errors: Array<{ message: string }> }).errors[0];
                setVerifyError(clerkError?.message || "Invalid verification code.");
            } else {
                setVerifyError("Invalid verification code. Please try again.");
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleOAuthSignUp = async (provider: "oauth_google" | "oauth_github") => {
        if (!isLoaded) return;
        try {
            await signUp.authenticateWithRedirect({
                strategy: provider,
                redirectUrl: "/sso-callback",
                redirectUrlComplete: "/",
            });
        } catch (err) {
            console.error("OAuth error:", err);
        }
    };

    // Verification View
    if (pendingVerification) {
        return (
            <>
                {/* Loading Overlay */}
                <AuthLoadingOverlay
                    isLoading={isLoading}
                    isSuccess={false}
                    loadingMessage="Verifying your email..."
                    type="verify"
                />

                <div className="flex min-h-screen items-center justify-center bg-[var(--background)] p-6 relative overflow-hidden">
                    {/* Background decorative elements */}
                    <div className="absolute inset-0 pointer-events-none">
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="absolute top-1/4 -left-32 w-64 h-64 bg-[var(--primary)]/10 rounded-full blur-3xl"
                        />
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.2 }}
                            className="absolute bottom-1/4 -right-32 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl"
                        />
                    </div>

                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        transition={{ duration: 0.5, ease: "easeOut" }}
                        className="w-full max-w-md relative z-10"
                    >
                        {/* Card with glassmorphism */}
                        <div className="bg-[var(--card)]/80 backdrop-blur-xl border border-[var(--border)] p-8 md:p-10 shadow-2xl">
                            {/* Header */}
                            <div className="text-center mb-8">
                                {/* Animated icon */}
                                <motion.div
                                    initial={{ scale: 0, rotate: -180 }}
                                    animate={{ scale: 1, rotate: 0 }}
                                    transition={{ type: "spring", stiffness: 200, damping: 15, delay: 0.1 }}
                                    className="relative mx-auto mb-6 w-20 h-20"
                                >
                                    <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-[var(--primary)] to-[var(--primary)]/60 flex items-center justify-center shadow-lg shadow-[var(--primary)]/30 mx-auto">
                                        <Mail className="h-10 w-10 text-white" />
                                    </div>
                                    {/* Pulse ring */}
                                    <motion.div
                                        initial={{ scale: 0.8, opacity: 0 }}
                                        animate={{ scale: 1.2, opacity: 0 }}
                                        transition={{ duration: 2, repeat: Infinity, ease: "easeOut" }}
                                        className="absolute inset-0 rounded-2xl border-2 border-[var(--primary)]"
                                    />
                                </motion.div>

                                <motion.h2
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.2 }}
                                    className="text-3xl font-bold text-[var(--foreground)] mb-2"
                                >
                                    Verify your email
                                </motion.h2>
                                <motion.p
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.3 }}
                                    className="text-[var(--muted-foreground)]"
                                >
                                    Enter the 6-digit code sent to
                                </motion.p>
                                <motion.p
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.35 }}
                                    className="font-semibold text-[var(--foreground)] mt-1"
                                >
                                    {email}
                                </motion.p>
                            </div>

                            <form onSubmit={handleVerify} className="space-y-6">
                                {/* OTP Input */}
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.4 }}
                                    className="flex justify-center"
                                >
                                    <InputOTP
                                        maxLength={6}
                                        value={code}
                                        onChange={(value) => {
                                            setCode(value);
                                            if (verifyError) setVerifyError("");
                                        }}
                                        containerClassName="gap-3"
                                    >
                                        <InputOTPGroup className="gap-2">
                                            <InputOTPSlot index={0} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                            <InputOTPSlot index={1} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                            <InputOTPSlot index={2} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                        </InputOTPGroup>
                                        <InputOTPSeparator className="text-[var(--muted-foreground)]" />
                                        <InputOTPGroup className="gap-2">
                                            <InputOTPSlot index={3} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                            <InputOTPSlot index={4} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                            <InputOTPSlot index={5} className={`h-14 w-12 text-2xl font-bold rounded-lg border-2 ${verifyError ? 'border-red-500' : 'border-[var(--border)]'} bg-[var(--background)] focus-within:border-[var(--primary)] focus-within:ring-2 focus-within:ring-[var(--primary)]/30`} />
                                        </InputOTPGroup>
                                    </InputOTP>
                                </motion.div>

                                {/* Verification Error */}
                                <AnimatePresence mode="wait">
                                    {verifyError && (
                                        <motion.div
                                            initial={{ opacity: 0, height: 0 }}
                                            animate={{ opacity: 1, height: "auto" }}
                                            exit={{ opacity: 0, height: 0 }}
                                            transition={{ duration: 0.1 }}
                                            className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-600 dark:text-red-400 text-sm flex items-center gap-2"
                                        >
                                            <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                            <span>{verifyError}</span>
                                        </motion.div>
                                    )}
                                </AnimatePresence>

                                {/* Submit Button */}
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.5 }}
                                >
                                    <StatefulButton
                                        type="submit"
                                        className="w-full h-12 rounded-none bg-[var(--primary)] hover:ring-[var(--primary)] text-base font-semibold"
                                        disabled={code.length !== 6}
                                    >
                                        <span className="flex items-center gap-2">
                                            <CheckCircle2 className="h-5 w-5" />
                                            Verify & Continue
                                        </span>
                                    </StatefulButton>
                                </motion.div>

                                {/* Resend Code */}
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.6 }}
                                    className="text-center space-y-3"
                                >
                                    <p className="text-[var(--muted-foreground)] text-sm">
                                        Didn&apos;t receive the code?
                                    </p>
                                    <button
                                        type="button"
                                        onClick={() => signUp?.prepareEmailAddressVerification({ strategy: "email_code" })}
                                        className="text-[var(--primary)] font-medium hover:underline text-sm inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                                    >
                                        <Mail className="h-4 w-4" />
                                        Resend verification code
                                    </button>
                                </motion.div>

                                {/* Back to sign up */}
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.7 }}
                                    className="pt-4 border-t border-[var(--border)]">
                                    <button
                                        type="button"
                                        onClick={() => setPendingVerification(false)}
                                        className="w-full text-sm text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors cursor-pointer"
                                    >
                                        ← Back to sign up
                                    </button>
                                </motion.div>
                            </form>
                        </div>
                    </motion.div>

                    <div className="fixed bottom-6 right-6 z-50">
                        <ThemeToggle />
                    </div>
                </div>
            </>
        );
    }

    // Sign Up View
    return (
        <>
            {/* Loading Overlay */}
            <AuthLoadingOverlay
                isLoading={isLoading}
                isSuccess={false}
                loadingMessage="Creating your account..."
                type="signup"
            />

            <div className="flex min-h-screen">
                {/* Left Side - Showcase */}
                <div className="hidden lg:flex w-1/2 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 relative overflow-hidden">
                    {/* Premium Vertical Partition Bar */}
                    <div className="absolute inset-y-0 right-0 w-[2px] bg-gradient-to-b from-transparent via-white/10 to-transparent backdrop-blur-sm z-30"></div>
                    <div className="absolute inset-y-0 right-0 w-[1px] bg-gradient-to-b from-transparent via-white/30 to-transparent shadow-[0_0_20px_2px_rgba(255,255,255,0.2)] z-30"></div>
                    <div className="absolute inset-y-0 right-0 w-16 bg-gradient-to-l from-black/20 to-transparent z-20 pointer-events-none" />

                    {/* Background Effects */}
                    <div className="absolute inset-0">
                        <div className="absolute top-0 left-0 w-[500px] h-[500px] bg-gradient-radial from-purple-500/20 to-transparent rounded-full blur-3xl" />
                        <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-gradient-radial from-teal-500/15 to-transparent rounded-full blur-3xl" />
                    </div>

                    {/* Content */}
                    <div className="relative z-10 flex flex-col justify-center px-12 xl:px-20">
                        {/* Logo */}
                        <motion.div
                            initial={{ opacity: 0, y: -20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="flex items-center gap-3 mb-16"
                        >
                            <div className="relative w-10 h-10">
                                <Image
                                    src="/assets/nexus_logo.svg"
                                    alt="NEXUS Logo"
                                    fill
                                    className="object-contain"
                                    priority
                                />
                            </div>
                            <span className="text-2xl font-bold text-white">NEXUS</span>
                        </motion.div>

                        <motion.div
                            initial={{ opacity: 0, y: 30 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.2 }}
                            className="mb-12"
                        >
                            <h2 className="text-4xl font-bold text-white leading-tight">
                                Start securing your
                                <br />
                                <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">
                                    infrastructure today
                                </span>
                            </h2>
                            <p className="mt-4 text-lg text-slate-400 max-w-md">
                                Join security teams worldwide using NEXUS for advanced threat detection.
                            </p>
                        </motion.div>

                        {/* Benefit Cards */}
                        <div className="space-y-4">
                            <BenefitItem
                                icon={Server}
                                title="Multi-Protocol Support"
                                description="SSH, FTP, and MySQL honeypot monitoring and analysis"
                                delay={0.4}
                                color="bg-blue-500/20 text-blue-400"
                            />
                            <BenefitItem
                                icon={Sparkles}
                                title="AI-Powered Insights"
                                description="Multi LLM configuration facilities"
                                delay={0.5}
                                color="bg-purple-500/20 text-purple-400"
                            />
                            <BenefitItem
                                icon={Globe2}
                                title="Logging"
                                description="Real time logging and analysis"
                                delay={0.6}
                                color="bg-teal-500/20 text-teal-400"
                            />
                        </div>
                    </div>
                </div>

                {/* Right Side - Form */}
                <div className="w-full lg:w-1/2 flex flex-col justify-center px-6 py-12 lg:px-16 xl:px-24 bg-[var(--background)]">
                    <div className="w-full max-w-md mx-auto">
                        {/* Mobile Logo */}
                        <motion.div
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="flex items-center gap-3 mb-12 lg:hidden"
                        >
                            <div className="relative w-10 h-10">
                                <Image
                                    src="/assets/nexus_logo.svg"
                                    alt="NEXUS Logo"
                                    fill
                                    className="object-contain"
                                    priority
                                />
                            </div>
                            <span className="text-2xl font-bold text-[var(--foreground)]">NEXUS</span>
                        </motion.div>

                        {/* Header */}
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.1 }}
                            className="mb-10"
                        >
                            <h1 className="text-4xl font-bold text-[var(--foreground)] tracking-tight">
                                Create account
                            </h1>
                            <p className="mt-3 text-lg text-[var(--muted-foreground)]">
                                Get started with your free account
                            </p>
                        </motion.div>

                        <form onSubmit={handleSubmit} className="space-y-5">
                            {/* OAuth Buttons */}
                            <div className="grid grid-cols-2 gap-4">
                                <OAuthButton
                                    icon={
                                        <svg className="h-5 w-5" viewBox="0 0 24 24">
                                            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                                            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                                            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                                            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                                        </svg>
                                    }
                                    label="Google"
                                    onClick={() => handleOAuthSignUp("oauth_google")}
                                    delay={0.2}
                                />
                                <OAuthButton
                                    icon={
                                        <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                                        </svg>
                                    }
                                    label="GitHub"
                                    onClick={() => handleOAuthSignUp("oauth_github")}
                                    delay={0.3}
                                />
                            </div>

                            {/* Divider */}
                            <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: 0.4 }}
                                className="relative flex items-center gap-4 py-2"
                            >
                                <div className="flex-1 h-[1px] bg-gradient-to-r from-transparent via-[var(--border)] to-transparent" />
                                <span className="text-sm text-[var(--muted-foreground)] font-medium">or register with email</span>
                                <div className="flex-1 h-[1px] bg-gradient-to-r from-transparent via-[var(--border)] to-transparent" />
                            </motion.div>

                            {/* Name Fields */}
                            <div className="grid grid-cols-2 gap-4">
                                <AnimatedAuthInput
                                    ref={firstNameInputRef}
                                    placeholders={["First name", "John", "Your first name"]}
                                    icon={User}
                                    value={firstName}
                                    onChange={(e) => handleFieldChange("firstName", e.target.value)}
                                    name="firstName"
                                    error={touched.firstName ? errors.firstName : undefined}
                                />
                                <AnimatedAuthInput
                                    ref={lastNameInputRef}
                                    placeholders={["Last name", "Doe", "Your last name"]}
                                    value={lastName}
                                    onChange={(e) => handleFieldChange("lastName", e.target.value)}
                                    name="lastName"
                                    error={touched.lastName ? errors.lastName : undefined}
                                />
                            </div>

                            {/* Email */}
                            <AnimatedAuthInput
                                ref={emailInputRef}
                                placeholders={["Email address", "name@company.com", "Enter your email"]}
                                type="email"
                                icon={Mail}
                                value={email}
                                onChange={(e) => handleFieldChange("email", e.target.value)}
                                name="email"
                                error={touched.email ? errors.email : undefined}
                            />

                            {/* Password */}
                            <AnimatedAuthInput
                                ref={passwordInputRef}
                                placeholders={["Password", "Min. 8 characters", "Create a password"]}
                                type={showPassword ? "text" : "password"}
                                icon={Lock}
                                value={password}
                                onChange={(e) => handleFieldChange("password", e.target.value)}
                                name="password"
                                error={touched.password ? errors.password : undefined}
                                rightElement={
                                    <motion.button
                                        type="button"
                                        onClick={() => setShowPassword(!showPassword)}
                                        whileHover={{ scale: 1.1 }}
                                        whileTap={{ scale: 0.9 }}
                                        className="text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors"
                                    >
                                        {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                                    </motion.button>
                                }
                            />

                            {/* Submit Error */}
                            <AnimatePresence>
                                {submitError && (
                                    <motion.div
                                        initial={{ opacity: 0, y: -10, height: 0 }}
                                        animate={{ opacity: 1, y: 0, height: "auto" }}
                                        exit={{ opacity: 0, y: -10, height: 0 }}
                                        className="p-4 bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 text-sm flex items-center gap-2"
                                    >
                                        <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                        <span>{submitError}</span>
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            {/* Clerk CAPTCHA - Required for bot protection */}
                            <div id="clerk-captcha" />

                            {/* Submit Button */}
                            <StatefulButton type="submit" className="w-full rounded-none bg-[var(--primary)] hover:ring-[var(--primary)]">
                                Create Account
                            </StatefulButton>

                            {/* Sign In Link */}
                            <motion.p
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: 0.8 }}
                                className="text-center text-[var(--muted-foreground)]"
                            >
                                Already have an account?{" "}
                                <Link href="/sign-in" className="font-semibold text-[var(--primary)] hover:underline">
                                    Sign in
                                </Link>
                            </motion.p>

                            {/* Terms */}
                            <motion.p
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: 0.85 }}
                                className="text-center text-xs text-[var(--muted-foreground)]"
                            >
                                By creating an account, you agree to our{" "}
                                <Link href="/terms" className="text-[var(--primary)] hover:underline">Terms</Link>
                                {" "}and{" "}
                                <Link href="/privacy" className="text-[var(--primary)] hover:underline">Privacy Policy</Link>
                            </motion.p>
                        </form>
                    </div>
                </div>

                {/* Theme Toggle */}
                <div className="fixed bottom-6 right-6 z-50">
                    <ThemeToggle />
                </div>
            </div>
        </>
    );
}
