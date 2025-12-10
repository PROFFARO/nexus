"use client";

import { useState, useRef } from "react";
import Link from "next/link";
import { useSignIn } from "@clerk/nextjs";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import Image from "next/image";
import {
    Mail,
    Eye,
    EyeOff,
    ArrowRight,
    Loader2,
    Lock,
    Shield,
    Activity,
    Zap,
    CheckCircle2
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button as StatefulButton } from "@/components/ui/stateful-button";
import { AnimatedAuthInput, AnimatedAuthInputRef } from "@/components/ui/animated-auth-input";
import { AuthLoadingOverlay } from "@/components/ui/auth-loading-overlay";
import { signInSchema, validateField, validateForm } from "@/lib/validations/auth";


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

// Feature Card for Showcase
function FeatureCard({
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
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay, duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] }}
            whileHover={{ scale: 1.02, x: -5 }}
            className="group flex items-start gap-4 p-6 rounded-2xl bg-white/5 backdrop-blur-md border border-white/10 hover:bg-white/10 hover:border-white/20 transition-all duration-300 shadow-lg shadow-black/5 cursor-default relative overflow-hidden"
        >
            <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/5 to-white/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000" />
            <motion.div
                className={`p-3 rounded-xl ${color}`}
                whileHover={{ rotate: [0, -10, 10, 0] }}
                transition={{ duration: 0.5 }}
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

export default function SignInPage() {
    const { isLoaded, signIn, setActive } = useSignIn();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [touched, setTouched] = useState<Record<string, boolean>>({});
    const [submitError, setSubmitError] = useState("");
    const router = useRouter();

    // Refs for vanish effect
    const emailInputRef = useRef<AnimatedAuthInputRef>(null);
    const passwordInputRef = useRef<AnimatedAuthInputRef>(null);

    // Validate single field immediately
    const validateSingleField = (field: "email" | "password", value: string) => {
        const error = validateField(signInSchema, field, value);
        setErrors(prev => ({ ...prev, [field]: error || "" }));
    };

    // Handle field change with immediate validation
    const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setEmail(value);
        setTouched(prev => ({ ...prev, email: true }));
        validateSingleField("email", value);
    };

    const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setPassword(value);
        setTouched(prev => ({ ...prev, password: true }));
        validateSingleField("password", value);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!isLoaded) return;

        // Validate all fields on submit
        const formErrors = validateForm(signInSchema, { email, password });
        setErrors(formErrors);
        setTouched({ email: true, password: true });

        // If there are validation errors, don't submit
        if (Object.keys(formErrors).length > 0) {
            return;
        }

        // Trigger vanish effect on all inputs
        emailInputRef.current?.triggerVanish();
        passwordInputRef.current?.triggerVanish();

        setIsLoading(true);
        setSubmitError("");

        try {
            const result = await signIn.create({ identifier: email, password });
            if (result.status === "complete") {
                setSuccess(true);
                await setActive({ session: result.createdSessionId });
                setTimeout(() => router.push("/"), 500);
            }
        } catch (err: unknown) {
            console.error("Sign in error:", err);
            if (err && typeof err === 'object' && 'errors' in err) {
                const clerkError = (err as { errors: Array<{ message: string; code: string }> }).errors[0];
                setSubmitError(clerkError?.message || "Invalid credentials. Please try again.");
            } else {
                setSubmitError("Invalid credentials. Please try again.");
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleOAuthSignIn = async (provider: "oauth_google" | "oauth_github") => {
        if (!isLoaded) return;
        try {
            await signIn.authenticateWithRedirect({
                strategy: provider,
                redirectUrl: "/sso-callback",
                redirectUrlComplete: "/",
            });
        } catch (err) {
            console.error("OAuth error:", err);
        }
    };

    return (
        <>
            {/* Loading Overlay */}
            <AuthLoadingOverlay
                isLoading={isLoading}
                isSuccess={success}
                loadingMessage="Signing you in..."
                type="signin"
            />

            <div className="flex min-h-screen">
                {/* Left Side - Form */}
                <div className="w-full lg:w-1/2 flex flex-col justify-center px-6 py-12 lg:px-16 xl:px-24 bg-[var(--background)]">
                    <div className="w-full max-w-md mx-auto">
                        {/* Logo */}
                        <motion.div
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="flex items-center gap-3 mb-12"
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
                                Welcome back
                            </h1>
                            <p className="mt-3 text-lg text-[var(--muted-foreground)]">
                                Sign in to access your security dashboard
                            </p>
                        </motion.div>

                        {/* Success State */}
                        <AnimatePresence>
                            {success && (
                                <motion.div
                                    initial={{ opacity: 0, scale: 0.9 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    exit={{ opacity: 0, scale: 0.9 }}
                                    className="flex flex-col items-center justify-center py-20"
                                >
                                    <motion.div
                                        initial={{ scale: 0 }}
                                        animate={{ scale: 1 }}
                                        transition={{ type: "spring", stiffness: 200, damping: 15 }}
                                        className="w-20 h-20 rounded-full bg-green-500/10 flex items-center justify-center mb-6"
                                    >
                                        <CheckCircle2 className="h-10 w-10 text-green-500" />
                                    </motion.div>
                                    <h2 className="text-2xl font-bold text-[var(--foreground)]">Welcome back!</h2>
                                    <p className="text-[var(--muted-foreground)] mt-2">Redirecting to dashboard...</p>
                                </motion.div>
                            )}
                        </AnimatePresence>

                        {!success && (
                            <form onSubmit={handleSubmit} className="space-y-6">
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
                                        onClick={() => handleOAuthSignIn("oauth_google")}
                                        delay={0.2}
                                    />
                                    <OAuthButton
                                        icon={
                                            <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                                                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                                            </svg>
                                        }
                                        label="GitHub"
                                        onClick={() => handleOAuthSignIn("oauth_github")}
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
                                    <span className="text-sm text-[var(--muted-foreground)] font-medium">or continue with email</span>
                                    <div className="flex-1 h-[1px] bg-gradient-to-r from-transparent via-[var(--border)] to-transparent" />
                                </motion.div>

                                {/* Form Fields */}
                                <div className="space-y-4">
                                    <AnimatedAuthInput
                                        ref={emailInputRef}
                                        placeholders={["Email address", "name@company.com", "Enter your email"]}
                                        type="email"
                                        icon={Mail}
                                        value={email}
                                        onChange={handleEmailChange}
                                        name="email"
                                        error={touched.email ? errors.email : undefined}
                                    />

                                    <div className="space-y-2">
                                        <AnimatedAuthInput
                                            ref={passwordInputRef}
                                            placeholders={["Password", "Enter your password", "••••••••"]}
                                            type={showPassword ? "text" : "password"}
                                            icon={Lock}
                                            value={password}
                                            onChange={handlePasswordChange}
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
                                        <motion.div
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            transition={{ delay: 0.7 }}
                                            className="flex justify-end"
                                        >
                                            <Link
                                                href="/forgot-password"
                                                className="text-sm font-medium text-[var(--primary)] hover:underline"
                                            >
                                                Forgot password?
                                            </Link>
                                        </motion.div>
                                    </div>
                                </div>

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
                                <StatefulButton
                                    type="submit"
                                    className="w-full rounded-none bg-[var(--primary)] hover:ring-[var(--primary)]"
                                >
                                    Sign In
                                </StatefulButton>

                                {/* Sign Up Link */}
                                <motion.p
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.9 }}
                                    className="text-center text-[var(--muted-foreground)]"
                                >
                                    Don&apos;t have an account?{" "}
                                    <Link
                                        href="/sign-up"
                                        className="font-semibold text-[var(--primary)] hover:underline"
                                    >
                                        Create account
                                    </Link>
                                </motion.p>
                            </form>
                        )}
                    </div>
                </div>

                {/* Right Side - Showcase */}
                <div className="hidden lg:flex w-1/2 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 relative overflow-hidden">
                    {/* Premium Vertical Partition Bar */}
                    <div className="absolute inset-y-0 left-0 w-[2px] bg-gradient-to-b from-transparent via-white/10 to-transparent backdrop-blur-sm z-30"></div>
                    <div className="absolute inset-y-0 left-0 w-[1px] bg-gradient-to-b from-transparent via-white/30 to-transparent shadow-[0_0_20px_2px_rgba(255,255,255,0.2)] z-30"></div>
                    <div className="absolute inset-y-0 left-0 w-16 bg-gradient-to-r from-black/20 to-transparent z-20 pointer-events-none" />

                    {/* Background Effects */}
                    <div className="absolute inset-0">
                        <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-gradient-radial from-teal-500/20 to-transparent rounded-full blur-3xl" />
                        <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-gradient-radial from-purple-500/10 to-transparent rounded-full blur-3xl" />
                    </div>

                    {/* Content */}
                    <div className="relative z-10 flex flex-col justify-center px-12 xl:px-20">
                        <motion.div
                            initial={{ opacity: 0, y: 30 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.3, duration: 0.8 }}
                            className="mb-12"
                        >
                            <h2 className="text-4xl font-bold text-white leading-tight">
                                Sign In to access
                                <br />
                                <span className="text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-cyan-400">
                                    AI based Honeypot Platform
                                </span>
                            </h2>
                            <p className="mt-4 text-lg text-slate-400 max-w-md">
                                Monitor, analyze, and protect your infrastructure with ML-powered threat detection.
                            </p>
                        </motion.div>

                        {/* Feature Cards */}
                        <div className="space-y-4">
                            <FeatureCard
                                icon={Shield}
                                title="Real-time Protection"
                                description="Monitoring of SSH, FTP, and MySQL honeypots"
                                delay={0.5}
                                color="bg-teal-500/20 text-teal-400"
                            />
                            <FeatureCard
                                icon={Activity}
                                title="ML-Powered Analysis"
                                description="Anomaly detection | Risk assessment | vulnerability assessment"
                                delay={0.6}
                                color="bg-purple-500/20 text-purple-400"
                            />
                            <FeatureCard
                                icon={Zap}
                                title="Instant Alerts"
                                description="Get notified of threats in real-time"
                                delay={0.7}
                                color="bg-amber-500/20 text-amber-400"
                            />
                        </div>
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
