"use client";

import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useRef, useState, useImperativeHandle, forwardRef } from "react";
import { cn } from "@/lib/utils";
import { AlertCircle } from "lucide-react";

export interface AnimatedAuthInputRef {
    triggerVanish: () => void;
}

export const AnimatedAuthInput = forwardRef<AnimatedAuthInputRef, {
    placeholders: string[];
    value: string;
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
    type?: string;
    icon?: React.ElementType;
    rightElement?: React.ReactNode;
    required?: boolean;
    className?: string;
    name?: string;
    error?: string;
    onBlur?: () => void;
}>(({
    placeholders,
    value,
    onChange,
    type = "text",
    icon: Icon,
    rightElement,
    required = true,
    className,
    name,
    error,
    onBlur,
}, ref) => {
    const [currentPlaceholder, setCurrentPlaceholder] = useState(0);
    const [isFocused, setIsFocused] = useState(false);
    const [animating, setAnimating] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const newDataRef = useRef<any[]>([]);
    const intervalRef = useRef<NodeJS.Timeout | null>(null);

    const startAnimation = () => {
        intervalRef.current = setInterval(() => {
            setCurrentPlaceholder((prev) => (prev + 1) % placeholders.length);
        }, 3000);
    };

    const handleVisibilityChange = () => {
        if (document.visibilityState !== "visible" && intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
        } else if (document.visibilityState === "visible") {
            startAnimation();
        }
    };

    useEffect(() => {
        startAnimation();
        document.addEventListener("visibilitychange", handleVisibilityChange);

        return () => {
            if (intervalRef.current) {
                clearInterval(intervalRef.current);
            }
            document.removeEventListener("visibilitychange", handleVisibilityChange);
        };
    }, [placeholders]);

    const draw = useCallback(() => {
        if (!inputRef.current) return;
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        canvas.width = 800;
        canvas.height = 800;
        ctx.clearRect(0, 0, 800, 800);
        const computedStyles = getComputedStyle(inputRef.current);

        const fontSize = parseFloat(computedStyles.getPropertyValue("font-size"));
        ctx.font = `${fontSize * 2}px ${computedStyles.fontFamily}`;
        ctx.fillStyle = "#FFF";
        ctx.fillText(value, 16, 40);

        const imageData = ctx.getImageData(0, 0, 800, 800);
        const pixelData = imageData.data;
        const newData: any[] = [];

        for (let t = 0; t < 800; t++) {
            let i = 4 * t * 800;
            for (let n = 0; n < 800; n++) {
                let e = i + 4 * n;
                if (
                    pixelData[e] !== 0 &&
                    pixelData[e + 1] !== 0 &&
                    pixelData[e + 2] !== 0
                ) {
                    newData.push({
                        x: n,
                        y: t,
                        color: [
                            pixelData[e],
                            pixelData[e + 1],
                            pixelData[e + 2],
                            pixelData[e + 3],
                        ],
                    });
                }
            }
        }

        newDataRef.current = newData.map(({ x, y, color }) => ({
            x,
            y,
            r: 1,
            color: `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${color[3]})`,
        }));
    }, [value]);

    useEffect(() => {
        draw();
    }, [value, draw]);

    const animate = (start: number) => {
        const animateFrame = (pos: number = 0) => {
            requestAnimationFrame(() => {
                const newArr = [];
                for (let i = 0; i < newDataRef.current.length; i++) {
                    const current = newDataRef.current[i];
                    if (current.x < pos) {
                        newArr.push(current);
                    } else {
                        if (current.r <= 0) {
                            current.r = 0;
                            continue;
                        }
                        current.x += Math.random() > 0.5 ? 1 : -1;
                        current.y += Math.random() > 0.5 ? 1 : -1;
                        current.r -= 0.05 * Math.random();
                        newArr.push(current);
                    }
                }
                newDataRef.current = newArr;
                const ctx = canvasRef.current?.getContext("2d");
                if (ctx) {
                    ctx.clearRect(pos, 0, 800, 800);
                    newDataRef.current.forEach((t) => {
                        const { x: n, y: i, r: s, color: color } = t;
                        if (n > pos) {
                            ctx.beginPath();
                            ctx.rect(n, i, s, s);
                            ctx.fillStyle = color;
                            ctx.strokeStyle = color;
                            ctx.stroke();
                        }
                    });
                }
                if (newDataRef.current.length > 0) {
                    animateFrame(pos - 8);
                } else {
                    setAnimating(false);
                }
            });
        };
        animateFrame(start);
    };

    const triggerVanish = useCallback(() => {
        if (!value || animating) return;
        setAnimating(true);
        draw();

        if (value && inputRef.current) {
            const maxX = newDataRef.current.reduce(
                (prev, current) => (current.x > prev ? current.x : prev),
                0
            );
            animate(maxX);
        }
    }, [value, animating, draw]);

    // Expose triggerVanish to parent via ref
    useImperativeHandle(ref, () => ({
        triggerVanish,
    }), [triggerVanish]);

    const handleBlur = () => {
        setIsFocused(false);
        onBlur?.();
    };

    const hasError = !!error;

    return (
        <div className="w-full">
            <div
                className={cn(
                    "relative w-full bg-[var(--card)] border transition-all duration-200 overflow-hidden",
                    hasError
                        ? "border-red-500 ring-2 ring-red-500/20"
                        : isFocused
                            ? "border-[var(--primary)] ring-2 ring-[var(--primary)]/20"
                            : "border-[var(--border)]",
                    className
                )}
            >
                {/* Canvas for vanish effect */}
                <canvas
                    ref={canvasRef}
                    className={cn(
                        "absolute pointer-events-none text-base transform scale-50 origin-top-left filter invert dark:invert-0",
                        Icon ? "top-[20%] left-12" : "top-[20%] left-4",
                        !animating ? "opacity-0" : "opacity-100"
                    )}
                />

                {/* Icon */}
                {Icon && (
                    <motion.div
                        animate={{
                            color: hasError
                                ? "rgb(239 68 68)"
                                : isFocused
                                    ? "var(--primary)"
                                    : "var(--muted-foreground)",
                            scale: isFocused ? 1.1 : 1,
                        }}
                        transition={{ duration: 0.2 }}
                        className="absolute left-4 top-1/2 -translate-y-1/2 z-20"
                    >
                        <Icon className="h-5 w-5" />
                    </motion.div>
                )}

                <input
                    ref={inputRef}
                    type={type}
                    value={value}
                    onChange={(e) => {
                        if (!animating) {
                            onChange(e);
                        }
                    }}
                    onFocus={() => setIsFocused(true)}
                    onBlur={handleBlur}
                    name={name}
                    autoComplete="off"
                    className={cn(
                        "w-full bg-transparent py-4 text-[var(--foreground)] outline-none text-base z-10 relative",
                        Icon ? "pl-12" : "pl-4",
                        rightElement ? "pr-12" : "pr-4",
                        animating && "text-transparent"
                    )}
                />

                {/* Animated Placeholder */}
                {!value && !animating && (
                    <div
                        className={cn(
                            "absolute top-0 bottom-0 flex items-center pointer-events-none overflow-hidden",
                            Icon ? "left-12 right-12" : "left-4 right-4"
                        )}
                    >
                        <AnimatePresence mode="wait">
                            <motion.span
                                key={`placeholder-${currentPlaceholder}`}
                                initial={{ y: 5, opacity: 0 }}
                                animate={{ y: 0, opacity: 1 }}
                                exit={{ y: -15, opacity: 0 }}
                                transition={{ duration: 0.3, ease: "linear" }}
                                className="text-[var(--muted-foreground)] text-base truncate whitespace-nowrap"
                            >
                                {placeholders[currentPlaceholder]}
                            </motion.span>
                        </AnimatePresence>
                    </div>
                )}

                {/* Right Element (e.g., password toggle) */}
                {rightElement && (
                    <div className="absolute right-4 top-1/2 -translate-y-1/2 z-20">
                        {rightElement}
                    </div>
                )}

                {/* Focus indicator line */}
                <motion.div
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: isFocused ? 1 : 0 }}
                    transition={{ duration: 0.3 }}
                    className={cn(
                        "absolute bottom-0 left-0 right-0 h-0.5 origin-left z-30",
                        hasError ? "bg-red-500" : "bg-[var(--primary)]"
                    )}
                />
            </div>

            {/* Error Message */}
            <AnimatePresence mode="wait">
                {error && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.1 }}
                        className="flex items-center gap-1.5 mt-1.5 text-red-500 text-sm"
                    >
                        <AlertCircle className="h-3.5 w-3.5 flex-shrink-0" />
                        <span>{error}</span>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
});

AnimatedAuthInput.displayName = "AnimatedAuthInput";
