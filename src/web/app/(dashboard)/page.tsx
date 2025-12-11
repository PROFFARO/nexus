"use client";

import { BackgroundRippleEffect } from "@/components/ui/background-ripple-effect";
import {
    HeroSection,
    ArchitectureSection,
    MLSection,
    DatasetsSection,
    ServicesSection,
    FooterSection
} from "@/components/dashboard/dashboard-sections";

export default function DashboardPage() {
    return (
        <div className="relative min-h-screen w-full overflow-x-hidden">
            {/* Background Ripple Effect - Fixed position with pointer-events-none */}
            <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
                <BackgroundRippleEffect rows={15} cols={40} cellSize={48} />
            </div>

            {/* Main Content - Scrollable */}
            <main className="relative z-10 w-full">
                {/* Section 0: Hero with Sparkles */}
                <section id="hero">
                    <HeroSection />
                </section>

                {/* Section 1: Architecture Diagram */}
                <section id="architecture">
                    <ArchitectureSection />
                </section>

                {/* Section 2: ML Algorithms */}
                <section id="ml">
                    <MLSection />
                </section>

                {/* Section 3: Datasets */}
                <section id="datasets">
                    <DatasetsSection />
                </section>

                {/* Section 4: Services */}
                <section id="services">
                    <ServicesSection />
                </section>

                {/* Section 5: Footer */}
                <FooterSection />
            </main>
        </div>
    );
}
