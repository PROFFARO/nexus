import React from "react";

export default function TermsPage() {
    return (
        <div className="max-w-4xl mx-auto py-12 px-6">
            <h1 className="text-4xl font-bold mb-8">Terms of Service</h1>
            <p className="text-slate-500 dark:text-slate-400 mb-8">Last updated: December 10, 2025</p>

            <div className="space-y-8 text-slate-700 dark:text-slate-300">
                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">1. Acceptance of Terms</h2>
                    <p>
                        By accessing and using the NEXUS Honeypot Platform ("Service"), you accept and agree to be bound by the terms and provision of this agreement.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">2. Description of Service</h2>
                    <p>
                        NEXUS provides a security information and event management (SIEM) dashboard designed to monitor honeypot service activity, analyze threats using Machine Learning, and visualize attack data.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">3. User Conduct</h2>
                    <p>
                        You agree to use the Service only for lawful purposes and in a way that does not infringe the rights of, restrict or inhibit anyone else's use and enjoyment of the Service. Prohibited behavior includes harassing or causing distress or inconvenience to any other user, transmitting obscene or offensive content, or disrupting the normal flow of dialogue within the Service.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">4. Data Usage</h2>
                    <p>
                        The Service collects data regarding network traffic, potential attacks, and system interactions ("Security Data"). You acknowledge that this data is used for analysis and improvement of security protocols. NEXUS is not responsible for the content of the traffic captured by the honeypot services.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">5. Disclaimer</h2>
                    <p>
                        The Service is provided "as is". NEXUS makes no warranties, expressed or implied, and hereby disclaims and negates all other warranties, including without limitation, implied warranties or conditions of merchantability, fitness for a particular purpose, or non-infringement of intellectual property or other violation of rights.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">6. Changes to Terms</h2>
                    <p>
                        NEXUS reserves the right to modify these terms at any time. We will do so by posting and drawing attention to the updated terms on the Site. Your decision to continue to visit and make use of the Site after such changes have been made constitutes your formal acceptance of the new Terms of Service.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">7. Contact Us</h2>
                    <p>
                        If you have any questions about these Terms, please contact us at <a href="mailto:dayabindhani2005@gmail.com" className="text-blue-500 hover:underline">dayabindhani2005@gmail.com</a>.
                    </p>
                </section>
            </div>
        </div>
    );
}
