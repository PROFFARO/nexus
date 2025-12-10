import React from "react";

export default function PrivacyPage() {
    return (
        <div className="max-w-4xl mx-auto py-12 px-6">
            <h1 className="text-4xl font-bold mb-8">Privacy Policy</h1>
            <p className="text-slate-500 dark:text-slate-400 mb-8">Last updated: December 10, 2025</p>

            <div className="space-y-8 text-slate-700 dark:text-slate-300">
                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">1. Introduction</h2>
                    <p>
                        At NEXUS ("we", "us", "our"), we respect your privacy and are committed to protecting it through our compliance with this policy. This policy describes the types of information we may collect from you or that you may provide when you visit the website or use our services.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">2. Information We Collect</h2>
                    <ul className="list-disc pl-5 space-y-2">
                        <li><strong>Account Information:</strong> Name, email address, and authentication details provided via Clerk.</li>
                        <li><strong>Security Data:</strong> IP addresses, attack vectors, logs, and other technical data captured by the honeypot services.</li>
                        <li><strong>Usage Data:</strong> Information on how the Service is accessed and used.</li>
                    </ul>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">3. How We Use Your Information</h2>
                    <p>
                        We use the information we collect to:
                    </p>
                    <ul className="list-disc pl-5 space-y-2 mt-2">
                        <li>Provide, maintain, and improve our services.</li>
                        <li>Analyze security threats and generate ML insights.</li>
                        <li>Authenticate users and secure their accounts.</li>
                        <li>Send administrative information, such as updates, security alerts, and support messages.</li>
                    </ul>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">4. Data Sharing</h2>
                    <p>
                        We do not sell your personal data. We may share generic aggregated demographic information not linked to any personal identification information regarding visitors and users with our business partners, trusted affiliates, and advertisers for the purposes outlined above.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">5. Security of Your Information</h2>
                    <p>
                        We use administrative, technical, and physical security measures to help protect your personal information. While we have taken reasonable steps to secure the personal information you provide to us, please be aware that despite our efforts, no security measures are perfect or impenetrable, and no method of data transmission can be guaranteed against any interception or other type of misuse.
                    </p>
                </section>

                <section>
                    <h2 className="text-2xl font-semibold mb-4 text-slate-900 dark:text-white">6. Contact Us</h2>
                    <p>
                        If you have any questions about this Privacy Policy, please contact us at privacy@nexus-security.io.
                    </p>
                </section>
            </div>
        </div>
    );
}
