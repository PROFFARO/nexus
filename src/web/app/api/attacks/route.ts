import { NextRequest, NextResponse } from 'next/server';
import { getRecentLogs, getLogStats } from '@/lib/logs';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET(req: NextRequest) {
    try {
        const { searchParams } = new URL(req.url);
        const limitParam = searchParams.get('limit');
        const getStats = searchParams.get('stats') === 'true';

        // Default limit 500, max 10000
        let limit = 500;
        if (limitParam) {
            limit = parseInt(limitParam, 10);
            if (isNaN(limit)) limit = 500;
            if (limit > 10000) limit = 10000;
        }

        if (getStats) {
            const stats = await getLogStats();
            return NextResponse.json(stats, {
                headers: {
                    'Cache-Control': 'no-store, no-cache, must-revalidate',
                },
            });
        }

        const logs = await getRecentLogs(limit);
        return NextResponse.json(logs, {
            headers: {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
            },
        });

    } catch (error) {
        console.error("API Error in /api/attacks:", error);
        return NextResponse.json(
            { error: "Internal Server Error", message: String(error) },
            { status: 500 }
        );
    }
}
