import { put, get } from "@vercel/blob";

export const prerender = false;

interface StatsPayload {
  total: number;
  seguros: number;
  maliciosos: number;
  errores: number;
  nsfw: number;
  vt_usage_minuto: number;
  vt_usage_diario: number;
  se_usage_diario: number;
  timestamp: number;
}

const emptyPayload: StatsPayload = {
  total: 0,
  seguros: 0,
  maliciosos: 0,
  errores: 0,
  nsfw: 0,
  vt_usage_minuto: 0,
  vt_usage_diario: 0,
  se_usage_diario: 0,
  timestamp: 0,
};

const BLOB_KEY = "stats.json";

export async function POST({ request }: { request: Request }): Promise<Response> {
  const auth = request.headers.get("Authorization");
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token || token !== import.meta.env.STATS_TOKEN) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    const body = await request.json();
    const payload: StatsPayload = {
      total: Number(body.total) || 0,
      seguros: Number(body.seguros) || 0,
      maliciosos: Number(body.maliciosos) || 0,
      errores: Number(body.errores) || 0,
      nsfw: Number(body.nsfw) || 0,
      vt_usage_minuto: Number(body.vt_usage_minuto) || 0,
      vt_usage_diario: Number(body.vt_usage_diario) || 0,
      se_usage_diario: Number(body.se_usage_diario) || 0,
      timestamp: Number(body.timestamp) || Date.now() / 1000,
    };

    await put(BLOB_KEY, JSON.stringify(payload), {
      access: "public",
      addRandomSuffix: false,
      contentType: "application/json",
    });

    return new Response("OK", { status: 200 });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("Stats POST error:", msg);
    return new Response(msg, { status: 400 });
  }
}

export async function GET(): Promise<Response> {
  try {
    const blob = await get(BLOB_KEY);
    const text = await blob.text();
    const data: StatsPayload = JSON.parse(text);
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  } catch {
    return new Response(JSON.stringify(emptyPayload), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  }
}
