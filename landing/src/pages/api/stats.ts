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

const jsonResponse = (data: StatsPayload) =>
  new Response(JSON.stringify(data), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Vercel-CDN-Cache-Control": "no-cache",
    },
  });

export async function POST({ request }: { request: Request }): Promise<Response> {
  const auth = request.headers.get("Authorization");
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token || token !== process.env.STATS_TOKEN) {
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

    const blobResult = await put(BLOB_KEY, JSON.stringify(payload), {
      access: "private",
      contentType: "application/json",
      allowOverwrite: true,
      token: process.env.BLOB_READ_WRITE_TOKEN,
    });

    return new Response(JSON.stringify({ status: "OK" }), { status: 200 });
  } catch (e) {
    console.error("[stats POST]", e);
    return new Response("Bad Request", { status: 400 });
  }
}

export async function GET(): Promise<Response> {
  try {
    const result = await get(BLOB_KEY, {
      access: "private",
      token: process.env.BLOB_READ_WRITE_TOKEN,
    });
    if (!result || result.statusCode !== 200 || !result.stream) {
      return jsonResponse(emptyPayload);
    }
    const text = await new Response(result.stream).text();
    const data: StatsPayload = JSON.parse(text);
    return jsonResponse(data);
  } catch (e) {
    console.error("[stats GET]", e);
    return jsonResponse(emptyPayload);
  }
}
