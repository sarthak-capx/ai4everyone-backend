import express, { Request, Response } from 'express';
import axios, { AxiosError } from 'axios';
import { supabase, supabaseAnon, getUserSupabaseClient, jwtPublicKey } from '../index';
import { body, validationResult } from 'express-validator';
import { AppError } from '../index';
import fileType from 'file-type';
import jwt from 'jsonwebtoken';

const router = express.Router();

// Configuration
const INFERENCE_API_URL = 'https://api.inference.net/v1';
const FAL_API_URL = process.env.FAL_API_URL || 'https://fal.run';
const FAL_API_KEY = process.env.FAL_API_KEY;

// Helper function to validate API key
export async function validateApiKey(apiKey: string): Promise<boolean> {
  try {
    const userId = await getUserIdFromApiKey(apiKey);
    return !!userId;
  } catch (err) {
    console.error('Unexpected error in validateApiKey:', err);
    return false;
  }
}

// Helper to get user_id from API key
export async function getUserIdFromApiKey(apiKey: string): Promise<string | null> {
  try {
    // Single secure path: server-side validation of full API key
    const { data, error } = await supabaseAnon.rpc('validate_and_update_api_key', {
      p_api_key: apiKey,
      p_user_ip: null
    });
    if (error) {
      return null;
    }
    if (data && (data as any).valid && (data as any).user_id) {
      return (data as any).user_id as string;
    }
    return null;
  } catch (error) {
    console.error('API key validation error:', error);
    return null;
  }
}

// Helper: get userId from API key OR JWT 
async function getUserIdFromAuthHeader(authorizationHeader?: string): Promise<{ userId: string | null, userEmail?: string | null, apiKey?: string | null }> {
  if (!authorizationHeader) return { userId: null };
  const token = authorizationHeader.split(' ')[1];
  if (!token) return { userId: null };

  // Try API key path first (fast path for existing clients)
  const viaApiKey = await getUserIdFromApiKey(token);
  if (viaApiKey) {
    try {
      const userClient = getUserSupabaseClient(viaApiKey);
      const { data: prof } = await userClient
        .from('profiles')
        .select('email')
        .eq('id', viaApiKey)
        .single();
      return { userId: viaApiKey, userEmail: prof?.email || null, apiKey: token };
    } catch {
      return { userId: viaApiKey, userEmail: null, apiKey: token };
    }
  }

  // Fallback: treat token as JWT and verify
  try {
    if (!jwtPublicKey) return { userId: null };
    const decoded: any = jwt.verify(token, jwtPublicKey, {
      algorithms: ['RS256'],
      issuer: 'https://api.ai4everyone.com',
      audience: 'ai4everyone-api'
    });
    const userId = decoded?.sub || null;
    if (!userId) return { userId: null };
    try {
      const userClient = getUserSupabaseClient(userId);
      const { data: prof } = await userClient
        .from('profiles')
        .select('email')
        .eq('id', userId)
        .single();
      return { userId, userEmail: prof?.email || null, apiKey: null };
    } catch {
      return { userId, userEmail: null, apiKey: null };
    }
  } catch {
    return { userId: null };
  }
}

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

function isBase64DataUri(str: string): boolean {
  return /^data:([a-zA-Z0-9][a-zA-Z0-9\/+\-\.]*);base64,/.test(str);
}

function getBase64Buffer(base64Data: string): Buffer {
  let data = base64Data;
  if (isBase64DataUri(base64Data)) {
    const match = /^data:([a-zA-Z0-9][a-zA-Z0-9\/+\-\.]*);base64,(.+)$/.exec(base64Data);
    if (match) data = match[2];
  }
  return Buffer.from(data, 'base64');
}

// Allowed MIME sets
const ALLOWED_IMAGE_MIME = new Set([
  'image/png', 'image/jpeg', 'image/webp', 'image/gif'
]);
const ALLOWED_AUDIO_MIME = new Set([
  'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm'
]);
const ALLOWED_VIDEO_MIME = new Set([
  'video/mp4', 'video/webm', 'video/ogg'
]);

async function validateMediaBase64(
  base64Data: string,
  type: 'image' | 'audio' | 'video',
  maxBytes: number
): Promise<void> {
  // Pre-check estimated decoded size to avoid large allocations
  const commaIdx = base64Data.indexOf(',');
  const payload = commaIdx >= 0 ? base64Data.slice(commaIdx + 1) : base64Data;
  const estimatedBytes = Math.floor((payload.length * 3) / 4);
  if (estimatedBytes > maxBytes) {
    throw new AppError(413, `Payload too large. Max ${Math.floor(maxBytes / (1024 * 1024))}MB`);
  }

  const buffer = getBase64Buffer(base64Data);
  if (buffer.length > maxBytes) {
    throw new AppError(413, `Decoded payload too large. Max ${Math.floor(maxBytes / (1024 * 1024))}MB`);
  }
  const detected = await fileType.fromBuffer(buffer);
  const mime = detected?.mime || '';
  if (type === 'image' && !ALLOWED_IMAGE_MIME.has(mime)) {
    throw new AppError(400, `Unsupported image type: ${mime || 'unknown'}`);
  }
  if (type === 'audio' && !ALLOWED_AUDIO_MIME.has(mime)) {
    throw new AppError(400, `Unsupported audio type: ${mime || 'unknown'}`);
  }
  if (type === 'video' && !ALLOWED_VIDEO_MIME.has(mime)) {
    throw new AppError(400, `Unsupported video type: ${mime || 'unknown'}`);
  }
}

async function preValidateMediaInputs(body: any): Promise<void> {
  // Images
  if (typeof body?.image_file_base64 === 'string') {
    await validateMediaBase64(body.image_file_base64, 'image', 10 * 1024 * 1024);
  }
  if (Array.isArray(body?.image_files_base64)) {
    for (const img of body.image_files_base64) {
      if (typeof img === 'string') {
        await validateMediaBase64(img, 'image', 10 * 1024 * 1024);
      }
    }
  }
  // Audio
  if (typeof body?.audio_file_base64 === 'string') {
    await validateMediaBase64(body.audio_file_base64, 'audio', 20 * 1024 * 1024);
  }
  // Video
  if (typeof body?.video_file_base64 === 'string') {
    await validateMediaBase64(body.video_file_base64, 'video', MAX_FILE_SIZE);
  }
  if (typeof body?.mask_video_file_base64 === 'string') {
    await validateMediaBase64(body.mask_video_file_base64, 'video', MAX_FILE_SIZE);
  }
}

// Proxy endpoint for /v1/completions
router.post('/v1/completions', async (req: Request, res: Response) => {
  // Conditional validation
  const { provider, appId, source } = req.body;
  // Media sanity checks (no behavior change otherwise)
  try {
    await preValidateMediaInputs(req.body);
  } catch (e: any) {
    const status = typeof e?.statusCode === 'number' ? e.statusCode : 400;
    return res.status(status).json({ error: e?.message || 'Invalid media input' });
  }
  // Only require prompt for non-special playground models
  const isSpecialPlayground =
    provider === 'capx_ivmodels' &&
    source === 'playground' &&
    (
      appId === 'ace-step' ||
      appId === 'fal-ai/ace-step' ||
      appId === 'elevenlabs/sound-effects' ||
      appId === 'fal-ai/elevenlabs/sound-effects' ||
      appId === 'elevenlabs/tts/multilingual-v2' ||
      appId === 'fal-ai/elevenlabs/tts/multilingual-v2' ||
      appId === 'kokoro/brazilian-portuguese' ||
      appId === 'fal-ai/kokoro/brazilian-portuguese' ||
      appId === 'kokoro/hindi' ||
      appId === 'fal-ai/kokoro/hindi' ||
      appId === 'playai/inpaint/diffusion' ||
      appId === 'fal-ai/playai/inpaint/diffusion' ||
      appId === 'ace-step/audio-outpaint' ||
      appId === 'fal-ai/ace-step/audio-outpaint' ||
      appId === 'ace-step/audio-inpaint' ||
      appId === 'fal-ai/ace-step/audio-inpaint' ||
      appId === 'ace-step/audio-to-audio' ||
      appId === 'fal-ai/ace-step/audio-to-audio' ||
      appId === 'hunyuan3d-v21' ||
      appId === 'fal-ai/hunyuan3d-v21' ||
      appId === 'trellis/multi' ||
      appId === 'fal-ai/trellis/multi' ||
      appId === 'hunyuan3d/v2' ||
      appId === 'fal-ai/hunyuan3d/v2' ||
      appId === 'hunyuan3d/v2/turbo' ||
      appId === 'fal-ai/hunyuan3d/v2/turbo' ||
      appId === 'hyper3d/rodin' ||
      appId === 'fal-ai/hyper3d/rodin' ||
      appId === 'trellis' ||
      appId === 'fal-ai/trellis' ||
      appId === 'triposr' ||
      appId === 'fal-ai/triposr' ||
      appId === 'clarity-upscale' ||
      appId === 'fal-ai/clarity-upscale' ||
      appId === 'chain-of-zoom' ||
      appId === 'fal-ai/chain-of-zoom' ||
      appId === 'pasd' ||
      appId === 'fal-ai/pasd' ||
      appId === 'object-removal' ||
      appId === 'fal-ai/object-removal' ||
      appId === 'recraft/vectorize' ||
      appId === 'fal-ai/recraft/vectorize' ||
      appId === 'image-editing/cartoonify' ||
      appId === 'fal-ai/image-editing/cartoonify' ||
      appId === 'hidream-e1-full' ||
      appId === 'fal-ai/hidream-e1-full' ||
      appId === 'gpt-image-1/edit-image/byok' ||
      appId === 'fal-ai/gpt-image-1/edit-image/byok' ||
      appId === 'plushify' ||
      appId === 'fal-ai/plushify' ||
      appId === 'ghiblify' ||
      appId === 'fal-ai/ghiblify' ||
      appId === 'gemini-flash-edit' ||
      appId === 'fal-ai/gemini-flash-edit' ||
      appId === 'invisible-watermark' ||
      appId === 'fal-ai/invisible-watermark' ||
      appId === 'ddcolor' ||
      appId === 'fal-ai/ddcolor' ||
      appId === 'codeformer' ||
      appId === 'fal-ai/codeformer' ||
      appId === 'ltx-video-v095/image-to-video' ||
      appId === 'fal-ai/ltx-video-v095/image-to-video' ||
      appId === 'kling-video/v2/master/image-to-video' ||
      appId === 'fal-ai/kling-video/v2/master/image-to-video' ||
      appId === 'wan-effects' ||
      appId === 'fal-ai/wan-effects' ||
      appId === 'veo2/image-to-video' ||
      appId === 'fal-ai/veo2/image-to-video' ||
      appId === 'kling-video/v1.6/pro/image-to-video' ||
      appId === 'fal-ai/kling-video/v1.6/pro/image-to-video' ||
      appId === 'minimax/video-01/image-to-video' ||
      appId === 'fal-ai/minimax/video-01/image-to-video' ||
      appId === 'bytedance/seedance/v1/lite/image-to-video' ||
      appId === 'fal-ai/bytedance/seedance/v1/lite/image-to-video' ||
      appId === 'hunyuan-avatar' ||
      appId === 'fal-ai/hunyuan-avatar' ||
      appId === 'ltx-video-13b-dev/image-to-video' ||
      appId === 'fal-ai/ltx-video-13b-dev/image-to-video' ||
      appId === 'pixverse/v4.5/transition' ||
      appId === 'fal-ai/pixverse/v4.5/transition' ||
      appId === 'pika/v2/turbo/image-to-video' ||
      appId === 'fal-ai/pika/v2/turbo/image-to-video' ||
      appId === 'pika/v2.2/pikascenes' ||
      appId === 'fal-ai/pika/v2.2/pikascenes' ||
      appId === 'pika/v2.1/image-to-video' ||
      appId === 'fal-ai/pika/v2.1/image-to-video' ||
      appId === 'hunyuan-video-image-to-video' ||
      appId === 'fal-ai/hunyuan-video-image-to-video' ||
      appId === 'hunyuan-video-img2vid-lora' ||
      appId === 'fal-ai/hunyuan-video-img2vid-lora' ||
      appId === 'stable-video' ||
      appId === 'fal-ai/stable-video' ||
      appId === 'smart-turn' ||
      appId === 'fal-ai/smart-turn' ||
      appId === 'speech-to-text/turbo' ||
      appId === 'fal-ai/speech-to-text/turbo' ||
      appId === 'speech-to-text/turbo/stream' ||
      appId === 'fal-ai/speech-to-text/turbo/stream' ||
      appId === 'elevenlabs/speech-to-text' ||
      appId === 'fal-ai/elevenlabs/speech-to-text' ||
      appId === 'wizper' ||
      appId === 'fal-ai/wizper' ||
      appId === 'whisper' ||
      appId === 'fal-ai/whisper' ||
      appId === 'wan-vace-14b/outpainting' ||
      appId === 'fal-ai/wan-vace-14b/outpainting' ||
      appId === 'wan-vace-14b/inpainting' ||
      appId === 'fal-ai/wan-vace-14b/inpainting' ||
      appId === 'ltx-video-13b-distilled/extend' ||
      appId === 'fal-ai/ltx-video-13b-distilled/extend' ||
      appId === 'ltx-video-13b-dev/extend' ||
      appId === 'fal-ai/ltx-video-13b-dev/extend' ||
      appId === 'ben/v2/video' ||
      appId === 'fal-ai/ben/v2/video'
    );

  // For text models only, validate input; image/video models (capx_ivmodels) don't use max_tokens
  if (provider !== 'capx_ivmodels') {
    if (!req.body.prompt || typeof req.body.prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }
    if (req.body.max_tokens !== undefined && (typeof req.body.max_tokens !== 'number' || req.body.max_tokens < 1)) {
      return res.status(400).json({ error: 'max_tokens must be a positive integer' });
    }
  }
  // Log at route entry
  if (process.env.NODE_ENV !== 'production') {
    console.log('[proxy.ts] /v1/completions route entered');
  }
  let logFields: any = {};
  let statusCode = 500;
  let wasDeducted = false;
  let response: any;
  try {
    // Get user from Authorization header: support API key or JWT
    const authHeader = req.headers['authorization'] as string | undefined;
    const auth = await getUserIdFromAuthHeader(authHeader);
    const apiKey = auth.apiKey || null;
    const apiKeyPrefix = apiKey ? apiKey.slice(0, 12) : null;
    if (!auth.userId) {
      statusCode = 401;
      return res.status(401).json({ error: 'Unauthorized' });
    }
    // --- RATE LIMITING: 60 requests per minute per user ---
    const now = new Date();
    now.setSeconds(0, 0);
    const windowStart = now.toISOString();
    // We have userId from either API key or JWT
    const userId = auth.userId;
    let userEmail: string | undefined = auth.userEmail || undefined;
    if (!userEmail) {
      const userClient = getUserSupabaseClient(userId);
      const { data: prof } = await userClient
        .from('profiles')
        .select('email')
        .eq('id', userId)
        .single();
      userEmail = prof?.email;
    }
    let requestCount = 1;
    if (userEmail) {
      const { data: upserted, error: upsertError } = await supabaseAnon.rpc('increment_rate_limit', {
        p_user_email: userEmail,
        p_window_start: windowStart
      });
      if (upsertError) {
        console.warn('[rate-limit] tracking failed (continuing without blocking):', upsertError);
        requestCount = 1; // degrade gracefully
      } else {
        const record = Array.isArray(upserted) ? upserted[0] : upserted;
        requestCount = record?.request_count || 1;
      }
      if (requestCount > 60) {
        statusCode = 429;
        return res.status(429).json({ error: 'Rate limit exceeded. Please wait before making more requests.' });
      }
    }
    // --- END RATE LIMITING ---
    // --- PRE-CHECK: Calculate cost and check user balance before making external API call ---
    const prompt_tokens = req.body.prompt_tokens || (req.body.prompt ? req.body.prompt.length / 4 : 0);
    const completion_tokens = req.body.max_tokens || 0;
    const base_cost_usd = (prompt_tokens * 0.0015 / 1000) + (completion_tokens * 0.0020 / 1000);
    const markup_percentage = 10;
    const final_cost_usd = base_cost_usd * (1 + markup_percentage / 100);
    const final_cost_cents = final_cost_usd * 100;
    if (userEmail) {
      // Prefer user-scoped check by user_id (email fallback retained)
      let userBalance: any = null;
      if (userId) {
        const { data } = await getUserSupabaseClient(userId)
          .from('profiles')
          .select('balance_usd_cents')
          .eq('id', userId)
          .single();
        userBalance = data;
      } else if (userEmail) {
        const { data } = await supabase
          .from('profiles')
          .select('balance_usd_cents')
          .eq('email', userEmail)
          .single();
        userBalance = data;
      }
      if (userBalance && userBalance.balance_usd_cents < final_cost_cents) {
        statusCode = 402;
        return res.status(402).json({ error: 'Insufficient balance to process this request.' });
      }
    }
    // --- END PRE-CHECK ---
    // Multi-provider logic
    let provider = req.body.provider || 'capx_textmodels';
    if (provider === 'capx_ivmodels') {
      if (process.env.NODE_ENV !== 'production') {
        // console.log('[proxy.ts] FAL provider branch entered');

      }
      if (!FAL_API_KEY) {
        console.error('FAL_API_KEY is not set in the environment!');
        return res.status(500).json({ error: 'FAL API key not configured.' });
      }

      // Dynamic cost calculation based on actual parameters - CRITICAL FIX!
      function calculateRealFalCost(appId: string, requestBody: any): number {

        // IMPROVED: Extract duration from multiple possible parameter names with validation
        function extractDuration(requestBody: any, defaultDuration: number = 60): number {
          const durationParams = [
            requestBody.duration,
            requestBody.duration_seconds,
            requestBody.seconds_total,
            requestBody.seconds_start,
            requestBody.length,
            requestBody.audio_duration,
            requestBody.video_duration,
            requestBody.time,
            requestBody.runtime,
            requestBody.seconds,
            requestBody.duration_ms && requestBody.duration_ms / 1000, // Convert milliseconds
            requestBody.time_seconds
          ];

          // Find the first valid duration parameter
          for (const param of durationParams) {
            if (param !== undefined && param !== null && typeof param === 'number' && param > 0 && param <= 3600) {

              return Math.max(param, 0.1); // Minimum 0.1 seconds
            }
          }


          return defaultDuration;
        }

        // IMPROVED: Extract dimensions from multiple possible parameter names with validation
        function extractDimensions(requestBody: any): { width: number; height: number } {
          // Try various parameter names for width
          const width = requestBody.width ||
            requestBody.image_width ||
            requestBody.output_width ||
            requestBody.w ||
            (requestBody.size && typeof requestBody.size === 'object' ? requestBody.size.width : null) ||
            (requestBody.dimensions && requestBody.dimensions.width) ||
            (requestBody.resolution && requestBody.resolution.width) ||
            1024;

          // Try various parameter names for height  
          const height = requestBody.height ||
            requestBody.image_height ||
            requestBody.output_height ||
            requestBody.h ||
            (requestBody.size && typeof requestBody.size === 'object' ? requestBody.size.height : null) ||
            (requestBody.dimensions && requestBody.dimensions.height) ||
            (requestBody.resolution && requestBody.resolution.height) ||
            1024;

          // Validate dimensions (must be positive numbers, reasonable limits)
          const validWidth = Math.max(64, Math.min(8192, Math.floor(Number(width)) || 1024));
          const validHeight = Math.max(64, Math.min(8192, Math.floor(Number(height)) || 1024));

          return { width: validWidth, height: validHeight };
        }

        // IMPROVED: Extract text from multiple possible parameter names with validation  
        function extractText(requestBody: any): string {
          const text = requestBody.text ||
            requestBody.prompt ||
            requestBody.lyrics ||
            requestBody.input_text ||
            requestBody.message ||
            requestBody.content ||
            requestBody.query ||
            requestBody.instruction ||
            '';

          // Return trimmed text, ensure it's a string
          return typeof text === 'string' ? text.trim() : String(text || '').trim();
        }

        // Video models with duration-based pricing
        const VIDEO_DURATION_MODELS: { [key: string]: number } = {
          'Veo2': 0.50,
          'Veo3': 0.75,
          'magi': 0.25,
          'minimax/hailuo-02/pro/text-to-video': 0.08,
          'kling-video/v2/master/image-to-video': 0.30,
          'veo2/image-to-video': 0.50,
          'kling-video/v1.6/pro/image-to-video': 0.095,
          'bytedance/seedance/v1/lite/image-to-video': 0.20,
          'pika/v2.2/pikascenes': 0.10,
          'Luma-Dream-Machine/ray-2': 0.10,
          // Text-to-Video models (newly added)
          'bytedance/seedance/v1/lite/text-to-video': 0.15,
          // Audio models with per-second pricing (moved from other categories)
          'lyria2': 0.004,
          'stable-audio': 0.006,  // Uses seconds_total parameter
          'mmaudio-v2/text-to-audio': 0.001,  // Uses duration parameter
          'ace-step': 0.0055,  // Uses duration parameter (moved from FLAT_RATE)
          'elevenlabs/sound-effects': 0.0037  // Uses duration_seconds parameter ($0.11/30sec = $0.0037/sec)
        };

        // Flat rate models (removed duration-based models)
        const FLAT_RATE_MODELS: { [key: string]: number } = {
          'ltx-video-13b-dev': 0.20,
          'ltx-video-13b-distilled': 0.04,
          'LTX-Video-v095': 0.04,
          'Wan-T2V': 0.40,
          'Wan-t2v-lora': 0.35,  // Newly added
          'Fast-svd/text-to-video': 0.15,  // Newly added
          'Fast-Animatediff/text-to-video': 0.15,  // Newly added
          'Transpixar': 0.40,
          'Luma-Dream-Machine': 0.50,
          'mochi-v1': 0.40,
          'wan-effects': 0.35,
          'minimax/video-01/image-to-video': 0.50,
          'hunyuan-avatar': 0.30,
          'ltx-video-13b-dev/image-to-video': 0.20,
          'pika/v2/turbo/image-to-video': 0.20,
          'pika/v2.1/image-to-video': 0.40,
          'hunyuan-video-image-to-video': 0.40,
          'ltx-video-v095/image-to-video': 0.04,
          'hunyuan-video-img2vid-lora': 0.30,
          'stable-video': 0.075,
          'pixverse/v4.5/transition': 0.80,
          // Image models
          'Fast-SDXL': 0.04,  // Newly added
          'Ideogram/v2': 0.08,
          'Imagen4/preview/fast': 0.02,
          'Bagel': 0.10,
          'Ideogram/v3': 0.09,
          'Flux-pro/v1.1-ultra': 0.06,
          'hidream-e1-full': 0.06,
          'plushify': 0.10,
          'ghiblify': 0.05,
          'gemini-flash-edit': 0.04,
          'chain-of-zoom': 0.025,
          'object-removal': 0.024,
          'recraft/vectorize': 0.04,
          'image-editing/cartoonify': 0.06,
          'invisible-watermark': 0.01,
          'gpt-image-1/edit-image/byok': 0.40,  // Newly added
          // 3D models
          'hunyuan3d-v21': 0.30,
          'trellis/multi': 0.02,
          'hunyuan3d/v2': 0.16,
          'hunyuan3d/v2/turbo': 0.14,
          'hyper3d/rodin': 0.40,
          'trellis': 0.02,
          'triposr': 0.07,
          // Audio models with FLAT RATES ONLY (no duration dependency)
          'ace-step/audio-outpaint': 1.50,
          'ace-step/audio-inpaint': 1.50,
          'ace-step/audio-to-audio': 1.50,
          'playai/inpaint/diffusion': 0.50,  // Newly added audio-to-audio
          // Video-to-Video models (newly added)
          'wan-vace-14b/outpainting': 1.00,  // Per video generation
          'wan-vace-14b/inpainting': 1.00,   // Per video generation
          'ltx-video-13b-distilled/extend': 0.15,
          'ltx-video-13b-dev/extend': 0.20,
        };

        // Clean appId (remove fal-ai/ prefix)
        const cleanAppId = appId.replace('fal-ai/', '');

        // Check for duration-based models
        if (VIDEO_DURATION_MODELS[cleanAppId]) {
          const duration = extractDuration(requestBody, 5); // Default 5 seconds for video
          const ratePerSecond = VIDEO_DURATION_MODELS[cleanAppId];
          const costUsd = duration * ratePerSecond;

          const costCents = costUsd * 100; // NO ROUNDING - PRECISE BILLING!
          // Apply 20% markup for non-text models
          const finalCostCents = provider !== 'capx_textmodels' ? costCents * 1.2 : costCents;
          return finalCostCents;
        }

        // Check for flat rate models
        if (cleanAppId === 'trellis') {
          // Hardcode final cost for trellis to 0.024 USD (2.4 cents)
          const finalCostCents = 2.4;
          return finalCostCents;
        }
        if (FLAT_RATE_MODELS[cleanAppId]) {
          const costUsd = FLAT_RATE_MODELS[cleanAppId];
          const costCents = costUsd * 100; // NO ROUNDING - PRECISE BILLING!
          // Apply 20% markup for non-text models
          const finalCostCents = provider !== 'capx_textmodels' ? costCents * 1.2 : costCents;
          return finalCostCents;
        }

        // Megapixel-based models (images)
        const MEGAPIXEL_MODELS: { [key: string]: number } = {
          'HiDream-i1-full': 0.05,  // Moved from flat rate for megapixel pricing
          'HiDream-I1-Dev': 0.03,   // Moved from flat rate for megapixel pricing
          'Flux/dev': 0.025,
          'Stable-Diffusion-V35-Large': 0.065,
          'Flux-Lora': 0.035,
          'Flux-1/schnell': 0.003,
          'Dreamo': 0.05,
          'Sana/v1.5/1.6b': 0.0075,
          'sana/v1.5/4.8b': 0.01,
          'cogview4': 0.1,
          'clarity-upscale': 0.03,  // Newly added image-to-image
          'pasd': 0.03,            // Newly added image-to-image
          'ddcolor': 0.001,         // Newly added image-to-image
          'codeformer': 0.0021,     // Newly added image-to-image
          'ben/v2/video': 0.001
        };

        if (MEGAPIXEL_MODELS[cleanAppId]) {
          let megapixels;

          if (cleanAppId === 'ben/v2/video' && requestBody._videoMetadata) {
            // 🎯 USE REAL VIDEO ANALYSIS DATA
            megapixels = requestBody._videoMetadata.megapixels;
          } else if (cleanAppId === 'ben/v2/video') {
            // Fallback for external API calls or analysis failure
            megapixels = 75; // Conservative estimate based on your averages
          } else {
            // Other models: use dimension-based calculation
            const { width, height } = extractDimensions(requestBody);
            megapixels = (width * height) / 1000000;
          }

          const ratePerMP = MEGAPIXEL_MODELS[cleanAppId];
          const costUsd = megapixels * ratePerMP;
          const costCents = costUsd * 100; // NO ROUNDING - PRECISE BILLING!
          // Apply 20% markup for non-text models
          const finalCostCents = provider !== 'capx_textmodels' ? costCents * 1.2 : costCents;



          return finalCostCents;
        }

        // Character-based models (TTS)
        const CHAR_MODELS: { [key: string]: number } = {
          'elevenlabs/tts/multilingual-v2': 0.11,
          'kokoro/brazilian-portuguese': 0.022,
          'kokoro/hindi': 0.022
        };

        if (CHAR_MODELS[cleanAppId]) {
          const text = extractText(requestBody);
          const charCount = text.length || 100; // Default 100 chars
          const ratePerThousandChars = CHAR_MODELS[cleanAppId];
          const costUsd = (charCount / 1000) * ratePerThousandChars;
          const costCents = costUsd * 100; // NO ROUNDING - PRECISE BILLING!
          // Apply 20% markup for non-text models
          const finalCostCents = provider !== 'capx_textmodels' ? costCents * 1.2 : costCents;
          return finalCostCents;
        }

        // Audio duration models (for transcription/speech-to-text) - ESTIMATION-BASED MODELS ONLY
        const AUDIO_DURATION_MODELS: { [key: string]: number } = {
          'elevenlabs/speech-to-text': 0.03,  // Per minute, will be converted to seconds
          'speech-to-text/turbo': 0.0008,  // Per second  
          'speech-to-text/turbo/stream': 0.0008,  // Per second
        };

        // Compute-time-based models (charge per actual processing time) - DYNAMIC BILLING MODELS
        const COMPUTE_TIME_MODELS: { [key: string]: number } = {
          'wizper': 0.002,  // $0.002 per compute second
          'whisper': 0.002,  // $0.002 per compute second (UPDATED PRICING - WAS 0.008)
          'smart-turn': 0.002,  // $0.002 per compute second (UPDATED PRICING - WAS 0.008)
        };

        if (AUDIO_DURATION_MODELS[cleanAppId]) {
          const duration = extractDuration(requestBody, 60); // Default 1 minute for audio
          const rate = AUDIO_DURATION_MODELS[cleanAppId];



          let costUsd = 0;
          if (cleanAppId === 'elevenlabs/speech-to-text') {
            // Special case: elevenlabs charges per minute
            const durationMinutes = duration / 60;
            costUsd = durationMinutes * rate;  // Convert seconds to minutes

          } else {
            // All other audio-to-text models charge per second
            costUsd = duration * rate;

          }

          const costCents = costUsd * 100; // NO ROUNDING - PRECISE BILLING!
          // Apply 20% markup for non-text models
          const finalCostCents = provider !== 'capx_textmodels' ? costCents * 1.2 : costCents;




          return finalCostCents;
        }

        // Check for compute-time-based models (DYNAMIC BILLING!)
        if (COMPUTE_TIME_MODELS[cleanAppId]) {

          // DON'T OVERWRITE EXISTING TIMING DATA (important for multiple calls)
          if (!requestBody._computeEstimate || !requestBody._computeEstimate.isRealTimeMeasurement) {
            // Start timing for ACTUAL processing measurement (upload → response)
            const startTime = Date.now();
            requestBody._computeStartTime = startTime;

            // Get audio duration for logging purposes
            const audioDuration = extractDuration(requestBody, 60);
            const ratePerComputeSecond = COMPUTE_TIME_MODELS[cleanAppId];

            // Store data for real-time calculation when we get the response
            requestBody._computeEstimate = {
              audioDuration,
              ratePerComputeSecond,
              startTime,
              isRealTimeMeasurement: true,
              estimatedCostCents: 0, // Will be calculated after actual measurement
              estimatedCostUsd: 0
            };
          } else {
            // Preserve existing timing data
          }



          return 0; // No upfront charge - charge based on actual processing time
        }

        // IMPROVED FALLBACK: Try case-insensitive matching before failing

        // Create case-insensitive lookup maps
        const allModels = {
          ...VIDEO_DURATION_MODELS,
          ...FLAT_RATE_MODELS,
          ...MEGAPIXEL_MODELS,
          ...CHAR_MODELS,
          ...AUDIO_DURATION_MODELS,
          ...COMPUTE_TIME_MODELS
        };

        // Try case-insensitive matching
        const modelKeys = Object.keys(allModels);
        const caseInsensitiveMatch = modelKeys.find(key =>
          key.toLowerCase() === cleanAppId.toLowerCase()
        );

        if (caseInsensitiveMatch) {
          // Recursively call with the correct case
          return calculateRealFalCost(caseInsensitiveMatch, requestBody);
        }

        // FINAL FALLBACK: Throw error instead of charging wrong amount

        // Don't charge anything - throw error for proper handling
        throw new Error(`PRICING_ERROR: Model "${cleanAppId}" not found in pricing database. Available models: ${Object.keys(allModels).length} total.`);
      }

      try {
        let appId = req.body.appId;
        if (!appId) {
          appId = 'fal-ai/any-llm';
        } else if (!appId.startsWith('fal-ai/')) {
          appId = `fal-ai/${appId}`;
        }
        let falPayload: any = { ...req.body }; // Default: just forward the body
        // Special handling for ace-step from Playground (tags fixed, lyrics from prompt)
        if ((appId === 'fal-ai/ace-step' || appId === 'ace-step') && req.body.source === 'playground') {
          // Playground: hardcoded/defaults
          falPayload = {
            tags: 'lofi, hiphop, drum and bass, trap, chill',
            lyrics: req.body.prompt,
            duration: 10,
            number_of_steps: 27,
            scheduler: 'euler',
            guidance_type: 'apg',
            granularity_scale: 10,
            guidance_interval: 0.5,
            guidance_interval_decay: 0,
            guidance_scale: 15,
            minimum_guidance_scale: 3,
            tag_guidance_scale: 5,
            lyric_guidance_scale: 1.5
          };
        } else if (appId === 'fal-ai/ace-step' || appId === 'ace-step') {
          // External API: require all params from req.body
          const requiredFields = [
            'tags', 'lyrics', 'duration', 'number_of_steps', 'scheduler', 'guidance_type',
            'granularity_scale', 'guidance_interval', 'guidance_interval_decay', 'guidance_scale',
            'minimum_guidance_scale', 'tag_guidance_scale', 'lyric_guidance_scale'
          ];
          const missingFields = requiredFields.filter(f => req.body[f] === undefined || req.body[f] === null);
          if (missingFields.length > 0) {
            return res.status(400).json({ error: `Missing required fields for ace-step: ${missingFields.join(', ')}` });
          }
          falPayload = {
            tags: req.body.tags,
            lyrics: req.body.lyrics,
            duration: req.body.duration,
            number_of_steps: req.body.number_of_steps,
            scheduler: req.body.scheduler,
            guidance_type: req.body.guidance_type,
            granularity_scale: req.body.granularity_scale,
            guidance_interval: req.body.guidance_interval,
            guidance_interval_decay: req.body.guidance_interval_decay,
            guidance_scale: req.body.guidance_scale,
            minimum_guidance_scale: req.body.minimum_guidance_scale,
            tag_guidance_scale: req.body.tag_guidance_scale,
            lyric_guidance_scale: req.body.lyric_guidance_scale
          };
        }
        // Special handling for elevenlabs/sound-effects
        else if (appId === 'elevenlabs/sound-effects' || appId === 'fal-ai/elevenlabs/sound-effects') {
          if (req.body.source === 'playground') {
            // Playground: use chatbox input for text, hardcode duration_seconds to 5
            falPayload = {
              text: req.body.text,
              prompt_influence: 0.3,
              duration_seconds: 5
            };
          } else {
            // External API: require text
            if (!req.body.text) {
              return res.status(400).json({ error: 'Missing required field for elevenlabs/sound-effects: text' });
            }
            falPayload = {
              text: req.body.text
            };
            if (req.body.duration_seconds !== undefined) {
              falPayload.duration_seconds = req.body.duration_seconds;
            }
            if (req.body.prompt_influence !== undefined) {
              falPayload.prompt_influence = req.body.prompt_influence;
            }
          }
        }
        // Special handling for elevenlabs/tts/multilingual-v2
        else if (appId === 'elevenlabs/tts/multilingual-v2' || appId === 'fal-ai/elevenlabs/tts/multilingual-v2') {
          if (req.body.source === 'playground') {
            // Playground: use chatbox input for text, hardcode demo values
            falPayload = {
              text: req.body.text,
              voice: 'Aria',
              stability: 0.5,
              similarity_boost: 0.75,
              speed: 1
            };
          } else {
            // External API: require text
            if (!req.body.text) {
              return res.status(400).json({ error: 'Missing required field for elevenlabs/tts/multilingual-v2: text' });
            }
            falPayload = {
              text: req.body.text
            };
            if (req.body.voice !== undefined) falPayload.voice = req.body.voice;
            if (req.body.stability !== undefined) falPayload.stability = req.body.stability;
            if (req.body.similarity_boost !== undefined) falPayload.similarity_boost = req.body.similarity_boost;
            if (req.body.speed !== undefined) falPayload.speed = req.body.speed;
            if (req.body.style !== undefined) falPayload.style = req.body.style;
            if (req.body.timestamps !== undefined) falPayload.timestamps = req.body.timestamps;
            if (req.body.previous_text !== undefined) falPayload.previous_text = req.body.previous_text;
            if (req.body.next_text !== undefined) falPayload.next_text = req.body.next_text;
            if (req.body.language_code !== undefined) falPayload.language_code = req.body.language_code;
          }
        }
        // Special handling for mmaudio-v2/text-to-audio
        else if (appId === 'mmaudio-v2/text-to-audio' || appId === 'fal-ai/mmaudio-v2/text-to-audio') {
          if (req.body.source === 'playground') {
            // Playground: use chatbox input for prompt, hardcode num_steps, duration, cfg_strength
            falPayload = {
              prompt: req.body.prompt,
              num_steps: 25,
              duration: 4,
              cfg_strength: 4.5
            };
          } else {
            // External API: require prompt
            if (!req.body.prompt) {
              return res.status(400).json({ error: 'Missing required field for mmaudio-v2/text-to-audio: prompt' });
            }
            falPayload = {
              prompt: req.body.prompt
            };
            if (req.body.negative_prompt !== undefined) falPayload.negative_prompt = req.body.negative_prompt;
            if (req.body.seed !== undefined) falPayload.seed = req.body.seed;
            if (req.body.num_steps !== undefined) falPayload.num_steps = req.body.num_steps;
            if (req.body.duration !== undefined) falPayload.duration = req.body.duration;
            if (req.body.cfg_strength !== undefined) falPayload.cfg_strength = req.body.cfg_strength;
            if (req.body.mask_away_clip !== undefined) falPayload.mask_away_clip = req.body.mask_away_clip;
          }
        }
        // Special handling for stable-audio
        else if (appId === 'stable-audio' || appId === 'fal-ai/stable-audio') {
          if (req.body.source === 'playground') {
            // Playground: use chatbox input for prompt, hardcode seconds_total and steps
            falPayload = {
              prompt: req.body.prompt,
              seconds_total: 10,
              steps: 100
            };
          } else {
            // External API: require prompt
            if (!req.body.prompt) {
              return res.status(400).json({ error: 'Missing required field for stable-audio: prompt' });
            }
            falPayload = {
              prompt: req.body.prompt
            };
            if (req.body.seconds_start !== undefined) falPayload.seconds_start = req.body.seconds_start;
            if (req.body.seconds_total !== undefined) falPayload.seconds_total = req.body.seconds_total;
            if (req.body.steps !== undefined) falPayload.steps = req.body.steps;
          }
        }
        // Special handling for playai/inpaint/diffusion
        else if (appId === 'playai/inpaint/diffusion' || appId === 'fal-ai/playai/inpaint/diffusion') {
          if (req.body.source === 'playground') {
            // Playground: require audio file and prompt, hardcode other fields
            // Expect frontend to send: { audio_file_base64, prompt }
            const { audio_file_base64, prompt } = req.body;
            if (!audio_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for playai/inpaint/diffusion playground: audio_file_base64, prompt' });
            }

            // Upload audio file using Fal client
            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) fileData = match[1];

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Create a Blob with proper MIME type
            const blob = new Blob([buffer], { type: 'audio/mpeg' });

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: 'audio.mp3',
              writable: false
            });

            // Upload file to Fal storage
            let audio_url;
            try {
              audio_url = await fal.storage.upload(blob);
              console.log('File uploaded successfully to Fal storage:', audio_url);
            } catch (uploadError) {
              console.error('Failed to upload file to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload audio file to storage.' });
            }

            // Validate that we got a proper URL
            if (!audio_url || typeof audio_url !== 'string' || !audio_url.startsWith('http')) {
              console.error('Invalid audio URL returned from Fal storage:', audio_url);
              return res.status(500).json({ error: 'Invalid audio URL returned from storage.' });
            }

            // Hardcoded demo values for playground
            falPayload = {
              audio_url,
              text: 'The answer is out there Neo. It\'s looking for you.',
              output_text: prompt,
              chunks: [
                { text: 'The', timestamp: [0, 0.12] },
                { text: 'answer', timestamp: [0.12, 0.44] },
                { text: 'is', timestamp: [0.44, 0.66] },
                { text: 'out', timestamp: [0.66, 0.9] },
                { text: 'there', timestamp: [0.9, 1.12] },
                { text: 'Neo.', timestamp: [1.12, 1.7] },
                { text: 'It\'s', timestamp: [1.7, 3.38] },
                { text: 'looking', timestamp: [3.38, 3.6] },
                { text: 'for', timestamp: [3.6, 3.88] },
                { text: 'you.', timestamp: [3.88, 4.22] }
              ],
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { audio_url, text, output_text, chunks } = req.body;
            if (!audio_url || !text || !output_text || !chunks) {
              return res.status(400).json({ error: 'Missing required fields for playai/inpaint/diffusion: audio_url, text, output_text, chunks' });
            }
            falPayload = {
              audio_url,
              text,
              output_text,
              chunks,
              logs: true
            };
          }
        }
        // Special handling for ace-step/audio-outpaint
        else if (appId === 'ace-step/audio-outpaint' || appId === 'fal-ai/ace-step/audio-outpaint') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file and prompt, hardcode everything else
            // Expect frontend to send: { audio_file_base64, prompt }
            const { audio_file_base64, prompt } = req.body;
            if (!audio_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-outpaint playground: audio_file_base64, prompt' });
            }

            // Upload audio file using Fal client (same approach as playai/inpaint/diffusion)
            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) fileData = match[1];

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Create a Blob with proper MIME type
            const blob = new Blob([buffer], { type: 'audio/mpeg' });

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: 'audio.mp3',
              writable: false
            });

            // Upload file to Fal storage
            let audio_url;
            try {
              audio_url = await fal.storage.upload(blob);
              console.log('File uploaded successfully to Fal storage:', audio_url);
            } catch (uploadError) {
              console.error('Failed to upload file to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload audio file to storage.' });
            }

            // Validate that we got a proper URL
            if (!audio_url || typeof audio_url !== 'string' || !audio_url.startsWith('http')) {
              console.error('Invalid audio URL returned from Fal storage:', audio_url);
              return res.status(500).json({ error: 'Invalid audio URL returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            falPayload = {
              audio_url: audio_url,
              tags: prompt,  // Use the prompt as tags (required field)
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { audio_url, tags } = req.body;
            if (!audio_url || !tags) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-outpaint: audio_url, tags' });
            }
            // Use flat structure (same as playground)
            falPayload = {
              audio_url: req.body.audio_url,
              extend_before_duration: req.body.extend_before_duration || 0,
              extend_after_duration: req.body.extend_after_duration || 30,
              tags: req.body.tags,
              lyrics: req.body.lyrics || "",
              number_of_steps: req.body.number_of_steps || 27,
              seed: req.body.seed,
              scheduler: req.body.scheduler || "euler",
              guidance_type: req.body.guidance_type || "apg",
              granularity_scale: req.body.granularity_scale || 10,
              guidance_interval: req.body.guidance_interval || 0.5,
              guidance_interval_decay: req.body.guidance_interval_decay || 0,
              guidance_scale: req.body.guidance_scale || 15,
              minimum_guidance_scale: req.body.minimum_guidance_scale || 3,
              tag_guidance_scale: req.body.tag_guidance_scale || 5,
              lyric_guidance_scale: req.body.lyric_guidance_scale || 1.5,
              logs: true
            };
          }
        }
        // Special handling for ace-step/audio-inpaint
        else if (appId === 'ace-step/audio-inpaint' || appId === 'fal-ai/ace-step/audio-inpaint') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file and prompt, hardcode everything else
            // Expect frontend to send: { audio_file_base64, prompt }
            const { audio_file_base64, prompt } = req.body;
            if (!audio_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-inpaint playground: audio_file_base64, prompt' });
            }

            // Upload audio file using Fal client (same approach as audio-outpaint)
            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) fileData = match[1];

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Use WAV format for better compatibility with ace-step/audio-inpaint
            const blob = new Blob([buffer], { type: 'audio/wav' });

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: 'audio.wav',
              writable: false
            });

            // Upload file to Fal storage
            let audio_url;
            try {
              audio_url = await fal.storage.upload(blob);
              console.log('File uploaded successfully to Fal storage:', audio_url);
            } catch (uploadError) {
              console.error('Failed to upload file to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload audio file to storage.' });
            }

            // Validate that we got a proper URL
            if (!audio_url || typeof audio_url !== 'string' || !audio_url.startsWith('http')) {
              console.error('Invalid audio URL returned from Fal storage:', audio_url);
              return res.status(500).json({ error: 'Invalid audio URL returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            falPayload = {
              audio_url: audio_url,
              tags: prompt,  // Use the prompt as tags (required field)
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { audio_url, tags } = req.body;
            if (!audio_url || !tags) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-inpaint: audio_url, tags' });
            }
            // Use flat structure (same as playground)
            falPayload = {
              audio_url: req.body.audio_url,
              start_time_relative_to: req.body.start_time_relative_to || "start",
              start_time: req.body.start_time || 0,
              end_time_relative_to: req.body.end_time_relative_to || "start",
              end_time: req.body.end_time || 30,
              tags: req.body.tags,
              lyrics: req.body.lyrics || "",
              variance: req.body.variance || 0.5,
              number_of_steps: req.body.number_of_steps || 27,
              seed: req.body.seed,
              scheduler: req.body.scheduler || "euler",
              guidance_type: req.body.guidance_type || "apg",
              granularity_scale: req.body.granularity_scale || 10,
              guidance_interval: req.body.guidance_interval || 0.5,
              guidance_interval_decay: req.body.guidance_interval_decay || 0,
              guidance_scale: req.body.guidance_scale || 15,
              minimum_guidance_scale: req.body.minimum_guidance_scale || 3,
              tag_guidance_scale: req.body.tag_guidance_scale || 5,
              lyric_guidance_scale: req.body.lyric_guidance_scale || 1.5,
              logs: true
            };
          }
        }
        // Special handling for ace-step/audio-to-audio
        else if (appId === 'ace-step/audio-to-audio' || appId === 'fal-ai/ace-step/audio-to-audio') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file and prompt, hardcode everything else
            // Expect frontend to send: { audio_file_base64, prompt }
            const { audio_file_base64, prompt } = req.body;
            if (!audio_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-to-audio playground: audio_file_base64, prompt' });
            }

            // Upload audio file using Fal client (same approach as other ace-step models)
            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) fileData = match[1];

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Use WAV format for better compatibility with ace-step models
            const blob = new Blob([buffer], { type: 'audio/wav' });

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: 'audio.wav',
              writable: false
            });

            // Upload file to Fal storage
            let audio_url;
            try {
              audio_url = await fal.storage.upload(blob);
              console.log('File uploaded successfully to Fal storage:', audio_url);
            } catch (uploadError) {
              console.error('Failed to upload file to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload audio file to storage.' });
            }

            // Validate that we got a proper URL
            if (!audio_url || typeof audio_url !== 'string' || !audio_url.startsWith('http')) {
              console.error('Invalid audio URL returned from Fal storage:', audio_url);
              return res.status(500).json({ error: 'Invalid audio URL returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            // For audio-to-audio, we need both original_tags and tags
            falPayload = {
              audio_url: audio_url,
              original_tags: "lofi, hiphop, drum and bass, trap, chill",  // Hardcoded original style
              tags: prompt,  // Use the prompt as new tags (required field)
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { audio_url, original_tags, tags } = req.body;
            if (!audio_url || !original_tags || !tags) {
              return res.status(400).json({ error: 'Missing required fields for ace-step/audio-to-audio: audio_url, original_tags, tags' });
            }
            // Use flat structure (same as playground)
            falPayload = {
              audio_url: req.body.audio_url,
              edit_mode: req.body.edit_mode || "remix",
              original_tags: req.body.original_tags,
              original_lyrics: req.body.original_lyrics || "",
              tags: req.body.tags,
              lyrics: req.body.lyrics || "",
              number_of_steps: req.body.number_of_steps || 27,
              seed: req.body.seed,
              scheduler: req.body.scheduler || "euler",
              guidance_type: req.body.guidance_type || "apg",
              granularity_scale: req.body.granularity_scale || 10,
              guidance_interval: req.body.guidance_interval || 0.5,
              guidance_interval_decay: req.body.guidance_interval_decay || 0,
              guidance_scale: req.body.guidance_scale || 15,
              minimum_guidance_scale: req.body.minimum_guidance_scale || 3,
              tag_guidance_scale: req.body.tag_guidance_scale || 5,
              lyric_guidance_scale: req.body.lyric_guidance_scale || 1.5,
              original_seed: req.body.original_seed,
              logs: true
            };
          }
        }
        // Special handling for hunyuan3d-v21
        else if (appId === 'hunyuan3d-v21' || appId === 'fal-ai/hunyuan3d-v21') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            // Expect frontend to send: { image_file_base64 }
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for hunyuan3d-v21 playground: image_file_base64' });
            }

            // Upload image file using Fal client
            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let input_image_url;
            try {
              input_image_url = await fal.storage.upload(blob);
              console.log('File uploaded successfully to Fal storage:', input_image_url);
            } catch (uploadError) {
              console.error('Failed to upload file to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image file to storage.' });
            }

            // Validate that we got a proper URL
            if (!input_image_url || typeof input_image_url !== 'string' || !input_image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', input_image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            falPayload = {
              input_image_url: input_image_url,
              num_inference_steps: 50,
              guidance_scale: 7.5,
              octree_resolution: 256,
              textured_mesh: true,  // Generate textured mesh for better quality
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { input_image_url } = req.body;
            if (!input_image_url) {
              return res.status(400).json({ error: 'Missing required field for hunyuan3d-v21: input_image_url' });
            }
            // Use flat structure (same as playground)
            falPayload = {
              input_image_url: req.body.input_image_url,
              seed: req.body.seed,
              num_inference_steps: req.body.num_inference_steps || 50,
              guidance_scale: req.body.guidance_scale || 7.5,
              octree_resolution: req.body.octree_resolution || 256,
              textured_mesh: req.body.textured_mesh || false,
              logs: true
            };
          }
        }
        // Special handling for trellis/multi
        else if (appId === 'trellis/multi' || appId === 'fal-ai/trellis/multi') {
          if (req.body.source === 'playground') {
            // Playground: require multiple image files, hardcode everything else
            // Expect frontend to send: { image_files_base64: [...] }
            const { image_files_base64 } = req.body;
            if (!image_files_base64 || !Array.isArray(image_files_base64) || image_files_base64.length === 0) {
              return res.status(400).json({ error: 'Missing required field for trellis/multi playground: image_files_base64 (array of images)' });
            }

            // Upload all image files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            let image_urls = [];

            for (let i = 0; i < image_files_base64.length; i++) {
              const base64 = image_files_base64[i];

              // Strip data URI prefix if present
              let fileData = base64;
              const match = /^data:.*;base64,(.*)$/.exec(base64);
              if (match) fileData = match[1];

              // Convert base64 to buffer
              const buffer = Buffer.from(fileData, 'base64');

              // Detect image MIME type or use default
              let mimeType = 'image/png';
              const originalMatch = /^data:(.*?);base64,/.exec(base64);
              if (originalMatch && originalMatch[1]) {
                mimeType = originalMatch[1];
              }

              // Create a Blob with detected MIME type
              const blob = new Blob([buffer], { type: mimeType });

              // Use appropriate file extension based on MIME type
              let fileExtension = '.png';
              if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
                fileExtension = '.jpg';
              } else if (mimeType.includes('png')) {
                fileExtension = '.png';
              } else if (mimeType.includes('webp')) {
                fileExtension = '.webp';
              }

              // Add file properties to the blob
              Object.defineProperty(blob, 'name', {
                value: `image_${i}${fileExtension}`,
                writable: false
              });

              // Upload file to Fal storage
              try {
                const image_url = await fal.storage.upload(blob);
                console.log(`Image ${i} uploaded successfully to Fal storage:`, image_url);
                image_urls.push(image_url);
              } catch (uploadError) {
                console.error(`Failed to upload image ${i} to Fal storage:`, uploadError);
                return res.status(500).json({ error: `Failed to upload image ${i} to storage.` });
              }
            }

            // Validate that we got proper URLs
            if (image_urls.length === 0) {
              console.error('No valid image URLs returned from Fal storage');
              return res.status(500).json({ error: 'No valid image URLs returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            falPayload = {
              image_urls: image_urls,
              ss_guidance_strength: 7.5,
              ss_sampling_steps: 12,
              slat_guidance_strength: 3,
              slat_sampling_steps: 12,
              mesh_simplify: 0.95,
              texture_size: 1024,
              multiimage_algo: "stochastic",
              logs: true
            };
          } else {
            // API/developer: require all fields
            const { image_urls } = req.body;
            if (!image_urls || !Array.isArray(image_urls) || image_urls.length === 0) {
              return res.status(400).json({ error: 'Missing required field for trellis/multi: image_urls (array)' });
            }
            // Use flat structure (same as playground)
            falPayload = {
              image_urls: req.body.image_urls,
              seed: req.body.seed,
              ss_guidance_strength: req.body.ss_guidance_strength || 7.5,
              ss_sampling_steps: req.body.ss_sampling_steps || 12,
              slat_guidance_strength: req.body.slat_guidance_strength || 3,
              slat_sampling_steps: req.body.slat_sampling_steps || 12,
              mesh_simplify: req.body.mesh_simplify || 0.95,
              texture_size: typeof req.body.texture_size === 'number' ? req.body.texture_size : 1024, // force number
              multiimage_algo: req.body.multiimage_algo || "stochastic",
              logs: true
            };
          }
        }
        // Special handling for hunyuan3d/v2 and hunyuan3d/v2/turbo
        else if (appId === 'hunyuan3d/v2' || appId === 'fal-ai/hunyuan3d/v2' || appId === 'hunyuan3d/v2/turbo' || appId === 'fal-ai/hunyuan3d/v2/turbo') {
          if (req.body.source === 'playground') {
            // Playground: require image file(s), hardcode everything else
            // Support both single image and multiple images like trellis/multi
            const { image_files_base64 } = req.body;
            if (!image_files_base64 || !Array.isArray(image_files_base64) || image_files_base64.length === 0) {
              return res.status(400).json({ error: 'Missing required field for hunyuan3d/v2 playground: image_files_base64 (array of images)' });
            }

            // Upload all image files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            let image_urls = [];

            for (let i = 0; i < image_files_base64.length; i++) {
              const base64 = image_files_base64[i];

              // Strip data URI prefix if present
              let fileData = base64;
              const match = /^data:.*;base64,(.*)$/.exec(base64);
              if (match) fileData = match[1];

              // Convert base64 to buffer
              const buffer = Buffer.from(fileData, 'base64');

              // Detect image MIME type or use default
              let mimeType = 'image/png';
              const originalMatch = /^data:(.*?);base64,/.exec(base64);
              if (originalMatch && originalMatch[1]) {
                mimeType = originalMatch[1];
              }

              // Create a Blob with detected MIME type
              const blob = new Blob([buffer], { type: mimeType });

              // Use appropriate file extension based on MIME type
              let fileExtension = '.png';
              if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
                fileExtension = '.jpg';
              } else if (mimeType.includes('png')) {
                fileExtension = '.png';
              } else if (mimeType.includes('webp')) {
                fileExtension = '.webp';
              }

              // Add file properties to the blob
              Object.defineProperty(blob, 'name', {
                value: `image_${i}${fileExtension}`,
                writable: false
              });

              // Upload file to Fal storage
              try {
                const image_url = await fal.storage.upload(blob);
                console.log(`Image ${i} uploaded successfully to Fal storage:`, image_url);
                image_urls.push(image_url);
              } catch (uploadError) {
                console.error(`Failed to upload image ${i} to Fal storage:`, uploadError);
                return res.status(500).json({ error: `Failed to upload image ${i} to storage.` });
              }
            }

            // Validate that we got proper URLs
            if (image_urls.length === 0) {
              console.error('No valid image URLs returned from Fal storage');
              return res.status(500).json({ error: 'No valid image URLs returned from storage.' });
            }

            // Use flat structure (confirmed working with curl testing)
            // For single image, use input_image_url. For multiple images, use front/back/left format (assuming up to 3 images)
            if (image_urls.length === 1) {
              falPayload = {
                input_image_url: image_urls[0],
                num_inference_steps: 50,
                guidance_scale: 7.5,
                octree_resolution: 256,
                textured_mesh: true,
                logs: true
              };
            } else {
              // For multiple images, use front/back/left format (assuming up to 3 images)
              falPayload = {
                front_image_url: image_urls[0],
                back_image_url: image_urls[1] || image_urls[0], // fallback to first image
                left_image_url: image_urls[2] || image_urls[0], // fallback to first image
                num_inference_steps: 50,
                guidance_scale: 7.5,
                octree_resolution: 256,
                textured_mesh: true,
                logs: true
              };
            }
          } else {
            // API/developer: require all fields
            const { input_image_url, front_image_url } = req.body;
            if (!input_image_url && !front_image_url) {
              return res.status(400).json({ error: 'Missing required field for hunyuan3d/v2: input_image_url or front_image_url' });
            }

            // Use flat structure (same as playground)
            if (input_image_url) {
              // Single image mode
              falPayload = {
                input_image_url: req.body.input_image_url,
                seed: req.body.seed,
                num_inference_steps: req.body.num_inference_steps || 50,
                guidance_scale: req.body.guidance_scale || 7.5,
                octree_resolution: req.body.octree_resolution || 256,
                textured_mesh: req.body.textured_mesh || false,
                logs: true
              };
            } else {
              // Multi-view mode
              falPayload = {
                front_image_url: req.body.front_image_url,
                back_image_url: req.body.back_image_url,
                left_image_url: req.body.left_image_url,
                seed: req.body.seed,
                num_inference_steps: req.body.num_inference_steps || 50,
                guidance_scale: req.body.guidance_scale || 7.5,
                octree_resolution: req.body.octree_resolution || 256,
                textured_mesh: req.body.textured_mesh || false,
                logs: true
              };
            }
          }
        }
        // Special handling for hyper3d/rodin
        else if (appId === 'hyper3d/rodin' || appId === 'fal-ai/hyper3d/rodin') {
          if (req.body.source === 'playground') {
            // Playground mode: support both text-to-3D and image-to-3D
            // Check if images are provided for Image-to-3D mode
            const { image_files_base64, prompt } = req.body;

            if (image_files_base64 && Array.isArray(image_files_base64) && image_files_base64.length > 0) {
              // Image-to-3D mode: upload images and use them
              const { fal } = require('@fal-ai/client');
              fal.config({ credentials: FAL_API_KEY });

              let image_urls = [];

              for (let i = 0; i < image_files_base64.length; i++) {
                const base64 = image_files_base64[i];

                // Strip data URI prefix if present
                let fileData = base64;
                const match = /^data:.*;base64,(.*)$/.exec(base64);
                if (match) fileData = match[1];

                // Convert base64 to buffer
                const buffer = Buffer.from(fileData, 'base64');

                // Detect image MIME type or use default
                let mimeType = 'image/png';
                const originalMatch = /^data:(.*?);base64,/.exec(base64);
                if (originalMatch && originalMatch[1]) {
                  mimeType = originalMatch[1];
                }

                // Create a Blob with detected MIME type
                const blob = new Blob([buffer], { type: mimeType });

                // Use appropriate file extension based on MIME type
                let fileExtension = '.png';
                if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
                  fileExtension = '.jpg';
                } else if (mimeType.includes('png')) {
                  fileExtension = '.png';
                } else if (mimeType.includes('webp')) {
                  fileExtension = '.webp';
                }

                // Add file properties to the blob
                Object.defineProperty(blob, 'name', {
                  value: `image_${i}${fileExtension}`,
                  writable: false
                });

                // Upload file to Fal storage
                try {
                  const image_url = await fal.storage.upload(blob);
                  console.log(`Image ${i} uploaded successfully to Fal storage:`, image_url);
                  image_urls.push(image_url);
                } catch (uploadError) {
                  console.error(`Failed to upload image ${i} to Fal storage:`, uploadError);
                  return res.status(500).json({ error: `Failed to upload image ${i} to storage.` });
                }
              }

              // Validate that we got proper URLs
              if (image_urls.length === 0) {
                console.error('No valid image URLs returned from Fal storage');
                return res.status(500).json({ error: 'No valid image URLs returned from storage.' });
              }

              // Use flat structure for Image-to-3D mode
              falPayload = {
                input_image_urls: image_urls,
                prompt: prompt || "", // Optional prompt for Image-to-3D
                condition_mode: "fuse", // Use fuse mode for multiple images
                geometry_file_format: "glb",
                material: "PBR",
                quality: "medium",
                tier: "Regular",
                use_hyper: false,
                logs: true
              };
            } else if (prompt) {
              // Text-to-3D mode: use only prompt
              falPayload = {
                prompt: prompt,
                geometry_file_format: "glb",
                material: "PBR",
                quality: "medium",
                tier: "Regular",
                use_hyper: false,
                logs: true
              };
            } else {
              return res.status(400).json({ error: 'Missing required field for hyper3d/rodin playground: either image_files_base64 (array of images) or prompt (text)' });
            }
          } else {
            // API/developer mode: require either prompt or input_image_urls
            const { prompt, input_image_urls } = req.body;
            if (!prompt && (!input_image_urls || !Array.isArray(input_image_urls) || input_image_urls.length === 0)) {
              return res.status(400).json({ error: 'Missing required field for hyper3d/rodin: either prompt (for Text-to-3D) or input_image_urls (for Image-to-3D)' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              prompt: req.body.prompt || "",
              input_image_urls: req.body.input_image_urls || [],
              condition_mode: req.body.condition_mode || "fuse",
              seed: req.body.seed,
              geometry_file_format: req.body.geometry_file_format || "glb",
              material: req.body.material || "PBR",
              quality: req.body.quality || "medium",
              use_hyper: req.body.use_hyper || false,
              tier: req.body.tier || "Regular",
              TAPose: req.body.TAPose,
              bbox_condition: req.body.bbox_condition,
              addons: req.body.addons,
              logs: true
            };
          }
        }
        // Special handling for trellis (single-image 3D model)
        else if (appId === 'trellis' || appId === 'fal-ai/trellis') {
          if (req.body.source === 'playground') {
            // Playground: require single image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for trellis playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let image_url;
            try {
              image_url = await fal.storage.upload(blob);
              console.log('Image uploaded successfully to Fal storage:', image_url);
            } catch (uploadError) {
              console.error('Failed to upload image to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image to storage.' });
            }

            // Validate that we got a proper URL
            if (!image_url || typeof image_url !== 'string' || !image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure (consistent with other models)
            falPayload = {
              image_url: image_url,
              ss_guidance_strength: 7.5,
              ss_sampling_steps: 12,
              slat_guidance_strength: 3,
              slat_sampling_steps: 12,
              mesh_simplify: 0.95,
              texture_size: 1024, // <-- number, not string
              logs: true
            };
          } else {
            // API/developer: require image_url
            const { image_url } = req.body;
            if (!image_url) {
              return res.status(400).json({ error: 'Missing required field for trellis: image_url' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              image_url: req.body.image_url,
              seed: req.body.seed,
              ss_guidance_strength: req.body.ss_guidance_strength || 7.5,
              ss_sampling_steps: req.body.ss_sampling_steps || 12,
              slat_guidance_strength: req.body.slat_guidance_strength || 3,
              slat_sampling_steps: req.body.slat_sampling_steps || 12,
              mesh_simplify: req.body.mesh_simplify || 0.95,
              texture_size: typeof req.body.texture_size === 'number' ? req.body.texture_size : 1024, // force number
              logs: true
            };
          }
        }
        // Special handling for triposr (single-image 3D model)
        else if (appId === 'triposr' || appId === 'fal-ai/triposr') {
          if (req.body.source === 'playground') {
            // Playground: require single image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for triposr playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let image_url;
            try {
              image_url = await fal.storage.upload(blob);
              console.log('Image uploaded successfully to Fal storage:', image_url);
            } catch (uploadError) {
              console.error('Failed to upload image to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image to storage.' });
            }

            // Validate that we got a proper URL
            if (!image_url || typeof image_url !== 'string' || !image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure (consistent with other models)
            falPayload = {
              image_url: image_url,
              output_format: "glb",
              do_remove_background: true,
              foreground_ratio: 0.9,
              mc_resolution: 256,
              logs: true
            };
          } else {
            // API/developer: require image_url
            const { image_url } = req.body;
            if (!image_url) {
              return res.status(400).json({ error: 'Missing required field for triposr: image_url' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              image_url: req.body.image_url,
              output_format: req.body.output_format || "glb",
              do_remove_background: req.body.do_remove_background !== undefined ? req.body.do_remove_background : true,
              foreground_ratio: req.body.foreground_ratio || 0.9,
              mc_resolution: req.body.mc_resolution || 256,
              logs: true
            };
          }
        }
        // Special handling for chain-of-zoom (Image-to-Image model)
        else if (appId === 'chain-of-zoom' || appId === 'fal-ai/chain-of-zoom') {
          if (req.body.source === 'playground') {
            // Playground: require single image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for chain-of-zoom playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let image_url;
            try {
              image_url = await fal.storage.upload(blob);
              console.log('Image uploaded successfully to Fal storage:', image_url);
            } catch (uploadError) {
              console.error('Failed to upload image to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image to storage.' });
            }

            // Validate that we got a proper URL
            if (!image_url || typeof image_url !== 'string' || !image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure for chain-of-zoom (confirmed with curl testing)
            falPayload = {
              image_url: image_url,
              scale: 5,  // Default zoom scale (powers of 2)
              center_x: 0.5,  // Center X coordinate (0-1)
              center_y: 0.5,  // Center Y coordinate (0-1)
              user_prompt: ""  // Additional prompt text
            };
          } else {
            // API/developer: require image_url
            const { image_url } = req.body;
            if (!image_url) {
              return res.status(400).json({ error: 'Missing required field for chain-of-zoom: image_url' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              image_url: req.body.image_url,
              scale: req.body.scale || 5,
              center_x: req.body.center_x || 0.5,
              center_y: req.body.center_y || 0.5,
              user_prompt: req.body.user_prompt || "",
              sync_mode: req.body.sync_mode
            };
          }
        }
        // Special handling for clarity-upscale (Image-to-Image model)
        else if (appId === 'clarity-upscale' || appId === 'fal-ai/clarity-upscale') {
          if (req.body.source === 'playground') {
            // Playground: require single image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for clarity-upscale playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let image_url;
            try {
              image_url = await fal.storage.upload(blob);
              console.log('Image uploaded successfully to Fal storage:', image_url);
            } catch (uploadError) {
              console.error('Failed to upload image to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image to storage.' });
            }

            // Validate that we got a proper URL
            if (!image_url || typeof image_url !== 'string' || !image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure for clarity-upscaler (confirmed with curl testing)
            falPayload = {
              image_url: image_url
            };
          } else {
            // API/developer: require image_url
            const { image_url } = req.body;
            if (!image_url) {
              return res.status(400).json({ error: 'Missing required field for clarity-upscale: image_url' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              image_url: req.body.image_url
            };
          }
        }
        // Special handling for pasd (Image-to-Image model)
        else if (appId === 'pasd' || appId === 'fal-ai/pasd') {
          if (req.body.source === 'playground') {
            // Playground: require single image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for pasd playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) fileData = match[1];

            // Convert base64 to buffer
            const buffer = Buffer.from(fileData, 'base64');

            // Detect image MIME type or use default
            let mimeType = 'image/png';
            const originalMatch = /^data:(.*?);base64,/.exec(image_file_base64);
            if (originalMatch && originalMatch[1]) {
              mimeType = originalMatch[1];
            }

            // Create a Blob with detected MIME type
            const blob = new Blob([buffer], { type: mimeType });

            // Use appropriate file extension based on MIME type
            let fileExtension = '.png';
            if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
              fileExtension = '.jpg';
            } else if (mimeType.includes('png')) {
              fileExtension = '.png';
            } else if (mimeType.includes('webp')) {
              fileExtension = '.webp';
            }

            // Add file properties to the blob
            Object.defineProperty(blob, 'name', {
              value: `image${fileExtension}`,
              writable: false
            });

            // Upload file to Fal storage
            let image_url;
            try {
              image_url = await fal.storage.upload(blob);
              console.log('Image uploaded successfully to Fal storage:', image_url);
            } catch (uploadError) {
              console.error('Failed to upload image to Fal storage:', uploadError);
              return res.status(500).json({ error: 'Failed to upload image to storage.' });
            }

            // Validate that we got a proper URL
            if (!image_url || typeof image_url !== 'string' || !image_url.startsWith('http')) {
              console.error('Invalid image URL returned from Fal storage:', image_url);
              return res.status(500).json({ error: 'Invalid image URL returned from storage.' });
            }

            // Use flat structure for pasd (confirmed with curl testing)
            falPayload = {
              image_url: image_url,
              scale: 2,  // Default upscaling factor (1-4x)
              steps: 25,  // Default inference steps (10-50)
              guidance_scale: 7,  // Default guidance scale (1.0-20.0)
              conditioning_scale: 0.8,  // Default ControlNet conditioning scale (0.1-1.0)
              prompt: "",  // Additional prompt to guide super-resolution
              negative_prompt: "blurry, dirty, messy, frames, deformed, dotted, noise, raster lines, unclear, lowres, over-smoothed, painting, ai generated"
            };
          } else {
            // API/developer: require image_url
            const { image_url } = req.body;
            if (!image_url) {
              return res.status(400).json({ error: 'Missing required field for pasd: image_url' });
            }

            // Use flat structure (same as playground)
            falPayload = {
              image_url: req.body.image_url,
              scale: req.body.scale || 2,
              steps: req.body.steps || 25,
              guidance_scale: req.body.guidance_scale || 7,
              conditioning_scale: req.body.conditioning_scale || 0.8,
              prompt: req.body.prompt || "",
              negative_prompt: req.body.negative_prompt || "blurry, dirty, messy, frames, deformed, dotted, noise, raster lines, unclear, lowres, over-smoothed, painting, ai generated"
            };
          }
        }
        // Special handling for object-removal (Image-to-Image model with prompt)
        else if (appId === 'object-removal' || appId === 'fal-ai/object-removal') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for object-removal playground: image_file_base64' });
            }
            if (!prompt || prompt.trim() === '') {
              return res.status(400).json({ error: 'Missing required field for object-removal playground: prompt (describe what to remove)' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for object-removal (confirmed with curl testing)
            falPayload = {
              image_url: image_url,
              prompt: prompt.trim(),
              model: "best_quality",
              mask_expansion: 15
            };
          } else {
            // API/Developer: allow all parameters
            falPayload = {
              image_url: req.body.image_url,
              prompt: req.body.prompt,
              model: req.body.model || "best_quality",
              mask_expansion: req.body.mask_expansion !== undefined ? req.body.mask_expansion : 15
            };
          }
        }
        // Special handling for recraft/vectorize (Image-to-Image model)
        else if (appId === 'recraft/vectorize' || appId === 'fal-ai/recraft/vectorize') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for recraft/vectorize playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for recraft/vectorize
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for image-editing/cartoonify (Image-to-Image model)
        else if (appId === 'image-editing/cartoonify' || appId === 'fal-ai/image-editing/cartoonify') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for image-editing/cartoonify playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for image-editing/cartoonify
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url,
              scale: 1,
              guidance_scale: 3.5,
              num_inference_steps: 28,
              enable_safety_checker: true
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for hidream-e1-full (Image-to-Image model with edit instruction)
        else if (appId === 'hidream-e1-full' || appId === 'fal-ai/hidream-e1-full') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and edit instruction
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for hidream-e1-full playground: image_file_base64' });
            }
            if (!prompt || prompt.trim() === '') {
              return res.status(400).json({ error: 'Missing required field for hidream-e1-full playground: prompt (edit instruction)' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for hidream-e1-full
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url,
              edit_instruction: prompt.trim(),
              negative_prompt: "low resolution, blur",
              num_inference_steps: 50,
              guidance_scale: 3.5,
              image_guidance_scale: 2,
              num_images: 1,
              enable_safety_checker: true,
              output_format: "jpeg"
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for gpt-image-1/edit-image/byok (Image-to-Image model with BYOK)
        else if (appId === 'gpt-image-1/edit-image/byok' || appId === 'fal-ai/gpt-image-1/edit-image/byok') {
          if (req.body.source === 'playground') {
            // Playground: require image file, prompt, and OpenAI API key
            const { image_file_base64, prompt, openai_api_key } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for gpt-image-1/edit-image/byok playground: image_file_base64' });
            }
            if (!prompt || prompt.trim() === '') {
              return res.status(400).json({ error: 'Missing required field for gpt-image-1/edit-image/byok playground: prompt (edit instruction)' });
            }
            if (!openai_api_key || openai_api_key.trim() === '') {
              return res.status(400).json({ error: 'Missing required field for gpt-image-1/edit-image/byok playground: openai_api_key (OpenAI API key required)' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for gpt-image-1/edit-image/byok
            // Hardcode parameters for playground mode
            falPayload = {
              image_urls: [image_url],
              prompt: prompt.trim(),
              openai_api_key: openai_api_key.trim(),
              image_size: "auto",
              num_images: 1,
              quality: "auto"
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for plushify (Image-to-Image model)
        else if (appId === 'plushify' || appId === 'fal-ai/plushify') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for plushify playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for plushify
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url,
              prompt: "",
              scale: 1,
              guidance_scale: 3.5,
              num_inference_steps: 28,
              enable_safety_checker: true,
              num_images: 1
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for ghiblify (Image-to-Image model)
        else if (appId === 'ghiblify' || appId === 'fal-ai/ghiblify') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for ghiblify playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for ghiblify
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url,
              enable_safety_checker: true
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for gemini-flash-edit (Image-to-Image model that requires both image and prompt)
        else if (appId === 'gemini-flash-edit' || appId === 'fal-ai/gemini-flash-edit') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for gemini-flash-edit playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for gemini-flash-edit
            falPayload = {
              prompt: prompt,
              image_url: image_url
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for invisible-watermark (Image-to-Image model)
        else if (appId === 'invisible-watermark' || appId === 'fal-ai/invisible-watermark') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode watermark text
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for invisible-watermark playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for invisible-watermark
            // Hardcode parameters for playground mode (encode watermark)
            falPayload = {
              image_url: image_url,
              watermark: "AI4Everyone",
              decode: false
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for ddcolor (Image-to-Image model)
        else if (appId === 'ddcolor' || appId === 'fal-ai/ddcolor') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode everything else
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for ddcolor playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for ddcolor
            // Hardcode parameters for playground mode
            falPayload = {
              image_url: image_url
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for codeformer (Image-to-Image model for face restoration)
        else if (appId === 'codeformer' || appId === 'fal-ai/codeformer') {
          if (req.body.source === 'playground') {
            // Playground: require only image file, hardcode sensible defaults
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for codeformer playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for codeformer
            // Hardcode sensible defaults for playground mode
            falPayload = {
              image_url: image_url,
              fidelity: 0.7,
              upscaling: 2,
              aligned: false,
              only_center_face: false,
              face_upscale: true
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for ltx-video-v095/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'ltx-video-v095/image-to-video' || appId === 'fal-ai/ltx-video-v095/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-v095/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for ltx-video-v095/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              negative_prompt: "worst quality, inconsistent motion, blurry, jittery, distorted",
              resolution: "720p",
              aspect_ratio: "16:9",
              num_inference_steps: 40,
              expand_prompt: true
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for kling-video/v2/master/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'kling-video/v2/master/image-to-video' || appId === 'fal-ai/kling-video/v2/master/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for kling-video/v2/master/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for kling-video/v2/master/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              duration: "5",
              negative_prompt: "blur, distort, and low quality",
              cfg_scale: 0.5
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for wan-effects (Image-to-Video model that requires both image and subject)
        else if (appId === 'wan-effects' || appId === 'fal-ai/wan-effects') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt (used as subject)
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for wan-effects playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for wan-effects
            // Hardcode sensible defaults for playground mode
            falPayload = {
              subject: prompt,
              image_url: image_url,
              effect_type: "cakeify",
              num_frames: 81,
              frames_per_second: 16,
              aspect_ratio: "16:9",
              num_inference_steps: 30,
              lora_scale: 1,
              turbo_mode: false
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for veo2/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'veo2/image-to-video' || appId === 'fal-ai/veo2/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for veo2/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for veo2/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              aspect_ratio: "auto",
              duration: "5s"
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for kling-video/v1.6/pro/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'kling-video/v1.6/pro/image-to-video' || appId === 'fal-ai/kling-video/v1.6/pro/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for kling-video/v1.6/pro/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for kling-video/v1.6/pro/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              duration: "5",
              aspect_ratio: "16:9",
              negative_prompt: "blur, distort, and low quality",
              cfg_scale: 0.5
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for minimax/video-01/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'minimax/video-01/image-to-video' || appId === 'fal-ai/minimax/video-01/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for minimax/video-01/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for minimax/video-01/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              prompt_optimizer: true
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for bytedance/seedance/v1/lite/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'bytedance/seedance/v1/lite/image-to-video' || appId === 'fal-ai/bytedance/seedance/v1/lite/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for bytedance/seedance/v1/lite/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for bytedance/seedance/v1/lite/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              resolution: "720p",
              duration: "5",
              camera_fixed: false,
              seed: -1
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for hunyuan-avatar (Avatar animation model that requires both audio and image files)
        else if (appId === 'hunyuan-avatar' || appId === 'fal-ai/hunyuan-avatar') {
          if (req.body.source === 'playground') {
            // Playground: require both audio file and image file
            const { audio_file_base64, image_file_base64, prompt } = req.body;
            if (!audio_file_base64 || !image_file_base64) {
              return res.status(400).json({ error: 'Missing required fields for hunyuan-avatar playground: audio_file_base64 and image_file_base64' });
            }

            // Upload both files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Upload audio file
            let audioFileData = audio_file_base64;
            const audioMatch = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (audioMatch) {
              audioFileData = audioMatch[1];
            }
            const audioBuffer = Buffer.from(audioFileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Upload image file
            let imageFileData = image_file_base64;
            const imageMatch = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (imageMatch) {
              imageFileData = imageMatch[1];
            }
            const imageBuffer = Buffer.from(imageFileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for hunyuan-avatar
            // Hardcode sensible defaults for playground mode
            falPayload = {
              audio_url: audio_url,
              image_url: image_url,
              text: prompt || "A person is speaking.",
              num_inference_steps: 30,
              turbo_mode: true,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for ltx-video-13b-dev/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'ltx-video-13b-dev/image-to-video' || appId === 'fal-ai/ltx-video-13b-dev/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-13b-dev/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for ltx-video-13b-dev/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              negative_prompt: "worst quality, inconsistent motion, blurry, jittery, distorted",
              resolution: "720p",
              aspect_ratio: "auto",
              number_of_frames: 121,
              first_pass_number_of_steps: 30,
              first_pass_skip_final_steps: 3,
              second_pass_number_of_steps: 30,
              second_pass_skip_initial_steps: 17,
              frame_rate: 30,
              expand_prompt: false,
              reverse_video: false,
              enable_safety_checker: true,
              constant_rate_factor: 35,
              loras: []
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for pixverse/v4.5/transition (Transition model that requires two image files and prompt)
        else if (appId === 'pixverse/v4.5/transition' || appId === 'fal-ai/pixverse/v4.5/transition') {
          if (req.body.source === 'playground') {
            // Playground: require two image files and prompt
            const { first_image_file_base64, last_image_file_base64, prompt } = req.body;
            if (!first_image_file_base64 || !last_image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for pixverse/v4.5/transition playground: first_image_file_base64, last_image_file_base64, and prompt' });
            }

            // Upload both image files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Upload first image file
            let firstFileData = first_image_file_base64;
            const firstMatch = /^data:.*;base64,(.*)$/.exec(first_image_file_base64);
            if (firstMatch) {
              firstFileData = firstMatch[1];
            }
            const firstImageBuffer = Buffer.from(firstFileData, 'base64');
            const first_image_url = await fal.storage.upload(firstImageBuffer);

            // Upload last image file
            let lastFileData = last_image_file_base64;
            const lastMatch = /^data:.*;base64,(.*)$/.exec(last_image_file_base64);
            if (lastMatch) {
              lastFileData = lastMatch[1];
            }
            const lastImageBuffer = Buffer.from(lastFileData, 'base64');
            const last_image_url = await fal.storage.upload(lastImageBuffer);

            // Use flat structure for pixverse/v4.5/transition
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              first_image_url: first_image_url,
              last_image_url: last_image_url,
              aspect_ratio: "16:9",
              resolution: "720p",
              duration: "5",
              negative_prompt: "blurry, low quality, low resolution, pixelated, noisy, grainy, out of focus, poorly lit, poorly exposed, poorly composed, poorly framed, poorly cropped, poorly color corrected, poorly color graded",
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for pika/v2/turbo/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'pika/v2/turbo/image-to-video' || appId === 'fal-ai/pika/v2/turbo/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for pika/v2/turbo/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for pika/v2/turbo/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              image_url: image_url,
              prompt: prompt,
              negative_prompt: "",
              resolution: "720p",
              duration: 5,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for pika/v2.2/pikascenes (Multi-Image-to-Video model that requires multiple images and prompt)
        else if (appId === 'pika/v2.2/pikascenes' || appId === 'fal-ai/pika/v2.2/pikascenes') {
          if (req.body.source === 'playground') {
            // Playground: require multiple image files and prompt
            const { image_files_base64, prompt } = req.body;
            if (!image_files_base64 || !Array.isArray(image_files_base64) || image_files_base64.length === 0 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for pika/v2.2/pikascenes playground: image_files_base64 (array) and prompt' });
            }

            // Upload all image files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            const imageUrls = [];
            for (const imageBase64 of image_files_base64) {
              // Strip data URI prefix if present
              let fileData = imageBase64;
              const match = /^data:.*;base64,(.*)$/.exec(imageBase64);
              if (match) {
                fileData = match[1];
              }

              const imageBuffer = Buffer.from(fileData, 'base64');
              const image_url = await fal.storage.upload(imageBuffer);
              imageUrls.push({ image_url: image_url });
            }

            // Use flat structure for pika/v2.2/pikascenes
            // Hardcode sensible defaults for playground mode
            falPayload = {
              images: imageUrls,
              prompt: prompt,
              negative_prompt: "",
              aspect_ratio: "16:9",
              resolution: "720p",
              duration: 5,
              ingredients_mode: "creative",
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for pika/v2.1/image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'pika/v2.1/image-to-video' || appId === 'fal-ai/pika/v2.1/image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for pika/v2.1/image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for pika/v2.1/image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              image_url: image_url,
              prompt: prompt,
              negative_prompt: "",
              resolution: "720p",
              duration: 5,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for hunyuan-video-image-to-video (Image-to-Video model that requires both image and prompt)
        else if (appId === 'hunyuan-video-image-to-video' || appId === 'fal-ai/hunyuan-video-image-to-video') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for hunyuan-video-image-to-video playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for hunyuan-video-image-to-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              aspect_ratio: "16:9",
              resolution: "720p",
              num_frames: "129",
              i2v_stability: false,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for hunyuan-video-img2vid-lora (Image-to-Video model that requires both image and prompt)
        else if (appId === 'hunyuan-video-img2vid-lora' || appId === 'fal-ai/hunyuan-video-img2vid-lora') {
          if (req.body.source === 'playground') {
            // Playground: require both image file and prompt
            const { image_file_base64, prompt } = req.body;
            if (!image_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for hunyuan-video-img2vid-lora playground: image_file_base64 and prompt' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for hunyuan-video-img2vid-lora
            // Hardcode sensible defaults for playground mode
            falPayload = {
              prompt: prompt,
              image_url: image_url,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Special handling for smart-turn (Audio-to-Text model for turn detection)
        else if (appId === 'smart-turn' || appId === 'fal-ai/smart-turn') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for smart-turn playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for smart-turn
            falPayload = {
              audio_url: audio_url
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for smart-turn: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url
            };
          }
        }
        // Special handling for speech-to-text/turbo (Audio-to-Text model for speech transcription)
        else if (appId === 'speech-to-text/turbo' || appId === 'fal-ai/speech-to-text/turbo') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for speech-to-text/turbo playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for speech-to-text/turbo
            // Default to use punctuation & capitalization
            falPayload = {
              audio_url: audio_url,
              use_pnc: true
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for speech-to-text/turbo: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url,
              use_pnc: req.body.use_pnc !== undefined ? req.body.use_pnc : true
            };
          }
        }
        // Special handling for speech-to-text/turbo/stream (Streaming Audio-to-Text model for speech transcription)
        else if (appId === 'speech-to-text/turbo/stream' || appId === 'fal-ai/speech-to-text/turbo/stream') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for speech-to-text/turbo/stream playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for speech-to-text/turbo/stream
            // Default to use punctuation & capitalization
            falPayload = {
              audio_url: audio_url,
              use_pnc: true
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for speech-to-text/turbo/stream: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url,
              use_pnc: req.body.use_pnc !== undefined ? req.body.use_pnc : true
            };
          }
        }
        // Special handling for elevenlabs/speech-to-text (Advanced Audio-to-Text model with speaker identification)
        else if (appId === 'elevenlabs/speech-to-text' || appId === 'fal-ai/elevenlabs/speech-to-text') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for elevenlabs/speech-to-text playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for elevenlabs/speech-to-text
            // Default to enable audio events tagging and speaker diarization
            falPayload = {
              audio_url: audio_url,
              language_code: "eng",
              tag_audio_events: true,
              diarize: true
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for elevenlabs/speech-to-text: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url,
              language_code: req.body.language_code || "eng",
              tag_audio_events: req.body.tag_audio_events !== undefined ? req.body.tag_audio_events : true,
              diarize: req.body.diarize !== undefined ? req.body.diarize : true
            };
          }
        }
        // Special handling for wizper (Whisper-based Audio-to-Text model with chunking)
        else if (appId === 'wizper' || appId === 'fal-ai/wizper') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for wizper playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for wizper
            // Default to transcribe task, English language, segment chunks, version 3
            falPayload = {
              audio_url: audio_url,
              task: "transcribe",
              language: "en",
              chunk_level: "segment",
              version: "3"
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for wizper: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url,
              task: req.body.task || "transcribe",
              language: req.body.language || "en",
              chunk_level: req.body.chunk_level || "segment",
              version: req.body.version || "3"
            };
          }
        }
        // Special handling for whisper (Audio-to-Text model with transcription and translation)
        else if (appId === 'whisper' || appId === 'fal-ai/whisper') {
          if (req.body.source === 'playground') {
            // Playground: require only audio file, hardcode sensible defaults
            const { audio_file_base64 } = req.body;
            if (!audio_file_base64) {
              return res.status(400).json({ error: 'Missing required field for whisper playground: audio_file_base64' });
            }

            // Upload audio file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = audio_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(audio_file_base64);
            if (match) {
              fileData = match[1];
            }

            const audioBuffer = Buffer.from(fileData, 'base64');
            const audio_url = await fal.storage.upload(audioBuffer);

            // Use flat structure for whisper with sensible defaults
            falPayload = {
              audio_url: audio_url,
              task: "transcribe",
              language: null,
              diarize: false,
              chunk_level: "segment",
              version: "3",
              batch_size: 64,
              prompt: "",
              num_speakers: null
            };
          } else {
            // API/Developer: user must provide audio_url
            if (!req.body.audio_url) {
              return res.status(400).json({ error: 'Missing required field for whisper: audio_url' });
            }
            falPayload = {
              audio_url: req.body.audio_url,
              task: req.body.task || "transcribe",
              language: req.body.language || null,
              diarize: req.body.diarize || false,
              chunk_level: req.body.chunk_level || "segment",
              version: req.body.version || "3",
              batch_size: req.body.batch_size || 64,
              prompt: req.body.prompt || "",
              num_speakers: req.body.num_speakers || null
            };
          }
        }
        // Special handling for wan-vace-14b/outpainting (Video-to-Video model for outpainting)
        else if (appId === 'wan-vace-14b/outpainting' || appId === 'fal-ai/wan-vace-14b/outpainting') {
          if (req.body.source === 'playground') {
            // Playground: require video file and prompt, hardcode sensible defaults
            const { video_file_base64, prompt } = req.body;
            if (!video_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for wan-vace-14b/outpainting playground: video_file_base64, prompt' });
            }

            // Upload video file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = video_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(video_file_base64);
            if (match) {
              fileData = match[1];
            }

            const videoBuffer = Buffer.from(fileData, 'base64');
            const video_url = await fal.storage.upload(videoBuffer);

            // Use flat structure for wan-vace-14b/outpainting with sensible defaults
            falPayload = {
              prompt: prompt,
              video_url: video_url,
              negative_prompt: "bright colors, overexposed, static, blurred details, subtitles, style, artwork, painting, picture, still, overall gray, worst quality, low quality, JPEG compression residue, ugly, incomplete, extra fingers, poorly drawn hands, poorly drawn faces, deformed, disfigured, malformed limbs, fused fingers, still picture, cluttered background, three legs, many people in the background, walking backwards",
              match_input_num_frames: false,
              num_frames: 81,
              match_input_frames_per_second: false,
              frames_per_second: 16,
              seed: null,
              resolution: "720p",
              aspect_ratio: "auto",
              num_inference_steps: 30,
              guidance_scale: 5,
              enable_safety_checker: true,
              enable_prompt_expansion: false,
              expand_left: true,
              expand_right: true,
              expand_top: true,
              expand_bottom: true,
              expand_ratio: 0.25
            };
          } else {
            // API/Developer: user must provide all required parameters
            if (!req.body.video_url || !req.body.prompt) {
              return res.status(400).json({ error: 'Missing required fields for wan-vace-14b/outpainting: video_url, prompt' });
            }
            falPayload = {
              prompt: req.body.prompt,
              video_url: req.body.video_url,
              negative_prompt: req.body.negative_prompt || "bright colors, overexposed, static, blurred details, subtitles, style, artwork, painting, picture, still, overall gray, worst quality, low quality, JPEG compression residue, ugly, incomplete, extra fingers, poorly drawn hands, poorly drawn faces, deformed, disfigured, malformed limbs, fused fingers, still picture, cluttered background, three legs, many people in the background, walking backwards",
              match_input_num_frames: req.body.match_input_num_frames !== undefined ? req.body.match_input_num_frames : false,
              num_frames: req.body.num_frames || 81,
              match_input_frames_per_second: req.body.match_input_frames_per_second !== undefined ? req.body.match_input_frames_per_second : false,
              frames_per_second: req.body.frames_per_second || 16,
              seed: req.body.seed || null,
              resolution: req.body.resolution || "720p",
              aspect_ratio: req.body.aspect_ratio || "auto",
              num_inference_steps: req.body.num_inference_steps || 30,
              guidance_scale: req.body.guidance_scale || 5,
              enable_safety_checker: req.body.enable_safety_checker !== undefined ? req.body.enable_safety_checker : true,
              enable_prompt_expansion: req.body.enable_prompt_expansion !== undefined ? req.body.enable_prompt_expansion : false,
              expand_left: req.body.expand_left !== undefined ? req.body.expand_left : true,
              expand_right: req.body.expand_right !== undefined ? req.body.expand_right : true,
              expand_top: req.body.expand_top !== undefined ? req.body.expand_top : true,
              expand_bottom: req.body.expand_bottom !== undefined ? req.body.expand_bottom : true,
              expand_ratio: req.body.expand_ratio !== undefined ? req.body.expand_ratio : 0.25
            };
          }
        }
        // Special handling for wan-vace-14b/inpainting (Video-to-Video model for inpainting)
        else if (appId === 'wan-vace-14b/inpainting' || appId === 'fal-ai/wan-vace-14b/inpainting') {
          if (req.body.source === 'playground') {
            // Playground: require video file, mask video file, and prompt, hardcode sensible defaults
            const { video_file_base64, mask_video_file_base64, prompt } = req.body;
            if (!video_file_base64 || !mask_video_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for wan-vace-14b/inpainting playground: video_file_base64, mask_video_file_base64, prompt' });
            }

            // Upload both video files using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Upload source video
            let videoFileData = video_file_base64;
            const videoMatch = /^data:.*;base64,(.*)$/.exec(video_file_base64);
            if (videoMatch) {
              videoFileData = videoMatch[1];
            }
            const videoBuffer = Buffer.from(videoFileData, 'base64');
            const video_url = await fal.storage.upload(videoBuffer);

            // Upload mask video
            let maskFileData = mask_video_file_base64;
            const maskMatch = /^data:.*;base64,(.*)$/.exec(mask_video_file_base64);
            if (maskMatch) {
              maskFileData = maskMatch[1];
            }
            const maskBuffer = Buffer.from(maskFileData, 'base64');
            const mask_video_url = await fal.storage.upload(maskBuffer);

            // Use flat structure for wan-vace-14b/inpainting with sensible defaults
            falPayload = {
              prompt: prompt,
              video_url: video_url,
              mask_video_url: mask_video_url,
              negative_prompt: "bright colors, overexposed, static, blurred details, subtitles, style, artwork, painting, picture, still, overall gray, worst quality, low quality, JPEG compression residue, ugly, incomplete, extra fingers, poorly drawn hands, poorly drawn faces, deformed, disfigured, malformed limbs, fused fingers, still picture, cluttered background, three legs, many people in the background, walking backwards",
              match_input_num_frames: false,
              num_frames: 81,
              match_input_frames_per_second: false,
              frames_per_second: 16,
              seed: null,
              resolution: "720p",
              aspect_ratio: "auto",
              num_inference_steps: 30,
              guidance_scale: 5,
              ref_image_urls: [],
              enable_safety_checker: true,
              enable_prompt_expansion: false
            };
          } else {
            // API/Developer: user must provide all required parameters
            if (!req.body.video_url || !req.body.mask_video_url || !req.body.prompt) {
              return res.status(400).json({ error: 'Missing required fields for wan-vace-14b/inpainting: video_url, mask_video_url, prompt' });
            }
            falPayload = {
              prompt: req.body.prompt,
              video_url: req.body.video_url,
              mask_video_url: req.body.mask_video_url,
              negative_prompt: req.body.negative_prompt || "bright colors, overexposed, static, blurred details, subtitles, style, artwork, painting, picture, still, overall gray, worst quality, low quality, JPEG compression residue, ugly, incomplete, extra fingers, poorly drawn hands, poorly drawn faces, deformed, disfigured, malformed limbs, fused fingers, still picture, cluttered background, three legs, many people in the background, walking backwards",
              match_input_num_frames: req.body.match_input_num_frames !== undefined ? req.body.match_input_num_frames : false,
              num_frames: req.body.num_frames || 81,
              match_input_frames_per_second: req.body.match_input_frames_per_second !== undefined ? req.body.match_input_frames_per_second : false,
              frames_per_second: req.body.frames_per_second || 16,
              seed: req.body.seed || null,
              resolution: req.body.resolution || "720p",
              aspect_ratio: req.body.aspect_ratio || "auto",
              num_inference_steps: req.body.num_inference_steps || 30,
              guidance_scale: req.body.guidance_scale || 5,
              ref_image_urls: req.body.ref_image_urls || [],
              enable_safety_checker: req.body.enable_safety_checker !== undefined ? req.body.enable_safety_checker : true,
              enable_prompt_expansion: req.body.enable_prompt_expansion !== undefined ? req.body.enable_prompt_expansion : false
            };
          }
        }
        // Special handling for ltx-video-13b-distilled/extend (Video-to-Video model for extending videos)
        else if (appId === 'ltx-video-13b-distilled/extend' || appId === 'fal-ai/ltx-video-13b-distilled/extend') {
          if (req.body.source === 'playground') {
            // Playground: require video file and prompt, hardcode sensible defaults
            const { video_file_base64, prompt } = req.body;
            if (!video_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-13b-distilled/extend playground: video_file_base64, prompt' });
            }

            // Upload video file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = video_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(video_file_base64);
            if (match) {
              fileData = match[1];
            }

            const videoBuffer = Buffer.from(fileData, 'base64');
            const video_url = await fal.storage.upload(videoBuffer);

            // Use flat structure for ltx-video-13b-distilled/extend with sensible defaults
            falPayload = {
              prompt: prompt,
              negative_prompt: "worst quality, inconsistent motion, blurry, jittery, distorted",
              loras: [],
              resolution: "720p",
              aspect_ratio: "auto",
              seed: null,
              number_of_frames: 121,
              first_pass_number_of_steps: 8,
              first_pass_skip_final_steps: 1,
              second_pass_number_of_steps: 8,
              second_pass_skip_initial_steps: 5,
              frame_rate: 30,
              expand_prompt: false,
              reverse_video: false,
              enable_safety_checker: true,
              constant_rate_factor: 35,
              video: {
                strength: 1,
                video_url: video_url,
                start_frame_num: 24
              }
            };
          } else {
            // API/Developer: user must provide all required parameters
            if (!req.body.prompt || !req.body.video || !req.body.video.video_url) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-13b-distilled/extend: prompt, video.video_url' });
            }
            falPayload = {
              prompt: req.body.prompt,
              negative_prompt: req.body.negative_prompt || "worst quality, inconsistent motion, blurry, jittery, distorted",
              loras: req.body.loras || [],
              resolution: req.body.resolution || "720p",
              aspect_ratio: req.body.aspect_ratio || "auto",
              seed: req.body.seed || null,
              number_of_frames: req.body.number_of_frames || 121,
              first_pass_number_of_steps: req.body.first_pass_number_of_steps || 8,
              first_pass_skip_final_steps: req.body.first_pass_skip_final_steps || 1,
              second_pass_number_of_steps: req.body.second_pass_number_of_steps || 8,
              second_pass_skip_initial_steps: req.body.second_pass_skip_initial_steps || 5,
              frame_rate: req.body.frame_rate || 30,
              expand_prompt: req.body.expand_prompt || false,
              reverse_video: req.body.reverse_video || false,
              enable_safety_checker: req.body.enable_safety_checker !== undefined ? req.body.enable_safety_checker : true,
              constant_rate_factor: req.body.constant_rate_factor || 35,
              video: {
                strength: req.body.video.strength || 1,
                video_url: req.body.video.video_url,
                start_frame_num: req.body.video.start_frame_num || 24
              }
            };
          }
        }
        // Special handling for ltx-video-13b-dev/extend (Video-to-Video model for extending videos - dev version)
        else if (appId === 'ltx-video-13b-dev/extend' || appId === 'fal-ai/ltx-video-13b-dev/extend') {
          if (req.body.source === 'playground') {
            // Playground: require video file and prompt, hardcode sensible defaults
            const { video_file_base64, prompt } = req.body;
            if (!video_file_base64 || !prompt) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-13b-dev/extend playground: video_file_base64, prompt' });
            }

            // Upload video file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = video_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(video_file_base64);
            if (match) {
              fileData = match[1];
            }

            const videoBuffer = Buffer.from(fileData, 'base64');
            const video_url = await fal.storage.upload(videoBuffer);

            // Use flat structure for ltx-video-13b-dev/extend with sensible defaults (different from distilled)
            falPayload = {
              prompt: prompt,
              negative_prompt: "worst quality, inconsistent motion, blurry, jittery, distorted",
              loras: [],
              resolution: "720p",
              aspect_ratio: "auto",
              seed: null,
              number_of_frames: 121,
              first_pass_number_of_steps: 30,
              first_pass_skip_final_steps: 3,
              second_pass_number_of_steps: 30,
              second_pass_skip_initial_steps: 17,
              frame_rate: 30,
              expand_prompt: false,
              reverse_video: false,
              enable_safety_checker: true,
              constant_rate_factor: 35,
              video: {
                strength: 1,
                video_url: video_url,
                start_frame_num: 24
              }
            };
          } else {
            // API/Developer: user must provide all required parameters
            if (!req.body.prompt || !req.body.video || !req.body.video.video_url) {
              return res.status(400).json({ error: 'Missing required fields for ltx-video-13b-dev/extend: prompt, video.video_url' });
            }
            falPayload = {
              prompt: req.body.prompt,
              negative_prompt: req.body.negative_prompt || "worst quality, inconsistent motion, blurry, jittery, distorted",
              loras: req.body.loras || [],
              resolution: req.body.resolution || "720p",
              aspect_ratio: req.body.aspect_ratio || "auto",
              seed: req.body.seed || null,
              number_of_frames: req.body.number_of_frames || 121,
              first_pass_number_of_steps: req.body.first_pass_number_of_steps || 30,
              first_pass_skip_final_steps: req.body.first_pass_skip_final_steps || 3,
              second_pass_number_of_steps: req.body.second_pass_number_of_steps || 30,
              second_pass_skip_initial_steps: req.body.second_pass_skip_initial_steps || 17,
              frame_rate: req.body.frame_rate || 30,
              expand_prompt: req.body.expand_prompt || false,
              reverse_video: req.body.reverse_video || false,
              enable_safety_checker: req.body.enable_safety_checker !== undefined ? req.body.enable_safety_checker : true,
              constant_rate_factor: req.body.constant_rate_factor || 35,
              video: {
                strength: req.body.video.strength || 1,
                video_url: req.body.video.video_url,
                start_frame_num: req.body.video.start_frame_num || 24
              }
            };
          }
        }
        // Special handling for ben/v2/video (Video-to-Video model for background removal)
        else if (appId === 'ben/v2/video' || appId === 'fal-ai/ben/v2/video') {
          if (req.body.source === 'playground') {
            // Playground: require video file only, no prompt needed
            const { video_file_base64 } = req.body;
            if (!video_file_base64) {
              return res.status(400).json({ error: 'Missing required field for ben/v2/video playground: video_file_base64' });
            }

            console.log('🎬 [BEN/V2/VIDEO] Starting video processing...');

            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = video_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(video_file_base64);
            if (match) {
              fileData = match[1];
              console.log('🎬 [BEN/V2/VIDEO] Stripped data URI prefix');
            }

            const videoBuffer = Buffer.from(fileData, 'base64');
            console.log('🎬 [BEN/V2/VIDEO] Video buffer created, size:', videoBuffer.length, 'bytes');

            // 🎯 BILLING METADATA (NO LOCAL FFMPEG) — derive from request params or fallback
            let videoMetadata;
            const reqWidth = Number((req.body && req.body.width) || (req.body && req.body.video_width));
            const reqHeight = Number((req.body && req.body.height) || (req.body && req.body.video_height));
            const reqFps = Number((req.body && req.body.fps) || (req.body && req.body.video_fps));
            const reqDuration = Number((req.body && req.body.duration) || (req.body && req.body.video_duration));

            const hasAllParams =
              Number.isFinite(reqWidth) && reqWidth > 0 &&
              Number.isFinite(reqHeight) && reqHeight > 0 &&
              Number.isFinite(reqFps) && reqFps > 0 && reqFps <= 120 &&
              Number.isFinite(reqDuration) && reqDuration > 0 && reqDuration <= 600; // cap 10 min

            if (hasAllParams) {
              const totalFrames = Math.ceil(reqDuration * reqFps);
              const megapixels = totalFrames * ((reqWidth * reqHeight) / 1_000_000);
              videoMetadata = {
                width: reqWidth,
                height: reqHeight,
                duration: reqDuration,
                fps: reqFps,
                totalFrames,
                megapixels,
                fileSize: videoBuffer.length,
                codec: 'unknown',
                bitrate: 0
              };
              console.log('🎬 [BEN/V2/VIDEO] Using request parameters for billing metadata:', {
                width: reqWidth, height: reqHeight, fps: reqFps, duration: reqDuration,
                totalFrames, megapixels: Number(megapixels.toFixed(6))
              });
            } else {
              // Conservative fallback (matches previous behavior when analysis failed)
              videoMetadata = {
                width: 1280,
                height: 720,
                duration: 3.24,
                fps: 25,
                totalFrames: 81,
                megapixels: 75, // Conservative estimate
                fileSize: videoBuffer.length,
                codec: 'unknown',
                bitrate: 0
              };
              console.log('⚠️ [BEN/V2/VIDEO] Missing/invalid params; using conservative billing metadata (75 MP)');
            }

            // Store metadata for downstream billing calculation
            req.body._videoMetadata = videoMetadata;

            // Upload video to FAL storage
            console.log('🎬 [BEN/V2/VIDEO] Uploading video to FAL storage...');
            const video_url = await fal.storage.upload(videoBuffer);
            console.log('✅ [BEN/V2/VIDEO] Video uploaded to:', video_url);

            // Use flat structure for ben/v2/video (background removal)
            falPayload = {
              video_url: video_url,
              seed: null
            };
          } else {
            // API/Developer: user must provide video_url
            if (!req.body.video_url) {
              return res.status(400).json({ error: 'Missing required field for ben/v2/video: video_url' });
            }
            console.log('🎬 [BEN/V2/VIDEO] External API call - no analysis needed');
            falPayload = {
              video_url: req.body.video_url,
              seed: req.body.seed || null
            };
          }
        }
        // Special handling for stable-video (Image-to-Video model that requires only image, no prompt)
        else if (appId === 'stable-video' || appId === 'fal-ai/stable-video') {
          if (req.body.source === 'playground') {
            // Playground: require only image file (no prompt needed)
            const { image_file_base64 } = req.body;
            if (!image_file_base64) {
              return res.status(400).json({ error: 'Missing required field for stable-video playground: image_file_base64' });
            }

            // Upload image file using Fal client
            const { fal } = require('@fal-ai/client');
            fal.config({ credentials: FAL_API_KEY });

            // Strip data URI prefix if present
            let fileData = image_file_base64;
            const match = /^data:.*;base64,(.*)$/.exec(image_file_base64);
            if (match) {
              fileData = match[1];
            }

            const imageBuffer = Buffer.from(fileData, 'base64');
            const image_url = await fal.storage.upload(imageBuffer);

            // Use flat structure for stable-video
            // Hardcode sensible defaults for playground mode
            falPayload = {
              image_url: image_url,
              motion_bucket_id: 127,
              cond_aug: 0.02,
              fps: 25,
              seed: Math.floor(Math.random() * 1000000)
            };
          } else {
            // API/Developer: user must provide all required parameters in correct format
            // No defaults - user must send exactly what the API expects
            falPayload = req.body;
          }
        }
        // Always use the fal.run endpoint for fal
        const falBaseUrl = 'https://fal.run';
        // Fix the endpoint for ace-step models
        let endpoint = appId;

        if (appId === 'ace-step/audio-outpaint') {
          endpoint = 'fal-ai/ace-step/audio-outpaint';  // Use audio-outpaint endpoint (confirmed working)
        } else if (appId === 'ace-step/audio-inpaint') {
          endpoint = 'fal-ai/ace-step/audio-inpaint';   // Use audio-inpaint endpoint
        } else if (appId === 'ace-step/audio-to-audio') {
          endpoint = 'fal-ai/ace-step/audio-to-audio';  // Use audio-to-audio endpoint
        } else if (appId === 'hunyuan3d-v21') {
          endpoint = 'fal-ai/hunyuan3d-v21';  // Use hunyuan3d-v21 endpoint
        } else if (appId === 'trellis/multi') {
          endpoint = 'fal-ai/trellis/multi';  // Use trellis/multi endpoint
        } else if (appId === 'hunyuan3d/v2') {
          endpoint = 'fal-ai/hunyuan3d/v2';  // Use hunyuan3d/v2 endpoint
        } else if (appId === 'hunyuan3d/v2/turbo') {
          endpoint = 'fal-ai/hunyuan3d/v2/turbo';  // Use hunyuan3d/v2/turbo endpoint
        } else if (appId === 'hyper3d/rodin') {
          endpoint = 'fal-ai/hyper3d/rodin';  // Use hyper3d/rodin endpoint
        } else if (appId === 'trellis') {
          endpoint = 'fal-ai/trellis';  // Use trellis endpoint
        } else if (appId === 'triposr') {
          endpoint = 'fal-ai/triposr';  // Use triposr endpoint
        } else if (appId === 'clarity-upscale' || appId === 'fal-ai/clarity-upscale') {
          endpoint = 'fal-ai/clarity-upscaler';  // Use clarity-upscaler endpoint

        } else if (appId === 'chain-of-zoom' || appId === 'fal-ai/chain-of-zoom') {
          endpoint = 'fal-ai/chain-of-zoom';  // Use chain-of-zoom endpoint
        } else if (appId === 'pasd' || appId === 'fal-ai/pasd') {
          endpoint = 'fal-ai/pasd';  // Use pasd endpoint
        } else if (appId === 'object-removal' || appId === 'fal-ai/object-removal') {
          endpoint = 'fal-ai/object-removal';  // Use object-removal endpoint
        } else if (appId === 'recraft/vectorize' || appId === 'fal-ai/recraft/vectorize') {
          endpoint = 'fal-ai/recraft/vectorize';  // Use recraft/vectorize endpoint
        } else if (appId === 'image-editing/cartoonify' || appId === 'fal-ai/image-editing/cartoonify') {
          endpoint = 'fal-ai/cartoonify';  // Use cartoonify endpoint
        } else if (appId === 'hidream-e1-full' || appId === 'fal-ai/hidream-e1-full') {
          endpoint = 'fal-ai/hidream-e1-full';  // Use hidream-e1-full endpoint
        } else if (appId === 'gpt-image-1/edit-image/byok' || appId === 'fal-ai/gpt-image-1/edit-image/byok') {
          endpoint = 'fal-ai/gpt-image-1/edit-image/byok';  // Use gpt-image-1/edit-image/byok endpoint
        } else if (appId === 'plushify' || appId === 'fal-ai/plushify') {
          endpoint = 'fal-ai/plushify';  // Use plushify endpoint
        } else if (appId === 'ghiblify' || appId === 'fal-ai/ghiblify') {
          endpoint = 'fal-ai/ghiblify';  // Use ghiblify endpoint
        } else if (appId === 'gemini-flash-edit' || appId === 'fal-ai/gemini-flash-edit') {
          endpoint = 'fal-ai/gemini-flash-edit';  // Use gemini-flash-edit endpoint
        } else if (appId === 'invisible-watermark' || appId === 'fal-ai/invisible-watermark') {
          endpoint = 'fal-ai/invisible-watermark';  // Use invisible-watermark endpoint
        } else if (appId === 'ddcolor' || appId === 'fal-ai/ddcolor') {
          endpoint = 'fal-ai/ddcolor';  // Use ddcolor endpoint
        } else if (appId === 'codeformer' || appId === 'fal-ai/codeformer') {
          endpoint = 'fal-ai/codeformer';  // Use codeformer endpoint
        } else if (appId === 'ltx-video-v095/image-to-video' || appId === 'fal-ai/ltx-video-v095/image-to-video') {
          endpoint = 'fal-ai/ltx-video-v095/image-to-video';  // Use ltx-video-v095/image-to-video endpoint
        } else if (appId === 'kling-video/v2/master/image-to-video' || appId === 'fal-ai/kling-video/v2/master/image-to-video') {
          endpoint = 'fal-ai/kling-video/v2/master/image-to-video';  // Use kling-video/v2/master/image-to-video endpoint
        } else if (appId === 'wan-effects' || appId === 'fal-ai/wan-effects') {
          endpoint = 'fal-ai/wan-effects';  // Use wan-effects endpoint
        } else if (appId === 'veo2/image-to-video' || appId === 'fal-ai/veo2/image-to-video') {
          endpoint = 'fal-ai/veo2/image-to-video';  // Use veo2/image-to-video endpoint
        } else if (appId === 'kling-video/v1.6/pro/image-to-video' || appId === 'fal-ai/kling-video/v1.6/pro/image-to-video') {
          endpoint = 'fal-ai/kling-video/v1.6/pro/image-to-video';  // Use kling-video/v1.6/pro/image-to-video endpoint
        } else if (appId === 'minimax/video-01/image-to-video' || appId === 'fal-ai/minimax/video-01/image-to-video') {
          endpoint = 'fal-ai/minimax/video-01/image-to-video';  // Use minimax/video-01/image-to-video endpoint
        } else if (appId === 'bytedance/seedance/v1/lite/image-to-video' || appId === 'fal-ai/bytedance/seedance/v1/lite/image-to-video') {
          endpoint = 'fal-ai/bytedance/seedance/v1/lite/image-to-video';  // Use bytedance/seedance/v1/lite/image-to-video endpoint
        } else if (appId === 'hunyuan-avatar' || appId === 'fal-ai/hunyuan-avatar') {
          endpoint = 'fal-ai/hunyuan-avatar';  // Use hunyuan-avatar endpoint
        } else if (appId === 'ltx-video-13b-dev/image-to-video' || appId === 'fal-ai/ltx-video-13b-dev/image-to-video') {
          endpoint = 'fal-ai/ltx-video-13b-dev/image-to-video';  // Use ltx-video-13b-dev/image-to-video endpoint
        } else if (appId === 'pixverse/v4.5/transition' || appId === 'fal-ai/pixverse/v4.5/transition') {
          endpoint = 'fal-ai/pixverse/v4.5/transition';  // Use pixverse/v4.5/transition endpoint
        } else if (appId === 'pika/v2/turbo/image-to-video' || appId === 'fal-ai/pika/v2/turbo/image-to-video') {
          endpoint = 'fal-ai/pika/v2/turbo/image-to-video';  // Use pika/v2/turbo/image-to-video endpoint
        } else if (appId === 'pika/v2.2/pikascenes' || appId === 'fal-ai/pika/v2.2/pikascenes') {
          endpoint = 'fal-ai/pika/v2.2/pikascenes';  // Use pika/v2.2/pikascenes endpoint
        } else if (appId === 'pika/v2.1/image-to-video' || appId === 'fal-ai/pika/v2.1/image-to-video') {
          endpoint = 'fal-ai/pika/v2.1/image-to-video';  // Use pika/v2.1/image-to-video endpoint
        } else if (appId === 'hunyuan-video-image-to-video' || appId === 'fal-ai/hunyuan-video-image-to-video') {
          endpoint = 'fal-ai/hunyuan-video-image-to-video';  // Use hunyuan-video-image-to-video endpoint
        } else if (appId === 'hunyuan-video-img2vid-lora' || appId === 'fal-ai/hunyuan-video-img2vid-lora') {
          endpoint = 'fal-ai/hunyuan-video-img2vid-lora';  // Use hunyuan-video-img2vid-lora endpoint
        } else if (appId === 'stable-video' || appId === 'fal-ai/stable-video') {
          endpoint = 'fal-ai/stable-video';  // Use stable-video endpoint
        } else if (appId === 'smart-turn' || appId === 'fal-ai/smart-turn') {
          endpoint = 'fal-ai/smart-turn';  // Use smart-turn endpoint
        } else if (appId === 'speech-to-text/turbo' || appId === 'fal-ai/speech-to-text/turbo') {
          endpoint = 'fal-ai/speech-to-text/turbo';  // Use speech-to-text/turbo endpoint
        } else if (appId === 'speech-to-text/turbo/stream' || appId === 'fal-ai/speech-to-text/turbo/stream') {
          endpoint = 'fal-ai/speech-to-text/turbo/stream';  // Use speech-to-text/turbo/stream endpoint
        } else if (appId === 'elevenlabs/speech-to-text' || appId === 'fal-ai/elevenlabs/speech-to-text') {
          endpoint = 'fal-ai/elevenlabs/speech-to-text';  // Use elevenlabs/speech-to-text endpoint
        } else if (appId === 'wizper' || appId === 'fal-ai/wizper') {
          endpoint = 'fal-ai/wizper';  // Use wizper endpoint
        } else if (appId === 'whisper' || appId === 'fal-ai/whisper') {
          endpoint = 'fal-ai/whisper';  // Use whisper endpoint
        } else if (appId === 'wan-vace-14b/outpainting' || appId === 'fal-ai/wan-vace-14b/outpainting') {
          endpoint = 'fal-ai/wan-vace-14b/outpainting';  // Use wan-vace-14b/outpainting endpoint
        } else if (appId === 'wan-vace-14b/inpainting' || appId === 'fal-ai/wan-vace-14b/inpainting') {
          endpoint = 'fal-ai/wan-vace-14b/inpainting';  // Use wan-vace-14b/inpainting endpoint
        } else if (appId === 'ltx-video-13b-distilled/extend' || appId === 'fal-ai/ltx-video-13b-distilled/extend') {
          endpoint = 'fal-ai/ltx-video-13b-distilled/extend';  // Use ltx-video-13b-distilled/extend endpoint
        } else if (appId === 'ltx-video-13b-dev/extend' || appId === 'fal-ai/ltx-video-13b-dev/extend') {
          endpoint = 'fal-ai/ltx-video-13b-dev/extend';  // Use ltx-video-13b-dev/extend endpoint
        } else if (appId === 'ben/v2/video' || appId === 'fal-ai/ben/v2/video') {
          endpoint = 'fal-ai/ben/v2/video';  // Use ben/v2/video endpoint
        }


        const finalUrl = `${falBaseUrl}/${endpoint}`;

        // CRITICAL FIX: Pre-check balance before making FAL.AI API call
        let wasDeducted = false; // Declare for scope
        if (userEmail) {
          let falCostCents: number;
          try {
            falCostCents = calculateRealFalCost(appId, req.body);
          } catch (pricingError: any) {
            console.error(`🚨 [PRICING ERROR] ${pricingError.message}`);
            statusCode = 400;
            return res.status(400).json({
              error: 'PRICING_ERROR',
              message: `Model "${appId}" is not supported or has invalid pricing configuration.`
            });
          }
          const { data: userBalance, error: balanceError } = await supabase
            .from('profiles')
            .select('balance_usd_cents')
            .eq('email', userEmail)
            .single();
          if (userBalance && userBalance.balance_usd_cents < falCostCents) {
            return res.status(402).json({ error: 'Insufficient balance to process this request.' });
          }
        }

        // 🎯 START PRECISE TIMING (right before FAL.ai request)
        const falRequestStartTime = Date.now();
        if (req.body._computeEstimate && req.body._computeEstimate.isRealTimeMeasurement) {
          req.body._computeEstimate.actualStartTime = falRequestStartTime;

        }

        response = await axios.post(
          finalUrl,
          falPayload,
          {
            headers: {
              'Authorization': `Key ${FAL_API_KEY}`,
              'Content-Type': 'application/json'
            }
          }
        );

        // 🎯 END PRECISE TIMING (right after complete response received)
        const falRequestEndTime = Date.now();
        if (req.body._computeEstimate && req.body._computeEstimate.isRealTimeMeasurement) {
          req.body._computeEstimate.actualEndTime = falRequestEndTime;
          const actualProcessingTime = (falRequestEndTime - falRequestStartTime) / 1000;

          req.body._computeEstimate.measuredProcessingTime = actualProcessingTime;
        }


        // Handle synchronous responses (models that return results immediately)
        if (response.data && !response.data.request_id) {
          // Check if it's a direct result (has images, video, audio, etc.)
          if (response.data.images || response.data.audio || response.data.video || response.data.videos || response.data.text || response.data.model || response.data.mesh || response.data.model_mesh || response.data.model_url || response.data.glb || response.data.obj) {
            // Handle synchronous FAL.AI billing
            if (userEmail) {
              const userId = auth.userId as string;

              let falCostCents: number;
              try {
                falCostCents = calculateRealFalCost(appId, req.body);
              } catch (pricingError: any) {
                console.error(`🚨 [PRICING ERROR] ${pricingError.message}`);
                return res.status(400).json({
                  error: 'PRICING_ERROR',
                  message: `Model "${appId}" is not supported or has invalid pricing configuration.`
                });
              }


              // ⏱️ DYNAMIC BILLING - Calculate & charge based on ACTUAL processing time

              if (req.body._computeEstimate && req.body._computeEstimate.isRealTimeMeasurement && req.body._computeEstimate.measuredProcessingTime) {
                const actualProcessingTime = req.body._computeEstimate.measuredProcessingTime;
                const data = req.body._computeEstimate;



                // Calculate actual cost based on measured processing time
                const actualCostUsd = actualProcessingTime * data.ratePerComputeSecond;
                const actualCostCents = actualCostUsd * 100; // NO ROUNDING - PRECISE BILLING!




                // 💰 CHARGE THE ACTUAL AMOUNT (no estimation, no adjustment needed!)
                if (actualCostCents > 0) {


                  try {
                    const { data: deductResult, error: deductError } = await supabase.rpc('deduct_balance_atomic', {
                      user_email: userEmail,
                      amount_cents: falCostCents
                    });
                    if (deductError) {
                      return res.status(500).json({ error: 'Could not process your request. Please try again later.' });
                    }
                    if (!deductResult) {
                      return res.status(402).json({ error: 'Insufficient balance to process this request.' });
                    }
                    wasDeducted = true;

                    const userIdForCharge = auth.userId as string;
                    const userClientForCharge = userIdForCharge ? getUserSupabaseClient(userIdForCharge) : null;
                    const { data: balanceData, error: balanceError } = userClientForCharge ? await userClientForCharge
                      .from('profiles')
                      .select('balance_usd_cents')
                      .eq('id', userIdForCharge)
                      .single() : { data: null, error: 'no-user' } as any;

                    if (!balanceError && balanceData) {
                      const oldBalance = balanceData.balance_usd_cents;
                      const newBalance = oldBalance - actualCostCents;

                      if (userClientForCharge && userIdForCharge) {
                        const { data: updateResult, error: updateError } = await userClientForCharge
                          .rpc('deduct_balance_atomic', {
                            p_user_id: userIdForCharge,
                            p_amount_cents: actualCostCents
                          });

                        if (!updateError && updateResult?.success) {
                          // Balance deducted successfully
                        } else {
                          // Balance deduction failed
                        }
                      }



                      // Update falCostCents to reflect the actual charged amount
                      falCostCents = actualCostCents;
                    }
                  } catch (error) {
                    // Error charging actual amount
                  }
                } else {
                  console.log('💰 [DYNAMIC BILLING] Processing time was minimal - no charge applied');
                  falCostCents = 0;
                }


              }

              // CRITICAL FIX: Deduct balance for synchronous FAL.AI models (skip if already handled by dynamic billing)
              if (userEmail && !wasDeducted) {
                const userIdForSync = auth.userId as string;
                const userClientForSync = userIdForSync ? getUserSupabaseClient(userIdForSync) : null;
                const { data: userBalance, error: balanceError } = userClientForSync ? await userClientForSync
                  .from('profiles')
                  .select('balance_usd_cents')
                  .eq('id', userIdForSync)
                  .single() : { data: null, error: 'no-user' } as any;

                if (userBalance && userBalance.balance_usd_cents >= falCostCents) {

                  if (userClientForSync && userIdForSync) {
                    // ATOMIC BALANCE UPDATE - NO RACE CONDITION
                    const { data: updateResult, error: updateError } = await userClientForSync
                      .rpc('deduct_balance_atomic', {
                        p_user_id: userIdForSync,
                        p_amount_cents: falCostCents
                      });

                    if (!updateError && updateResult && updateResult.success) {
                      wasDeducted = true;
                    } else {
                      // If atomic update fails, return error to prevent double-spending
                      return res.status(402).json({
                        error: 'Insufficient balance or balance update failed'
                      });
                    }
                  }
                } else {
                  return res.status(402).json({ error: 'Insufficient balance to process this request.' });
                }
              }



              const logResult = userId ? await getUserSupabaseClient(userId).from('api_logs').insert({
                user_id: userId,
                api_key_prefix_used: apiKeyPrefix,
                endpoint_called: '/v1/completions',
                inference_usage_json: {
                  model: appId,
                  provider: 'capx_ivmodels',
                  result: 'Generated successfully',
                  prompt: falPayload.prompt || req.body.prompt || 'Image/Video/Audio generation',
                  image_url: response.data.images?.[0]?.url || response.data.images?.[0] || null,
                  video_url: response.data.video?.url || response.data.videos?.[0]?.url || null,
                  audio_url: response.data.audio?.url || null,
                  text_result: response.data.text || null,
                  model_3d_url: response.data.model?.url || response.data.mesh?.url || response.data.model_mesh?.url || response.data.model_url || response.data.glb?.url || response.data.obj?.url || null
                },
                inference_cost_usd: falCostCents / 100,
                markup_percentage: 10,
                final_cost_usd_cents: falCostCents,
                status_code_returned: 200,
                was_deducted: wasDeducted, // Use actual deduction status
                timestamp: new Date().toISOString()
              }) : null;



              // Add cost information to the response
              let responseData = response.data;
              responseData._cost_info = {
                cost_usd: falCostCents / 100,
                cost_cents: falCostCents,
                model: appId,
                provider: 'capx_ivmodels'
              };
              return res.json(responseData);
            } else {
              return res.json(response.data);
            }
          }
        }
        // If this is an async model, return only the task_id for polling
        if (response.data && response.data.request_id) {
          // LOG THE FAL.AI REQUEST BEFORE RETURNING (CRITICAL FIX!)
          if (userEmail) {
            const userId = auth.userId as string;
            let falCostCents: number;
            try {
              falCostCents = calculateRealFalCost(appId, req.body); // DYNAMIC PRICING FIX!
            } catch (pricingError: any) {
              console.error(`🚨 [PRICING ERROR] ${pricingError.message}`);
              return res.status(400).json({
                error: 'PRICING_ERROR',
                message: `Model "${appId}" is not supported or has invalid pricing configuration.`,
                details: pricingError.message
              });
            }

            // CRITICAL FIX: Pre-check balance for asynchronous FAL.AI models
            if (userEmail && userId) {
              const { data: userBalance } = await getUserSupabaseClient(userId)
                .from('profiles')
                .select('balance_usd_cents')
                .eq('id', userId)
                .single();
              if (userBalance && userBalance.balance_usd_cents < falCostCents) {
                return res.status(402).json({ error: 'Insufficient balance to process this request.' });
              }
            }

            await getUserSupabaseClient(userId!).from('api_logs').insert({
              user_id: userId,
              api_key_prefix_used: apiKeyPrefix,
              endpoint_called: '/v1/completions',
              inference_usage_json: {
                model: appId,
                provider: 'capx_ivmodels',
                task_id: response.data.request_id,
                prompt: falPayload.prompt || req.body.prompt || 'Image/Video/Audio generation',
                original_request_body: req.body // Store original request for cost calculation reference
              },
              inference_cost_usd: falCostCents / 100,
              markup_percentage: 10,
              final_cost_usd_cents: falCostCents,
              status_code_returned: 200,
              was_deducted: false, // Will be deducted when result is fetched
              timestamp: new Date().toISOString()
            });

            // Add cost information to the response
            let responseData: any = {
              task_id: response.data.request_id,
              _cost_info: {
                cost_usd: falCostCents / 100,
                cost_cents: falCostCents,
                model: appId,
                provider: 'capx_ivmodels'
              }
            };
            return res.json(responseData);
          }
          return res.json({ task_id: response.data.request_id });
        }
      } catch (falError) {
        // Log the error response from Fal
        if (axios.isAxiosError(falError)) {
          console.error('[ACE-STEP DEBUG] Fal.ai error response:', falError.response?.data || falError.message);
        }
        throw falError;
      }
    } else {
      const model = req.body.model;
      if (!model) {
        return res.status(400).json({ error: 'Model is required' });
      }
      response = await axios.post(
        `${INFERENCE_API_URL}/completions`,
        {
          ...req.body,
          model
        },
        {
          headers: {
            'Authorization': `Bearer ${process.env.INFERENCE_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );
    }
    statusCode = response.status;
    // Cost calculation from actual usage
    const usage = response.data.usage;
    let actualPromptTokens = usage?.prompt_tokens ?? prompt_tokens;
    let actualCompletionTokens = usage?.completion_tokens ?? completion_tokens;
    let actualTotalTokens = usage?.total_tokens ?? (actualPromptTokens + actualCompletionTokens);
    let actualBaseCostUsd = (actualPromptTokens * 0.0015 / 1000) + (actualCompletionTokens * 0.0020 / 1000);
    let actualFinalCostUsd = actualBaseCostUsd * (1 + markup_percentage / 100);
    let actualFinalCostCents = actualFinalCostUsd * 100;
    // ATOMIC BALANCE DEDUCTION - NO RACE CONDITION
    if (userEmail && userId) {
      const { data: updateResult, error: updateError } = await getUserSupabaseClient(userId)
        .rpc('deduct_balance_atomic', {
          p_user_id: userId,
          p_amount_cents: actualFinalCostCents
        });

      if (!updateError && updateResult && updateResult.success) {
        wasDeducted = true;
        console.log('✅ [ATOMIC] Balance deducted successfully. New balance:', updateResult.new_balance, 'cents');
      } else {
        console.log('❌ [ATOMIC] Balance deduction failed:', updateError?.message);
        // Return error to prevent double-spending
        return res.status(402).json({
          error: 'Insufficient balance or balance update failed'
        });
      }
    }
    // Log the API call in our database (after deduction attempt)
    if (userEmail && userId) {
      await getUserSupabaseClient(userId).from('api_logs').insert({
        user_id: userId,
        api_key_prefix_used: apiKeyPrefix,
        endpoint_called: '/v1/completions',
        inference_usage_json: {
          prompt_tokens: actualPromptTokens,
          completion_tokens: actualCompletionTokens,
          total_tokens: actualTotalTokens
        },
        inference_cost_usd: actualBaseCostUsd,
        markup_percentage,
        final_cost_usd_cents: actualFinalCostCents,
        status_code_returned: statusCode,
        was_deducted: wasDeducted,
        timestamp: new Date().toISOString()
      });
    }
    // Return the response with cost information
    let responseData: any = response.data;
    if (userEmail && usage) {
      responseData._cost_info = {
        cost_usd: actualFinalCostUsd,
        cost_cents: actualFinalCostCents,
        model: req.body.model,
        provider: 'capx_textmodels',
        tokens: {
          prompt_tokens: actualPromptTokens,
          completion_tokens: actualCompletionTokens,
          total_tokens: actualTotalTokens
        }
      };
    }
    res.status(statusCode).json(responseData);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      statusCode = error.response?.status || 500;
      // Log error API call
      if (error.config && error.config.headers && typeof error.config.headers['Authorization'] === 'string') {
        const authHeaderRaw = error.config.headers['Authorization'] as string;
        const auth = await getUserIdFromAuthHeader(authHeaderRaw);
        const apiKeyPrefix = auth.apiKey ? auth.apiKey.slice(0, 12) : null;
        const userId = auth.userId as string | undefined;
        if (userId) {
          await getUserSupabaseClient(userId).from('api_logs').insert({
            user_id: userId,
            api_key_prefix_used: apiKeyPrefix,
            endpoint_called: '/v1/completions',
            inference_usage_json: null,
            inference_cost_usd: null,
            markup_percentage: 10,
            final_cost_usd_cents: null,
            status_code_returned: statusCode,
            was_deducted: false,
            timestamp: new Date().toISOString()
          });
        }
      }
      res.status(statusCode).json(error.response?.data || { error: 'Internal server error' });
    } else {
      statusCode = 500;
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Proxy endpoint for /v1/chat/completions
router.post('/v1/chat/completions', [
  body('messages').isArray({ min: 1 }).withMessage('messages must be a non-empty array'),
  body('max_tokens').isInt({ min: 1 }).withMessage('max_tokens must be a positive integer')
], async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  let logFields: any = {};
  let statusCode = 500;
  let wasDeducted = false;
  let response: any;
  try {
    // Get user from Authorization header: support API key or JWT
    const authHeader = req.headers['authorization'] as string | undefined;
    const auth = await getUserIdFromAuthHeader(authHeader);
    const apiKey = auth.apiKey || null;
    const apiKeyPrefix = apiKey ? apiKey.slice(0, 12) : null;
    if (!auth.userId) {
      statusCode = 401;
      return res.status(401).json({ error: 'Unauthorized' });
    }
    // --- RATE LIMITING: 60 requests per minute per user ---
    const now = new Date();
    now.setSeconds(0, 0);
    const windowStart = now.toISOString();
    // Resolve user id from auth
    const userId = auth.userId;
    let userEmail: string | undefined = auth.userEmail || undefined;
    if (!userEmail) {
      const userClient = getUserSupabaseClient(userId);
      const { data: prof } = await userClient
        .from('profiles')
        .select('email')
        .eq('id', userId)
        .single();
      userEmail = prof?.email;
    }
    let requestCount = 1;
    if (userEmail) {
      const { data: upserted, error: upsertError } = await supabaseAnon.rpc('increment_rate_limit', {
        p_user_email: userEmail,
        p_window_start: windowStart
      });
      if (upsertError) {
        console.warn('[rate-limit] tracking failed (continuing without blocking):', upsertError);
        requestCount = 1; // degrade gracefully
      } else {
        const record = Array.isArray(upserted) ? upserted[0] : upserted;
        requestCount = record?.request_count || 1;
      }
      if (requestCount > 60) {
        statusCode = 429;
        return res.status(429).json({ error: 'Rate limit exceeded. Please wait before making more requests.' });
      }
    }
    // --- END RATE LIMITING ---
    // --- PRE-CHECK: Calculate cost and check user balance before making external API call ---
    const prompt_tokens = req.body.prompt_tokens || (req.body.messages ? JSON.stringify(req.body.messages).length / 4 : 0);
    const completion_tokens = req.body.max_tokens || 0;
    const base_cost_usd = (prompt_tokens * 0.0015 / 1000) + (completion_tokens * 0.0020 / 1000);
    const markup_percentage = 10;
    const final_cost_usd = base_cost_usd * (1 + markup_percentage / 100);
    const final_cost_cents = final_cost_usd * 100;
    if (userEmail && userId) {
      const { data: userBalance } = await getUserSupabaseClient(userId)
        .from('profiles')
        .select('balance_usd_cents')
        .eq('id', userId)
        .single();
      if (userBalance && userBalance.balance_usd_cents < final_cost_cents) {
        statusCode = 402;
        return res.status(402).json({ error: 'Insufficient balance to process this request.' });
      }
    }
    // --- END PRE-CHECK ---
    // Forward request to inference.net using our inference API key
    const response = await axios.post(
      `${INFERENCE_API_URL}/chat/completions`,
      {
        ...req.body,
        model: req.body.model // <-- Use the model from the request body
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.INFERENCE_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    statusCode = response.status;
    // Cost calculation from actual usage
    const usage = response.data.usage;
    let actualPromptTokens = usage?.prompt_tokens ?? prompt_tokens;
    let actualCompletionTokens = usage?.completion_tokens ?? completion_tokens;
    let actualTotalTokens = usage?.total_tokens ?? (actualPromptTokens + actualCompletionTokens);
    let actualBaseCostUsd = (actualPromptTokens * 0.0015 / 1000) + (actualCompletionTokens * 0.0020 / 1000);
    let actualFinalCostUsd = actualBaseCostUsd * (1 + markup_percentage / 100);
    let actualFinalCostCents = actualFinalCostUsd * 100;
    // ATOMIC BALANCE DEDUCTION - NO RACE CONDITION
    if (userEmail && userId) {
      const { data: updateResult, error: updateError } = await getUserSupabaseClient(userId)
        .rpc('deduct_balance_atomic', {
          p_user_id: userId,
          p_amount_cents: actualFinalCostCents
        });

      if (!updateError && updateResult && updateResult.success) {
        wasDeducted = true;
        console.log('✅ [ATOMIC] Balance deducted successfully. New balance:', updateResult.new_balance, 'cents');
      } else {
        console.log('❌ [ATOMIC] Balance deduction failed:', updateError?.message);
        // Return error to prevent double-spending
        return res.status(402).json({
          error: 'Insufficient balance or balance update failed'
        });
      }
    }
    // Log the API call in our database (after deduction attempt)
    if (userEmail && userId) {
      await getUserSupabaseClient(userId).from('api_logs').insert({
        user_id: userId,
        api_key_prefix_used: apiKeyPrefix,
        endpoint_called: '/v1/chat/completions',
        inference_usage_json: {
          prompt_tokens: actualPromptTokens,
          completion_tokens: actualCompletionTokens,
          total_tokens: actualTotalTokens
        },
        inference_cost_usd: actualBaseCostUsd,
        markup_percentage,
        final_cost_usd_cents: actualFinalCostCents,
        status_code_returned: statusCode,
        was_deducted: wasDeducted,
        timestamp: new Date().toISOString()
      });
    }

    // Return the response with cost information
    let responseData: any = response.data;
    if (userEmail && usage) {
      responseData._cost_info = {
        cost_usd: actualFinalCostUsd,
        cost_cents: actualFinalCostCents,
        model: req.body.model,
        provider: 'capx_textmodels',
        tokens: {
          prompt_tokens: actualPromptTokens,
          completion_tokens: actualCompletionTokens,
          total_tokens: actualTotalTokens
        }
      };
    }
    res.status(statusCode).json(responseData);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      statusCode = error.response?.status || 500;
      // Log error API call
      if (error.config && error.config.headers && typeof error.config.headers['Authorization'] === 'string') {
        const authHeaderRaw = error.config.headers['Authorization'] as string;
        const auth = await getUserIdFromAuthHeader(authHeaderRaw);
        const apiKeyPrefix = auth.apiKey ? auth.apiKey.slice(0, 12) : null;
        const userId = auth.userId as string | undefined;
        if (userId) {
          await getUserSupabaseClient(userId).from('api_logs').insert({
            user_id: userId,
            api_key_prefix_used: apiKeyPrefix,
            endpoint_called: '/v1/chat/completions',
            inference_usage_json: null,
            inference_cost_usd: null,
            markup_percentage: 10,
            final_cost_usd_cents: null,
            status_code_returned: statusCode,
            was_deducted: false,
            timestamp: new Date().toISOString()
          });
        }
      }
      res.status(statusCode).json(error.response?.data || { error: 'Internal server error' });
    } else {
      statusCode = 500;
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});


// Get recent API logs for a user or api_key
router.get('/logs', async (req, res) => {
  const { user_id, api_key } = req.query;
  let resolvedUserId = user_id;

  // If api_key is provided, look up the user_id
  if (api_key && !user_id) {
    const { data, error } = await supabase
      .from('api_keys')
      .select('user_id')
      .eq('key', api_key)
      .maybeSingle();
    if (error || !data?.user_id) {
      return res.status(400).json({ error: 'Invalid api_key' });
    }
    resolvedUserId = data.user_id;
  }

  if (!resolvedUserId) {
    return res.status(400).json({ error: 'Missing user_id or api_key' });
  }

  try {
    const { data, error } = await supabase
      .from('api_logs')
      .select('*')
      .eq('user_id', resolvedUserId)
      .order('timestamp', { ascending: false })
      .limit(10);
    if (error) {
      return res.status(500).json({ error: 'Failed to fetch logs' });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add Fal.ai status polling endpoint for async image generation
router.get('/v1/completions/status/:task_id', async (req, res) => {
  const { task_id } = req.params;
  if (!task_id) return res.status(400).json({ error: 'Missing task_id' });

  // Optionally, validate the user's API key here

  // Reconstruct the Fal.ai status URL
  const statusUrl = `https://fal.run/fal-ai/fast-sdxl/requests/${task_id}/status`;

  try {
    const falRes = await axios.get(statusUrl, {
      headers: {
        'Authorization': `Key ${process.env.FAL_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    res.json(falRes.data);
  } catch (err) {
    let errorMsg = 'Unknown error';
    let errorDetails = undefined;
    if (err && typeof err === 'object') {
      if ('response' in err && err.response && typeof err.response === 'object' && 'data' in err.response) {
        errorDetails = (err.response as any).data;
      }
      if ('message' in err && typeof err.message === 'string') {
        errorMsg = err.message;
      }
    }
    console.error('Fal.ai status poll error:', errorDetails || errorMsg);
    res.status(500).json({ error: 'Failed to poll Fal.ai status' });
  }
});

// Add Fal.ai result fetching endpoint for async image generation
router.get('/v1/completions/result/:task_id', async (req, res) => {
  const { task_id } = req.params;
  const { appId } = req.query;
  if (!task_id) return res.status(400).json({ error: 'Missing task_id' });

  // Require and validate Authorization (API key or JWT)
  const authHeader = req.headers['authorization'] as string | undefined;
  const auth = await getUserIdFromAuthHeader(authHeader);
  if (!auth.userId) return res.status(401).json({ error: 'Unauthorized' });
  const userId = auth.userId;
  const userClient = getUserSupabaseClient(userId);
  const { data: profileData } = await userClient
    .from('profiles')
    .select('email')
    .eq('id', userId)
    .single();
  const userEmail = profileData?.email || auth.userEmail || null;
  const apiKeyPrefix = auth.apiKey ? auth.apiKey.slice(0, 12) : null;

  try {
    let result;
    // Special handling for ace-step result fetching
    if (appId === 'ace-step' || appId === 'fal-ai/ace-step') {
      const falRes = await axios.post(
        'https://api.fal.ai/v1/fal-ai/ace-step/result',
        { requestId: task_id },
        {
          headers: {
            'Authorization': `Key ${process.env.FAL_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );
      result = falRes.data;
    } else {
      // Default: GET from fal.run endpoint
      const responseUrl = `https://fal.run/fal-ai/fast-sdxl/requests/${task_id}`;
      const falRes = await axios.get(responseUrl, {
        headers: {
          'Authorization': `Key ${process.env.FAL_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      result = falRes.data;
    }

    // Determine if the generation was successful
    let isSuccess = false;
    let isFailed = false;
    let isProcessing = false;

    // Check for success indicators (adjust for different models if needed)
    if (result.status === 'COMPLETED' &&
      ((result.images && result.images.length > 0) ||
        (result.videos && result.videos.length > 0) ||
        (result.audio && result.audio) ||
        (result.model && result.model.url))) {
      isSuccess = true;
    } else if (result.status === 'FAILED' || result.error || result.logs?.errors?.length > 0) {
      isFailed = true;
    } else if (result.status === 'PROCESSING' || result.status === 'PENDING') {
      isProcessing = true;
    }

    // Deduct a fixed cost only if successful
    let wasDeducted = false;
    let actualCostCents = 0;

    // Find the original request log entry using task_id
    const { data: originalLog, error: logError } = await getUserSupabaseClient(userId)
      .from('api_logs')
      .select('*')
      .eq('user_id', userId)
      .contains('inference_usage_json', { task_id: task_id })
      .eq('was_deducted', false)
      .order('timestamp', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (originalLog && originalLog.final_cost_usd_cents) {
      actualCostCents = originalLog.final_cost_usd_cents;
      console.log(`[RESULT ENDPOINT] Found log for task_id ${task_id}, cost: $${(actualCostCents / 100).toFixed(6)}`);

      if (isSuccess) {
        // Only deduct if successful
        // ATOMIC BALANCE DEDUCTION - NO RACE CONDITION
        if (userEmail) {
          const { data: updateResult, error: updateError } = await getUserSupabaseClient(userId)
            .rpc('deduct_balance_atomic', {
              p_user_id: userId,
              p_amount_cents: actualCostCents
            });

          if (!updateError && updateResult && updateResult.success) {
            wasDeducted = true;
            console.log('✅ [ATOMIC] Balance deducted successfully. New balance:', updateResult.new_balance, 'cents');
            // Update the original log to mark it as deducted and successful
            await getUserSupabaseClient(userId)
              .from('api_logs')
              .update({ was_deducted: true, status_code_returned: 200 })
              .eq('log_id', originalLog.log_id);
          } else {
            console.log('❌ [ATOMIC] Balance deduction failed:', updateError?.message);
            // Return error to prevent double-spending
            return res.status(402).json({
              error: 'Insufficient balance or balance update failed'
            });
          }
        }
      } else if (isFailed) {
        // Update log to reflect failure: no charge, status 500
        await getUserSupabaseClient(userId)
          .from('api_logs')
          .update({
            was_deducted: false,
            status_code_returned: 500,
            final_cost_usd_cents: 0,
            inference_usage_json: {
              ...originalLog.inference_usage_json,
              status: 'failed',
              error: result.error || result.logs?.errors || 'Generation failed'
            }
          })
          .eq('log_id', originalLog.log_id);
        actualCostCents = 0;
        console.log(`[RESULT ENDPOINT] Marked task_id ${task_id} as failed, no charge applied`);
      } else if (isProcessing) {
        // Still processing, no action on log or balance
        actualCostCents = 0;
        console.log(`[RESULT ENDPOINT] Task ${task_id} still processing, no charge yet`);
      }
    } else {
      console.warn(`[RESULT ENDPOINT] No log found for task_id ${task_id}, returning fallback cost 0.`);
      actualCostCents = 0;
    }

    // Attach _cost_info to the result before sending (0 if not charged)
    result._cost_info = {
      cost_usd: actualCostCents / 100,
      cost_cents: actualCostCents,
      model: originalLog?.inference_usage_json?.model || appId,
      provider: originalLog?.inference_usage_json?.provider || 'capx_ivmodels',
      status: isSuccess ? 'success' : (isFailed ? 'failed' : (isProcessing ? 'processing' : 'unknown'))
    };

    console.log(`[RESULT ENDPOINT] Returning result for task_id ${task_id} with cost_usd: $${(actualCostCents / 100).toFixed(6)}, status: ${result._cost_info.status}`);
    res.json(result);

  } catch (err) {
    let errorMsg = 'Unknown error';
    let errorDetails = undefined;
    if (err && typeof err === 'object') {
      if ('response' in err && err.response && typeof err.response === 'object' && 'data' in err.response) {
        errorDetails = (err.response as any).data;
      }
      if ('message' in err && typeof err.message === 'string') {
        errorMsg = err.message;
      }
    }
    console.error('Fal.ai result fetch error:', errorDetails || errorMsg);
    res.status(500).json({ error: 'Failed to fetch Fal.ai result' });
  }
});

// Monthly usage and spending stats endpoint
router.get('/usage/monthly-stats', async (req, res) => {
  // Accept user_id as a query param or header
  const userIdFromQuery = req.query.user_id;
  const userIdFromHeader = req.headers['x-user-id'];
  let userId = userIdFromQuery || userIdFromHeader;
  let apiKey = req.headers['authorization']?.replace('Bearer ', '').trim();

  if (!userId && !apiKey) {
    return res.status(401).json({ error: 'API key or user_id required' });
  }
  try {
    // If user_id is not provided, get it from API key
    if (!userId && apiKey) {
      const { data: apiKeyData, error: apiKeyError } = await supabase
        .from('api_keys')
        .select('user_id')
        .eq('key', apiKey)
        .maybeSingle();
      if (apiKeyError || !apiKeyData?.user_id) {
        return res.status(401).json({ error: 'Invalid API key' });
      }
      userId = apiKeyData.user_id;
    }
    // Get profile creation date
    const { data: profileData, error: profileError } = await supabase
      .from('profiles')
      .select('created_at')
      .eq('id', userId)
      .maybeSingle();
    if (profileError || !profileData?.created_at) {
      return res.status(404).json({ error: 'User profile not found' });
    }
    const createdAt = new Date(profileData.created_at);
    const now = new Date();
    // BULLETPROOF months generation using string parsing
    const months = [];
    const accountCreatedMonth = createdAt.toISOString().slice(0, 7); // "2025-06"
    const currentMonth = now.toISOString().slice(0, 7); // "2025-07"
    const [accountYear, accountMonthNum] = accountCreatedMonth.split('-').map(Number);
    const [currentYear, currentMonthNum] = currentMonth.split('-').map(Number);
    let y = accountYear, m = accountMonthNum;
    while (y < currentYear || (y === currentYear && m <= currentMonthNum)) {
      months.push(`${y.toString().padStart(4, '0')}-${m.toString().padStart(2, '0')}`);
      m++;
      if (m > 12) { m = 1; y++; }
    }
    // Fetch all API logs for this user
    const { data: apiLogs, error: logsError } = await supabase
      .from('api_logs')
      .select('*')
      .eq('user_id', userId)
      .order('timestamp', { ascending: false });
    if (logsError) {
      return res.status(500).json({ error: 'Failed to fetch logs' });
    }
    // Fetch all transactions for this user
    const { data: transactions, error: txError } = await supabase
      .from('transactions')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    if (txError) {
      return res.status(500).json({ error: 'Failed to fetch transactions' });
    }
    // Aggregate by month
    const stats = months.map(month => {
      // API logs
      const logsForMonth = apiLogs.filter(log => log.timestamp && log.timestamp.startsWith(month));
      const api_calls = logsForMonth.length;
      const api_cost_usd = logsForMonth.reduce((sum, log) => sum + (log.final_cost_usd_cents || 0) / 100, 0);
      // Transactions
      const txForMonth = transactions.filter(tx => tx.created_at && tx.created_at.startsWith(month));
      const spending_usd = txForMonth.reduce((sum, tx) => sum + (tx.amount || 0), 0);
      return { month, api_calls, api_cost_usd, spending_usd };
    });
    res.json({
      stats,
      debug_info: {
        server_timestamp: new Date().toISOString(),
        code_version: "v5_bulletproof_strings",
        months_generated: months,
        account_created: createdAt.toISOString().slice(0, 7),
        current_month: now.toISOString().slice(0, 7)
      }
    });
  } catch (err) {
    console.error('Error in /usage/monthly-stats:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to fetch recent generation cost for a user and task
router.get('/api/recent-generation-cost', async (req, res) => {
  const { user_id, task_id } = req.query;
  if (!user_id || !task_id) {
    return res.status(400).json({ error: 'Missing user_id or task_id' });
  }
  try {
    const { data, error } = await supabase
      .from('api_logs')
      .select('final_cost_usd_cents')
      .eq('user_id', user_id)
      .contains('inference_usage_json', { task_id })
      .order('timestamp', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) {
      return res.status(500).json({ error: 'Failed to fetch cost' });
    }
    if (!data) {
      return res.status(404).json({ error: 'No log found for this user and task' });
    }
    return res.json({ final_cost_usd_cents: data.final_cost_usd_cents });
  } catch (err) {
    return res.status(500).json({ error: 'An error occurred' });
  }
});

export default router; 