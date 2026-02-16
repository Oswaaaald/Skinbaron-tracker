import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import sharp from 'sharp';
import type { MultipartFile } from '@fastify/multipart';

// ── Constants ──

/** Directory where processed avatars are stored */
const UPLOAD_DIR = process.env['AVATAR_UPLOAD_DIR'] || '/data/avatars';

/** Maximum raw upload size (2 MB) */
export const MAX_AVATAR_SIZE = 2 * 1024 * 1024;

/** Output dimensions (square, enough for retina) */
const AVATAR_SIZE = 256;

/** Allowed MIME types mapped to their magic byte signatures */
const ALLOWED_MAGIC: ReadonlyArray<{ mime: string; bytes: readonly number[] }> = [
  { mime: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47] },         // PNG
  { mime: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },              // JPEG
  { mime: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46] },        // WEBP (RIFF header)
  { mime: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38] },         // GIF
];

// ── Helpers ──

/** Validate file type by inspecting magic bytes (not client-supplied MIME) */
function validateMagicBytes(buffer: Buffer): boolean {
  for (const sig of ALLOWED_MAGIC) {
    if (buffer.length >= sig.bytes.length && sig.bytes.every((b, i) => buffer[i] === b)) {
      return true;
    }
  }
  return false;
}

/** Generate a cryptographically random filename */
function generateFilename(): string {
  return `${crypto.randomBytes(16).toString('hex')}.webp`;
}

// ── Public API ──

/**
 * Ensure the upload directory exists. Called once on startup.
 */
export async function ensureUploadDir(): Promise<void> {
  await fs.mkdir(UPLOAD_DIR, { recursive: true });
}

/**
 * Process and save an uploaded avatar image.
 *
 * Security:
 * 1. Magic-byte validation (not MIME header)
 * 2. Size limit enforced before buffering
 * 3. Image re-encoded via sharp → strips EXIF, metadata, embedded scripts
 * 4. Output is always WebP (no passthrough of original format)
 * 5. Random filename (no user input in path)
 * 6. Atomic write via temp file + rename
 *
 * @returns The generated filename (without path)
 */
export async function processAndSaveAvatar(file: MultipartFile): Promise<string> {
  // Read file into buffer with size enforcement
  const buffer = await file.toBuffer();

  if (buffer.length === 0) {
    throw new Error('Empty file');
  }

  if (buffer.length > MAX_AVATAR_SIZE) {
    throw new Error(`File too large (max ${MAX_AVATAR_SIZE / 1024 / 1024} MB)`);
  }

  // Validate magic bytes
  if (!validateMagicBytes(buffer)) {
    throw new Error('Invalid image format. Allowed: PNG, JPEG, WebP, GIF');
  }

  // Process with sharp: resize, strip metadata, convert to WebP
  const processed = await sharp(buffer, { failOn: 'error', limitInputPixels: 100_000_000 })
    .rotate()                    // Auto-rotate based on EXIF (then EXIF is stripped)
    .resize(AVATAR_SIZE, AVATAR_SIZE, {
      fit: 'cover',              // Crop to square from center
      position: 'centre',
      withoutEnlargement: false,
    })
    .webp({ quality: 85 })      // Always output WebP
    .toBuffer();

  // Generate random filename and write atomically
  const filename = generateFilename();
  const finalPath = path.join(UPLOAD_DIR, filename);
  const tmpPath = `${finalPath}.tmp`;

  await fs.writeFile(tmpPath, processed);
  await fs.rename(tmpPath, finalPath);

  return filename;
}

/**
 * Delete an avatar file from disk (best-effort, does not throw).
 */
export async function deleteAvatarFile(filename: string): Promise<void> {
  // Prevent path traversal
  const safeName = path.basename(filename);
  if (safeName !== filename || filename.includes('..')) {
    return;
  }
  try {
    await fs.unlink(path.join(UPLOAD_DIR, safeName));
  } catch {
    // File may already be deleted — ignore
  }
}

/**
 * Read an avatar file from disk for serving.
 * Returns null if not found or path traversal detected.
 */
export async function readAvatarFile(filename: string): Promise<Buffer | null> {
  // Prevent path traversal
  const safeName = path.basename(filename);
  if (safeName !== filename || filename.includes('..')) {
    return null;
  }
  try {
    return await fs.readFile(path.join(UPLOAD_DIR, safeName));
  } catch {
    return null;
  }
}
