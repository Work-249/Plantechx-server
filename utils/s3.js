const fs = require('fs');
const path = require('path');

// This utility replaces S3 usage when no bucket is configured so the app
// works on App Runner (ephemeral local storage). If an S3 bucket is set
// in environment, it will attempt to use S3 — otherwise it writes files
// to the local `uploads/` directory and returns a URL path under `/uploads`.

const REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
const BUCKET = process.env.AWS_S3_BUCKET || process.env.AWS_BUCKET;

let s3Client = null;
let useS3 = false;
if (BUCKET) {
  try {
    // Lazy-load AWS SDK only when needed
    const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
    s3Client = new S3Client({ region: REGION });
    // store PutObjectCommand constructor for later
    uploadBufferToS3._PutObjectCommand = PutObjectCommand;
    useS3 = true;
  } catch (err) {
    console.warn('AWS SDK not available; falling back to local storage.');
    useS3 = false;
  }
} else {
  console.info('No S3 bucket configured; using local uploads directory.');
}

async function uploadBufferToS3(buffer, key, contentType) {
  if (useS3 && s3Client) {
    const PutObjectCommand = uploadBufferToS3._PutObjectCommand;
    const params = {
      Bucket: BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType,
      ACL: 'public-read'
    };
    await s3Client.send(new PutObjectCommand(params));
    const base = process.env.AWS_S3_BASE_URL || `https://${BUCKET}.s3.${REGION}.amazonaws.com`;
    const url = `${base}/${encodeURIComponent(key)}`;
    return { key, url };
  }

  // Fallback to local storage under /uploads
  const uploadsDir = path.join(__dirname, '..', 'uploads');
  // Keep files organized under an uploads subfolder (e.g., notifications)
  const destPath = path.join(uploadsDir, key);
  const destDir = path.dirname(destPath);
  await fs.promises.mkdir(destDir, { recursive: true });
  await fs.promises.writeFile(destPath, buffer);

  // Build a relative URL path that can be served by Express static middleware
  const urlPath = `/uploads/${encodeURIComponent(key)}`;
  return { key, url: urlPath };
}

module.exports = {
  uploadBufferToS3
};
