const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const path = require('path');

const REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
const BUCKET = process.env.AWS_S3_BUCKET || process.env.AWS_BUCKET;

if (!BUCKET) {
  console.warn('AWS S3 bucket is not configured. Set AWS_S3_BUCKET or AWS_BUCKET in environment.');
}

const s3Client = new S3Client({ region: REGION });

async function uploadBufferToS3(buffer, key, contentType) {
  if (!BUCKET) throw new Error('S3 bucket not configured');
  const params = {
    Bucket: BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ACL: 'public-read'
  };

  await s3Client.send(new PutObjectCommand(params));

  // Build a public URL. If custom base provided use it.
  const base = process.env.AWS_S3_BASE_URL || `https://${BUCKET}.s3.${REGION}.amazonaws.com`;
  const url = `${base}/${encodeURIComponent(key)}`;
  return { key, url };
}

module.exports = {
  uploadBufferToS3
};
