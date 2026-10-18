/** @type {import('next').NextConfig} */
const nextConfig = {
  // The preview host is not known at build time, so the dev server must accept
  // any origin rather than an allowlist.
  allowedDevOrigins: ['*'],
  reactStrictMode: true,
};

export default nextConfig;
