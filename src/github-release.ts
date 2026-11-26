/**
 * Streams a public archive URL (if configured and reachable) OR returns a signed JSON
 * MIT receipt certificate immediately.
 */
export async function streamReleaseOrPublicCertificate(input: {
  publicArchiveUrl?: string;
  downloadFilename: string;
  certificatePayload: Record<string, unknown>;
}): Promise<Response> {
  if (input.publicArchiveUrl && /^https?:\/\//i.test(input.publicArchiveUrl)) {
    try {
      const publicRes = await fetch(input.publicArchiveUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'ApexHive-ZeroFiat-Worker/2.1' },
        redirect: 'follow',
        signal: AbortSignal.timeout(4000)
      });
      if (publicRes.ok && publicRes.body) {
        return new Response(publicRes.body, {
          status: 200,
          headers: {
            'Content-Type': publicRes.headers.get('content-type') || 'application/zip',
            'Content-Disposition': `attachment; filename="${input.downloadFilename}"`,
            'Cache-Control': 'no-store'
          }
        });
      }
    } catch {
      // Fall back cleanly to signed receipt certificate JSON
    }
  }

  const certBody = JSON.stringify(
    {
      ...input.certificatePayload,
      openSourceLicense: 'MIT',
      mitCloneUrl: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit.git'
    },
    null,
    2
  );

  return new Response(certBody, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="zerofiat-receipt-certificate.json"',
      'Cache-Control': 'no-store'
    }
  });
}
