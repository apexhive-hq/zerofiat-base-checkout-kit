/**
 * Streams a GitHub Release archive OR returns a signed JSON entitlement certificate
 * for Public MIT repositories when GITHUB_RELEASE_READ_TOKEN is intentionally unset.
 */
export async function streamReleaseOrPublicCertificate(input: {
  assetUrl: string;
  publicArchiveUrl?: string;
  githubToken?: string;
  downloadFilename: string;
  certificatePayload: Record<string, unknown>;
}): Promise<Response> {
  const hasPrivateToken =
    Boolean(input.githubToken) &&
    !input.githubToken!.startsWith('REPLACE_WITH_') &&
    Boolean(input.assetUrl) &&
    !input.assetUrl.includes('REPLACE_ASSET_ID');

  if (hasPrivateToken) {
    const headers: Record<string, string> = {
      Accept: 'application/octet-stream',
      Authorization: `Bearer ${input.githubToken}`,
      'User-Agent': 'ApexHive-ZeroFiat-Worker/2.0',
      'X-GitHub-Api-Version': '2022-11-28'
    };

    const upstream = await fetch(input.assetUrl, {
      method: 'GET',
      headers,
      redirect: 'follow'
    });

    if (!upstream.ok || !upstream.body) {
      return Response.json(
        {
          error: 'UPSTREAM_RELEASE_ERROR',
          message: `GitHub release asset returned HTTP ${upstream.status}.`
        },
        { status: 502 }
      );
    }

    return new Response(upstream.body, {
      status: 200,
      headers: {
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="${input.downloadFilename}"`,
        'Cache-Control': 'no-store'
      }
    });
  }

  // Public MIT Open-Source mode: if PUBLIC_ARCHIVE_URL is a reachable HTTP(S) archive, stream it;
  // otherwise return 200 OK with the signed JSON entitlement certificate immediately (never fail 503).
  if (input.publicArchiveUrl && /^https?:\/\//i.test(input.publicArchiveUrl)) {
    try {
      const publicRes = await fetch(input.publicArchiveUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'ApexHive-ZeroFiat-Worker/2.0' },
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
      // Fall back cleanly to signed entitlement certificate JSON
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
      'Content-Disposition': 'attachment; filename="zerofiat-license-certificate.json"',
      'Cache-Control': 'no-store'
    }
  });
}
