/**
 * Streams a private GitHub Release binary asset directly through Cloudflare Workers.
 * Network I/O consumes 0 ms of Workers CPU time (no buffering/R2 required).
 */
export async function streamPrivateGithubRelease(input: {
  assetUrl: string;
  githubToken?: string;
  downloadFilename: string;
}): Promise<Response> {
  if (
    !input.githubToken ||
    input.githubToken.startsWith('REPLACE_WITH_') ||
    !input.assetUrl ||
    input.assetUrl.includes('REPLACE_ASSET_ID')
  ) {
    return Response.json(
      {
        error: 'RELEASE_NOT_ATTACHED',
        message:
          'Private GitHub Release asset URL or read-only token is not configured yet. Your signed license token remains valid.'
      },
      { status: 503 }
    );
  }

  const headers: Record<string, string> = {
    Accept: 'application/octet-stream',
    Authorization: `Bearer ${input.githubToken}`,
    'User-Agent': 'ApexHive-ZeroFiat-Worker/1.0',
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
