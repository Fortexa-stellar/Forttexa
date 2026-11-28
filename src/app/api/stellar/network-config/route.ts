import { NextRequest, NextResponse } from "next/server";

import { securityHeadersForRequest } from "@/lib/security/headers";
import {
  getStellarHorizonUrl,
  getStellarNetworkFingerprint,
  inferStellarNetworkProfile,
  resolveStellarNetworkConfig,
} from "@/lib/stellar/network-config";

export function GET(request: NextRequest) {
  return NextResponse.json(
    {
      profile: inferStellarNetworkProfile(getStellarHorizonUrl()),
      fingerprint: getStellarNetworkFingerprint(),
      valid: resolveStellarNetworkConfig().ok,
    },
    { headers: { "Cache-Control": "no-store", ...securityHeadersForRequest(request) } },
  );
}
