// Turn a browser WebAuthn assertion (navigator.credentials.get) into the raw
// byte shape the LazorKit SDK's `plan.migrate.finalize()` expects. The on-chain
// program re-derives and checks the challenge, so the passkey approves exactly
// this migration and nothing else.

/** Matches the SDK's `finalize(response)` parameter — kept structural on purpose. */
export interface WebAuthnResponse {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}

export interface AssertionOptions {
  /** The rpId the passkey was registered under (e.g. "lazorkit.app"). */
  rpId?: string;
  /** Credential ids to allow — usually the user's known passkey(s). */
  allowCredentialIds?: Uint8Array[];
}

/**
 * Prompt the user's passkey to sign `challenge`. Wire `rpId`/`allowCredentialIds`
 * from your own auth layer. This is the default the hook uses for secp256r1
 * owners; pass your own if you need custom transports or UV settings.
 */
export async function getPasskeyAssertion(
  challenge: Uint8Array,
  opts: AssertionOptions = {},
): Promise<WebAuthnResponse> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: opts.rpId,
      allowCredentials: (opts.allowCredentialIds ?? []).map((id) => ({
        id,
        type: 'public-key' as const,
      })),
      userVerification: 'preferred',
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey prompt was dismissed');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
  };
}
