import {
  CredentialDataManager,
  CredentialDataResponse,
  DeferredCredentialData,
  InTimeCredentialData,
  W3CVcIssuer
} from "@/core/credentials/index.js";
import {
  AuthzDetailsBuilderFactory,
  AuthzRequestBuilder,
  CredentialRequest,
  CredentialResponse,
  CredentialSupportedBuilder,
  IdTokenRequest,
  IdTokenResponse,
  JWA_ALGS,
  TokenRequest,
  W3CDataModel,
  W3CVerifiableCredentialFormats,
  decodeToken,
  generateDefaultAuthorisationServerMetadata
} from "../src/index.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { SignJWT, importJWK } from "jose";
import { MemoryStateManager } from "@/core/state/index.js";
import { Result } from "@/classes";
import { OpenIdRPStepBuilder } from "@/core/rp/builder.js";
import { JwtPayload } from "jsonwebtoken";
import { generateChallenge } from "pkce-challenge";
import { expect, test, describe } from '@jest/globals';

const memoryManager = new MemoryStateManager();

const issuerUrl = "https://issuer";
const codeVerifier = "test";
const holderJWK = {
  "kty": "EC",
  "d": "xEHP5NWUHL5tXqrhQlJo_LgaqsFxh75_PPUtatXl-Ek",
  "use": "sig",
  "crv": "P-256",
  "kid": "bUD-_xV9bm71mtDbQ44opyIiN919v3UOvrm8ja0w1as",
  "x": "DZLdhzWtSHJQrsMnnsMgWyok26N172KMEG9McrrG-eE",
  "y": "UmXBOYIICFyQ6cF1R1BDsBuV3xr_E61tl_e6H2LmJw0",
  "alg": "ES256"
};

const holderDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboxCaZdensP4av2bfpZ9kMwQnnjftpb3mEnh2qouVjyWsmdvWQSDKhKTNQN5jgpYLk82ToEcC8tq5gaGQxsH366uEVrwUHWytbghxynS4qNGzaLTQga3qvTYc5NwyuhfCqa";
const holderKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KboxCaZdensP4av2bfpZ9kMwQnnjftpb3mEnh2qouVjyWsmdvWQSDKhKTNQN5jgpYLk82ToEcC8tq5gaGQxsH366uEVrwUHWytbghxynS4qNGzaLTQga3qvTYc5NwyuhfCqa";

const issuerJWK = {
  "kty": "EC",
  "d": "ytyKElsW0ZSAUe56jHYxWwMwPdqyp0CYNsD1rv75mTg",
  "use": "sig",
  "crv": "P-256",
  "kid": "D5eDdKiUFRn3_FhmaL4QENmG5asYP95DEdjE93T6o6Q",
  "x": "hasujoWNW2dY100kuBOZBF23NWOlpPPLXOltuiRRe0A",
  "y": "JcdfowA_nhVSjoOMiTJioTYxzIYt58PgwfzxLXq1Fps",
  "alg": "ES256"
}

const issuerDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const issuerKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const authServerDid = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";
const authServerKid = "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrmHVD1QbodChiJ88ePBkcBQubkha4sN8L1471yQwkLXYR4K9WroVupKaGN2jssXaeCn4vxRV9xjMtWHe4RSx9GJS1XCcdfQ3VJfX5iJ1iUSx1jKd5qT7gUvF9J1P11tEYk";

const authServerJWK = {
  "kty": "EC",
  "d": "ytyKElsW0ZSAUe56jHYxWwMwPdqyp0CYNsD1rv75mTg",
  "use": "sig",
  "crv": "P-256",
  "kid": "D5eDdKiUFRn3_FhmaL4QENmG5asYP95DEdjE93T6o6Q",
  "x": "hasujoWNW2dY100kuBOZBF23NWOlpPPLXOltuiRRe0A",
  "y": "JcdfowA_nhVSjoOMiTJioTYxzIYt58PgwfzxLXq1Fps",
  "alg": "ES256"
}

const signCallback = async (payload: JwtPayload, _supportedAlgs?: JWA_ALGS[]) => {
  const header = {
    alg: "ES256",
    kid: `${authServerDid}#${authServerKid}`
  };
  const keyLike = await importJWK(authServerJWK);
  return await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .sign(keyLike);
};

describe("VC Issuance tests", () => {

  const vcIssuer = new W3CVcIssuer(
    {
      credential_issuer: issuerUrl,
      credential_endpoint: issuerUrl + "/credential",
      credential_configurations_supported: {
        "VcTest": new CredentialSupportedBuilder().
          addProofTypeSupported("jwt", ["ES256"])
          .withTypes(["VcTest"])
          .build(),
        "DeferredVc": new CredentialSupportedBuilder()
          .addProofTypeSupported("jwt", ["ES256"])
          .withTypes(["DeferredVc"])
          .build(),
        "WithId": new CredentialSupportedBuilder()
          .addProofTypeSupported("jwt", ["ES256"])
          .withTypes(["VcTestWithId"])
          .build()
      }
    },
    new Resolver(getResolver()),
    issuerDid,
    async (_format, vc) => {
      const header = {
        alg: "ES256",
        kid: `${issuerDid}#${issuerKid}`
      };
      const keyLike = await importJWK(issuerJWK);
      return await new SignJWT(vc)
        .setProtectedHeader(header)
        .sign(keyLike);
    },
    memoryManager,
    new class extends CredentialDataManager {
      async getCredentialData(types: string[], holder: string): Promise<CredentialDataResponse> {
        if (types.includes("DeferredVc")) {
          return {
            type: "Deferred",
            transactionId: "1234"
          }
        }
        return {
          type: "InTime",
          data: {
            id: holder,
          },
          schema: {
            id: "https://test.com/schema",
            type: "CustomType"
          },
          metadata: {}
        }
      }
      async deferredExchange(
        _acceptanceToken: string
      ): Promise<
        Result<DeferredCredentialData |
          (InTimeCredentialData & { format: W3CVerifiableCredentialFormats, types: string[] }), Error>
      > {
        return Result.Ok({
          type: "InTime",
          data: {
            id: holderDid,
          },
          schema: {
            id: "https://test.com/schema",
            type: "CustomType"
          },
          metadata: {},
          format: "jwt_vc",
          types: ["CustomType"]
        })
      }
    }
  );

  describe("In-Time flow", () => {
    test("Should successfully issue a VC", async () => {
      const tokenResponse = await generateTokenResponse({ vc: "VcTest" });
      const credentialRequest: CredentialRequest = {
        credential_definition: {
          type: ["VcTest"]
        },
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      const credentialResponse = await vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      );
      expect(credentialResponse.credential).not.toBeUndefined;
    });
    test("Should successfully issue a VC using ID", async () => {
      const tokenResponse = await generateTokenResponse({ configId: "WithId" });
      const credentialRequest: CredentialRequest = {
        credential_definition: {
          type: ["VcTestWithId"]
        },
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      const credentialResponse = await vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      );
      expect(credentialResponse.credential).not.toBeUndefined;
    });
    test("Should not be possible to request a different VC that the one authorized", async () => {
      const tokenResponse = await generateTokenResponse({ configId: "WithId" });
      const credentialRequest: CredentialRequest = {
        credential_definition: {
          type: ["VcTest"]
        },
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      await expect(vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      )).rejects.toThrow();
    });
    test("Should not be possible to request a VC using VC ID", async () => {
      const tokenResponse = await generateTokenResponse({ vc: "VcTest" });
      const credentialRequest: CredentialRequest = {
        credential_identifier: "eu.id.not.supported",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      await expect(vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      )).rejects.toThrow();
    });
    test("Should not be possible to combine both vc identifier and format when requesting a VC", async () => {
      const tokenResponse = await generateTokenResponse({ vc: "VcTest" });
      const credentialRequest: CredentialRequest = {
        credential_identifier: "eu.id.not.supported",
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      await expect(vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      )).rejects.toThrow();
    });
    test("Should not be possible to request an unssuported credential", async () => {
      const tokenResponse = await generateTokenResponse({ vc: "DoesNotExist" });
      const credentialRequest: CredentialRequest = {
        credential_definition: {
          type: ["DoesNotExist"]
        },
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      await expect(vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      )).rejects.toThrow();
    });
  });
  describe("Deferred flow", () => {
    test("Should successfully issue a VC", async () => {
      const tokenResponse = await generateTokenResponse({ vc: "DeferredVc" });
      const credentialRequest: CredentialRequest = {
        credential_definition: {
          type: ["DeferredVc"]
        },
        format: "jwt_vc_json",
        proof: {
          proof_type: "jwt",
          jwt: await generateProof(tokenResponse.c_nonce)
        }
      };
      let credentialResponse: CredentialResponse;
      const accessToken = await vcIssuer.verifyAccessToken(
        tokenResponse.access_token,
        issuerJWK
      );
      credentialResponse = await vcIssuer.generateCredentialResponse(
        accessToken,
        credentialRequest,
        W3CDataModel.V2,
      );
      expect(credentialResponse.transaction_id).not.toBeUndefined;
      credentialResponse = await vcIssuer.exchangeAcceptanceTokenForVc(
        credentialResponse.transaction_id!,
        W3CDataModel.V2
      );
      expect(credentialResponse.credential).not.toBeUndefined;
    });
  });
});

async function generateProof(nonce: string) {
  const header = {
    typ: "openid4vci-proof+jwt",
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  return await new SignJWT({ nonce: nonce })
    .setProtectedHeader(header)
    .setExpirationTime("15m")
    .setIssuer(holderDid)
    .setAudience(issuerUrl)
    .setIssuedAt()
    .sign(keyLike);
}

async function generateIdToken(idRequest: IdTokenRequest): Promise<IdTokenResponse> {
  const { payload } = decodeToken(idRequest.request);
  const header = {
    alg: "ES256",
    kid: `${holderDid}#${holderKid}`
  };
  const keyLike = await importJWK(holderJWK);
  const idToken = await new SignJWT({ nonce: idRequest.requestParams.nonce })
    .setProtectedHeader(header)
    .setIssuer(holderDid)
    .setAudience((payload as JwtPayload).iss!)
    .setSubject(holderDid)
    .setExpirationTime("15m")
    .sign(keyLike);
  return {
    id_token: idToken
  }
}

async function generateTokenResponse(data: { vc?: string, configId?: string }) {
  const vc = data.vc;
  const rp = new OpenIdRPStepBuilder(
    generateDefaultAuthorisationServerMetadata("https://issuer"),
  )
    .setDefaultHolderMetadata({
      "authorization_endpoint": "openid:",
      "response_types_supported": ["vp_token", "id_token"],
      "vp_formats_supported": {
        "jwt_vp": {
          "alg_values_supported": ["ES256"]
        },
        "jwt_vc": {
          "alg_values_supported": ["ES256"]
        }
      },
      "scopes_supported": ["openid"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["ES256"],
      "request_object_signing_alg_values_supported": ["ES256"],
      "subject_syntax_types_supported": [
        "urn:ietf:params:oauth:jwk-thumbprint",
        "did:key:jwk_jcs-pub"
      ],
      "id_token_types_supported": ["subject_signed_id_token"]
    })
    .withDidResolver(new Resolver(getResolver()))
    .withTokenSignCallback((payload, algs) => {
      return signCallback(payload, algs);
    })
    .withStateManager(memoryManager)
    .build();

  const authzRequest = AuthzRequestBuilder.holderAuthzRequestBuilder(
    "code",
    holderDid,
    "openid:",
    {},
    await generateChallenge(codeVerifier),
    "ES256"
  ).addAuthzDetails(
    vc ? AuthzDetailsBuilderFactory.generateBuilder("openid_credential")
    .withFormat("jwt_vc_json")
    .withCredentialTypes([vc])
    .build() :
    AuthzDetailsBuilderFactory.generateBuilder("openid_credential")
    .withCredentialConfiguration("WithId")
    .build()
  ).build();
  // Verify AuthzRequest
  let verifiedAuthzRequest = await rp.verifyBaseAuthzRequest(
    authzRequest,
  );
  // Create ID Token Request
  const idTokenRequest = await rp.createIdTokenRequest(
    verifiedAuthzRequest.authzRequest.client_metadata?.authorization_endpoint!,
    verifiedAuthzRequest.authzRequest.client_id,
    issuerUrl + "/direct_post",
    {
      type: "Issuance",
      verifiedBaseAuthzRequest: verifiedAuthzRequest,
    }
  );
  // Create ID Token Response
  const idTokenResponse = await generateIdToken(idTokenRequest);

  // Verify ID Token Response
  const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
    idTokenResponse,
  );
  // Create Token Request
  const tokenRequest: TokenRequest = {
    grant_type: "authorization_code",
    client_id: holderDid,
    code_verifier: codeVerifier,
    code: verifiedIdTokenResponse.authzCode
  };
  // Create Token Response
  return await rp.generateAccessToken(
    tokenRequest,
    false,
    // signCallback,
    issuerUrl,
    authServerJWK
  );
}
