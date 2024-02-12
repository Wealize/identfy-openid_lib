import { JWA_ALGS } from "common/constants";

interface ClientMetadata {
  authorization_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: JWA_ALGS[];
  request_object_signing_alg_values_supported?: JWA_ALGS[];
  vp_formats_supported: {
    jwt_vp: {
      alg_values_supported: JWA_ALGS[]
    },
    jwt_vc: {
      alg_values_supported: JWA_ALGS[]
    }
  };
  subject_syntax_types_supported: string[];
  id_token_types_supported: string[]
}

export type HolderMetadata = ClientMetadata;

export type ServiceMetadata = ClientMetadata & { jwks_uri: string };
