import {JWA_ENCRYPTION_ALGS, JWA_ENCRYPTION_ENC} from '../constants/index.js';
import {W3CVerifiableCredentialFormats} from '../formats/index.js';

/**
 * Defines the credential issuer metadata in accordance to OID4VCI
 */
export interface IssuerMetadata {
  credential_issuer: string,
  authorization_server?: string[],
  credential_endpoint: string,
  deferred_credential_endpoint?: string,
  batch_credential_endpoint?: string,
  notification_endpoint?: string,
  credential_response_encryption?: CredentialResponseEncryption,
  credential_identifiers_supported?: boolean,
  credential_configurations_supported: Record<
    string,
    CredentialConfigurationSupportedForJwtJsonFormat
  >
}

/**
 * Defines information related to the encryption of VCs
 */
export interface CredentialResponseEncryption {
  alg_values_supported: JWA_ENCRYPTION_ALGS[],
  enc_values_supported: JWA_ENCRYPTION_ENC[],
  encryption_required: boolean
}

/**
 * Defines the credential supported object that can appear
 * in the issuer metadata in accordance to OID4VCI
 */
export interface BaseCredentialConfigurationSupported<Format = W3CVerifiableCredentialFormats> {
  format: Format,
  scope?: string,
  cryptographic_binding_methods_supported?: string[],
  credential_signing_alg_values_supported?: string[],
  // This specification only supports jwt
  proof_types_supported?: Record<string, ProofTypesSupported>,
  display?: VerifiableCredentialDisplay[],
}

export interface CredentialConfigurationSupportedForJwtJsonFormat
  extends BaseCredentialConfigurationSupported<"jwt_vc_json"> {
  credential_definition: {
    type: string[];
    credentialSubject?: Record<
      string,
      JwtVcJsonFormatCreentialSubject | JwtVcJsonFormatCreentialSubject[]
    >
  }
}

export interface JwtVcJsonFormatCreentialSubject {
  mandatory?: boolean;
  value_type?: string;
  display?: {
    name?: string;
    locale?: string;
  }[]
}

export interface ProofTypesSupported {
  proof_signing_alg_values_supported: string[]
}

/**
 * Defines the display information of a credential
 */
export interface VerifiableCredentialDisplay {
  name: string,
  locale?: string, // RFC 5646
  logo?: {
    uri: string,
    alt_text?: string,
  },
  description?: string,
  background_color?: string, // CSS-Color
  background_image?: {
    uri: string
  },
  text_color?: string // CSS-Color
}
