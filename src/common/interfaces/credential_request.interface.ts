import { JWK } from 'jose';
import {W3CVerifiableCredentialFormats} from '../formats/index.js';
import {BaseControlProof} from './control_proof.interface.js';
import { JwtVcJsonFormatCreentialSubject } from './issuer_metadata.interface.js';
import {JWA_ENCRYPTION_ALGS, JWA_ENCRYPTION_ENC} from '../constants/index.js';

/**
 * Type for CredentialRequest
 */
export type CredentialRequest = BaseCredentialRequest |
  JwtVcJsonCredentialRequest;

/**
 * Defines a credential request object in accordance to OID4VCI
 */
export interface BaseCredentialRequest<Format = W3CVerifiableCredentialFormats> {
  format?: Format; // Must not be present with credential_identifier
  proof: BaseControlProof;
  credential_identifier?: string;
  credential_response_encryption?: CredentialEncryptionInterface;
}

/**
 * Defines a credential request object when using the format parameter with value "jwt_vc_json"
 */
export interface JwtVcJsonCredentialRequest extends BaseCredentialRequest<"jwt_vc_json"> {
  credential_definition: {
    type: string[];
    credentialSubject?: Record<string, Pick<JwtVcJsonFormatCreentialSubject, "mandatory">>;
  },
}

export interface CredentialEncryptionInterface {
  jwk: JWK;
  alg: JWA_ENCRYPTION_ALGS;
  enc: JWA_ENCRYPTION_ENC
}
