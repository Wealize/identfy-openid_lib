import {W3CVerifiableCredentialFormats} from '../formats/index.js';
import {JwtVcJsonFormatCreentialSubject} from './issuer_metadata.interface.js';

/**
 * Type for AuthorizationDetails
 */
export type AuthorizationDetails = AuthorizationDetailsForJwtVcJson;

/**
 * Defines the details of an Authorization Request in accordance to
 * OID4VCI and RFC 9396 "OAuth 2.0 Rich Authorization Requests"
 */
export interface BaseAuthorizationDetails<
  Format = W3CVerifiableCredentialFormats
> { // OAuth 2.0 Rich Authorization Requests Section 2
  type: string, // OID4VCI Section 5.1.1
  format?: Format, // OID4VCI Section 5.1.1
  credential_configuration_id?: string, // OID4VCI Section 5.1.1
  locations?: string[],
  actions?: string[],
  datatypes?: string[],
  identifier?: string,
  privileges?: string[]
}

/**
 * Authorization Details data for W3C Verifiable Credentials in "jwt_vc_json" format
 */
export interface AuthorizationDetailsForJwtVcJson extends BaseAuthorizationDetails<"jwt_vc_json"> {
  credential_definition?: {
    type?: string[];
    credentialSubject?: Record<string, Pick<JwtVcJsonFormatCreentialSubject, "mandatory">>
  }
}
