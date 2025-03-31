import {ClientAssertionTypes} from '../formats/index.js';
import {GrantType} from '../types/index.js';


/**
 * Token Request Data type
 */
export type TokenRequest = TokenRequestForAuthCode |
  TokenRequestForPreAuthCode |
  TokenRequestForVpToken;

/**
 * Defines an Access Token Request in accordance to
 * RFC 6749 "The OAuth 2.0 Authorization Framework" and OID4VCI
 */
export interface BaseTokenRequest<Grant = GrantType> {
  grant_type: Grant;
  client_id?: string;
}

/**
 * Extenstion so support the use of an autorization_code as grant
 */
export interface TokenRequestForAuthCode
  extends BaseTokenRequest<"authorization_code"> {
  code?: string;
  code_verifier?: string;
  client_assertion?: string;
  client_assertion_type?: ClientAssertionTypes
}

/**
 * Extension to support pre-auth flow in accordance to section OID4VCI Section 6.1
 */
export interface TokenRequestForPreAuthCode
  extends BaseTokenRequest<
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  > {
  "pre-authorized_code": string;
  tx_code?: string;
}

export interface TokenRequestForVpToken extends BaseTokenRequest<"vp_token"> {
  vp_token: string
}
