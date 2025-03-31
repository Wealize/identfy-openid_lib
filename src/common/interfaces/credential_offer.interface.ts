/**
 * Defines the Grant pre-authorize_code for a Credential Offer in
 * accordance to OID4VCI Draft 13
 */
export interface GrantPreAuthorizeCode {
  "pre-authorized_code": string;
  tx_code?: PreAuthTxCode;
}

/**
 * Defines the data structure for a tx code to included in the pre-auth code
 * grant type
 */
export interface PreAuthTxCode {
  input_mode?: "numeric" | "text";
  length?: number;
  description?: string;
  interval?: number;
  authorization_server?: string;
}

/**
 * Defines the Grant authorize_code for a Credential Offer in
 * accordance to OID4VCI Draft 13
 */
export interface GrantAuthorizationCode {
  issuer_state?: string;
  authorization_server?: string;
}

/**
 * Defines the Grant field for a Credential Offer in
 * accordance to OID4VCI Draft 13
 */
export interface CredentialOfferGrants {
  authorization_code?: GrantAuthorizationCode;
  "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: GrantPreAuthorizeCode;
}

/**
 * Defines a Credential Offer in accordance to OID4VCI Draft 13
 */
export interface CredentialOffer {
  credential_issuer: string;
  // Each of them refers to one key from credential_configurations_supported Credential Issuer metadata
  credential_configuration_ids: string[];
  grants?: CredentialOfferGrants;
}