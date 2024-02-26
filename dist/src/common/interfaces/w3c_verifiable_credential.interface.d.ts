/**
 * Defines a Verifiable Credential in accordance to W3C VC Data Model 2.0
 */
export interface W3CVerifiableCredential {
    '@context': string[];
    type: string[];
    credentialSchema?: W3CVcSchemaDefinition[];
    issuer: string;
    validFrom?: string;
    validUntil?: string;
    id?: string;
    credentialStatus?: W3CCredentialStatus;
    description?: string;
    credentialSubject: W3CSingleCredentialSubject;
    proof?: EmbeddedProof;
    [x: string]: any;
}
/**
 * Defines the schema definition of a credential in
 * accordance to W3C VC Data Model 2.0
 */
export interface W3CVcSchemaDefinition {
    id: string;
    type: string;
}
/**
 * Defines the status information of a credential in
 * accordance to W3C VC Data Model 2.0
 */
export interface W3CCredentialStatus {
    id?: string;
    type: string;
    [key: string]: any;
}
/**
 * Defines subject data of a credential in accordance to W3C VC Data Model 2.0
 */
export interface W3CSingleCredentialSubject {
    id?: string;
    [key: string]: any;
}
/**
 * Defines an embedded proof for a VC in accordance to W3C Data Model 2.0
 * @see https://www.w3.org/TR/vc-data-integrity/#proofs
 */
export interface EmbeddedProof {
    id?: string;
    type: string;
    proofPurpose: string;
    verificationMethod: string;
    created?: string;
    expires?: string;
    domain?: string;
    challenge?: string;
    proofValue: string;
    previousProof?: string | string[];
    nonce?: string;
}
