import { W3CVerifiableCredentialFormats } from '../formats/index.js';
import {
  CredentialConfigurationSupportedForJwtJsonFormat,
  IssuerMetadata,
  JwtVcJsonFormatCreentialSubject,
  VerifiableCredentialDisplay,
} from '../interfaces/issuer_metadata.interface.js';
import { isHttps } from '../utils/index.js';
import { InvalidDataProvided } from '../classes/index.js';

/**
 * Builder class for Credential Issuer Metadata
 */
export class IssuerMetadataBuilder {
  // For now, the Library does not support encryption or identifiers
  // For now, we dont support notification endpoint
  private authorization_server?: string;
  private deferred_credential_endpoint?: string;
  private batch_credential_endpoint?: string;
  private credential_configurations_supported: Record<
    string, CredentialConfigurationSupportedForJwtJsonFormat
  > = {};
  /**
   * Constructor of IssuerMetadataBuilder
   * @param credential_issuer URI of the credential issuer
   * @param credential_endpoint Credential issuer endpoint in which credential
   * request should be sended
   * @param imposeHttps Flag that indicates if the builder should check if
   * the provided URL are HTTPS
   * @throws if imposeHttps is true an a not HTTPS URI is provided
   */
  constructor(
    private credential_issuer: string,
    private credential_endpoint: string,
    private imposeHttps = true,
  ) {
    if (imposeHttps) {
      if (!isHttps(credential_issuer)) {
        throw new InvalidDataProvided('Is not https');
      }
      if (!isHttps(credential_endpoint)) {
        throw new InvalidDataProvided('Is not https');
      }
    }
  }

  private assertUrlIsHttps(url: string, assertedParameter: string) {
    if (this.imposeHttps) {
      if (!isHttps(url)) {
        throw new InvalidDataProvided(`${assertedParameter} is not https`);
      }
    }
  }

  /**
   * Set authorization server paramater for issuer metadata
   * @param url URI of the authorization server
   * @returns This object
   */
  withAuthorizationServer(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, 'authorization_server');
    this.authorization_server = url;
    return this;
  }

  /**
   * Set deferred credential endpoint paramater for issuer metadata
   * @param url Endpoint for deferred credentials
   * @returns This object
   */
  withDeferredCredentialEndpoint(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, 'deferred_credential_endpoint');
    this.deferred_credential_endpoint = url;
    return this;
  }

  /**
   * Set batch credential endpoint paramater for issuer metadata
   * @param url Endpoint fot batch credentials issuance
   * @returns This object
   */
  withBatchCredentialEndpoint(url: string): IssuerMetadataBuilder {
    this.assertUrlIsHttps(url, 'batch_credential_endpoint');
    this.batch_credential_endpoint = url;
    return this;
  }

  /**
   * Add a new credential supported for issuer metadata
   * @param supportedCredential Credential specification
   * @returns This object
   * @throws If the credential already exists
   */
  addCredentialSupported(
    credentialId: string,
    credentialInformation: CredentialConfigurationSupportedForJwtJsonFormat
  ): IssuerMetadataBuilder {
    if (this.credential_configurations_supported[credentialId]) {
      // TODO: Define error enum
      throw new InvalidDataProvided('Credential supported already defined');
    }
    this.credential_configurations_supported[credentialId] = credentialInformation;
    return this;
  }

  /**
   * Generate IssuerMetadata from the data contained in the builder
   * @returns IssuerMetadata instance
   */
  build(): IssuerMetadata {
    return {
      credential_issuer: this.credential_issuer,
      authorization_server: this.authorization_server ? [
        this.authorization_server
      ] : undefined,
      credential_endpoint: this.credential_endpoint,
      deferred_credential_endpoint: this.deferred_credential_endpoint,
      batch_credential_endpoint: this.batch_credential_endpoint,
      credential_identifiers_supported: false, // HARDCODED until feature is added
      credential_configurations_supported: this.credential_configurations_supported,
    };
  }
}

/**
 * Builder class for Credential Supported objects in Credential Issuer Metadata
 */
export class CredentialSupportedBuilder {
  private scope?: string;
  private cryptographic_binding_methods_supported?: string[];
  private credential_signing_alg_values_supported?: string[];
  private proof_types_supported?: Record<string,
    { proof_signing_alg_values_supported: string[] }
  >;
  private credentialSubject?: Record<string,
    JwtVcJsonFormatCreentialSubject | JwtVcJsonFormatCreentialSubject[]
  >;
  private types: string[] = [];
  private display?: VerifiableCredentialDisplay[];

  /**
   * Set the Scope of the credential issuance flow
   * @param id The scope of the flow
   * @returns This object
   */
  withScope(scope: string): CredentialSupportedBuilder {
    this.scope = scope;
    return this;
  }

  /**
   * Set the types of the credential
   * @param types The types of the credentials
   * @returns This object
   */
  withTypes(types: string[]): CredentialSupportedBuilder {
    this.types = types;
    return this;
  }

  /**
   * Add display information for the credential
   * @param display Information of how to display the credential
   * @returns This object
   */
  addDisplay(display: VerifiableCredentialDisplay): CredentialSupportedBuilder {
    if (!this.display) {
      this.display = [];
    }
    this.display.push(display);
    return this;
  }

  addBindingMethodSupported(method: "jwk" | string) {
    if (!this.cryptographic_binding_methods_supported) {
      this.cryptographic_binding_methods_supported = [];
    }
    this.cryptographic_binding_methods_supported.push(method);
    return this;
  }

  addCredentialSigningAlg(alg: string) {
    if (!this.credential_signing_alg_values_supported) {
      this.credential_signing_alg_values_supported = [];
    }
    this.credential_signing_alg_values_supported.push(alg);
    return this;
  }

  addProofTypeSupported(type: string, algs_supported: string[]) {
    if (!this.proof_types_supported) {
      this.proof_types_supported = {};
    }
    this.proof_types_supported[type] = {
      proof_signing_alg_values_supported: algs_supported
    }
    return this;
  }

  withCredentialSubjectDefinition(
    claim: string,
    data: JwtVcJsonFormatCreentialSubject | JwtVcJsonFormatCreentialSubject[]
  ) {
    if (!this.credentialSubject) {
      this.credentialSubject = {};
    }
    this.credentialSubject[claim] = data;
    return this;
  }

  /**
   * Generate CredentialSupported from the data contained in this builder
   * @returns CredentialSupported instance
   */
  build(): CredentialConfigurationSupportedForJwtJsonFormat {
    return {
      scope: this.scope,
      cryptographic_binding_methods_supported: this.cryptographic_binding_methods_supported,
      credential_signing_alg_values_supported: this.credential_signing_alg_values_supported,
      proof_types_supported: this.proof_types_supported as any,
      credential_definition: {
        type: this.types,
        credentialSubject: this.credentialSubject
      },
      format: "jwt_vc_json",
    };
  }
}

// TODO: REVISAR EN CREDENTIAL REQUEST LOS TIPOS DE PRUEBAS SOPORTADOS

/**
 * Builder for VC display information in CredentialSupported objects
 */
export class VerifiableCredentialDisplayBuilder {
  /**
   * Constructor of VerifiableCredentialDisplayBuilder
   * @param name String value of a display name for the Credential Issuer.
   */
  constructor(private name: string) { }
  private locale?: string;
  private logo?: {
    uri: string,
    alt_text?: string,
  };
  private description?: string;
  private background_color?: string;
  private text_color?: string;

  /**
   * Set the locale information of the display information
   * @param locale String value that identifies the language of this object
   * represented as a language tag taken from values defined in BCP47
   * @returns This object
   */
  withLocale(locale: string): VerifiableCredentialDisplayBuilder {
    this.locale = locale;
    return this;
  }

  /**
   * Set the logo information of the display information
   * @param logo Logo information
   * @returns This object
   */
  withLogo(logo: {
    uri: string,
    alt_text?: string,
  }): VerifiableCredentialDisplayBuilder {
    this.logo = logo;
    return this;
  }

  /**
   * Set the "description" attribute of the display information
   * @param description The description to include
   * @returns This object
   */
  withDescription(description: string): VerifiableCredentialDisplayBuilder {
    this.description = description;
    return this;
  }

  /**
   * Set the "background_color" attribute of the display information
   * @param color The color to include
   * @returns This object
   */
  withBackgroundColor(color: string): VerifiableCredentialDisplayBuilder {
    this.background_color = color;
    return this;
  }

  /**
   * Set the "text_color" attribute of the display information
   * @param textColor The color to include
   * @returns This object
   */
  withTextColor(textColor: string): VerifiableCredentialDisplayBuilder {
    this.text_color = textColor;
    return this;
  }

  /**
   * Generate VerifiableCredentialDisplay object from the data contained in the builder
   * @returns VerifiableCredentialDisplay instance
   */
  build(): VerifiableCredentialDisplay {
    return {
      name: this.name,
      locale: this.locale,
      logo: this.logo,
      description: this.description,
      background_color: this.background_color,
      text_color: this.text_color,
    };
  }
}
