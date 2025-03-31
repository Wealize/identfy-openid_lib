import {
  JwtVcJsonFormatCreentialSubject
} from "../../interfaces/issuer_metadata.interface.js";
import { InternalError } from "../../classes/error/index.js";
import { OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE } from '../../constants/index.js';
import { W3CVerifiableCredentialFormats } from '../../formats/index.js';
import {AuthorizationDetails} from '../../interfaces/authz_details.interface.js';
export class AuthzDetailsBuilderFactory {
  static generateBuilder(type: "openid_credential"): OpenIdCredentialAuthzDetailsBuilder;
  static generateBuilder(type: string): AuthzDetailsBuilder {
    if (type === OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE) {
      return new OpenIdCredentialAuthzDetailsBuilder();
    } else {
      return new BaseAuthzDetailsBuilder(type);
    }
  }

}

type AuthzDetailsBuilder = BaseAuthzDetailsBuilder | OpenIdCredentialAuthzDetailsBuilder

/**
 * Builder class for AuthorizationDetails
 */
abstract class AuthzDetailsBuilderTemplate {
  protected locations: string[] = [];
  protected actions: string[] = [];
  protected datatypes: string[] = [];
  protected identifier?: string;
  protected privileges: string[] = [];

  constructor(
    protected type: string,
    // private format: W3CVerifiableCredentialFormats,
  ) { }

  /**
   * Generate a builder with the required parameters to build
   * an instance of AuthorizationDetails valid for the issuance of W3C VC
   * @param format W3C VC format
   * @returns Instance of AuthzDetailsBuilder
   */
  // static openIdCredentialBuilder(
  //   // format: W3CVerifiableCredentialFormats,
  // ): AuthzDetailsBuilder {
  //   return new AuthzDetailsBuilder(
  //     OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
  //     // format,
  //   );
  // }

  /**
   * Set the attribute "locations" of a authorization details object
   * @param locations Locations to include
   * @returns This object
   */
  withLocations(locations: string[]) {
    this.locations = locations;
    return this;
  }

  /**
   * Set the attribute "actions" of a authorization details object
   * @param actions Actions to include
   * @returns This object
   */
  withActions(actions: string[]) {
    this.actions = actions;
    return this;
  }

  /**
   * Set the attribute "datatypes" of a authorization details object
   * @param datatypes Datatypes of the requested credentials
   * @returns This object
   */
  withDatatypes(datatypes: string[]) {
    this.datatypes = datatypes;
    return this;
  }

  /**
   * Set the attribute "identifier" of a authorization details object
   * @param datatypes Identifier of the requested credentials
   * @returns This object
   */
  withIdentifier(identifier: string) {
    this.identifier = identifier;
    return this;
  }

  /**
   * Set the attribute "privileges" of a authorization details object
   * @param datatypes Privileges of the requested credentials
   * @returns This object
   */
  withPrivileges(privileges: string[]) {
    this.privileges = privileges;
    return this;
  }
}

export class BaseAuthzDetailsBuilder extends AuthzDetailsBuilderTemplate {
  constructor(
    type: string
  ) {
    super(type)
  }

  /**
   * Generate AuthorizationDetails from the data contained in the builder
   * @returns AuthorizationDetails instance
   */
  build(): AuthorizationDetails {
    return {
      type: this.type,
      locations: this.locations,
      actions: this.actions,
      datatypes: this.datatypes,
      identifier: this.identifier,
      privileges: this.privileges,
    };
  }
}

// BaseOIDCAuthzDetailsBuilder
/**
 * Builder class for AuthorizationDetails when "type" is "openid_credential"
 */
class OpenIdCredentialAuthzDetailsBuilder extends BaseAuthzDetailsBuilder {
  private configurationId?: string;
  private credentialSubject:
    Record<string, Pick<JwtVcJsonFormatCreentialSubject, "mandatory">> = {}

  constructor(
  ) {
    super(OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE)
  }

  addCredentialSubject(key: string, data: Pick<JwtVcJsonFormatCreentialSubject, "mandatory">) {
    this.credentialSubject[key] = data;
    return this;
  }

  withFormat(format: W3CVerifiableCredentialFormats) {
    if (this.configurationId) {
      throw new InternalError(
        `"format" and "credential_configuration_id cannot" be used at the same time`
      );
    }
    if (format === "jwt_vc_json") {
      return new JwtFormatAuthzDetails()
    }
    throw new InternalError("Unssuported format");
  }

  withCredentialConfiguration(configurationId: string) {
    this.configurationId = configurationId;
    return this;
  }

  /**
  * Generate AuthorizationDetails from the data contained in the builder
  * @returns AuthorizationDetails instance
  */
    build(): AuthorizationDetails {
      if (!this.configurationId) {
        throw new InternalError(
          `Auth details requires at least one of format or credential_configuration_id parameters`
        )
      }
      return {
        type: this.type,
        locations: this.locations,
        actions: this.actions,
        datatypes: this.datatypes,
        identifier: this.identifier,
        privileges: this.privileges,
        credential_configuration_id: this.configurationId,
        credential_definition: {
          credentialSubject: this.credentialSubject
        }
      };
    }
}

class JwtFormatAuthzDetails extends BaseAuthzDetailsBuilder {
  private types: string[] = [];
  private credentialSubject:
    Record<string, Pick<JwtVcJsonFormatCreentialSubject, "mandatory">> = {}
  constructor(
  ) {
    super(OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE)
  }

  addCredentialSubject(key: string, data: Pick<JwtVcJsonFormatCreentialSubject, "mandatory">) {
    this.credentialSubject[key] = data;
    return this;
  }

  withCredentialTypes(types: string[]) {
    this.types = types;
    return this;
  }

  /**
  * Generate AuthorizationDetails from the data contained in the builder
  * @returns AuthorizationDetails instance
  */
  build(): AuthorizationDetails {
    const result: AuthorizationDetails = {
      type: this.type,
      format: "jwt_vc_json",
      locations: this.locations,
      actions: this.actions,
      datatypes: this.datatypes,
      identifier: this.identifier,
      privileges: this.privileges,
    };
    if (!this.types.length) {
      throw new InternalError(
        `Auth details for format "jwt_vc_json" needs "types" parameter to be provided`
      )
    }
    result.credential_definition = {
      type: this.types,
      credentialSubject: this.credentialSubject
    }
    return result;
  }
}
