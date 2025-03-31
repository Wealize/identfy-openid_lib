import {v4 as uuidv4} from 'uuid';
import {P, match} from 'ts-pattern';
import moment from 'moment';
import {Resolver} from 'did-resolver';
import {JWK} from 'jose';
import {Jwt, JwtPayload} from 'jsonwebtoken';
import {ControlProof} from '../../common/classes/control_proof.js';
import {
  CONTEXT_VC_DATA_MODEL_1,
  CONTEXT_VC_DATA_MODEL_2,
  C_NONCE_EXPIRATION_TIME,
} from '../../common/constants/index.js';
import {
  W3CDataModel,
  W3CVerifiableCredentialFormats,
} from '../../common/formats/index.js';
import {
  CredentialRequest,
  JwtVcJsonCredentialRequest
} from '../../common/interfaces/credential_request.interface.js';
import {
  CredentialConfigurationSupportedForJwtJsonFormat,
  IssuerMetadata
} from '../../common/interfaces/issuer_metadata.interface.js';
import {
  W3CVcSchemaDefinition,
  W3CVerifiableCredential,
  W3CVerifiableCredentialV1,
  W3CVerifiableCredentialV2,
} from '../../common/interfaces/w3c_verifiable_credential.interface.js';
import {
  decodeToken,
  verifyJwtWithExpAndAudience,
} from '../../common/utils/jwt.utils.js';
import {VcFormatter} from './formatters.js';
import {
  CredentialResponse
} from '../../common/interfaces/credential_response.interface.js';
import * as VcIssuerTypes from './types.js';
import {
  InternalNonceError,
  InvalidCredentialRequest,
  InvalidDataProvided,
  InvalidProof,
  InvalidToken,
  OpenIdError,
  Result,
  UnsupportedCredentialType,
} from '../../common/classes/index.js';
import {CredentialDataManager} from './credential_data_manager.js';
import {arraysAreEqual} from '../../common/utils/array.utils.js';
import {StateManager} from '../state/index.js';
import {NonceManager, RequestVcTypes} from '../nonce/index.js';
import {
  CredentialRequestCheckerFactory
} from '../../common/classes/checker/credential_request.checker.js';

/**
 * W3C credentials issuer in both deferred and In-Time flows
 */
export class W3CVcIssuer {
  /**
   * Constructor of the issuer
   * @param metadata Issuer metadata
   * @param didResolver Object that allows to resolve the DIDs found
   * @param issuerDid The DID of the issuer
   * @param signCallback Callback used to sign the VC generated
   * @param cNonceRetrieval Callback to recover the challenge nonce expected
   * for a control proof
   * @param getVcSchema Callback to recover the schema associated with a VC
   * @param getCredentialData Callback to recover the subject data to
   * include in the VC
   * It can also be used to specify if the user should follow the deferred flow
   */
  private nonceManager;
  constructor(
    private metadata: IssuerMetadata,
    private didResolver: Resolver,
    private issuerDid: string,
    private signCallback: VcIssuerTypes.VcSignCallback,
    stateManager: StateManager,
    private credentialDataManager: CredentialDataManager,
    private vcTypesContextRelationship?: Record<string, string>,
  ) {
    this.nonceManager = new NonceManager(stateManager);
  }

  /**
   * Allows to verify a JWT Access Token in string format
   * @param token The access token
   * @param publicKeyJwkAuthServer The public key that should verify the token
   * @param tokenVerifyCallback A callback that can be used to perform an
   * additional verification of the contents of the token
   * @returns Access token in JWT format
   * @throws If data provided is incorrect
   */
  async verifyAccessToken( // TODO: REVISE THIS DRAFT 13
    token: string,
    publicKeyJwkAuthServer: JWK,
    tokenVerifyCallback?: VcIssuerTypes.AccessTokenVerifyCallback,
  ): Promise<Jwt> {
    await verifyJwtWithExpAndAudience(
      token,
      publicKeyJwkAuthServer,
      this.metadata.credential_issuer,
    );
    const jwt = decodeToken(token);
    if (tokenVerifyCallback) {
      const verificationResult = await tokenVerifyCallback(
        jwt.header,
        jwt.payload as JwtPayload,
      );
      if (!verificationResult.valid) {
        throw new InvalidToken(
          `Invalid access token provided${verificationResult.error ? ': ' + verificationResult.error : '.'}`,
        );
      }
    }
    return jwt;
  }

  /**
   * Allows to generate a Credential Response in accordance to
   * the OID4VCI specification
   * @param acessToken The access token needed to perform the operation
   * @param credentialRequest The credential request sent by an user
   * @param dataModel The W3 VC Data Model version
   * @returns A credential response with a VC or a deferred code
   * @throws If data provided is incorrect
   */
  async generateCredentialResponse(
    acessToken: Jwt,
    credentialRequest: CredentialRequest,
    dataModel: W3CDataModel,
  ): Promise<CredentialResponse> {
    // TODO: PENDING TO ANALYZE credential_definition.credential_subject to detect what claims are mandatory
    // TODO: Add support for credential identifiers
    // TODO: For the time being, this version does not support requesting credentials using the scope parameter
    const jwtPayload = acessToken.payload as JwtPayload;
    const innerNonce = jwtPayload.nonce as string;
    if (credentialRequest.credential_identifier && credentialRequest.format) {
      throw new InvalidCredentialRequest(
        `Both "credential_identifier" and "format" parameters can not be present at the same time`
      );
    }
    if (credentialRequest.credential_identifier) {
      // TODO: For the time being, this version does not support credentials identifiers
      throw new UnsupportedCredentialType(
        `Credential identifiers are not supported`
      );
    }
    if (!credentialRequest.format) {
      // TODO: For the time being, this version only supports requesting credentials using format parameter
      throw new InvalidCredentialRequest(
        `Credentials request is missing parameter "format"`
      );
    }
    const credentialFormatCheckResult = CredentialRequestCheckerFactory.
      generateChecker(credentialRequest.format)
      .checkData(credentialRequest);
    if (credentialFormatCheckResult.isError()) {
      throw new InvalidCredentialRequest(credentialFormatCheckResult.unwrapError());
    }
    const cNonceResult = await this.nonceManager.getChallengeNonce(innerNonce);
    if (cNonceResult.isError()) {
      throw new InvalidProof('Invalid provided nonce for control proof');
    }
    const cNonce = cNonceResult.unwrap();
    if (cNonce.timestamp + cNonce.expirationTime <= Date.now()) {
      await this.nonceManager.deleteNonce(innerNonce);
      throw new InvalidCredentialRequest('Challenge nonce has expired');
    }
    let vcConfigurationData: CredentialConfigurationSupportedForJwtJsonFormat;
    match(cNonce)
      .with({operationType: {type: 'Verification'}}, _ => {
        throw new InvalidCredentialRequest('Invalid provided nonce');
      })
      .with({operationType: { type: 'Issuance', vcTypes: P.select()}},
        (vcTypes) => {
          const types = vcTypes as RequestVcTypes[];
          let validTypeFlag = false;
          for (const requestVcTypes of vcTypes) {
            match(requestVcTypes)
              .with({ type: "Uknown" }, _ => {
                // Most probably generated from pre-auth flow
              })
              .with(
                {
                  type: "Know",
                  vcTypes: P.select("validTypes"),
                },
                ({validTypes}) => {
                  const typesCheck = this.checkCredentialType(
                    credentialRequest as JwtVcJsonCredentialRequest, // For now we only support this format
                    validTypes!,
                  );
                  if (typesCheck.isOk()) {
                    vcConfigurationData = typesCheck.unwrap();
                    validTypeFlag = true;
                  }
              }).with(
                {
                  type: "Know",
                  credential_id: P.select("validId")
                },
                ({validId}) => {
                  const typesCheck = this.checkCredentialType(
                    credentialRequest as JwtVcJsonCredentialRequest, // For now we only support this format
                    undefined,
                    validId
                  );
                  if (typesCheck.isOk()) {
                    vcConfigurationData = typesCheck.unwrap();
                    validTypeFlag = true;
                  }
                }
              )
              if (validTypeFlag) {
                break;
              }
          }
          if (!validTypeFlag) {
            throw new InvalidCredentialRequest(
              'The provided token does not allow for the issuance of a VC of the specified types',
            );
          }
          // TODO: VERIFY IF NEEDED
          // if (!areDidUrlsSameDid(proofAssociatedClient, jwtPayload.sub!)) {
          //   throw new InvalidToken(
          //     'Access Token was issued for a different identifier that the one that sign the proof',
          //   );
          // }
        },
      )
      .otherwise(() => {
        throw new InternalNonceError(
          'Unexpected behaviour detected at nonce matching',
        );
      });
    let proofAssociatedClient
    if (vcConfigurationData!.proof_types_supported) {
      const controlProof = ControlProof.fromJSON(credentialRequest.proof);
      proofAssociatedClient = controlProof.getAssociatedIdentifier();
      const supportedAlgs = this.getSupportAlgForProof(
        vcConfigurationData!,
        controlProof.format
      );

      if (supportedAlgs.isError()) {
        throw supportedAlgs.unwrapError();
      }

      await controlProof.verifyProof(
        innerNonce,
        this.metadata.credential_issuer,
        this.didResolver,
        supportedAlgs.unwrap()
      );
    }
    const credentialSubject =
      await this.credentialDataManager.resolveCredentialSubject(
        jwtPayload.sub!,
        proofAssociatedClient,
      );
    const credentialResponse = await this.credentialResponseMatch(
      (credentialRequest as JwtVcJsonCredentialRequest).credential_definition.type,
      credentialSubject,
      credentialRequest.format,
      dataModel,
    );
    await this.nonceManager.deleteNonce(innerNonce);
    return credentialResponse;
  }

  private async credentialResponseMatch(
    types: string[],
    credentialSubject: string,
    format: W3CVerifiableCredentialFormats,
    dataModel: W3CDataModel,
  ) {
    const credentialDataOrDeferred =
      await this.credentialDataManager.getCredentialData(
        types,
        credentialSubject,
      );
    return match(credentialDataOrDeferred)
      .with({type: 'InTime'}, async data =>
        this.generateW3CCredential(
          types,
          data.schema,
          credentialSubject,
          data,
          format,
          dataModel,
        ),
      )
      .with({type: 'Deferred'}, data => {
        return {
          transaction_id: data.transactionId,
        };
      })
      .exhaustive();
  }

  /**
   * Allows for the generation of a VC without an Access Token
   * @param did The DID if the holder of the VC
   * @param dataModel The W3 VC Data Model version
   * @param types The types of the VCs
   * @param format The format of the VC
   * @returns A credential response with the VC
   */
  async generateVcDirectMode(
    did: string,
    dataModel: W3CDataModel,
    credentialConfigurationId: string
  ): Promise<CredentialResponse> {
    const configurationData = this.metadata.credential_configurations_supported[
      credentialConfigurationId
    ];
    if (!configurationData) {
      throw new InvalidCredentialRequest(
        "Unssuported Credential Configuration ID provided"
      );
    }
    return await this.credentialResponseMatch(
      configurationData.credential_definition.type, did, "jwt_vc_json", dataModel);
  }

  // TODO: valorar quitar iss de 'CredentialDataOrDeferred' y homogeneizar comportamiento entre V1 y V2
  // El motivo es que V1 incluye un campo issuanceDate, y además EBSI está obligando a que sea igual al 'iat' del token.
  // Sin embargo, en V2 ese campo no existe. La propusta sería:
  // - En V2, validFrom se asocia con nbf, y iat sería Date.now(). Según esto, en formatDataModel2, iat debería ajustarse a
  //   Date.now() y valorar quitar el nbf o también asignarlo a Date.now(). Notar diferencia entre info de la credencial y del token
  // - En V1, validFrom se asocia con nbf, issued y issuanceDate y iat con Date.now()
  private generateCredentialTimeStamps(data: VcIssuerTypes.CredentialMetadata) {
    if (data.validUntil && data.expiresInSeconds) {
      throw new InvalidDataProvided(
        '"expiresInSeconds" and "validUntil" can\'t be defined at the same time',
      );
    }

    const issuanceDate = (() => {
      const iss = data.iss ? moment(data.iss, true) : moment();
      if (!iss.isValid()) {
        throw new InvalidDataProvided(
          'Invalid specified date for "iss" parameter',
        );
      }
      return iss;
    })();

    const validFrom = (() => {
      const nbf = data.nbf ? moment(data.nbf, true) : issuanceDate.clone();
      if (!nbf.isValid()) {
        throw new InvalidDataProvided(
          'Invalid specified date for "nbf" parameter',
        );
      }
      if (nbf.isBefore(issuanceDate)) {
        throw new InvalidDataProvided(
          '"validFrom" can not be before "issuanceDate"',
        );
      }
      return nbf;
    })();

    const expirationDate = (() => {
      const exp = (() => {
        if (data.validUntil) {
          return moment(data.validUntil, true);
        } else if (data.expiresInSeconds) {
          return issuanceDate.clone().add(data.expiresInSeconds, 'seconds');
        } else {
          return undefined;
        }
      })();
      if (exp) {
        if (!exp.isValid()) {
          throw new InvalidDataProvided(
            'Invalid specified date for "expirationDate" parameter',
          );
        }
        if (exp.isBefore(validFrom)) {
          throw new InvalidDataProvided(
            '"expirationDate" can not be before "validFrom"',
          );
        }
      }
      return exp;
    })();

    return {
      issuanceDate: issuanceDate.utc().toISOString(),
      validFrom: validFrom.utc().toISOString(),
      expirationDate: expirationDate
        ? expirationDate.utc().toISOString()
        : undefined,
    };
  }

  private generateVcId() {
    return `urn:uuid:${uuidv4()}`;
  }

  private generateW3CDataForV1(
    type: string[],
    schema: W3CVcSchemaDefinition | W3CVcSchemaDefinition[],
    subject: string,
    vcData: VcIssuerTypes.InTimeCredentialData,
  ): W3CVerifiableCredentialV1 {
    const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
    const vcId = this.generateVcId();
    return {
      '@context': [CONTEXT_VC_DATA_MODEL_1],
      type,
      credentialSchema: schema,
      issuanceDate: timestamps.issuanceDate,
      validFrom: timestamps.validFrom,
      expirationDate: timestamps.expirationDate,
      id: vcId,
      credentialStatus: vcData.status,
      issuer: this.issuerDid,
      issued: timestamps.issuanceDate,
      termsOfUse: vcData.termfOfUse,
      credentialSubject: {
        id: subject,
        ...vcData.data,
      },
    };
  }

  private generateW3CDataForV2(
    type: string[],
    schema: W3CVcSchemaDefinition | W3CVcSchemaDefinition[],
    subject: string,
    vcData: VcIssuerTypes.InTimeCredentialData,
  ): W3CVerifiableCredentialV2 {
    const vcId = this.generateVcId();
    const timestamps = this.generateCredentialTimeStamps(vcData.metadata);
    return {
      '@context': [CONTEXT_VC_DATA_MODEL_2],
      type,
      credentialSchema: schema,
      validFrom: timestamps.validFrom,
      validUntil: timestamps.expirationDate,
      id: vcId,
      credentialStatus: vcData.status,
      termsOfUse: vcData.termfOfUse,
      issuer: this.issuerDid,
      credentialSubject: {
        id: subject,
        ...vcData.data,
      },
    };
  }

  private extendsVcContext(content: W3CVerifiableCredential) {
    if (!this.vcTypesContextRelationship) {
      return;
    }
    const typesToExtend = Object.keys(this.vcTypesContextRelationship);
    for (const type of content.type) {
      if (typesToExtend.includes(type)) {
        content['@context'].push(this.vcTypesContextRelationship[type]);
      }
    }
  }

  private async generateW3CCredential(
    type: string[],
    schema: W3CVcSchemaDefinition | W3CVcSchemaDefinition[],
    subject: string,
    vcData: VcIssuerTypes.InTimeCredentialData,
    format: W3CVerifiableCredentialFormats,
    dataModel: W3CDataModel,
  ): Promise<CredentialResponse> {
    const formatter = VcFormatter.fromVcFormat(format, dataModel);
    const content: W3CVerifiableCredential =
      dataModel === W3CDataModel.V1
        ? this.generateW3CDataForV1(type, schema, subject, vcData)
        : this.generateW3CDataForV2(type, schema, subject, vcData);
    this.extendsVcContext(content);
    const vcPreSign = formatter.formatVc(content);
    const signedVc = await this.signCallback(format, vcPreSign);
    // Generate a new nonce
    const nonce = uuidv4();
    const expirationTime = C_NONCE_EXPIRATION_TIME; // TODO: Make it configurable
    await this.nonceManager.saveNonce(nonce, {
      timestamp: Date.now(),
      sub: subject,
      operationType: {
        type: 'Issuance',
        vcTypes: [ // TODO: The new nonce should allow to request the same credentials as before
          {
            type: "Know",
            vcTypes: type
          }
        ],
      },
      type: 'ChallengeNonce',
      expirationTime,
    });
    return {
      format: format,
      credential: signedVc,
      c_nonce: nonce,
      c_nonce_expires_in: expirationTime, // TODO: This could be interesting to be configurable
    };
  }

  /**
   * Allows to exchange a deferred code for a VC
   * @param acceptanceToken The deferred code sent by the issuer in a
   * previous instance
   * @param dataModel The W3C VC Data Model version
   * @returns A credential response with the VC generated or a new
   * (or the same) deferred code
   */
  async exchangeAcceptanceTokenForVc(
    acceptanceToken: string,
    dataModel: W3CDataModel,
  ): Promise<CredentialResponse> {
    const exchangeResult =
      await this.credentialDataManager.deferredExchange(acceptanceToken);
    if (exchangeResult.isError()) {
      throw new InvalidToken(
        `Invalid acceptance token: ${exchangeResult.unwrapError().message}`,
      );
    }
    const credentialDataResponse = exchangeResult.unwrap();
    return await match(credentialDataResponse)
      .with({type: 'InTime'}, async dataResponse =>
        this.generateW3CCredential(
          dataResponse.types,
          dataResponse.schema,
          dataResponse.data.id!,
          dataResponse,
          dataResponse.format,
          dataModel,
        ),
      )
      .with({type: 'Deferred'}, data => {
        return {
          transaction_id: data.transactionId,
        };
      })
      .exhaustive();
  }

  private checkCredentialType(
    request: JwtVcJsonCredentialRequest,
    validTypes?: string[],
    validId?: string
  ): Result<CredentialConfigurationSupportedForJwtJsonFormat, string> {
    const requestedTypes = request.credential_definition.type;
    if (validId) {
      const configData = this.metadata.credential_configurations_supported[validId];
      if (configData && configData.format === "jwt_vc_json") {
        if (arraysAreEqual(requestedTypes, configData.credential_definition.type)) {
          return Result.Ok(this.metadata.credential_configurations_supported[validId]);
        }
      }
    }
    if (validTypes && arraysAreEqual(requestedTypes, validTypes)) {
      for (const vcConfigId in this.metadata.credential_configurations_supported) {
        const vcConfigData = this.metadata.credential_configurations_supported[vcConfigId];
        if (vcConfigData.format === "jwt_vc_json") {
          if (arraysAreEqual(
            request.credential_definition.type,
            vcConfigData.credential_definition.type
          )) {
            return Result.Ok(
              this.metadata.credential_configurations_supported[vcConfigId]
            );
          }
        }
      }
    }
    return Result.Err("Unsuported combination of credential types and format");
  }

  private getSupportAlgForProof(
    vcConfigurationData: CredentialConfigurationSupportedForJwtJsonFormat,
    proofType: string
  ): Result<string[], OpenIdError> {
    if (!Object.keys(vcConfigurationData.proof_types_supported!).includes(proofType)) {
      return Result.Err(new InvalidProof("Unssuported proof type for requested credential"));
    }
    return Result.Ok(
      vcConfigurationData.proof_types_supported![
        proofType
      ]["proof_signing_alg_values_supported"]
    );
  }
}
