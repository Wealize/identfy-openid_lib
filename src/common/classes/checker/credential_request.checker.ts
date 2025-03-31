import {
  CredentialRequest,
  JwtVcJsonCredentialRequest
} from "../../interfaces/credential_request.interface.js";
import {DataChecker } from "./index.js";
import {Result} from "../result.js";
import {W3CVerifiableCredentialFormats} from "../../formats/index.js";
import {InternalError} from "../error/internal.error.js";

abstract class CredentialRequestChecker extends DataChecker<CredentialRequest> {}

class CredentialRequestJwtFormatChecker extends CredentialRequestChecker {
  checkData(request: JwtVcJsonCredentialRequest): Result<null, string> {
    if (!request.credential_definition) {
      return Result.Err(`"credential_definition" parameter is missing`);
    }
    if (!request.credential_definition.type) {
      return Result.Err(`"credential_definition.type" parameter is missing`);
    }
    return Result.Ok(null);
  }
}

export class CredentialRequestCheckerFactory {
  static generateChecker(format: W3CVerifiableCredentialFormats): CredentialRequestChecker {
    if (format === "jwt_vc_json") {
      return new CredentialRequestJwtFormatChecker();
    } else {
      throw new InternalError("Unssuported format type for credential request");
    }
  }
}