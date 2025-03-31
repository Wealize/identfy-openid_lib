import {DataChecker } from "./index.js";
import {Result} from "../result.js";
import {W3CVerifiableCredentialFormats} from "../../formats/index.js";
import {
  AuthorizationDetailsForJwtVcJson,
  BaseAuthorizationDetails
} from "../../interfaces/authz_details.interface.js";
import {InternalError} from "../error/internal.error.js";


abstract class AuthDetailsChecker extends DataChecker<BaseAuthorizationDetails> {}

class AuthDetailsJwtVcChecker extends AuthDetailsChecker {
  checkData(details: AuthorizationDetailsForJwtVcJson): Result<null, string> {
    if (!details.credential_definition) {
      return Result.Err(`"credential_definition" is missing`);
    }
    if (!details.credential_definition.type ||
      !Array.isArray(details.credential_definition.type)) {
        return Result.Err(
          `"type" specification is required in "credential_definition" parameter and it must be an array`
        );
    }
    return Result.Ok(null);
  }
}

export class AuthDetailsCheckerFactory {
  static generateChecker(format: W3CVerifiableCredentialFormats): AuthDetailsChecker {
    if (format === "jwt_vc_json") {
      return new AuthDetailsJwtVcChecker();
    } else {
      throw new InternalError("Unssuported format type for auth details");
    }
  }
}
