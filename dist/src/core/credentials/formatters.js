import { InternalError } from "../../common/classes/index.js";
import { W3CDataModel } from "../../common/formats/index.js";
/**
 * Abstract class allowing to express unsigned W3C credentials in different formats.
 */
export class VcFormatter {
    constructor(dataModel) {
        this.dataModel = dataModel;
    }
    /**
     * Generates a formatter instance based on the specified format
     * @param format The format to consider
     * @param dataModel The W3C data model version
     * @returns A VcFormatter that allow to express unsigned VC in the specified format
     */
    static fromVcFormat(format, dataModel) {
        if (format === "jwt_vc" || format === "jwt_vc_json") {
            return new JwtVcFormatter(dataModel);
        }
        else if (format === "jwt_vc_json-ld" || format === "ldp_vc") {
            // TODO:
            throw new InternalError("Unimplemented");
        }
        else {
            throw new InternalError("Unsupported format");
        }
    }
    /**
     * Generates a format that allow to express VC in JWT format
     * @returns A VcFormatter
     */
    static jwtFormatter(dataModel) {
        return new JwtVcFormatter(dataModel);
    }
}
class JwtVcFormatter extends VcFormatter {
    formatVc(vc) {
        const token = {
            sub: vc.credentialSubject.id,
            iss: vc.issuer,
            vc
        };
        if (this.dataModel === W3CDataModel.V1) {
            return this.formatDataModel1(token, vc);
        }
        else {
            return this.formatDataModel2(token, vc);
        }
    }
    formatDataModel1(token, vc) {
        if (vc.issuanceDate) {
            token.iat = Date.parse(vc.issuanceDate);
            token.nbf = Date.parse(vc.issuanceDate);
        }
        else if (vc.validFrom) {
            token.iat = Date.parse(vc.validFrom);
            token.nbf = Date.parse(vc.validFrom);
        }
        if (vc.expirationDate) {
            token.exp = Date.parse(vc.validUntil);
        }
        return token;
    }
    formatDataModel2(token, vc) {
        if (vc.validFrom) {
            token.iat = Date.parse(vc.validFrom);
            token.nbf = Date.parse(vc.validFrom);
        }
        if (vc.validUntil) {
            token.exp = Date.parse(vc.validUntil);
        }
        return token;
    }
}