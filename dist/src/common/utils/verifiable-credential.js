import jsonpath from "jsonpath";
/**
 * Allows to obtain data from a VC given a JSON PATH
 * @param vc The VC from which obtain the data
 * @param path The JSON PATH to consider
 * @returns Undefined if there is not data, otherwise, the contained information
 */
export function extractFromCredential(vc, path) {
    const pathResult = jsonpath.query(vc, path, 1);
    if (pathResult.length) {
        return pathResult[0];
    }
    return undefined;
}
