import { Result } from "../result.js";

export abstract class DataChecker<Data> {
  abstract checkData(data: Data): Result<null, string>;
}
