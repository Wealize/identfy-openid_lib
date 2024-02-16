import { AuthzResponseMode } from "../formats/index.js";
import { AuthzResponseType } from "../types/index.js";

export class IdTokenRequest {
  params: IdTokenRequestParams;
  request: string;

  constructor(
    requestParams: IdTokenRequestParams,
    request: string,
    private clientAuthorizationEndpoint: string
  ) {
    this.params = requestParams;
    this.request = request;
  }

  toUri(): string {
    return `${this.clientAuthorizationEndpoint}?${new URLSearchParams(Object.entries(this.params)).toString()}`;
  }
}

export interface IdTokenRequestParams {
  response_type: AuthzResponseType;
  scope: string;
  redirect_uri: string;
  response_mode?: AuthzResponseMode;
  state?: string;
  nonce?: string;
}
