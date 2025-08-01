/**
 * This file was auto-generated by Fern from our API Definition.
 */

import * as environments from "../../../../environments.js";
import * as core from "../../../../core/index.js";
import * as Pipedream from "../../../index.js";
import { mergeHeaders, mergeOnlyDefinedHeaders } from "../../../../core/headers.js";
import * as errors from "../../../../errors/index.js";

export declare namespace Workflows {
  export interface Options {
    environment?: core.Supplier<environments.PipedreamEnvironment | string>;
    /** Specify a custom URL to connect the client to. */
    baseUrl?: core.Supplier<string>;
    projectId: string;
    token?: core.Supplier<core.BearerToken | undefined>;
    /** Override the x-pd-environment header */
    projectEnvironment?: core.Supplier<Pipedream.ProjectEnvironment | undefined>;
    /** Additional headers to include in requests. */
    headers?: Record<string, string | core.Supplier<string | undefined> | undefined>;
    /** Base domain for workflows. Used for custom domains. */
    workflowDomain?: string;
  }

  export interface RequestOptions {
    /** The maximum time to wait for a response in seconds. */
    timeoutInSeconds?: number;
    /** The number of times to retry the request. Defaults to 2. */
    maxRetries?: number;
    /** A hook to abort the request. */
    abortSignal?: AbortSignal;
    /** Override the x-pd-environment header */
    projectEnvironment?: Pipedream.ProjectEnvironment | undefined;
    /** Additional query string parameters to include in the request. */
    queryParams?: Record<string, unknown>;
    /** Additional headers to include in the request. */
    headers?: Record<string, string | core.Supplier<string | undefined> | undefined>;
  }
}

export class Workflows {
  protected readonly _options: Workflows.Options;
  private readonly workflowDomain: string;

  constructor(_options: Workflows.Options) {
    this._options = _options;
    this.workflowDomain = _options.workflowDomain ?? this._defaultWorkflowDomain;
  }

  private get _defaultWorkflowDomain(): string {
    return this._options.environment !== environments.PipedreamEnvironment.Prod &&
      this._options.environment !== environments.PipedreamEnvironment.Canary
      ? "m.d.pipedream.net"
      : "m.pipedream.net";
  }

  private get _urlProtocol(): string {
    return this._options.environment !== environments.PipedreamEnvironment.Prod &&
      this._options.environment !== environments.PipedreamEnvironment.Canary
      ? "http"
      : "https";
  }

  /**
   * Invokes a workflow using the URL of its HTTP interface(s), by sending an
   * HTTP request.
   *
   * @param {Pipedream.InvokeWorkflowOpts} request
   * @param {Pipedream.HTTPAuthType} authType - The type of authorization to use
   * for the request (defaults to None).
   * @param {Workflows.RequestOptions} requestOptions - Request-specific
   * configuration.
   *
   * @example
   *     await client.workflows.invoke({
   *         urlOrEndpoint: "https://en-your-endpoint.m.pipedream.net",
   *         body: {
   *             foo: 123,
   *             bar: "abc",
   *             baz: null
   *         },
   *         headers: {
   *             "Accept": "application/json"
   *         }
   *     }, Pipedream.HTTPAuthType.OAuth)
   */
  public invoke(
    request: Pipedream.InvokeWorkflowOpts,
    authType: Pipedream.HTTPAuthType = Pipedream.HTTPAuthType.None,
    requestOptions?: Workflows.RequestOptions,
  ): core.HttpResponsePromise<unknown> {
    return core.HttpResponsePromise.fromPromise(this.__invoke(request, authType, requestOptions));
  }

  private async __invoke(
    request: Pipedream.InvokeWorkflowOpts,
    authType: Pipedream.HTTPAuthType = Pipedream.HTTPAuthType.None,
    requestOptions?: Workflows.RequestOptions,
  ): Promise<core.WithRawResponse<unknown>> {
    const { urlOrEndpoint, body, method = "POST", headers = {} } = request;

    const url = this._buildWorkflowUrl(urlOrEndpoint);

    let authHeader: string | undefined;
    switch (authType) {
      case Pipedream.HTTPAuthType.StaticBearer:
        // It's expected that users will pass their own Authorization header in
        // the static bearer case
        authHeader = headers["Authorization"];
        break;
      case Pipedream.HTTPAuthType.OAuth:
        authHeader = await this._getAuthorizationHeader();
        break;
      default:
        break;
    }

    const _response = await core.fetcher({
      url,
      method: method.toUpperCase(),
      headers: mergeHeaders(
        this._options?.headers,
        mergeOnlyDefinedHeaders({
          Authorization: authHeader,
          "x-pd-environment": requestOptions?.projectEnvironment,
        }),
        headers,
        requestOptions?.headers,
      ),
      contentType: body != null ? "application/json" : undefined,
      queryParameters: requestOptions?.queryParams,
      requestType: body != null ? "json" : undefined,
      body,
      timeoutMs: requestOptions?.timeoutInSeconds != null ? requestOptions.timeoutInSeconds * 1000 : 60000,
      maxRetries: requestOptions?.maxRetries,
      abortSignal: requestOptions?.abortSignal,
    });

    if (!_response.ok) {
      throw new errors.PipedreamError({
        message: _response.error.reason,
        statusCode: _response.rawResponse.status,
        rawResponse: _response.rawResponse,
      });
    }

    return {
      data: _response.rawResponse,
      rawResponse: _response.rawResponse,
    };
  }

  /**
   * Invokes a workflow for a Pipedream Connect user in a project.
   *
   * @param {Pipedream.InvokeWorkflowForExternalUserOpts} request
   * @param {Workflows.RequestOptions} requestOptions - Request-specific
   * configuration.
   *
   * @example
   *     await client.workflows.invokeForExternalUser({
   *         urlOrEndpoint: "https://your-workflow-url.m.pipedream.net",
   *         externalUserId: "your-external-user-id",
   *         body: {
   *             foo: 123,
   *             bar: "abc",
   *             baz: null
   *         },
   *         headers: {
   *             "Accept": "application/json"
   *         }
   *     })
   */
  public invokeForExternalUser(
    request: Pipedream.InvokeWorkflowForExternalUserOpts,
    requestOptions?: Workflows.RequestOptions,
  ): core.HttpResponsePromise<unknown> {
    return core.HttpResponsePromise.fromPromise(this.__invokeForExternalUser(request, requestOptions));
  }

  private async __invokeForExternalUser(
    request: Pipedream.InvokeWorkflowForExternalUserOpts,
    requestOptions?: Workflows.RequestOptions,
  ): Promise<core.WithRawResponse<unknown>> {
    const { urlOrEndpoint, externalUserId, body, method, headers = {} } = request;

    if (!externalUserId?.trim()) {
      throw new Error("External user ID is required");
    }

    if (!urlOrEndpoint.trim()) {
      throw new Error("Workflow URL or endpoint ID is required");
    }

    const authHeader = await this._getAuthorizationHeader();
    if (!authHeader) {
      throw new Error(
        "OAuth or token is required for invoking workflows for external users. Please pass credentials for a valid OAuth client",
      );
    }

    // Delegate to invoke method with external user ID header and OAuth auth
    return this.__invoke(
      {
        urlOrEndpoint,
        body,
        method,
        headers: {
          ...headers,
          "X-PD-External-User-ID": externalUserId,
        },
      },
      Pipedream.HTTPAuthType.OAuth,
      requestOptions,
    );
  }

  /**
   * Builds a full workflow URL based on the input.
   *
   * @param input - Either a full URL (with or without protocol) or just an
   * endpoint ID.
   * @returns The fully constructed URL.
   * @throws If the input is a malformed URL, throws an error with a clear
   * message.
   */
  private _buildWorkflowUrl(input: string): string {
    const sanitizedInput = input
      .trim()
      .replace(/[^\w-./:]/g, "")
      .toLowerCase();
    if (!sanitizedInput) {
      throw new Error("URL or endpoint ID is required");
    }

    let url: string;
    const isUrl = sanitizedInput.includes(".") || sanitizedInput.startsWith("http");

    if (isUrl) {
      // Try to parse the input as a URL
      let parsedUrl: URL;
      try {
        const urlString = sanitizedInput.startsWith("http") ? sanitizedInput : `https://${sanitizedInput}`;
        parsedUrl = new URL(urlString);
      } catch {
        throw new Error(`The provided URL is malformed: "${sanitizedInput}". Please provide a valid URL.`);
      }

      // Validate the hostname to prevent potential DNS rebinding attacks
      if (!parsedUrl.hostname.endsWith(this.workflowDomain)) {
        throw new Error(`Invalid workflow domain. URL must end with ${this.workflowDomain}`);
      }

      url = parsedUrl.href;
    } else {
      // If the input is an ID, construct the full URL using the base domain
      if (!/^e(n|o)[a-z0-9-]+$/i.test(sanitizedInput)) {
        throw new Error(
          `Invalid endpoint ID format. Must contain only letters, numbers, and hyphens, and start with either "en" or "eo".`,
        );
      }

      url = `${this._urlProtocol}://${sanitizedInput}.${this.workflowDomain}`;
    }

    return url;
  }

  protected async _getAuthorizationHeader(): Promise<string | undefined> {
    const bearer = await core.Supplier.get(this._options.token);
    if (bearer != null) {
      return `Bearer ${bearer}`;
    }

    return undefined;
  }
}
