/**
 * This file was auto-generated by Fern from our API Definition.
 */

import * as environments from "../../../../environments.js";
import * as core from "../../../../core/index.js";
import * as Pipedream from "../../../index.js";
import { mergeHeaders, mergeOnlyDefinedHeaders } from "../../../../core/headers.js";
import * as errors from "../../../../errors/index.js";

export declare namespace AppCategories {
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

export class AppCategories {
    protected readonly _options: AppCategories.Options;

    constructor(_options: AppCategories.Options) {
        this._options = _options;
    }

    /**
     * @param {AppCategories.RequestOptions} requestOptions - Request-specific configuration.
     *
     * @example
     *     await client.appCategories.list()
     */
    public list(
        requestOptions?: AppCategories.RequestOptions,
    ): core.HttpResponsePromise<Pipedream.ListAppCategoriesResponse> {
        return core.HttpResponsePromise.fromPromise(this.__list(requestOptions));
    }

    private async __list(
        requestOptions?: AppCategories.RequestOptions,
    ): Promise<core.WithRawResponse<Pipedream.ListAppCategoriesResponse>> {
        const _response = await core.fetcher({
            url: core.url.join(
                (await core.Supplier.get(this._options.baseUrl)) ??
                    (await core.Supplier.get(this._options.environment)) ??
                    environments.PipedreamEnvironment.Prod,
                "v1/connect/app_categories",
            ),
            method: "GET",
            headers: mergeHeaders(
                this._options?.headers,
                mergeOnlyDefinedHeaders({
                    Authorization: await this._getAuthorizationHeader(),
                    "x-pd-environment": requestOptions?.projectEnvironment,
                }),
                requestOptions?.headers,
            ),
            queryParameters: requestOptions?.queryParams,
            timeoutMs: requestOptions?.timeoutInSeconds != null ? requestOptions.timeoutInSeconds * 1000 : 60000,
            maxRetries: requestOptions?.maxRetries,
            abortSignal: requestOptions?.abortSignal,
        });
        if (_response.ok) {
            return { data: _response.body as Pipedream.ListAppCategoriesResponse, rawResponse: _response.rawResponse };
        }

        if (_response.error.reason === "status-code") {
            throw new errors.PipedreamError({
                statusCode: _response.error.statusCode,
                body: _response.error.body,
                rawResponse: _response.rawResponse,
            });
        }

        switch (_response.error.reason) {
            case "non-json":
                throw new errors.PipedreamError({
                    statusCode: _response.error.statusCode,
                    body: _response.error.rawBody,
                    rawResponse: _response.rawResponse,
                });
            case "timeout":
                throw new errors.PipedreamTimeoutError("Timeout exceeded when calling GET /v1/connect/app_categories.");
            case "unknown":
                throw new errors.PipedreamError({
                    message: _response.error.errorMessage,
                    rawResponse: _response.rawResponse,
                });
        }
    }

    /**
     * @param {string} id - The ID of the app category to retrieve
     * @param {AppCategories.RequestOptions} requestOptions - Request-specific configuration.
     *
     * @example
     *     await client.appCategories.retrieve("id")
     */
    public retrieve(
        id: string,
        requestOptions?: AppCategories.RequestOptions,
    ): core.HttpResponsePromise<Pipedream.GetAppCategoryResponse> {
        return core.HttpResponsePromise.fromPromise(this.__retrieve(id, requestOptions));
    }

    private async __retrieve(
        id: string,
        requestOptions?: AppCategories.RequestOptions,
    ): Promise<core.WithRawResponse<Pipedream.GetAppCategoryResponse>> {
        const _response = await core.fetcher({
            url: core.url.join(
                (await core.Supplier.get(this._options.baseUrl)) ??
                    (await core.Supplier.get(this._options.environment)) ??
                    environments.PipedreamEnvironment.Prod,
                `v1/connect/app_categories/${encodeURIComponent(id)}`,
            ),
            method: "GET",
            headers: mergeHeaders(
                this._options?.headers,
                mergeOnlyDefinedHeaders({
                    Authorization: await this._getAuthorizationHeader(),
                    "x-pd-environment": requestOptions?.projectEnvironment,
                }),
                requestOptions?.headers,
            ),
            queryParameters: requestOptions?.queryParams,
            timeoutMs: requestOptions?.timeoutInSeconds != null ? requestOptions.timeoutInSeconds * 1000 : 60000,
            maxRetries: requestOptions?.maxRetries,
            abortSignal: requestOptions?.abortSignal,
        });
        if (_response.ok) {
            return { data: _response.body as Pipedream.GetAppCategoryResponse, rawResponse: _response.rawResponse };
        }

        if (_response.error.reason === "status-code") {
            throw new errors.PipedreamError({
                statusCode: _response.error.statusCode,
                body: _response.error.body,
                rawResponse: _response.rawResponse,
            });
        }

        switch (_response.error.reason) {
            case "non-json":
                throw new errors.PipedreamError({
                    statusCode: _response.error.statusCode,
                    body: _response.error.rawBody,
                    rawResponse: _response.rawResponse,
                });
            case "timeout":
                throw new errors.PipedreamTimeoutError(
                    "Timeout exceeded when calling GET /v1/connect/app_categories/{id}.",
                );
            case "unknown":
                throw new errors.PipedreamError({
                    message: _response.error.errorMessage,
                    rawResponse: _response.rawResponse,
                });
        }
    }

    protected async _getAuthorizationHeader(): Promise<string | undefined> {
        const bearer = await core.Supplier.get(this._options.token);
        if (bearer != null) {
            return `Bearer ${bearer}`;
        }

        return undefined;
    }
}
