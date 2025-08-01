/**
 * This file was auto-generated by Fern from our API Definition.
 */

import * as core from "../../../../../core/index.js";

/**
 * @example
 *     {
 *         url: "https://api.example.com/endpoint",
 *         external_user_id: "external_user_id",
 *         account_id: "account_id",
 *         params: { page: "1", limit: "10" },
 *         headers: { "X-Custom-Header": "value" }
 *     }
 */
export interface ProxyGetRequest {
    /**
     * Target URL to proxy request to
     */
    url: string;
    /**
     * The external user ID for the proxy request
     */
    external_user_id: string;
    /**
     * The account ID to use for authentication
     */
    account_id: string;
    /**
     * Query parameters to forward
     */
    params?: Record<string, string | string[] | object | object[] | null>;
    /**
     * Additional headers to include (will be prefixed with 'x-pd-proxy-')
     */
    headers?: Record<string, string | core.Supplier<string | undefined> | undefined>;
}
