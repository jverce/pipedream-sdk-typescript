/**
 * This file was auto-generated by Fern from our API Definition.
 */

/**
 * Options for creating a Connect token
 */
export interface ConnectTokenCreateOpts {
    /** Your end user ID, for whom you're creating the token */
    external_user_id: string;
    /** List of allowed origins for CORS */
    allowed_origins?: string[];
    /** URI to redirect to on error */
    error_redirect_uri?: string;
    /** URI to redirect to on success */
    success_redirect_uri?: string;
    /** Webhook URI for notifications */
    webhook_uri?: string;
}
