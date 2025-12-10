import type { CreateTokenResponse } from "../api/index.js";
import * as core from "../core/index.js";
import * as errors from "../errors/index.js";

export class ConnectTokenAuthProvider implements core.AuthProvider {
    private readonly _tokenCallback: ConnectTokenAuthProvider.TokenCallback;
    private readonly _externalUserId: string;
    private _token: string | undefined;
    private _tokenExpiresAt: Date | undefined;
    private _refreshPromise: Promise<string> | undefined;

    constructor(options: ConnectTokenAuthProvider.Options) {
        if (!options.externalUserId) {
            throw new errors.PipedreamError({
                message: "externalUserId is required",
            });
        }
        if (typeof options.tokenCallback !== "function") {
            throw new errors.PipedreamError({
                message: "tokenCallback is required and must be a function",
            });
        }
        this._externalUserId = options.externalUserId;
        this._tokenCallback = options.tokenCallback;
    }

    public static canCreate(options: unknown): options is ConnectTokenAuthProvider.Options {
        return (
            options != null &&
            typeof options === "object" &&
            "tokenCallback" in options &&
            typeof options.tokenCallback === "function" &&
            "externalUserId" in options &&
            typeof options.externalUserId === "string" &&
            options.externalUserId.length > 0
        );
    }

    public async getAuthRequest(_arg?: { endpointMetadata?: core.EndpointMetadata }): Promise<core.AuthRequest> {
        const token = await this.getToken();

        return {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        };
    }

    private async getToken(): Promise<string> {
        if (this._token && this._tokenExpiresAt && this._tokenExpiresAt > new Date()) {
            return this._token;
        }
        // If a refresh is already in progress, return the existing promise
        if (this._refreshPromise != null) {
            return this._refreshPromise;
        }
        return this.refresh();
    }

    private async refresh(): Promise<string> {
        this._refreshPromise = (async () => {
            try {
                const { token, expiresAt } = await this._tokenCallback({
                    externalUserId: this._externalUserId,
                });
                this._token = token;
                this._tokenExpiresAt = expiresAt;
                return token;
            } finally {
                this._refreshPromise = undefined;
            }
        })();
        return this._refreshPromise;
    }

    /**
     * Invalidates the cached token, forcing a refresh on the next getAuthRequest call.
     */
    public invalidate(): void {
        this._token = undefined;
    }
}

export namespace ConnectTokenAuthProvider {
    export type TokenCallback = (opts: { externalUserId: string }) => Promise<CreateTokenResponse>;

    export interface Options {
        tokenCallback: TokenCallback;
        externalUserId: string;
    }

    export function createInstance(options: Options): core.AuthProvider {
        if (ConnectTokenAuthProvider.canCreate(options)) {
            return new ConnectTokenAuthProvider(options);
        }
        throw new errors.PipedreamError({
            message:
                "Insufficient options to create ConnectTokenAuthProvider. Please provide both tokenCallback and externalUserId.",
        });
    }
}
