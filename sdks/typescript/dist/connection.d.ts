import type { JsonRpcRequest, JsonRpcResponse } from './types.js';
export interface Connection {
    send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
    close(): Promise<void>;
}
export declare class StdioConnection implements Connection {
    private process;
    private buffer;
    private nextId;
    private pending;
    private command;
    constructor(command?: string);
    private ensureProcess;
    private drainBuffer;
    send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
    close(): Promise<void>;
}
export declare class HttpConnection implements Connection {
    private url;
    private token;
    private tokenLoaded;
    constructor(url?: string);
    private loadToken;
    send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
    close(): Promise<void>;
}
export declare class AutoConnection implements Connection {
    private inner;
    private httpUrl;
    private command;
    constructor(httpUrl?: string, command?: string);
    private resolve;
    send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
    close(): Promise<void>;
}
export declare class FailOpenConnection implements Connection {
    private inner;
    constructor(inner: Connection);
    send(request: JsonRpcRequest): Promise<JsonRpcResponse>;
    private failOpenResponse;
    close(): Promise<void>;
}
//# sourceMappingURL=connection.d.ts.map