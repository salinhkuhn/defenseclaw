declare module "@openclaw/plugin-sdk" {
  interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
  }

  interface BeforeToolCallResult {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
  }

  interface ToolContext {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolName: string;
    toolCallId?: string;
  }

  interface CommandArg {
    name: string;
    description?: string;
    required?: boolean;
  }

  interface CommandRegistration {
    name: string;
    description: string;
    args?: CommandArg[];
    handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> | { text: string };
  }

  interface ServiceRegistration {
    id: string;
    start: () => Promise<{ stop: () => void }>;
  }

  export interface PluginApi {
    on(event: "before_tool_call", handler: (event: BeforeToolCallEvent, ctx: ToolContext) => BeforeToolCallResult | void | Promise<BeforeToolCallResult | void>): void;
    on(event: string, handler: (...args: any[]) => void | Promise<void>): void;
    registerCommand(def: CommandRegistration): void;
    registerService(def: ServiceRegistration): void;
  }

  type PluginEntry = (api: PluginApi) => void;

  export function definePluginEntry(fn: PluginEntry): PluginEntry;
}
