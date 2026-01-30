import crypto from "node:crypto";

import type { MoltbotConfig } from "../config/config.js";
import { writeConfigFile } from "../config/config.js";

/**
 * Ensures a gateway auth token exists: if neither config nor env has one,
 * generates a strong random token, writes it to config, and mutates `cfg` in place.
 * Called at gateway startup so the gateway can start without manual token setup.
 */
export async function ensureAndPersistGatewayToken(
  cfg: MoltbotConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const existing =
    (typeof cfg.gateway?.auth?.token === "string" && cfg.gateway.auth.token.trim().length > 0) ||
    (typeof env.CLAWDBOT_GATEWAY_TOKEN === "string" &&
      env.CLAWDBOT_GATEWAY_TOKEN.trim().length > 0);
  if (existing) return;

  const token = crypto.randomBytes(32).toString("hex");
  const gateway = cfg.gateway ?? {};
  const auth = gateway.auth ?? {};
  cfg.gateway = {
    ...gateway,
    auth: {
      ...auth,
      mode: "token",
      token,
    },
  };
  await writeConfigFile(cfg);
}
