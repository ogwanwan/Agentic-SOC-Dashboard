import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readExecutionProfile } from "./execution-profile.mjs";

const [command, ...args] = process.argv.slice(2);
if (!["dev", "build", "start"].includes(command)) throw new Error("Expected dev, build, or start.");
const managedLinux = readExecutionProfile() === "managed-linux";

const { syncResults } = await import("./sync-results.mjs");
await syncResults();

let dataWatcher;
if (command === "dev" || command === "start") {
  dataWatcher = spawn(process.execPath, [
    fileURLToPath(new URL("./watch-results.mjs", import.meta.url)),
  ], { stdio: "inherit", env: process.env });
  dataWatcher.on("error", (error) => {
    console.warn(`[run-framework] 결과 폴더 감시기를 시작하지 못했습니다: ${error.message}`);
  });
  process.once("exit", () => dataWatcher?.kill());
}

if (managedLinux && command === "build") {
  const result = spawnSync("bash", [
    fileURLToPath(new URL("./build-verified.sh", import.meta.url)), ...args,
  ], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}

// 미리보기 소유 프로세스가 PID와 신호를 유지하도록 현재 프로세스에서 불러옵니다.
if (command === "start") {
  await import("./sites-env.mjs");
  const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
  const server = spawn(process.execPath, [wrangler, "dev", "--config", "dist/server/wrangler.json",
    "--local", "--persist-to", ".wrangler/state", "--ip", "127.0.0.1", "--inspector-port", "0", ...args], {
    stdio: "inherit",
    env: process.env,
  });
  const status = await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.once("exit", (code) => resolve(code ?? 1));
  });
  dataWatcher?.kill();
  process.exit(status);
}

const cli = new URL(managedLinux
  ? "../node_modules/vite/bin/vite.js"
  : "../node_modules/vinext/dist/cli.js", import.meta.url);
process.argv = [process.execPath, fileURLToPath(cli), command,
  ...(!managedLinux && command === "dev" ? ["--port", "5173"] : []), ...args];
try {
  await import(cli.href);
} finally {
  dataWatcher?.kill();
}
