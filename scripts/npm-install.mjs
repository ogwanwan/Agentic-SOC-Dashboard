import { spawn, spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  ftruncateSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { constants as osConstants } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const MAX_PACKAGES = 100_000;

// npm은 tarball 캐시 읽기와 레지스트리 메타데이터 요청을 구분해 보고합니다.
// 이미지 시드나 네트워크 바이트가 아닌 설치된 고유 tarball URL을 계산합니다.
// 오래되거나 일부만 남은 로그가 미확인 상태를 유지하도록 설치 잠금 전체를 요구합니다.
export class NpmCacheProgress {
  entries = new Map();
  invalid = false;

  constructor(registry) {
    try {
      const value = new URL(registry);
      if (["http:", "https:"].includes(value.protocol)) this.registry = value;
    } catch {}
  }

  accept(line) {
    const match = line.match(
      /^npm http (?:cache |fetch GET 200 )(\S+) \d+ms(?: attempt #\d+)? \(cache (hit|miss|revalidated|updated|skip)\)$/,
    );
    if (!match) return;
    const [, spec, status] = match;
    // Pacote의 직접 콘텐츠 캐시 로그는 name@URL을, HTTP 캐시 로그는 URL을 사용합니다.
    const url = spec.replace(/^(?:@[^/]+\/)?[^@/]+@(?=https?:\/\/)/, "");
    if (
      url.length > 4096 ||
      (this.entries.size >= MAX_PACKAGES && !this.entries.has(url))
    ) {
      this.invalid = true;
      return;
    }
    const downloaded = !["hit", "revalidated"].includes(status);
    this.entries.set(url, downloaded || this.entries.get(url) === true);
  }

  counts(lock) {
    if (this.invalid || lock?.lockfileVersion !== 3 || !lock.packages)
      return {};
    const urls = new Set(
      Object.values(lock.packages)
        .map((pkg) => pkg?.resolved)
        .filter((url) => typeof url === "string" && /^https?:\/\//.test(url)),
    );
    if (!urls.size || urls.size > MAX_PACKAGES) return {};
    const observed = new Set();
    let downloaded = 0;
    for (const url of urls) {
      let candidates = [url];
      if (this.registry) {
        const locked = new URL(url);
        if (locked.hostname === "registry.npmjs.org") {
          // 임의 접미사가 아닌 npm의 실제 설정을 사용해 npm/pacote의 호스트 재작성과
          // registry-fetch의 경로 접두사를 일치시킵니다.
          candidates = [
            ...new Set([
              url,
              new URL(locked.pathname, this.registry).href,
              this.registry.href.replace(/\/$/, "") +
                locked.pathname +
                locked.search,
            ]),
          ];
        }
      }
      const matches = candidates.filter((candidate) =>
        this.entries.has(candidate),
      );
      if (
        !matches.length ||
        matches.some((candidate) => observed.has(candidate))
      )
        return {};
      for (const candidate of matches) observed.add(candidate);
      // 손상된 직접 캐시 적중 뒤 미러에서 가져온 경우는 다운로드로 계산합니다.
      if (matches.some((candidate) => this.entries.get(candidate)))
        downloaded++;
    }
    return {
      packages_reused: urls.size - downloaded,
      packages_downloaded: downloaded,
    };
  }
}

export async function runNpmInstall(command, cacheSeed = "not_applicable") {
  let descriptor;
  try {
    if (process.env.SITES_INSTALL_REPORT_PATH && constants.O_NOFOLLOW) {
      descriptor = openSync(
        process.env.SITES_INSTALL_REPORT_PATH,
        constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      if (!fstatSync(descriptor).isFile()) {
        closeSync(descriptor);
        descriptor = undefined;
      }
    }
  } catch {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {}
    }
    descriptor = undefined;
  }
  const env = { ...process.env };
  delete env.SITES_INSTALL_REPORT_PATH;
  const [executable, ...args] = command;
  let registry;
  const installIndex = args.indexOf("ci");
  if (descriptor !== undefined && installIndex >= 0) {
    try {
      const configured = spawnSync(
        executable,
        [...args.slice(0, installIndex), "config", "get", "registry"],
        {
          env,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 3000,
          maxBuffer: 4096,
        },
      );
      if (configured.status === 0) registry = configured.stdout.trim();
    } catch {}
  }
  const progress = new NpmCacheProgress(registry);
  let receivedSignal;
  const handlers = ["SIGINT", "SIGHUP", "SIGTERM"].map((signal) => {
    const handler = () => {
      receivedSignal ??= signal;
    };
    process.on(signal, handler);
    return [signal, handler];
  });
  let result = { code: 1, signal: null };
  try {
    const child = spawn(executable, [...args, "--loglevel=http"], {
      env,
      stdio: ["inherit", "inherit", "pipe"],
    });
    const lines = createInterface({ input: child.stderr, crlfDelay: Infinity });
    lines.on("line", (line) => {
      progress.accept(line);
      // 원격 측정만을 위해 일반 도우미 출력에 패키지 URL을 추가하지 않습니다.
      if (!line.startsWith("npm http ")) process.stderr.write(`${line}\n`);
    });
    let startError;
    child.once("error", (error) => {
      startError = error;
    });
    result = await new Promise((resolve) =>
      child.once("close", (code, signal) => {
        resolve({
          code: startError ? (startError.code === "ENOENT" ? 127 : 1) : code,
          signal,
        });
      }),
    );
    lines.close();
    if (startError) process.stderr.write("Unable to start npm.\n");
  } finally {
    for (const [signal, handler] of handlers)
      process.removeListener(signal, handler);
    result.signal ??= receivedSignal;
    try {
      let counts = {};
      if (result.code === 0 && !result.signal) {
        try {
          counts = progress.counts(
            JSON.parse(readFileSync("node_modules/.package-lock.json", "utf8")),
          );
        } catch {}
      }
      if (descriptor !== undefined) {
        ftruncateSync(descriptor, 0);
        writeFileSync(
          descriptor,
          `${JSON.stringify({
            version: 1,
            cache_seed:
              result.code === 0 && !result.signal
                ? cacheSeed
                : "decision_unavailable",
            ...counts,
          })}\n`,
        );
      }
    } catch {
      // 원격 측정은 설치 동작을 변경해서는 안 됩니다.
    } finally {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {}
      }
    }
  }
  return result;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const [cacheSeed, ...command] = process.argv.slice(2);
  const result = await runNpmInstall(command, cacheSeed);
  process.exitCode = result.signal
    ? 128 + (osConstants.signals[result.signal] ?? 0)
    : result.code ?? 1;
  if (result.signal) {
    try {
      process.kill(process.pid, result.signal);
    } catch {}
  }
}
