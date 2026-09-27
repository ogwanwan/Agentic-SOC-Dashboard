#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${SITES_ENV_READY:-}" != "1" ]]; then
  exec "${script_dir}/sites-env.sh" -- "$0" "$@"
fi

require_shared=0
prepare_only=0
for argument in "$@"; do
  case "${argument}" in
    --require-shared) require_shared=1 ;;
    --prepare-store) prepare_only=1 ;;
    *) echo "Unknown pnpm installation option: ${argument}" >&2; exit 64 ;;
  esac
done

for tool in flock timeout node; do
  command -v "${tool}" >/dev/null || { echo "pnpm setup requires Linux flock, GNU timeout, and Node.js." >&2; exit 69; }
done
cache_seed=decision_unavailable
store_scope=unknown
store_state=unavailable
report_store() {
  node "${script_dir}/pnpm-install.mjs" --report-store "${cache_seed}" "${store_scope}" "${store_state}" "${prepare_only}"
}
# 준비 단계의 실패도 보고하며, 선택형 보고 결과는 성공 여부를 결정하지 않습니다.
trap 'report_store || true' EXIT

if [[ -n "${SITES_PNPM_BIN:-}" && -f "${SITES_PNPM_BIN}" && -r "${SITES_PNPM_BIN}" ]]; then
  pnpm_command=(node "${SITES_PNPM_BIN}")
elif [[ "${require_shared}" == 1 ]]; then
  echo "[sites] the image-pinned pnpm is unavailable" >&2
  exit 69
elif command -v corepack >/dev/null; then
  # PATH에 다른 pnpm 버전이 있어도 Corepack은 프로젝트에 고정된 버전을 따릅니다.
  # Corepack이 없을 때만 기본 pnpm을 사용하고 이후 버전을 검증합니다.
  pnpm_command=(corepack pnpm)
elif command -v pnpm >/dev/null; then
  pnpm_command=(pnpm)
else
  echo "This pnpm project requires pnpm 11.25.0 or Corepack." >&2
  exit 69
fi

runtime_root="${SITES_RUNTIME_ROOT:-${SITES_PROJECT_ROOT}/.sites-runtime}"
private_store="${runtime_root}/pnpm-store"
if [[ "${HOME}" != "${runtime_root}/home" || -L "${private_store}" ]]; then
  echo "Dependency setup requires a project-owned writable home and pnpm store." >&2
  exit 78
fi
# 하나의 Node 프로세스가 두 임대 잠금의 일반 파일 설명자를 소유합니다.
# 이 셸의 종료를 포함해 입력이 닫히면 프로젝트 잠금이 해제됩니다.
coproc SITES_INSTALL_LOCKS {
  node "${script_dir}/pnpm-install.mjs" --hold-install-locks \
    "${runtime_root}/install.lock" "${SITES_PNPM_SHARED_STORE:-}.seed.lock" \
    "${SITES_PNPM_STORE_LOCK_TIMEOUT:-30}"
}
install_lock_pid="${SITES_INSTALL_LOCKS_PID}"
install_lock_output="${SITES_INSTALL_LOCKS[0]}"
install_lock_input="${SITES_INSTALL_LOCKS[1]}"
lock_status=unavailable
read -r lock_status <&"${install_lock_output}" || true
if [[ "${lock_status}" != locked ]]; then
  exec {install_lock_input}>&-
  exec {install_lock_output}<&-
  wait "${install_lock_pid}" || true
  if [[ "${lock_status}" == busy ]]; then
    echo "Another dependency install is already running for ${SITES_PROJECT_ROOT}." >&2
    exit 75
  fi
  echo "Dependency setup requires a regular, writable project install lock." >&2
  exit 78
fi
export XDG_CACHE_HOME="${runtime_root}/xdg-cache" XDG_DATA_HOME="${runtime_root}/xdg-data"
mkdir -p "${XDG_CACHE_HOME}" "${XDG_DATA_HOME}" || exit 70
pnpm_version="$(timeout --signal=TERM --kill-after="${SITES_INSTALL_KILL_AFTER:-15s}" \
  "${SITES_PNPM_BOOTSTRAP_TIMEOUT:-30s}" "${pnpm_command[@]}" --version)"
if [[ "${pnpm_version}" != "11.25.0" ]]; then
  echo "This project requires pnpm 11.25.0 and its v11 store format." >&2
  exit 69
fi

can_write_directory() {
  local probe
  # 커널 샌드박스가 쓰기를 거부해도 access() 또는 test -w는 성공할 수 있습니다.
  probe="$(mktemp "${1}/.sites-store-probe.XXXXXX" 2>/dev/null)" || return 1
  rm -f -- "${probe}" 2>/dev/null
}

release_shared_lock() {
  if [[ "${shared_lock_held:-}" == 1 ]]; then
    printf '%s\n' release-shared >&"${install_lock_input}"
    local status
    read -r status <&"${install_lock_output}" && [[ "${status}" == released ]] || return 70
    shared_lock_held=0
  fi
}

acquire_shared_lock() {
  # Node 잠금 소유자는 작업공간이 관리하는 항목을 링크 비추적·비차단 플래그로 열고,
  # 일반 파일임을 검증한 뒤 제한 시간 flock을 적용합니다.
  printf '%s\n' shared >&"${install_lock_input}"
  local status
  if read -r status <&"${install_lock_output}" && [[ "${status}" == locked ]]; then
    shared_lock_held=1
    return 0
  fi
  return 1
}

writable_store="${private_store}"
shared_store="${SITES_PNPM_SHARED_STORE:-}"
if [[ "${shared_store}" == "/workspace/.sites-runtime/pnpm-store" &&
      ! -L "${shared_store}" && ! -L "${shared_store%/*}" &&
      -d "${shared_store%/*/*}" ]]; then
  # 일반 실행 환경은 이미 소유자의 작업공간에 쓸 수 있습니다. 더 제한적인 프로필은
  # 권한을 넓히지 않고 실제 생성 검사를 통과해야 합니다.
  if mkdir -p "${shared_store%/*}" 2>/dev/null &&
      can_write_directory "${shared_store%/*}" &&
      acquire_shared_lock; then
    if [[ ! -L "${shared_store}" && ! -L "${shared_store%/*}" &&
          ( ! -e "${shared_store}" || ( -d "${shared_store}" && ! -L "${shared_store}" && -w "${shared_store}" ) ) ]] &&
        { [[ ! -d "${shared_store}" ]] || can_write_directory "${shared_store}"; }; then
      writable_store="${shared_store}"
      store_scope=workspace
    else
      release_shared_lock
    fi
  else
    release_shared_lock
  fi
fi
if [[ "${store_scope}" != workspace ]]; then
  if [[ "${require_shared}" == 1 ]]; then
    echo "[sites] the workspace pnpm store is unavailable" >&2
    exit 69
  fi
  store_scope=project
fi

seed="${SITES_PNPM_CACHE_SEED:-}"
cache_seed=seed_unavailable
if [[ -d "${writable_store}" ]]; then
  # 기존의 변경 가능한 저장소에는 더 새로운 이미지 시드를 병합하지 않습니다.
  store_state=reused
  cache_seed=not_applicable
  if [[ -f "${writable_store}/.sites-pnpm-seed-applied.json" ]]; then cache_seed=seed_used; fi
else
  seed_compatible=0
  if [[ -n "${seed}" && -d "${seed}/v11" ]] && node --input-type=module - "${seed}/.sites-pnpm-seed.json" <<'NODE'
import { readFileSync, statSync } from "node:fs";
try {
  const filename = process.argv[2];
  if (statSync(filename).size > 4096) process.exit(1);
  const seed = JSON.parse(readFileSync(filename, "utf8"));
  process.exit(seed.version === 1 && seed.pnpm_version === "11.25.0" &&
    seed.store_version === "v11" && /^[a-f0-9]{64}$/.test(seed.lockfile_sha256) ? 0 : 1);
} catch { process.exit(1); }
NODE
  then seed_compatible=1; fi
  if [[ "${seed_compatible}" == 1 ]]; then
    if [[ "${prepare_only}" == 1 ]]; then
      echo "[sites] copying the image seed into the writable ${store_scope} pnpm store" >&2
    else
      echo "[sites] copying the image seed into the writable ${store_scope} pnpm store"
    fi
    seed_stage="$(mktemp -d "${writable_store}.seed.XXXXXX")" || exit 70
    trap 'if [[ -n "${seed_stage:-}" ]]; then rm -rf -- "${seed_stage}"; fi; report_store || true' EXIT
    timeout --signal=TERM --kill-after="${SITES_INSTALL_KILL_AFTER:-15s}" \
      "${SITES_PNPM_STORE_PREPARE_TIMEOUT:-60s}" bash -c \
      'cp -a --no-preserve=ownership "$1/." "$2/" && chmod -R u+rwX "$2"' _ "${seed}" "${seed_stage}" || exit 70
    cp "${seed}/.sites-pnpm-seed.json" "${seed_stage}/.sites-pnpm-seed-applied.json" || exit 70
    # 일반 pnpm 명령은 시드 잠금 없이 저장소를 초기화할 수 있습니다.
    # 그 명령이 만든 빈 디렉터리라도 교체하지 않고 게시합니다.
    mv -T --update=none "${seed_stage}" "${writable_store}" || exit 70
    if [[ -d "${seed_stage}" ]]; then
      if [[ -L "${writable_store}" || ! -d "${writable_store}" ]]; then exit 78; fi
      rm -rf -- "${seed_stage}" || exit 70
      store_state=reused
      cache_seed=not_applicable
      if [[ -f "${writable_store}/.sites-pnpm-seed-applied.json" ]]; then cache_seed=seed_used; fi
    else
      store_state=seeded
      cache_seed=seed_used
    fi
    seed_stage=""
  else
    mkdir -p "${writable_store}" || exit 70
    store_state=created
  fi
fi
if ! can_write_directory "${writable_store}"; then store_state=unavailable; exit 70; fi
release_shared_lock
report_store
trap - EXIT
if [[ "${prepare_only}" == 1 ]]; then exit 0; fi

# 구성은 장비의 절대 경로를 포함하지 않은 채 소스와 함께 이동합니다.
# 이후 제한된 세션은 고정 복구 전에 전용 저장소를 선택합니다.
configured_store=.sites-runtime/pnpm-store
if [[ "${store_scope}" == workspace ]]; then
  configured_store='${SITES_PNPM_SHARED_STORE:-.sites-runtime/pnpm-store}'
elif [[ "${runtime_root}" != "${SITES_PROJECT_ROOT}/.sites-runtime" ]]; then
  configured_store='${SITES_RUNTIME_ROOT:-.sites-runtime}/pnpm-store'
fi
"${pnpm_command[@]}" config set package-import-method clone-or-copy --location project
"${pnpm_command[@]}" config set store-dir "${configured_store}" --location project
"${pnpm_command[@]}" config set cache-dir "${configured_store}/policy-cache" --location project

# CI=true를 사용하면 프롬프트, --force, 잠금 파일 변경, npm 변환 없이도
# 저장소 위치가 바뀐 모듈을 pnpm 설치 과정에서 다시 구성할 수 있습니다.
CI=true timeout --signal=TERM --kill-after="${SITES_INSTALL_KILL_AFTER:-15s}" \
  "${SITES_INSTALL_TIMEOUT:-8m}" node "${script_dir}/pnpm-install.mjs" \
  "${cache_seed}" "${store_scope}" "${store_state}" "${writable_store}" "${pnpm_command[@]}"
