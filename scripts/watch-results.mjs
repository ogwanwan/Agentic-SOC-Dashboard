import { watch } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { inputDir, syncResults } from "./sync-results.mjs";

const 검사_주기 = 1_000;
const 변경_대기 = 180;
const 재시도_대기 = 650;

let 디렉터리감시자;
let 동기화중 = false;
let 재실행필요 = false;
let 예약타이머;
let 재시도타이머;
let 주기타이머;
let 현재재시도대기 = 재시도_대기;
let 마지막지문 = "";

async function 디렉터리지문() {
  try {
    const 파일들 = (await readdir(inputDir)).filter((이름) => 이름.endsWith(".json")).sort();
    const 상태 = await Promise.all(파일들.map(async (이름) => {
      const 정보 = await stat(path.join(inputDir, 이름));
      return `${이름}:${정보.size}:${정보.mtimeMs}`;
    }));
    return 상태.join("|");
  } catch {
    return "__missing__";
  }
}

async function 동기화(이유) {
  if (동기화중) {
    재실행필요 = true;
    return;
  }

  동기화중 = true;
  try {
    const 결과 = await syncResults({ writeModuleSnapshot: false });
    if (결과) {
      마지막지문 = await 디렉터리지문();
      현재재시도대기 = 재시도_대기;
      clearTimeout(재시도타이머);
      console.log(`[watch-results] ${이유} 반영 완료`);
    }
  } catch (error) {
    const 대기 = 현재재시도대기;
    console.warn(`[watch-results] ${error.message} ${대기}ms 뒤 다시 확인합니다.`);
    clearTimeout(재시도타이머);
    재시도타이머 = setTimeout(() => void 동기화("부분 기록 재시도"), 대기);
    현재재시도대기 = Math.min(현재재시도대기 * 2, 10_000);
  } finally {
    동기화중 = false;
    if (재실행필요) {
      재실행필요 = false;
      변경예약("대기 중 변경");
    }
  }
}

function 변경예약(이유) {
  if (이유 !== "부분 기록 재시도") {
    clearTimeout(재시도타이머);
    현재재시도대기 = 재시도_대기;
  }
  clearTimeout(예약타이머);
  예약타이머 = setTimeout(() => void 동기화(이유), 변경_대기);
}

function 감시연결() {
  try {
    디렉터리감시자?.close();
    디렉터리감시자 = watch(inputDir, { persistent: true }, (_이벤트, 파일명) => {
      if (파일명 && !String(파일명).endsWith(".json")) return;
      변경예약("파일 변경");
    });
    디렉터리감시자.on("error", () => {
      디렉터리감시자?.close();
      디렉터리감시자 = undefined;
    });
    console.log(`[watch-results] 실시간 감시 시작: ${inputDir}`);
  } catch {
    // 아직 폴더가 없거나 네트워크 드라이브가 fs.watch를 지원하지 않아도
    // 아래의 주기적 지문 비교가 생성을 감지합니다.
  }
}

async function 시작() {
  await 동기화("시작");
  마지막지문 = await 디렉터리지문();
  감시연결();

  주기타이머 = setInterval(async () => {
    const 현재지문 = await 디렉터리지문();
    if (현재지문 !== 마지막지문) {
      const 폴더가새로생김 = 마지막지문 === "__missing__" && 현재지문 !== "__missing__";
      마지막지문 = 현재지문;
      if (폴더가새로생김 || !디렉터리감시자) 감시연결();
      변경예약("주기 확인");
    }
  }, 검사_주기);
}

function 종료() {
  clearTimeout(예약타이머);
  clearTimeout(재시도타이머);
  clearInterval(주기타이머);
  디렉터리감시자?.close();
  process.exit(0);
}

process.once("SIGINT", 종료);
process.once("SIGTERM", 종료);

await 시작();
