"""Python 가상환경에서 SSOC 대시보드를 설치하고 실행하는 진입점입니다."""

from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path


프로젝트_경로 = Path(__file__).resolve().parent
런타임_경로 = 프로젝트_경로 / ".ssoc-runtime"
노드_버전 = "22.23.3"
최소_노드_버전 = (22, 13, 0)
PNPM_버전 = "11.19.0"


def 출력_인코딩_설정() -> None:
    """Windows 터미널에서도 한글 안내가 깨지지 않도록 UTF-8을 사용합니다."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


@dataclass(frozen=True)
class 노드_환경:
    실행파일: Path
    npm_명령: tuple[str, ...]


def 명령_실행(명령: list[str], *, 검사: bool = True) -> subprocess.CompletedProcess[str]:
    """프로젝트 루트에서 하위 명령을 실행합니다."""

    return subprocess.run(
        명령,
        cwd=프로젝트_경로,
        check=검사,
        text=True,
    )


def 노드_버전_읽기(실행파일: Path) -> tuple[int, int, int] | None:
    try:
        결과 = subprocess.run(
            [str(실행파일), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        숫자 = 결과.stdout.strip().lstrip("v").split(".")
        return tuple(int(값) for 값 in 숫자[:3])  # type: ignore[return-value]
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def 시스템_노드_찾기() -> 노드_환경 | None:
    노드 = shutil.which("node")
    npm = shutil.which("npm")
    if not 노드 or not npm:
        return None

    실행파일 = Path(노드)
    버전 = 노드_버전_읽기(실행파일)
    if 버전 is None or 버전 < 최소_노드_버전:
        return None
    return 노드_환경(실행파일, (npm,))


def 노드_배포파일_정보() -> tuple[str, str]:
    운영체제 = platform.system()
    구조 = platform.machine().lower()

    if 구조 in {"x86_64", "amd64"}:
        구조 = "x64"
    elif 구조 in {"aarch64", "arm64"}:
        구조 = "arm64"
    else:
        raise RuntimeError(f"지원하지 않는 CPU 구조입니다: {platform.machine()}")

    if 운영체제 == "Windows":
        return f"node-v{노드_버전}-win-{구조}.zip", "zip"
    if 운영체제 == "Linux":
        return f"node-v{노드_버전}-linux-{구조}.tar.xz", "tar"
    if 운영체제 == "Darwin":
        return f"node-v{노드_버전}-darwin-{구조}.tar.gz", "tar"
    raise RuntimeError(f"지원하지 않는 운영체제입니다: {운영체제}")


def 주소_다운로드(주소: str, 대상: Path) -> None:
    요청 = urllib.request.Request(주소, headers={"User-Agent": "SSOC-Launcher/1.0"})
    with urllib.request.urlopen(요청, timeout=60) as 응답, 대상.open("wb") as 파일:
        shutil.copyfileobj(응답, 파일)


def 체크섬_검증(배포파일: Path, 배포파일명: str, 체크섬파일: Path) -> None:
    기대값 = None
    for 줄 in 체크섬파일.read_text(encoding="utf-8").splitlines():
        값, _, 이름 = 줄.partition("  ")
        if 이름 == 배포파일명:
            기대값 = 값
            break
    if 기대값 is None:
        raise RuntimeError("Node.js 배포 파일의 공식 체크섬을 찾지 못했습니다.")

    해시 = hashlib.sha256()
    with 배포파일.open("rb") as 파일:
        for 조각 in iter(lambda: 파일.read(1024 * 1024), b""):
            해시.update(조각)
    if 해시.hexdigest() != 기대값:
        raise RuntimeError("Node.js 배포 파일의 체크섬이 일치하지 않습니다.")


def tar_안전_해제(압축파일: tarfile.TarFile, 대상: Path) -> None:
    """Python 3.10 이상에서 경로 이탈을 막으며 tar 파일을 해제합니다."""

    기준경로 = 대상.resolve()
    for 항목 in 압축파일.getmembers():
        항목경로 = (대상 / 항목.name).resolve()
        if 항목경로 != 기준경로 and 기준경로 not in 항목경로.parents:
            raise RuntimeError("Node.js 압축 파일에 안전하지 않은 경로가 있습니다.")
        if 항목.isdev():
            raise RuntimeError("Node.js 압축 파일에 허용하지 않는 장치 파일이 있습니다.")
        if 항목.issym():
            연결경로 = (항목경로.parent / 항목.linkname).resolve()
            if 연결경로 != 기준경로 and 기준경로 not in 연결경로.parents:
                raise RuntimeError("Node.js 압축 파일에 안전하지 않은 심볼릭 링크가 있습니다.")
        if 항목.islnk():
            연결경로 = (대상 / 항목.linkname).resolve()
            if 연결경로 != 기준경로 and 기준경로 not in 연결경로.parents:
                raise RuntimeError("Node.js 압축 파일에 안전하지 않은 하드 링크가 있습니다.")
    압축파일.extractall(대상)


def 로컬_노드_설치() -> 노드_환경:
    설치경로 = 런타임_경로 / f"node-v{노드_버전}"
    윈도우 = platform.system() == "Windows"
    실행파일 = 설치경로 / ("node.exe" if 윈도우 else "bin/node")
    npm_스크립트 = 설치경로 / (
        "node_modules/npm/bin/npm-cli.js" if 윈도우 else "lib/node_modules/npm/bin/npm-cli.js"
    )
    if 노드_버전_읽기(실행파일) == tuple(int(값) for 값 in 노드_버전.split(".")):
        return 노드_환경(실행파일, (str(실행파일), str(npm_스크립트)))

    런타임_경로.mkdir(parents=True, exist_ok=True)
    배포파일명, 형식 = 노드_배포파일_정보()
    기본주소 = f"https://nodejs.org/dist/v{노드_버전}"
    print(f"SSOC 전용 Node.js {노드_버전}을 준비합니다.")

    with tempfile.TemporaryDirectory(prefix="ssoc-node-") as 임시문자열:
        임시경로 = Path(임시문자열)
        배포파일 = 임시경로 / 배포파일명
        체크섬파일 = 임시경로 / "SHASUMS256.txt"
        주소_다운로드(f"{기본주소}/{배포파일명}", 배포파일)
        주소_다운로드(f"{기본주소}/SHASUMS256.txt", 체크섬파일)
        체크섬_검증(배포파일, 배포파일명, 체크섬파일)

        압축해제경로 = 임시경로 / "압축해제"
        압축해제경로.mkdir()
        if 형식 == "zip":
            with zipfile.ZipFile(배포파일) as 압축파일:
                압축파일.extractall(압축해제경로)
        else:
            with tarfile.open(배포파일, "r:*") as 압축파일:
                tar_안전_해제(압축파일, 압축해제경로)

        원본경로 = next(압축해제경로.iterdir())
        임시설치경로 = 런타임_경로 / f".node-v{노드_버전}.준비중"
        if 임시설치경로.exists():
            shutil.rmtree(임시설치경로)
        shutil.move(str(원본경로), 임시설치경로)
        if 설치경로.exists():
            shutil.rmtree(설치경로)
        임시설치경로.replace(설치경로)

    return 노드_환경(실행파일, (str(실행파일), str(npm_스크립트)))


def 노드_준비() -> 노드_환경:
    시스템환경 = 시스템_노드_찾기()
    return 시스템환경 if 시스템환경 else 로컬_노드_설치()


def pnpm_준비(환경: 노드_환경) -> Path:
    pnpm_경로 = 런타임_경로 / "pnpm" / "node_modules/pnpm/bin/pnpm.cjs"
    if pnpm_경로.exists():
        결과 = subprocess.run(
            [str(환경.실행파일), str(pnpm_경로), "--version"],
            capture_output=True,
            text=True,
        )
        if 결과.returncode == 0 and 결과.stdout.strip() == PNPM_버전:
            return pnpm_경로

    print(f"SSOC 전용 pnpm {PNPM_버전}을 준비합니다.")
    pnpm_설치경로 = 런타임_경로 / "pnpm"
    pnpm_설치경로.mkdir(parents=True, exist_ok=True)
    명령_실행([
        *환경.npm_명령,
        "install",
        "--prefix",
        str(pnpm_설치경로),
        f"pnpm@{PNPM_버전}",
        "--no-audit",
        "--no-fund",
    ])
    return pnpm_경로


def 프론트엔드_설치(환경: 노드_환경, pnpm: Path) -> None:
    print("대시보드 의존성을 확인합니다.")
    명령_실행([
        str(환경.실행파일),
        str(pnpm),
        "install",
        "--frozen-lockfile",
        "--prefer-offline",
    ])


def 결과_동기화(환경: 노드_환경) -> None:
    print("조사 에이전트 결과를 대시보드 데이터로 변환합니다.")
    명령_실행([str(환경.실행파일), "scripts/sync-results.mjs"])


def 대시보드_명령(동작: str, 추가인수: list[str]) -> int:
    환경 = 노드_준비()

    if 동작 == "sync":
        결과_동기화(환경)
        return 0

    pnpm = pnpm_준비(환경)
    프론트엔드_설치(환경, pnpm)
    if 동작 == "install":
        결과_동기화(환경)
        print("SSOC 설치가 완료되었습니다.")
        return 0

    결과_동기화(환경)
    스크립트 = "dev" if 동작 == "run" else "build"
    명령 = [str(환경.실행파일), str(pnpm), "run", 스크립트]
    if 추가인수:
        명령.extend(["--", *추가인수])
    return 명령_실행(명령, 검사=False).returncode


def 인수_분석() -> argparse.Namespace:
    분석기 = argparse.ArgumentParser(
        description="SSOC 대시보드의 설치, 데이터 동기화, 실행, 빌드를 관리합니다.",
        add_help=False,
    )
    분석기._positionals.title = "위치 인수"
    분석기._optionals.title = "선택 인수"
    분석기.add_argument(
        "-h",
        "--help",
        action="help",
        help="도움말을 표시하고 종료합니다.",
    )
    분석기.add_argument(
        "동작",
        nargs="?",
        choices=("install", "sync", "run", "build"),
        default="run",
        help="수행할 동작이며 기본값은 run입니다.",
    )
    분석기.add_argument(
        "추가인수",
        nargs=argparse.REMAINDER,
        help="개발 서버나 빌드 명령에 전달할 추가 인수입니다.",
    )
    return 분석기.parse_args()


def 메인() -> int:
    출력_인코딩_설정()
    인수 = 인수_분석()
    추가인수 = 인수.추가인수
    if 추가인수[:1] == ["--"]:
        추가인수 = 추가인수[1:]
    try:
        return 대시보드_명령(인수.동작, 추가인수)
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, subprocess.CalledProcessError) as 오류:
        print(f"실행 실패: {오류}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(메인())
