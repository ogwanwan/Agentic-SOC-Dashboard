# SSOC 대시보드

SSOC(Security SOC)는 로컬 환경에서 보안 로그 분석 파이프라인의 결과를 확인하기 위한 데모 대시보드입니다. 현재는 조사 에이전트가 생성한 JSON 결과를 읽어 사건 현황과 상세 증거를 보여주며, 후속 단계인 ATT&CK 매핑·대응 생성·자율성 레벨은 데이터가 연결될 자리를 미리 제공합니다.

## 화면 구성

- **상황 개요**: 우선 확인 사건, 핵심 지표, 심각도 분포, 시간대별 판정 추이를 요약합니다.
- **사건 목록**: 조사 결과를 검색·필터링하고 사건을 선택해 타임라인, 증거, 판단 근거를 확인합니다.
- **운영 상태**: LLM 토큰 사용량, 단계별 실행 시간, 처리량 등의 운영 지표를 배치할 기본 틀입니다.
- **연결**: 수집부터 대시보드까지의 파이프라인, 현재 모델, 단계별 역할과 요약 프롬프트를 제한적으로 보여줍니다.

## 데이터 흐름

대시보드는 `results/*.json`을 직접 브라우저에서 읽지 않습니다. 감시 프로세스가 조사 에이전트 결과를 안전한 프론트엔드용 JSON으로 변환하고, 화면이 새 스냅샷을 자동으로 가져옵니다.

```text
results/*.json
  → scripts/watch-results.mjs (파일 변경 감지)
  → scripts/sync-results.mjs (정규화·원자적 저장)
  → public/data/incidents.generated.json
  → 브라우저 자동 갱신 (최대 약 1.25초)
  → SSOC 대시보드
```

개발 서버를 시작하면 감시 프로세스도 함께 실행되고, 서버 종료 시 같이 정리됩니다. 연속 변경은 하나로 묶어 처리하며, 생산 프로세스가 JSON을 쓰는 도중에는 기존 정상 스냅샷을 유지한 뒤 완성된 파일을 다시 읽습니다. 브라우저는 연결 상태, 마지막 반영 시각, 신규 사건 수를 표시합니다.

동기화 과정에서 원본 파일의 절대 경로는 노출하지 않으며, 화면에 필요한 사건 정보만 정규화합니다. 기본 입력 폴더는 프로젝트 루트의 `results/`입니다.

다른 결과 폴더를 사용하려면 프로젝트 루트의 `.env`에서 `SSOC_RESULTS_DIR`을 설정합니다. 상대 경로는 현재 터미널 위치가 아니라 `ssoc-dashboard` 프로젝트 루트를 기준으로 해석됩니다. 절대 경로도 사용할 수 있으며, 셸이나 배포 환경에서 직접 지정한 `SSOC_RESULTS_DIR` 값은 `.env`보다 우선합니다.

```dotenv
SSOC_RESULTS_DIR=./results
```

`.env`는 Git에 포함되지 않습니다. 공유할 기본 설정은 `.env.example`을 참고하면 됩니다.

## 설치와 실행

Python 3.10 이상을 사용합니다. Node.js와 pnpm이 설치되어 있지 않으면 첫 실행 때 프로젝트 내부의 `.ssoc-runtime/`에 전용 버전을 자동으로 준비하므로, 시스템 전역에 별도로 설치할 필요가 없습니다.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python ssoc.py
```

Windows PowerShell에서는 다음 명령으로 가상환경을 활성화합니다.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python ssoc.py
```

기본 개발 서버는 `http://localhost:5173`에서 실행됩니다. 첫 실행은 전용 실행 도구와 프론트엔드 패키지를 준비하므로 인터넷 연결이 필요하며, 이후에는 저장된 도구와 캐시를 재사용합니다.

### 실행 명령

```bash
python ssoc.py install  # 실행 도구, 패키지, 조사 결과 데이터 준비
python ssoc.py sync     # 조사 결과 JSON만 다시 동기화
python ssoc.py run      # 실시간 감시와 개발 서버 실행
python ssoc.py build    # 데이터 동기화 후 배포용 빌드 생성
```

`python ssoc.py`는 `python ssoc.py run`과 같습니다.

Node.js와 pnpm을 이미 사용하고 있다면 `pnpm dev`로도 동일한 실시간 감시가 시작됩니다. 빌드된 로컬 서버를 실행하는 `pnpm start`에도 감시기가 함께 실행되며, `pnpm build`는 빌드 전에 최신 결과를 자동 동기화합니다. 실행 중인 서버는 설정이나 실행 스크립트를 변경해도 자동으로 재시작되지 않으므로, 관련 파일을 수정했다면 서버를 한 번 다시 시작해야 합니다.

배포용 빌드는 다음과 같이 검증합니다.

```bash
python ssoc.py build
```

## 주요 디렉터리

```text
app/                            화면과 전역 스타일
results/                        원본 조사 결과 JSON(기본 입력 폴더)
data/incidents.generated.json  변환된 조사 결과
scripts/sync-results.mjs        조사 결과 동기화 스크립트
scripts/watch-results.mjs       결과 폴더 실시간 감시 프로세스
ssoc.py                         Python 설치·실행 진입점
requirements.txt                Python 가상환경 설치 명세
public/                         파비콘 등 정적 자산
.openai/hosting.json            Sites 배포 설정
```

## 현재 구현 범위

- 조사 에이전트 JSON 기반 사건 목록 및 상세 화면
- 결과 폴더 변경 감지와 실행 중 자동 갱신
- 전체 현황과 시간대별 판정 시각화
- 운영 지표와 파이프라인 스냅샷의 기본 레이아웃
- 다크 테마와 반응형 화면

다음 항목은 실제 산출물 또는 계측 데이터가 준비된 뒤 연결합니다.

- ATT&CK 기술 ID와 전술 매핑
- 근거가 포함된 대응 권고
- L0·L1·L2 자율성 판정 및 처리 결과
- 실제 LLM 토큰 사용량과 단계별 실행 시간

## 실시간 동작 범위

로컬 개발 서버는 같은 컴퓨터의 결과 폴더를 감시하므로 새 파일을 즉시 반영할 수 있습니다. 정적 호스팅이나 Cloudflare 배포 환경에서는 로컬 파일시스템에 접근할 수 없습니다. 배포본에서도 실시간 수집이 필요하면 결과 업로더와 R2/D1/API 같은 외부 저장소를 연결해야 합니다.

## 문서 및 주석 원칙

SSOC가 직접 관리하는 문서와 코드 주석은 한글로 작성합니다. 외부 라이브러리의 라이선스, 자동 생성 파일, 상류 프로젝트에서 그대로 가져온 코드의 주석은 출처와 무결성을 보존하기 위해 원문을 유지합니다.
