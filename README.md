# SSOC 대시보드

SSOC(Security SOC)는 로컬 환경에서 보안 로그 분석 파이프라인의 결과를 확인하기 위한 데모 대시보드입니다. 현재는 조사 에이전트가 생성한 JSON 결과를 읽어 사건 현황과 상세 증거를 보여주며, 후속 단계인 ATT&CK 매핑·대응 생성·자율성 레벨은 데이터가 연결될 자리를 미리 제공합니다.

## 화면 구성

- **Overview**: 시간대별 정상·위협 판정, 심각도 분포, 자율성별 처리 현황을 요약합니다.
- **사건 목록**: 조사 결과를 검색·필터링하고 사건을 선택해 타임라인, 증거, 판단 근거를 확인합니다.
- **운영 상태**: LLM 토큰 사용량, 단계별 실행 시간, 처리량 등의 운영 지표를 배치할 기본 틀입니다.
- **연결**: 수집부터 대시보드까지의 파이프라인, 현재 모델, 단계별 역할과 요약 프롬프트를 제한적으로 보여줍니다.

## 데이터 흐름

대시보드는 `../000/results/*.json`을 직접 브라우저에서 읽지 않습니다. 동기화 스크립트가 조사 에이전트 결과를 프론트엔드용 JSON으로 변환합니다.

```text
000/results/*.json
  → scripts/sync-results.mjs
  → data/incidents.generated.json
  → SSOC 대시보드
```

동기화 과정에서 원본 파일의 절대 경로는 노출하지 않으며, 화면에 필요한 사건 정보만 정규화합니다.

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
python ssoc.py run      # 데이터 동기화 후 개발 서버 실행
python ssoc.py build    # 데이터 동기화 후 배포용 빌드 생성
```

`python ssoc.py`는 `python ssoc.py run`과 같습니다.

배포용 빌드는 다음과 같이 검증합니다.

```bash
python ssoc.py build
```

## 주요 디렉터리

```text
app/                            화면과 전역 스타일
data/incidents.generated.json  변환된 조사 결과
scripts/sync-results.mjs        조사 결과 동기화 스크립트
ssoc.py                         Python 설치·실행 진입점
requirements.txt                Python 가상환경 설치 명세
public/                         파비콘 등 정적 자산
.openai/hosting.json            Sites 배포 설정
```

## 현재 구현 범위

- 조사 에이전트 JSON 기반 사건 목록 및 상세 화면
- 전체 현황과 시간대별 판정 시각화
- 운영 지표와 파이프라인 스냅샷의 기본 레이아웃
- 다크 테마와 반응형 화면

다음 항목은 실제 산출물 또는 계측 데이터가 준비된 뒤 연결합니다.

- ATT&CK 기술 ID와 전술 매핑
- 근거가 포함된 대응 권고
- L0·L1·L2 자율성 판정 및 처리 결과
- 실제 LLM 토큰 사용량과 단계별 실행 시간

## 문서 및 주석 원칙

SSOC가 직접 관리하는 문서와 코드 주석은 한글로 작성합니다. 외부 라이브러리의 라이선스, 자동 생성 파일, 상류 프로젝트에서 그대로 가져온 코드의 주석은 출처와 무결성을 보존하기 위해 원문을 유지합니다.
