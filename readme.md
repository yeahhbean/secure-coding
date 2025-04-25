# Secure Market

Flask 기반의 보안 강화 마켓 애플리케이션입니다.  
회원 관리, 상품 CRUD, 1:1·전체 채팅, 신고 시스템, 관리자 페이지까지 포함합니다.

---

## 🌟 주요 기능

| 영역               | 내용                                                                                 |
|------------------|------------------------------------------------------------------------------------|
| 회원가입/로그인       | • 사용자명·비밀번호 형식 검증<br>• 해시화된 비밀번호 저장 (Werkzeug)<br>• 로그인 실패 제한 및 차단 (Flask-Limiter) |
| CSRF 보호         | • 모든 POST 폼에 CSRF 토큰 적용 (Flask-WTF)                                           |
| 상품 관리           | • 제목/설명/가격 서버측 검증<br>• 데이터베이스 제약 (NOT NULL, FOREIGN KEY, CHECK)         |
| 채팅 (WebSocket)    | • 글로벌·1:1 채팅 (Flask-SocketIO)<br>• 메시지 길이 제한·XSS 방어 (bleach)<br>• Rate limit (5 msg/10s) |
| 신고 시스템          | • 형식·길이 검증<br>• 동일 대상 1회만 신고 가능<br>• 10회 이상 신고 시 자동 삭제          |
| 관리자 페이지        | • ROLE 기반 접근 제어<br>• 유저·상품 조회·삭제<br>• 신고 내역 초기화                   |
| 운영 및 보안 강화     | • 세션 타임아웃 (30분)<br>• 에러 핸들러 (400/404/500 페이지)<br>• 로깅 (RotatingFileHandler)<br>• HTTPS 리다이렉트 예시 |

---

## 📋 요구사항

- Python 3.8+
- SQLite 3.x

**의존 패키지**: `requirements.txt` 참고

```text
Flask==2.2.5
Flask-SocketIO==5.3.2
python-engineio==4.3.3
python-socketio==5.7.2
Werkzeug==2.3.4
Jinja2==3.1.2
Flask-WTF==1.1.1
bleach==6.0.0
Flask-Limiter==2.14.0


##환경 설정
git clone https://github.com/yeahhbean/secure-coding.git

##파이썬 가상환경 생성 및 활성화
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate.bat     # Windows

##의존성 설치
pip install -r requirements.txt

##실행 방법
- 데이터베이스 초기화
python
>>> from app import init_db
>>> init_db()
>>> exit()

- 애플리케이션 실행
python app.py

- 브라우저 열기
http://127.0.0.1:5000

- 기본 관리자 계정
계정	비밀번호	역할
admin	thisisadmin	관리자
**운영 환경에서는 초기 로그인 후 즉시 비밀번호 변경 권장**

- 디렉터리 구조
.
├── app.py
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── ...
│   └── errors/
│       ├── 404.html
│       └── 500.html
├── logs/
│   └── market.log
└── market.db
