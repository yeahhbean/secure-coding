import sqlite3
import uuid
import bleach
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter.util import get_remote_address
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, current_app
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room, emit, send, ConnectionRefusedError
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader, select_autoescape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger('market')
logger.setLevel(logging.WARNING)   # ← WARNING 이상만 기록

file_handler = RotatingFileHandler(
    'logs/market.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s [%(name)s] %(message)s'
))
logger.addHandler(file_handler)

# UUID 검사용 정규표현식
UUID_REGEX = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
USERNAME_REGEX = re.compile(r'^[A-Za-z0-9_]{3,20}$')
PASSWORD_REGEX = re.compile(r'^[A-Za-z0-9!@#$%^&*()_+]{6,20}$')
TITLE_REGEX = re.compile(r'^[\w가-힣\s\-_.]{1,100}$')
TARGET_REGEX = re.compile(r'^[\w가-힣\s\-_.]{1,100}$')
BIO_REGEX = re.compile(r'^[\w가-힣\s\.,!?\-_/()"]*$')
ALLOWED_TAGS   = []
ALLOWED_ATTRS  = {}
MAX_REASON_LEN = 500
MAX_BIO_LEN = 300
MAX_MSG_LEN = 500

app = Flask(__name__)

# 404 Not Found
@app.errorhandler(404)
def handle_404(e):
    return render_template('errors/404.html'), 404

# 500 Internal Server Error
@app.errorhandler(500)
def handle_500(e):
    # 서버 로그에만 스택트레이스 기록
    current_app.logger.error(f"예외 발생: {e}", exc_info=e)
    return render_template('errors/500.html'), 500

# CSRF 오류 처리
@app.errorhandler(CSRFError)
def handle_csrf(e):
    return render_template('errors/400_csrf.html', reason=e.description), 400

app.config['SECRET_KEY'] = 'secret!'
csrf = CSRFProtect(app)
app.debug = False
app.config['PROPAGATE_EXCEPTIONS'] = False
DATABASE = 'market.db'
socketio = SocketIO(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
BLOCK_TIME = timedelta(minutes=10)
MAX_FAILS = 3

limiter = Limiter(
    key_func=get_remote_address,      # ←첫 번째로 key_func (위치 아님)
    app=app,                          # ←app은 반드시 키워드 인자
    default_limits=["5 per 10 seconds"]
)

@app.before_request
def touch_session():
    session.permanent = True
    now = datetime.utcnow()
    last = session.get('last_activity')
    # 마지막 활동이 기록돼 있고, 무활동 시간이 초과하면 세션 초기화
    if last:
        elapsed = now - datetime.fromisoformat(last)
        if elapsed > app.permanent_session_lifetime:
            session.clear()
            flash('세션이 만료되어 자동 로그아웃되었습니다.')
            return redirect(url_for('login'))
    # 매 요청마다 마지막 활동 시간 갱신
    session['last_activity'] = now.isoformat()

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 메시지 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            msg TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # 채팅방 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS room (
            id TEXT PRIMARY KEY,
            user_a TEXT NOT NULL,
            user_b TEXT NOT NULL
        )
        """)

        # 사용자 테이블 (role, 로그인 실패 방어용 컬럼 포함)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            failed_count INTEGER NOT NULL DEFAULT 0,
            last_failed DATETIME
        )
        """)

        # 상품 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS product (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price TEXT NOT NULL,
            seller_id TEXT NOT NULL,
            FOREIGN KEY(seller_id) REFERENCES user(id) ON DELETE CASCADE
        )
        """)

        # 신고 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS report (
            id TEXT PRIMARY KEY,
            reporter_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """)
         # 기본 관리자 계정 보장
        cursor.execute(
            "SELECT 1 FROM user WHERE username = ?",
            ("admin",)
        )
        if not cursor.fetchone():
            # 비밀번호는 'thisisadmin' → 해시하여 저장
            from werkzeug.security import generate_password_hash
            admin_id = str(uuid.uuid4())
            pw_hash = generate_password_hash("thisisadmin")
            cursor.execute(
                "INSERT INTO user(id, username, password, role) VALUES (?,?,?, 'admin')",
                (admin_id, "admin", pw_hash)
            )
            current_app.logger.warning("Default admin account created (admin/thisisadmin).")

        db.commit()


@app.context_processor
def inject_current_user():
    from flask import session
    user = None
    if session.get('user_id'):
        user = get_db().execute(
            "SELECT * FROM user WHERE id = ?", 
            (session['user_id'],)
        ).fetchone()
    return dict(current_user=user)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        db = get_db()
        role = db.execute("SELECT role FROM user WHERE id=?", (user_id,)).fetchone()['role']
        if role != 'admin':
            flash('관리자 권한이 없습니다.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

#관리자페이지
@app.route('/admin')
@admin_required
def admin():
    db = get_db()

    # 사용자 목록 조회
    users = db.execute(
        "SELECT id, username, role, bio FROM user"
    ).fetchall()

    # 상품 목록 조회 (판매자 username 포함)
    products = db.execute("""
        SELECT p.id,
               p.title,
               u.username AS seller_username
        FROM product p
        JOIN user u ON p.seller_id = u.id
    """).fetchall()

    # 신고 집계: target_id별 건수
    rows = db.execute("""
        SELECT target_id, COUNT(*) AS cnt
        FROM report
        GROUP BY target_id
    """).fetchall()

    # 10회 이상 신고된 대상 자동 삭제
    for r in rows:
        if r["cnt"] >= 10:
            tid = r["target_id"]
            # 사용자인지 검사
            if db.execute("SELECT 1 FROM user WHERE id=?", (tid,)).fetchone():
                # 해당 사용자의 상품과 사용자 레코드 삭제
                db.execute("DELETE FROM product WHERE seller_id=?", (tid,))
                db.execute("DELETE FROM user WHERE id=?", (tid,))
            else:
                # 상품만 삭제
                db.execute("DELETE FROM product WHERE id=?", (tid,))
            # 삭제된 대상의 모든 신고 내역도 삭제
            db.execute("DELETE FROM report WHERE target_id=?", (tid,))
    db.commit()

    # 남은 신고 내역 다시 집계하여 템플릿 데이터 준비
    reports = []
    rows = db.execute("""
        SELECT target_id, COUNT(*) AS cnt
        FROM report
        GROUP BY target_id
    """).fetchall()
    for r in rows:
        tid, cnt = r["target_id"], r["cnt"]
        # 사용자명 또는 상품명으로 표시할 이름 결정
        user = db.execute("SELECT username FROM user WHERE id=?", (tid,)).fetchone()
        if user:
            name, typ = user["username"], "User"
        else:
            prod = db.execute("SELECT title FROM product WHERE id=?", (tid,)).fetchone()
            name, typ = (prod["title"] if prod else tid), "Product"
        reports.append({"target_name": name, "target_type": typ, "count": cnt})

    return render_template(
        'admin.html',
        users=users,
        products=products,
        reports=reports
    )

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')
from flask import session, redirect, url_for, flash, g

def on_connect(auth):
    # Flask 세션에서 user_id 가 없으면 인증되지 않은 상태
    if 'user_id' not in session:
        # return False 도 가능하지만, 에러 사유를 보내려면 예외를 던집니다
        raise ConnectionRefusedError('unauthorized')
    # 여기까지 내려오면 연결 허용

def sanitize_message(msg):
    # 1) 길이 제한
    if len(msg) > MAX_MSG_LEN:
        # 초과 시 잘라내거나 에러 처리
        msg = msg[:MAX_MSG_LEN]
    # 2) 스크립트 태그 및 모든 태그 제거
    return bleach.clean(msg, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)

# 회원가입
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # 1) 길이·문자 검증
        if not USERNAME_REGEX.match(username):
            flash('사용자명은 3~20자 영문·숫자·밑줄(_)만 가능합니다.')
            return redirect(url_for('register'))
        if not PASSWORD_REGEX.match(password):
            flash('비밀번호는 6~20자 영문·숫자·특수문자(!@#$%^&*()_+)만 가능합니다.')
            return redirect(url_for('register'))

        db = get_db()
        # 2) 중복 검사 (파라미터 바인딩으로 SQL 인젝션 방지)
        if db.execute("SELECT 1 FROM user WHERE username=?", (username,)).fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # 3) 비밀번호 해싱
        pw_hash = generate_password_hash(password)

        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO user(id, username, password) VALUES(?,?,?)",
            (user_id, username, pw_hash)
        )
        db.commit()
        flash('회원가입 완료! 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # 입력 형식 검증
        if not USERNAME_REGEX.match(username) or not PASSWORD_REGEX.match(password):
            flash('입력 형식이 올바르지 않습니다.')
            return redirect(url_for('login'))

        db = get_db()
        # 사용자 조회 (실패 카운트 포함)
        row = db.execute(
            "SELECT id, password, failed_count, last_failed FROM user WHERE username=?",
            (username,)
        ).fetchone()

        # 사용자 없을 때도 동일 메시지
        if row:
            uid = row['id']
            fails = row['failed_count']
            last = row['last_failed']
        else:
            uid = None
            fails = 0
            last = None

        # 차단 상태 검사
        if last:
            last_dt = datetime.fromisoformat(last)
            if datetime.utcnow() - last_dt < BLOCK_TIME and fails >= MAX_FAILS:
                flash(f'로그인 실패 {MAX_FAILS}회. {BLOCK_TIME.seconds//60}분 후 다시 시도하세요.')
                return redirect(url_for('login'))
            # 차단시간 지났다면 초기화
            if datetime.utcnow() - last_dt >= BLOCK_TIME:
                fails = 0

        # 인증
        if row and check_password_hash(row['password'], password):
            # 성공: 세션 설정, 실패 카운트 리셋
            session['user_id'] = uid
            db.execute("UPDATE user SET failed_count=0, last_failed=NULL WHERE id=?", (uid,))
            db.commit()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            # 실패: 카운트 증가, 마지막 실패 시간 갱신
            if uid:
                new_fails = fails + 1
                db.execute(
                    "UPDATE user SET failed_count=?, last_failed=? WHERE id=?",
                    (new_fails, datetime.utcnow().isoformat(), uid)
                )
                db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM product WHERE seller_id NOT IN (SELECT id FROM user)")
    db.commit()
    chat_history = db.execute("""
        SELECT u.username AS sender_name, m.msg
        FROM message m
        JOIN user u ON m.sender_id=u.id
        WHERE m.room = 'global'
        ORDER BY m.timestamp
    """).fetchall()

    # 검색어 파라미터 읽기
    search = request.args.get('q', '').strip()

    if search:
        # 제목이 정확히 일치하는 상품만 조회
        products = db.execute(
            "SELECT * FROM product WHERE title = ?", (search,)
        ).fetchall()
    else:
        products = db.execute("SELECT * FROM product").fetchall()

    user = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()
    return render_template('dashboard.html',
                           products=products,
                           user=user,
                           search_query=search,
                           chat_history=chat_history)



# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()

        # ── 서버 사이드 검증 시작 ──
        if len(bio) > MAX_BIO_LEN:
            flash(f'소개글은 최대 {MAX_BIO_LEN}자까지 입력할 수 있습니다.')
            return redirect(url_for('profile'))

        if bio and not BIO_REGEX.match(bio):
            flash('소개글에 허용되지 않은 문자가 포함되어 있습니다.')
            return redirect(url_for('profile'))
        # ── 검증 끝 ──

        cursor.execute(
            "UPDATE user SET bio = ? WHERE id = ?",
            (bio, session['user_id'])
        )
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

#비밀번호 변경
@app.route('/change_password', methods=['POST'])
def change_password():
    # 1) 로그인(인증) 확인
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    old = request.form['old_password']
    new = request.form['new_password']
    confirm = request.form['confirm_password']

    # 2) 새 비밀번호 형식 검증
    if not PASSWORD_REGEX.match(new):
        flash('새 비밀번호는 6~20자 영문·숫자·특수문자(!@#$%^&*()_+)만 가능합니다.')
        return redirect(url_for('profile'))
    if new != confirm:
        flash('새 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('profile'))

    db = get_db()
    row = db.execute("SELECT password FROM user WHERE id=?", (session['user_id'],)).fetchone()
    stored_hash = row['password'] if row else None

    # 3) 기존 비밀번호(평문 old) 검증
    if not stored_hash or not check_password_hash(stored_hash, old):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))

    # 4) 새 비밀번호 해싱 후 저장
    new_hash = generate_password_hash(new)
    db.execute("UPDATE user SET password=? WHERE id=?", (new_hash, session['user_id']))
    db.commit()

    flash('비밀번호가 변경되었습니다.')
    return redirect(url_for('profile'))

# 1:1 채팅 페이지
# open or create room on clicking 1:1
@app.route('/chat/<target_id>')
def open_chat(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']
    if me == target_id:
        flash('자기 자신과는 채팅할 수 없습니다.')
        return redirect(url_for('chat_list'))
    db = get_db()
    # 기존 방이 있으면 가져오고, 없으면 새로 만든다.
    row = db.execute(
        "SELECT id FROM room WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)",
        (me,target_id, target_id,me)
    ).fetchone()
    if row:
        room_id = row['id']
    else:
        room_id = str(uuid.uuid4())
        db.execute("INSERT INTO room (id,user_a,user_b) VALUES (?,?,?)", (room_id,me,target_id))
        db.commit()
    return redirect(url_for('chat_list', new_room=room_id))

# 개별 채팅방 뷰
@app.route('/chat/room/<room_id>')
def chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']
    db = get_db()

    # 방 정보 가져오기
    r = db.execute("SELECT * FROM room WHERE id=?", (room_id,)).fetchone()
    # 방 자체가 없거나, 나도 아니고 상대도 아니면 접근 금지
    if not r or me not in (r['user_a'], r['user_b']):
        flash('접근 권한이 없습니다.')
        return redirect(url_for('chat_list'))

    # 대화 상대가 아직 유효한지도 확인
    other = r['user_b'] if me == r['user_a'] else r['user_a']
    exists_other = db.execute("SELECT username FROM user WHERE id=?", (other,)).fetchone()
    if not exists_other:
        flash('대화 상대가 삭제되었거나 권한이 없습니다.')
        return redirect(url_for('chat_list'))

    other_username = exists_other['username']

    # 과거 대화 불러오기
    msgs = db.execute(
        "SELECT sender_id, msg, timestamp FROM message WHERE room=? ORDER BY timestamp",
        (room_id,)
    ).fetchall()
    history = []
    for m in msgs:
        sender = db.execute("SELECT username FROM user WHERE id=?", (m['sender_id'],)).fetchone()
        history.append({
            'sender_name': sender['username'] if sender else m['sender_id'],
            'msg': m['msg']
        })

    return render_template('chat.html',
        room=room_id,
        other_id=other,
        other_username=other_username,
        history=history
    )


# 상품 등록

@app.route('/product/new', methods=['GET','POST'])
def new_product():
    if 'user_id' not in session: return redirect(url_for('login'))
    if (request.method == 'POST'):
        title       = request.form['title'].strip()
        description = request.form['description'].strip()
        price_str   = request.form['price'].strip()

        # 1) 제목 검증
        if not TITLE_REGEX.match(title):
            flash('제목은 1~100자, 한글/영문/숫자/공백/-_. 만 가능합니다.')
            return redirect(url_for('new_product'))

        # 2) 설명 검증
        if not description or len(description)>1000:
            flash('설명은 최대 1000자까지 입력할 수 있습니다.')
            return redirect(url_for('new_product'))

        # 3) 가격 검증
        if not price_str.isdigit():
            flash('가격은 숫자만 입력할 수 있습니다.')
            return redirect(url_for('new_product'))
        price = int(price_str)
        if price <= 0 or price > 1_000_000_000:
            flash('가격은 1에서 1,000,000,000 사이여야 합니다.')
            return redirect(url_for('new_product'))

        # 기존 로직: 중복 제목 검사 → DB 삽입…
        db = get_db()
        if db.execute("SELECT 1 FROM product WHERE title=?", (title,)).fetchone():
            flash('이미 존재하는 상품 제목입니다.')
            return redirect(url_for('new_product'))

        pid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product(id,title,description,price,seller_id) VALUES(?,?,?,?,?)",
            (pid, title, description, str(price), session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 판매자 본인 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_my_product(product_id):
    # 1) 로그인 확인
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    # 2) product_id 포맷 검증
    if not UUID_REGEX.match(product_id):
        flash('잘못된 상품 ID 입니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    # 3) 해당 상품 조회 및 소유자 검사
    prod = db.execute(
        "SELECT seller_id FROM product WHERE id = ?", (product_id,)
    ).fetchone()
    if not prod:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))

    if prod['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 4) 삭제 실행
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 신고하기

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target = request.form['target_id'].strip()
        reason = request.form['reason'].strip()

        # 1) 입력 형식 검증
        if not TARGET_REGEX.match(target):
            flash('신고 대상은 1~100자, 한글·영문·숫자·공백·-_. 만 가능합니다.')
            return redirect(url_for('report'))

        if not reason:
            flash('신고 사유를 입력해주세요.')
            return redirect(url_for('report'))
        if len(reason) > MAX_REASON_LEN:
            flash(f'신고 사유는 최대 {MAX_REASON_LEN}자까지 입력할 수 있습니다.')
            return redirect(url_for('report'))

        db = get_db()

        # 1.5) 동일 대상에 대한 중복 신고 방지
        # target 이 username 이든 product title 이든, 내부적으로 target_id 를 구하기 전에
        # 사용자 입력 문자열로 바로 report 테이블 검색해 봅니다.
        existing = db.execute(
            "SELECT 1 FROM report WHERE reporter_id = ? AND target_id = "
            "(SELECT id FROM user WHERE username = ? UNION SELECT id FROM product WHERE title = ?)",
            (session['user_id'], target, target)
        ).fetchone()
        if existing:
            flash('이미 해당 대상을 신고하셨습니다. 동일 대상은 한 번만 신고할 수 있습니다.')
            return redirect(url_for('dashboard'))

        # 2) 대상 존재 검사 (기존 로직)
        user_row = db.execute(
            "SELECT id, role FROM user WHERE username = ?", (target,)
        ).fetchone()

        if user_row:
            if user_row['role'] == 'admin':
                flash('관리자는 신고할 수 없습니다.')
                return redirect(url_for('report'))
            target_id = user_row['id']
        else:
            prod_row = db.execute(
                "SELECT id, seller_id FROM product WHERE title = ?", (target,)
            ).fetchone()
            if prod_row:
                seller = db.execute(
                    "SELECT role FROM user WHERE id=?", (prod_row['seller_id'],)
                ).fetchone()
                if seller and seller['role'] == 'admin':
                    flash('관리자가 올린 상품은 신고할 수 없습니다.')
                    return redirect(url_for('report'))
                target_id = prod_row['id']
            else:
                flash('존재하지 않는 사용자명 또는 상품명입니다.')
                return redirect(url_for('report'))

        # 3) 신고 저장
        report_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')



@app.route('/admin/reset_reports', methods=['POST'])
@admin_required
def reset_reports():
    db = get_db()
    db.execute("DELETE FROM report;")
    db.commit()
    flash('신고 내역이 모두 초기화되었습니다.')
    return redirect(url_for('admin'))


# 사용자 단건 삭제 (판매자 상품도 함께 삭제)
@app.route('/delete_user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    # 이 사용자가 올린 상품들 먼저 삭제
    db.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))
    # 사용자 삭제
    db.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자가 삭제되었습니다.')
    return redirect(url_for('admin'))

# 상품 삭제
@app.route('/delete_product/<product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    db = get_db()
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin'))

# 선택한 여러 사용자 일괄 삭제
@app.route('/bulk_delete_users', methods=['POST'])
@admin_required
def bulk_delete_users():
    ids = request.form.getlist('user_ids')    # 체크된 checkbox 값들
    if ids:
        db = get_db()
        # 선택된 사용자들의 상품 먼저 삭제
        db.executemany("DELETE FROM product WHERE seller_id = ?", [(i,) for i in ids])
        # 사용자 삭제
        db.executemany("DELETE FROM user WHERE id = ?", [(i,) for i in ids])
        db.commit()
        flash(f"{len(ids)}명의 사용자를 삭제했습니다.")
    return redirect(url_for('admin'))

# 선택한 여러 상품 삭제
@app.route('/bulk_delete_products', methods=['POST'])
@admin_required
def bulk_delete_products():
    ids = request.form.getlist('product_ids')
    if ids:
        db = get_db()
        db.executemany("DELETE FROM product WHERE id = ?", [(i,) for i in ids])
        db.commit()
        flash(f"{len(ids)}개의 상품을 삭제했습니다.")
    return redirect(url_for('admin'))


# Socket.IO 핸들러
@socketio.on('join')
def on_join(data):
    join_room(data['room'])

@socketio.on('private_message')
def on_private_message(data):
    raw = data['msg']
    clean = sanitize_message(raw)
    db = get_db()
    db.execute(
      "INSERT INTO message (room, sender_id, msg) VALUES (?, ?, ?)",
      (data['room'], data['from'], clean)
    )
    db.commit()
    send({'from_name': data['from_name'], 'msg': clean}, room=data['room'])

# SocketIO 에도 동일하게 사용
@socketio.on('send_message')
@limiter.limit("5 per 10 seconds")   # ← 10초에 5개 메시지까지만 허용
def on_send_message(data):
    # 이제 rate-limit 이 넘어가면 자동으로 429 에러 발생
    clean = sanitize_message(data['msg'])
    db = get_db()
    db.execute(
      "INSERT INTO message (room, sender_id, msg) VALUES (?, ?, ?)",
      (data['room'], data['from'], clean)
    )
    db.commit()
    send({'from_name': data['from_name'], 'msg': clean}, room=data['room'])

# 채팅방 나가기
@app.route('/chat/leave/<room_id>', methods=['POST'])
@login_required
def leave_chat(room_id):
    me = session['user_id']
    db = get_db()

    # 1) 방 존재 및 권한 확인
    r = db.execute(
        "SELECT user_a, user_b FROM room WHERE id = ?",
        (room_id,)
    ).fetchone()
    if not r or me not in (r['user_a'], r['user_b']):
        flash('접근 권한이 없습니다.')
        return redirect(url_for('chat_list'))

    # 2) 메시지부터 삭제 → 방 삭제
    db.execute("DELETE FROM message WHERE room = ?", (room_id,))
    db.execute("DELETE FROM room    WHERE id   = ?", (room_id,))
    db.commit()

    flash('채팅방을 나가고, 해당 방의 대화 내역을 모두 삭제했습니다.')
    return redirect(url_for('chat_list'))


# 내 채팅방 목록 조회
@app.route('/chat_list')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']
    db = get_db()

    # 내 방을 모두 가져온 뒤
    rows = db.execute(
        "SELECT id, user_a, user_b FROM room WHERE user_a=? OR user_b=?",
        (me, me)
    ).fetchall()

    chats = []
    for r in rows:
        # 방의 양쪽 유저 존재 여부 확인
        exists_a = db.execute("SELECT 1 FROM user WHERE id=?", (r['user_a'],)).fetchone()
        exists_b = db.execute("SELECT 1 FROM user WHERE id=?", (r['user_b'],)).fetchone()
        if not (exists_a and exists_b):
            # 둘 중 하나라도 없으면 방 및 메시지 삭제
            db.execute("DELETE FROM message WHERE room=?", (r['id'],))
            db.execute("DELETE FROM room WHERE id=?", (r['id'],))
            continue

        # 정상 방만 리스트에 추가
        other = r['user_b'] if me == r['user_a'] else r['user_a']
        u = db.execute("SELECT username FROM user WHERE id=?", (other,)).fetchone()
        chats.append({
            'room_id':    r['id'],
            'other_username': u['username']
        })

    db.commit()
    return render_template('chat_list.html', chats=chats)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)