import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, current_app
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room, emit, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 메시지 테이블 생성
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            msg TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        # 메시지 테이블 바로 아래에 추가
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS room (
        id TEXT PRIMARY KEY,
        user_a TEXT NOT NULL,
        user_b TEXT NOT NULL
        )
        """)

        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
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

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
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
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

#비밀번호 변경
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    old = request.form['old_password']
    new = request.form['new_password']
    confirm = request.form['confirm_password']
    db = get_db()
    cur = db.execute("SELECT password FROM user WHERE id=?", (session['user_id'],))
    if cur.fetchone()['password'] != old:
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))
    if new != confirm:
        flash('새 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('profile'))
    db.execute("UPDATE user SET password=? WHERE id=?", (new, session['user_id']))
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
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description']
        price = request.form['price']
        # 가격은 숫자만 허용
        if not price.isdigit():
            flash('가격은 숫자만 입력할 수 있습니다.')
            return redirect(url_for('new_product'))
        db = get_db()
        # 중복 제목 검사
        if db.execute("SELECT 1 FROM product WHERE title = ?", (title,)).fetchone():
            flash('이미 존재하는 상품 제목입니다.')
            return redirect(url_for('new_product'))
        # 중복 없을 때만 삽입
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
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

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target = request.form['target_id'].strip()
        reason = request.form['reason'].strip()
        db = get_db()

        # 1) 대상이 사용자명인지 검사
        user_row = db.execute("SELECT id, role FROM user WHERE username = ?", (target,)).fetchone()
        if user_row:
            # 관리자 사용자 신고 차단
            if user_row['role'] == 'admin':
                flash('관리자는 신고할 수 없습니다.')
                return redirect(url_for('report'))
            target_id = user_row['id']

        else:
            # 2) 대상이 상품명인지 검사
            prod_row = db.execute("SELECT id, seller_id FROM product WHERE title = ?", (target,)).fetchone()
            if prod_row:
                # 상품 올린 사람이 관리자면 신고 차단
                seller = db.execute("SELECT role FROM user WHERE id=?", (prod_row['seller_id'],)).fetchone()
                if seller and seller['role'] == 'admin':
                    flash('관리자가 올린 상품은 신고할 수 없습니다.')
                    return redirect(url_for('report'))
                target_id = prod_row['id']
            else:
                flash('존재하지 않는 사용자명 또는 상품명입니다.')
                return redirect(url_for('report'))

        # 3) 유효 대상에 대해 신고 저장
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
    db = get_db()
    db.execute("INSERT INTO message (room, sender_id, msg) VALUES (?, ?, ?)", (data['room'], data['from'], data['msg']))
    db.commit()
    send({'from_name': data['from_name'], 'msg': data['msg']}, room=data['room'])

# 채팅방 나가기
@app.route('/chat/leave/<room_id>', methods=['POST'])
@login_required
def leave_chat(room_id):
    me = session['user_id']
    db = get_db()
    r = db.execute("SELECT user_a, user_b FROM room WHERE id=?", (room_id,)).fetchone()
    if not r or me not in (r['user_a'], r['user_b']):
        flash('접근 권한이 없습니다.')
        return redirect(url_for('chat_list'))
    # 방 및 메시지 삭제
    db.execute("DELETE FROM message WHERE room=?", (room_id,))
    db.execute("DELETE FROM room WHERE id=?", (room_id,))
    db.commit()
    flash('채팅방을 나갔습니다.')
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