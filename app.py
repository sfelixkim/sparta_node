from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import jwt
from datetime import datetime, timedelta
import hashlib
import json
import re
from functools import wraps
from flask_socketio import SocketIO, emit, send


app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = False

app.secret_key = b'SPARTA'
JWT_SECRET_KEY = 'SPARTA'
app.config['SECRET_KEY'] = JWT_SECRET_KEY
socketio = SocketIO(app)

#########################################################
#       Decorators
#########################################################
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("mytoken")
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            if "userId" in payload:
                return func(*args, **kwargs)
            else:
                return redirect(url_for("home", msg="로그인 먼저 해주세요!"))
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect(url_for("home"))
    return wrapper


@app.route('/')
def home():
    token = request.cookies.get("mytoken")
    if token is not None:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        if "userId" in payload:
            return redirect(url_for("goods"))
    return render_template("index.html")


@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/goods')
@login_required
def goods():
    return render_template("goods.html")


@app.route('/detail')
@login_required
def detail():
    return render_template("detail.html")


@app.route('/cart')
@login_required
def cart():
    return render_template("cart.html")


@app.route('/order')
@login_required
def order():
    return render_template("order.html")


### API ###

def find_one(array, fil):
    for row in array:
        if all(row.get(k)==v for k, v in fil.items()): return row


def find_all(array, fil):
    result = []
    for row in array:
        if all(row.get(k)==v for k, v in fil.items()): result.append(row)
    return result


@app.route('/api/goods')
@login_required
def get_goods():
    category = request.args.get("category")
    goods = json.load(open("./static/goods.json", encoding="utf-8"))
    if category is not None:
        goods = [r for r in goods if r["category"] == category]
    return jsonify({"result": "success", "goods": goods})


@app.route('/api/goods/<int:goods_id>')
@login_required
def get_detail(goods_id):
    print(goods_id)
    result = find_one(json.load(open("./static/goods.json", encoding="utf-8")), {"goodsId":goods_id})
    if result is not None:
        return jsonify({"result": "success", "detail": result})
    else:
        return "item not found", 404


@app.route('/api/auth', methods=["POST"])
def sign_in():
    email = request.form["email"]
    password = request.form["password"]
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(email, password_hash)
    users = json.load(open("./static/users.json", encoding="utf-8"))
    user = find_one(users, {"email": email, "password": password_hash})
    if user is not None:
        print("signing in...")
        payload = {
            'userId': user["userId"],
            'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
        return jsonify({'result': 'success', 'token': token, 'nickname': user["nickname"]})
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})


@app.route('/api/users', methods=["POST"])
def sign_up():
    nickname = request.form["nickname"]
    email = request.form["email"]
    password = request.form["password"]
    confirm_password = request.form["confirmPassword"]

    users = json.load(open("./static/users.json", encoding="utf-8"))

    if not re.search(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', email):
        return jsonify({"result": "fail", "msg": "이메일 형식을 확인해주세요."})
    if find_one(users, {"email": email}):
        return jsonify({"result": "fail", "msg": "이미 존재하는 이메일입니다."})
    if password != confirm_password:
        return jsonify({"result": "fail", "msg": "비밀번호가 일치하지 않습니다."})

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    doc = {
        "userId": len(users)+1,
        "email": email,
        "nickname": nickname,
        "password": password_hash
    }
    print(doc) # insert_one()
    return jsonify({"result": "success", "msg": "회원가입 성공!"})


@app.route('/api/cart', methods=["GET"])
@login_required
def get_cart():
    token = request.cookies.get("mytoken")

    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    user_id = payload["userId"]

    print(user_id)
    carts = json.load(open("./static/carts.json", encoding="utf-8"))
    my_cart = find_all(carts, {"userId": user_id})

    goods = json.load(open("./static/goods.json", encoding="utf-8"))

    for item in my_cart:
        good = find_one(goods, {"goodsId": item["goodsId"]})
        item.update(good)

    return jsonify({"result": "success", "cart": my_cart})


@app.route('/api/goods/<int:goods_id>/cart', methods=["POST", "PATCH", "DELETE"])
@login_required
def change_cart(goods_id):
    token = request.cookies.get("mytoken")

    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    user_id = payload["userId"]
    if request.method == 'DELETE':
        print(user_id, goods_id)  # delete_one()
        carts = json.load(open("./static/carts.json", encoding="utf-8"))
        if find_one(carts, {"userId": user_id, "goodsId": goods_id}):
            return jsonify({"result": "success", "msg": "장바구니를 수정했습니다."})
        else:
            return "장바구니에 존재하지 않는 상품입니다.", 400

    quantity = int(request.form["quantity"])
    if request.method == 'POST':
        print(user_id, goods_id, quantity)  # update_one()
        return jsonify({"result": "success", "msg": "장바구니에 담았습니다."})
    if request.method == 'PATCH':
        print(user_id, goods_id, quantity)  # update_one()
        return jsonify({"result": "success", "msg": "장바구니를 수정했습니다."})

    else:
        return jsonify({"result": "fail", "msg": "잘못된 메소드입니다."})


@socketio.on('newOrder')
def new_order(data):
    print('received json: ' + str(data))
    cart = json.loads(data)
    print(data)
    token = request.cookies.get("mytoken")

    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    user_id = payload["userId"]
    print(user_id)
    users = json.load(open("./static/users.json", encoding="utf-8"))
    user = find_one(users, {"userId":user_id})

    for item in cart:
        print("sending...")
        emit("orderSomething",
             {"userName": user["nickname"], "goodsName": item["goodsName"]},
             # namespace="/goods",
             broadcast=True)



if __name__ == '__main__':
    # app.run('0.0.0.0', port=5000, debug=True)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
