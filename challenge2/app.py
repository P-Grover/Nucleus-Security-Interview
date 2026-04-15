from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    a = data.get('a')
    b = data.get('b')
    op = data.get('op')

    if a is None or b is None or op is None:
        return jsonify({'error': 'Missing values'}), 400

    try:
        a, b = float(a), float(b)
    except ValueError:
        return jsonify({'error': 'Invalid numbers'}), 400

    if op == '+':
        result = a + b
    elif op == '-':
        result = a - b
    elif op == '*':
        result = a * b
    elif op == '/':
        if b == 0:
            return jsonify({'error': 'Cannot divide by zero'}), 400
        result = a / b
    else:
        return jsonify({'error': 'Unknown operator'}), 400

    # Return int if result is a whole number
    result = int(result) if result == int(result) else result
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
