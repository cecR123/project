from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
from flask_cors import CORS  #cross-origin requests
import mysql.connector
from mysql.connector import Error
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token

app = Flask(__name__)
CORS(app)  # to allow CORS requests
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
#  JWT manager
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change to a secure key



def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        port = "3306", 
        user="root",      
        password="root",  
        database="gs"  
    )
@app.route('/')
def home():
    return render_template('index.html') 


@app.route('/api/products', methods=['POST'])
def add_product():
   
    data = request.json
    name = data.get('name')
    price = data.get('price')
    category = data.get('category')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = 'INSERT INTO products (name, price, category) VALUES (%s, %s, %s)'
    cursor.execute(query, (name, price, category))

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'message': 'Product added successfully'}), 201



@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    # Validate input
    if not email or not password or not confirm_password:
        return jsonify({"message": "Email, password, and confirm password are required"}), 400

    if password != confirm_password:
        return jsonify({"message": "Passwords do not match"}), 400

    try:
        
        email = email.strip()

       
        conn = get_db_connection()
        cursor = conn.cursor()

    
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            cursor.close()
            conn.close()
            return jsonify({"message": "Email already exists. Please log in."}), 400

       
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

   
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201
    except Error as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    try:
       
        email = email.strip()

 
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid credentials"}), 401

        # Check password
        stored_password_hash = user[2]
        if bcrypt.check_password_hash(stored_password_hash, password):
            # Create JWT token
            access_token = create_access_token(identity=email)
            cursor.close()
            conn.close()
            return jsonify({"access_token": access_token}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid credentials"}), 401
    except Error as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
#
#@app.route('/submit-form', methods=['POST'])
#def submit_form():
#    
#    name = request.form.get('name')
#    address = request.form.get('address')
#    phone = request.form.get('phone')
#    payment_method = request.form.get('payment')
#
#    # Check if all fields are present
#    if not name or not address or not phone or not payment_method:
#        return jsonify({
#            'status': 'error',
#            'message': 'All fields (name, address, phone, payment method) are required!'
#        }), 400  # Return a 400 Bad Request if any field is missing
#
#    # Try to insert the data into the database using the helper function
#    success = insert_delivery_info(name, address, phone, payment_method)
#
#    if success:
#        # Return success response
#        return jsonify({
#            'status': 'success',
#            'message': 'Your delivery information has been successfully submitted!'
#        })
#    else:
#        # Return failure response if the database insertion failed
#        return jsonify({
#            'status': 'error',
#            'message': 'There was an error processing your request. Please try again later.'}), 500  # Return a 500 Internal Server Error if something goes wrong
#
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get the current user's email from the JWT token
    current_user = get_jwt_identity()

    # You can now access `current_user`, which is the email
    return jsonify({"message": f"Welcome, {current_user}! This is a protected route."}), 200








if __name__ == '__main__':
    app.run(debug=True)
