from flask import (Flask, render_template, request,
                   redirect, jsonify, url_for, flash)
from flask import session as login_session
from flask import make_response

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from db import Base, ProductType, Product, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from werkzeug.utils import secure_filename
from slugify import slugify

import random
import os
import string
import requests
import httplib2
import json


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Catalog Application"

UPLOAD_FOLD = os.path.join(app.root_path, 'static/img')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLD'] = UPLOAD_FOLD


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Function that display the view for login
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Function that validate the login for google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px; height: 300px;'
               'border-radius: 150px;-webkit-border-radius:'
               ' 150px;-moz-border-radius: 150px;"> ')
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions


# Create a user in the database if is new login
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


# Get user record by User Id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Get user record by email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Function to logout
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider, only GMAIL was implemented
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session.get('gplus_id'):
            del login_session['gplus_id']
        if login_session.get('credentials'):
            del login_session['credentials']
        if login_session.get('username'):
            del login_session['username']
        if login_session.get('email'):
            del login_session['email']
        if login_session.get('picture'):
            del login_session['picture']
        if login_session.get('user_id'):
            del login_session['user_id']
        if login_session.get('provider'):
            del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('products'))
    else:
        flash("You were not logged in")
        return redirect(url_for('products'))



# Function to display the products
@app.route('/', methods=["GET"])
@app.route('/products/<string:type>', methods=["GET"])
def products(type=None):
    product_types = (session.query(ProductType)
                     .order_by(asc(ProductType.type)))
    if type is None:
        products = (session.query(Product)
                    .order_by(asc(Product.name)))
    else:
        products = (session.query(Product)
                    .join(ProductType)
                    .filter(ProductType.type == type)
                    .order_by(asc(Product.name)))
    return render_template('products.html',
                           product_types=product_types,
                           products=products, type=type)



# Function to create a new item in the catalog
@app.route('/product/new/', methods=['GET', 'POST'])
def newProduct():
    if 'username' not in login_session:
        return redirect('/login')
    templateData = {'name': '',
                    'description': '', 'price': '',
                    'type': '',
                    }
    if request.method == 'POST':
        if (request.form.get('name') is None or
            request.form['name'] == "" or
            request.form.get("description") is None or
            request.form['description'] == "" or
            request.form.get('price') is None or
                request.form['price'] == ""):

            templateData = {'name': request.form.get('name'),
                            'description': request
                            .form.get('description'),
                            'price': request.form.get('price'),
                            'type': int(request.form.get('type'))
                            }
            product_types = (session.query(ProductType)
                             .order_by(asc(ProductType.type)))

            return render_template('newProduct.html',
                                   product_types=product_types,
                                   templateData=templateData)
        else:
            image = request.files['image']
            if image.filename is not None:
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    image.save(os.path.join(app.
                                            config['UPLOAD_FOLD'],
                                            filename))

            product = Product(name=request.form['name'],
                              slug=slugify(request.form['name']),
                              description=request
                              .form.get('description'),
                              price=request.form.get('price'),
                              user_id=login_session['user_id'],
                              product_type_id=int(request.form
                                                  .get('type')),
                              image_path='img/' + image.filename
                              if image.filename else '')
            session.add(product)
            session.commit()

            flash('New Product added Successfully Created')
            return redirect(url_for('products'))
    else:
        product_types = (session.query(ProductType)
                         .order_by(asc(ProductType.type)))
        return render_template('newproduct.html',
                               product_types=product_types,
                               templateData=templateData)


# Funcion to edit a product info
@app.route('/product/<string:slug>/edit', methods=['GET', 'POST'])
def editProduct(slug):
    if 'username' not in login_session:
        return redirect('/login')

    product = (session.query(Product)
               .filter_by(slug=slug).one())

    if product.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are"
                " not authorized to edit this product. Please "
                "create your own product in order to edit.');}"
                "</script><body onload='myFunction()'>")

    if request.method == 'POST':
        if request.form.get('slug') is None:
            return redirect(url_for('products'))

        if (request.form.get('name') is None or
            request.form['name'] == "" or
            request.form.get("description") is None or
            request.form['description'] == "" or
            request.form.get('price') is None or
                request.form['price'] == ""):

            templateData = {'name': product.name,
                            'description': product.description,
                            'price': product.price,
                            'image_path': product.image_path,
                            'type': product.product_type_id
                            }
            product_types = (session.query(ProductType)
                             .order_by(asc(ProductType.type)))

            return render_template('editproduct.html',
                                   product_types=product_types,
                                   templateData=templateData)
        else:
            new_image_path = string.replace(product.image_path,
                                            'img/', '')
            fileToRemove = os.path.join(
                app.root_path, 'static') + product.image_path

            image = request.files['image']
            if image.filename is not None and image.filename != '':
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    image.save(os.path.join(app.
                                            config['UPLOAD_FOLD'],
                                            filename))
                    new_image_path = image.filename
                    if os.path.exists(fileToRemove):
                        if not os.path.isdir(fileToRemove):
                            os.remove(fileToRemove)

            product.name = request.form['name']
            product.slug = slugify(request.form['name'])
            product.description = request.form.get('description')
            product.price = request.form.get('price')
            product.product_type_id = int(request.form.get('type'))

            if new_image_path != '':
                product.image_path = 'img/' + new_image_path
            else:
                product.image_path = ''
            session.add(product)
            session.commit()

            flash('New Product added Successfully Created')
            return redirect(url_for('products'))
    else:
        if product is None:
            return redirect(url_for('products'))
        templateData = {'name': product.name,
                        'slug': product.slug,
                        'description': product.description,
                        'price': product.price,
                        'image_path': product.image_path,
                        'type': product.product_type_id,
                        }
        product_types = (session.query(ProductType)
                         .order_by(asc(ProductType.type)))
        return render_template('editproduct.html',
                               product_types=product_types,
                               templateData=templateData)


# Check if the file is a picture
def allowed_file(filename):
    return ('.' in filename and filename
            .rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)


# Function to display a product, NO edit allowed
@app.route('/product/<string:slug>', methods=['GET'])
def viewProduct(slug):
    product = session.query(Product).filter_by(slug=slug).one()
    prod_type = (session.query(ProductType)
                 .filter_by(id=product.product_type_id).one())
    if product:
        templateData = {'name': product.name,
                        'description': product.description,
                        'price': product.price,
                        'type': prod_type.type,
                        'image_path': product.image_path
                        }
        return render_template('viewproduct.html',
                               templateData=templateData)
    else:
        return redirect(url_for('products'))


# Function to delete a product from the backend
@app.route('/product/<string:slug>/delete/', methods=['GET', 'POST'])
def deleteProduct(slug):
    if 'username' not in login_session:
        return redirect('/login')

    product = session.query(
        Product).filter_by(slug=slug).one()
    if product.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are"
                " not authorized to delete this product. Please "
                "create your own product in order to edit.');}"
                "</script><body onload='myFunction()'>")

    if request.method == 'POST':
        session.delete(product)
        flash('Successfully Product Deleted')
        session.commit()
        return redirect(url_for('products'))
    else:
        templateData = {'name': product.name,
                        'slug': product.slug,
                        'description': product.description,
                        'price': product.price,
                        'type': (session
                                 .query(ProductType)
                                 .filter_by(id=product
                                            .product_type_id)
                                 .one().type),
                        'image_path': product.image_path
                        }
        return render_template('deleteproduct.html',
                               templateData=templateData)


# Function to get a product info as JSON
@app.route('/product/<string:slug>/JSON')
def productJSON(slug):
    product = session.query(Product).filter_by(slug=slug).one()
    return jsonify(product=product.serialize)


# Function to get a list of products as JSON
@app.route('/products/JSON')
def productsJSON():
    products = session.query(Product).all()
    return jsonify(Products=[p.serialize for p in products])


# Main function
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
