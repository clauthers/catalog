#!/usr/bin/python3
from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
import psycopg2
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Base, ItemCatalog, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

application = Flask(__name__)
application.secret_key = 'super_secret_key'

engine = create_engine('postgresql://catalog:udacity@localhost:5432/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('/var/www/html/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Create anti-forgery state token
@application.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@application.route('/gconnect', methods=['POST'])
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
        oauth_flow = flow_from_clientsecrets('/var/www/html/catalog/client_secrets.json', scope='')
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
    body = h.request(url, 'GET')
    result = json.loads(body[1].decode('utf-8'))
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

    # Verify that the access token is valid for this application.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),  # NOQA
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '                                     # NOQA
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@application.route('/gdisconnect')
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
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))  # NOQA
        response.headers['Content-Type'] = 'application/json'
        return response


@application.route('/catalog/<int:category_id>/item.json')
def CategoryItemJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(ItemCatalog).filter_by(
        category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@application.route('/catalog/<int:category_id>/item/<int:item_id>.json')
def ItemJSON(category_id, item_id):
    Catalog_Item = session.query(ItemCatalog).filter_by(id=item_id).one()
    return jsonify(Catalog_Item=Catalog_Item.serialize)


@application.route('/catalog.json')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(Category=[c.serialize for c in categories])


# Show Catalog main page
@application.route('/')
@application.route('/catalog/')
def showcCategories():
    categories = session.query(Category).all()
    latest_items = session.query(ItemCatalog).\
        order_by('id desc').limit(5)
    if 'username' not in login_session:
        return render_template('publiccatalog.html',
                               categories=categories,
                               items=latest_items)
    else:
        return render_template('catalog.html',
                               categories=categories,
                               items=latest_items)


# Show a Catalog Category
@application.route('/catalog/<int:category_id>/')
@application.route('/catalog/<int:category_id>/item/')
def showItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(ItemCatalog).filter_by(
        category_id=category.id).all()
    if 'username' not in login_session:
        return render_template('publicitems.html',
                               items=items, category=category)
    else:
        return render_template('items.html',
                               items=items, category=category)


# Create a new Category Item
@application.route(
    '/catalog/<int:category_id>/item/new/', methods=['GET', 'POST'])
def newCatalogItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        itemcat = ItemCatalog(title=request.form['title'],
                              description=request.form['description'],
                              category_id=category_id,
                              user_id=login_session['user_id'])
        session.add(itemcat)
        session.commit()
        flash('New Catalog %s Item Successfully Created' % (itemcat.title))
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('newitem.html', category_id=category_id)


# Edit a Category Item
@application.route('/catalog/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editCatalogItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(ItemCatalog).filter_by(id=item_id).one()
    if login_session['user_id'] != editedItem.user_id:
        flash('You are not authorized to edit this Catalog Item. Please create your own item to edit.')  # NOQA
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Catalog Item Successfully Edited')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template(
            'edititem.html', category_id=category_id,
            item_id=item_id, item=editedItem)


# Delete a Category item
@application.route('/catalog/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteCatalogItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(ItemCatalog).filter_by(id=item_id).one()
    if login_session['user_id'] != itemToDelete.user_id:
        flash('You are not authorized to delete this Catalog Item. Please create your own item to delete.')  # NOQA
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Catalog Item Successfully Deleted')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


# Disconnect based on provider
@application.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showcCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showcCategories'))


if __name__ == '__main__':
    application.secret_key = 'super_secret_key'
    application.debug = False
    application.run()
