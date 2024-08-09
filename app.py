from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import pandas as pd
from flask_migrate import Migrate
from io import BytesIO
from flask import send_file
from bs4 import BeautifulSoup
import logging
import re
import os
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json
from urllib.parse import urlparse

# Funzione per estrarre il nome del fornitore dal dominio
def get_vendor_name(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    
    # Ritorna il secondo elemento se esiste, altrimenti ritorna il primo
    return domain_parts[-2] if len(domain_parts) > 1 else domain_parts[0]

app = Flask(__name__)

# Carica la configurazione dal file .env
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///competitors.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Assicurati di avere una chiave segreta nel file .env
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
update_secret = os.getenv('UPDATE_SECRET')

# Inizializza l'estensione di Flask
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Competitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    product_id = db.Column(db.String(100), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    price_selector = db.Column(db.String(100), nullable=False)
    competitor_price = db.Column(db.String(50), nullable=False)
    shopify_product = db.Column(db.Text, nullable=False)
    shopify_price = db.Column(db.String(50), nullable=True)  # Aggiungi questa colonna
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Competitor {self.url}>"

class DomainSelector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(500), unique=True, nullable=False)
    price_selector = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<DomainSelector {self.domain}>"

class PriceUpdateLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    product_id = db.Column(db.String(100), nullable=False)
    old_price = db.Column(db.String(50), nullable=False)
    new_price = db.Column(db.String(50), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # "varied" or "unchanged"

    def __repr__(self):
        return f"<PriceUpdateLog {self.product_id}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=150)])
    remember = BooleanField('remember me')

class UserForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=150)])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!')
    users = User.query.all()
    return render_template('manage_users.html', form=form, users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!')
    return redirect(url_for('manage_users'))

logging.basicConfig(level=logging.INFO)

@app.route('/get-vendors', methods=['GET'])
@login_required
def get_vendors():
    try:
        vendors = db.session.query(Competitor.vendor).distinct().all()
        vendor_list = [vendor[0] for vendor in vendors]
        return jsonify({'vendors': vendor_list})
    except Exception as e:
        app.logger.error(f"Error in get_vendors: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/search-competitor')
@login_required
def search_competitor():
    return render_template('search_competitor.html')

@app.route('/price-update-stats')
@login_required
def price_update_stats():
    return render_template('price_update_stats.html')

@app.route('/suggest-selector', methods=['POST'])
@login_required
def suggest_selector():
    try:
        url = request.json['url']
        parsed_url = urlparse(url)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        domain_selector = DomainSelector.query.filter_by(domain=domain).first()

        if domain_selector:
            return jsonify({'status': 'success', 'price_selector': domain_selector.price_selector})
        else:
            return jsonify({'status': 'error', 'message': 'No selector found for this domain'}), 404
    except Exception as e:
        app.logger.error(f"Error in suggest_selector: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/add-competitor', methods=['POST'])
@login_required
def add_competitor():
    try:
        url = request.form['url']
        product_id = request.form['product_id']
        vendor = request.form['vendor']
        price_selector = request.form['price_selector']

        app.logger.info(f"Adding competitor with URL: {url}, Product ID: {product_id}, Vendor: {vendor}, Price Selector: {price_selector}")

        if not price_selector:
            raise ValueError('Price selector not found')

        # Check for duplicate URL
        if Competitor.query.filter_by(url=url).first():
            return jsonify({'status': 'error', 'message': 'Duplicate URL'}), 400

        # Get the domain from the URL
        parsed_url = urlparse(url)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Check for duplicate Shopify product for the same competitor domain
        existing_competitor = Competitor.query.filter_by(product_id=product_id).all()
        for competitor in existing_competitor:
            competitor_domain = urlparse(competitor.url)
            competitor_domain_root = f"{competitor_domain.scheme}://{competitor_domain.netloc}"
            if competitor_domain_root == domain:
                return jsonify({'status': 'error', 'message': 'Duplicate Shopify product for this competitor domain'}), 400

        # Scrape the competitor's price
        competitor_price = scrape_price(url, price_selector)
        app.logger.info(f"Scraped price: {competitor_price}")

        if not competitor_price:
            raise ValueError('Could not find price with the given selector')

        # Get the product details from Shopify
        shopify_product = get_shopify_product(product_id)
        shopify_price = shopify_product['variants'][0]['price']  # Ottieni il prezzo Shopify

        # Add the competitor to the database
        new_competitor = Competitor(
            url=url,
            product_id=product_id,
            vendor=vendor,
            price_selector=price_selector,
            competitor_price=competitor_price,
            shopify_price=shopify_price,  # Aggiungi il prezzo Shopify
            shopify_product=json.dumps(shopify_product)
        )
        db.session.add(new_competitor)
        db.session.commit()

        # Save the price selector for the domain
        domain_selector = DomainSelector.query.filter_by(domain=domain).first()
        if not domain_selector:
            new_domain_selector = DomainSelector(domain=domain, price_selector=price_selector)
            db.session.add(new_domain_selector)
            db.session.commit()
        elif domain_selector.price_selector != price_selector:
            domain_selector.price_selector = price_selector
            db.session.commit()

        return jsonify({'status': 'success', 'competitor': {
            'id': new_competitor.id,
            'url': new_competitor.url,
            'product_id': new_competitor.product_id,
            'vendor': new_competitor.vendor,
            'price_selector': new_competitor.price_selector,
            'competitor_price': new_competitor.competitor_price,
            'shopify_price': new_competitor.shopify_price,  # Includi il prezzo Shopify nei dati di risposta
            'shopify_product': json.loads(new_competitor.shopify_product)
        }})
    except Exception as e:
        app.logger.error(f"Error in add_competitor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete-competitor', methods=['POST'])
@login_required
def delete_competitor():
    try:
        competitor_id = request.form['competitor_id']
        competitor = Competitor.query.get(competitor_id)
        if competitor:
            db.session.delete(competitor)
            db.session.commit()
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Invalid competitor ID'}), 400
    except Exception as e:
        app.logger.error(f"Error in delete_competitor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/export', methods=['GET'])
@login_required
def export_data():
    competitors = Competitor.query.all()
    
    data = []
    for competitor in competitors:
        shopify_product = json.loads(competitor.shopify_product)
        shopify_price = float(competitor.shopify_price.replace(',', '.'))
        competitor_price = float(competitor.competitor_price.replace(',', '.'))
        
        # Calcola il profitto
        profit_percentage = round(((shopify_price - competitor_price) / competitor_price) * 100, 2)
        
        # Estrai la radice del dominio usando la funzione get_vendor_name
        vendor_name = get_vendor_name(competitor.url)
        
        # Aggiungi i dati alla lista
        data.append([
            shopify_product['variants'][0]['sku'],
            shopify_price,
            vendor_name,  # Utilizza il nome del fornitore estratto
            competitor_price,
            f"{profit_percentage:.2f}%"
        ])
    
    # Converti i dati in un DataFrame
    df = pd.DataFrame(data, columns=[
        'SKU Prodotto Shopify', 
        'Prezzo Prodotto Shopify', 
        'Concorrente', 
        'Prezzo Concorrente', 
        'Profitto (%)'
    ])
    
    # Salva i dati in un file Excel in memoria
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)
    
    return send_file(output, as_attachment=True, download_name="concorrenza_export.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/get-competitors', methods=['GET'])
@login_required
def get_competitors():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        pagination = Competitor.query.paginate(page=page, per_page=per_page, error_out=False)
        competitors = pagination.items
        app.logger.info(f"Fetched {len(competitors)} competitors from page {page} with {per_page} per page")

        competitors_data = [{
            'id': c.id,
            'url': c.url,
            'product_id': c.product_id,
            'vendor': c.vendor,
            'price_selector': c.price_selector,
            'competitor_price': c.competitor_price,
            'shopify_price': c.shopify_price,  # Includi il prezzo Shopify nei dati
            'shopify_product': json.loads(c.shopify_product)
        } for c in competitors]

        response = {
            'competitors': competitors_data,
            'total': pagination.total,
            'pages': pagination.pages,
            'page': pagination.page,
            'per_page': pagination.per_page
        }
        
        app.logger.info(f"Competitors data prepared for response: {response}")
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Error in get_competitors: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Numero totale di prodotti integrati dei concorrenti
    total_competitor_products = db.session.query(Competitor).count()

    # Dettaglio per fornitore per l'intero database (solo se necessario mostrarlo)
    suppliers = db.session.query(Competitor.vendor, db.func.count(Competitor.id)).group_by(Competitor.vendor).all()

    results = {}
    if request.method == 'POST':
        from_date = request.form.get('from_date')
        to_date = request.form.get('to_date')

        # Converti le date in oggetti datetime e aggiungi la parte di tempo
        from_date = datetime.strptime(from_date, '%Y-%m-%d')
        to_date = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)  # Aggiungi un giorno per includere l'intera giornata finale

        # Filtra i prodotti per data
        products_in_range = Competitor.query.filter(
            Competitor.timestamp.between(from_date, to_date)
        ).all()

        # Conta il totale dei prodotti nel range
        total_products_in_range = len(products_in_range)

        # Conta i prodotti per fornitore nel range
        suppliers_in_range = db.session.query(
            Competitor.vendor, db.func.count(Competitor.id)
        ).filter(
            Competitor.timestamp.between(from_date, to_date)
        ).group_by(Competitor.vendor).all()

        results = {
            'total_products_in_range': total_products_in_range,
            'suppliers_in_range': suppliers_in_range,
            'from_date': from_date.strftime('%Y-%m-%d'),
            'to_date': to_date.strftime('%Y-%m-%d')
        }

    return render_template(
        'dashboard.html',
        total_competitor_products=total_competitor_products,
        suppliers=suppliers,
        results=results
    )

@app.route('/scrape-price', methods=['POST'])
@login_required
def scrape_price_route():
    try:
        url = request.json['url']
        price_selector = request.json['price_selector']
        if not price_selector:
            raise ValueError('Price selector not found')
        price = scrape_price(url, price_selector)
        return jsonify({'status': 'success', 'price_selector': price_selector, 'price': price})
    except Exception as e:
        app.logger.error(f"Error in scrape_price_route: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/update-prices', methods=['POST'])
def update_prices():
    if request.json.get('secret') != update_secret:
        abort(401)
    try:
        update_competitor_prices()
        update_shopify_prices()  # Aggiungi l'aggiornamento dei prezzi Shopify
        stats = get_price_update_stats_summary()  # Funzione per ottenere il riepilogo delle statistiche
        return jsonify({'status': 'success', 'message': 'Prices updated successfully', 'stats': stats})
    except Exception as e:
        app.logger.error(f"Error in update_prices: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def get_price_update_stats_summary():
    logs = PriceUpdateLog.query.all()
    varied = len([log for log in logs if log.status == "varied"])
    unchanged = len([log for log in logs if log.status == "unchanged"])
    return {
        "total_updates": len(logs),
        "varied": varied,
        "unchanged": unchanged
    }
    
@app.route('/get-update-results', methods=['GET'])
@login_required
def get_update_results():
    try:
        logs = PriceUpdateLog.query.order_by(PriceUpdateLog.timestamp.desc()).limit(100).all()
        results = {
            "varied": 0,
            "unchanged": 0,
            "vendors": {},
            "price_changes": []
        }

        for log in logs:
            if log.status == "varied":
                results["varied"] += 1
            else:
                results["unchanged"] += 1

            if log.vendor not in results["vendors"]:
                results["vendors"][log.vendor] = {
                    "varied": 0,
                    "unchanged": 0
                }
            results["vendors"][log.vendor][log.status] += 1

            competitor = Competitor.query.filter_by(product_id=log.product_id).first()
            if competitor:
                results["price_changes"].append({
                    "timestamp": log.timestamp,
                    "product_id": log.product_id,
                    "old_price": log.old_price,
                    "new_price": log.new_price,
                    "vendor": log.vendor,
                    "status": log.status,
                    "url": competitor.url,
                    "product_title": json.loads(competitor.shopify_product)["title"]
                })

        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error in get_update_results: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-shopify-products', methods=['GET'])
@login_required
def get_shopify_products():
    try:
        url = f"https://{os.getenv('SHOPIFY_STORE_NAME')}.myshopify.com/admin/api/2023-07/products.json"
        headers = {
            "X-Shopify-Access-Token": os.getenv('SHOPIFY_ACCESS_TOKEN')
        }
        
        products = []
        page_info = None

        while True:
            params = {'limit': 250}
            if page_info:
                params['page_info'] = page_info

            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            
            if 'products' in data:
                products.extend(data['products'])

            if 'link' in response.headers:
                links = requests.utils.parse_header_links(response.headers['link'])
                next_link = next((link for link in links if link['rel'] == 'next'), None)
                if next_link:
                    page_info = next_link['url'].split('page_info=')[1]
                else:
                    break
            else:
                break

        return jsonify({'products': products, 'total': len(products)})
    except Exception as e:
        app.logger.error(f"Error in get_shopify_products: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/get-shopify-vendors', methods=['GET'])
@login_required
def get_shopify_vendors():
    try:
        url = f"https://{os.getenv('SHOPIFY_STORE_NAME')}.myshopify.com/admin/api/2023-07/products.json"
        headers = {
            "X-Shopify-Access-Token": os.getenv('SHOPIFY_ACCESS_TOKEN')
        }
        
        vendors = set()
        page_info = None

        while True:
            params = {'limit': 250}
            if page_info:
                params['page_info'] = page_info

            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            
            if 'products' in data:
                for product in data['products']:
                    vendors.add(product['vendor'])

            if 'link' in response.headers:
                links = requests.utils.parse_header_links(response.headers['link'])
                next_link = next((link for link in links if link['rel'] == 'next'), None)
                if next_link:
                    page_info = next_link['url'].split('page_info=')[1]
                else:
                    break
            else:
                break

        return jsonify(list(vendors))
    except Exception as e:
        app.logger.error(f"Error in get_shopify_vendors: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/search-competitor-product', methods=['GET'])
@login_required
def search_competitor_product():
    try:
        query = request.args.get('query')
        vendor = request.args.get('vendor')  # Aggiungi questa linea per ottenere il parametro vendor
        competitors = Competitor.query.all()
        results = []
        
        for competitor in competitors:
            shopify_product = json.loads(competitor.shopify_product)
            if (query.lower() in shopify_product['title'].lower() or 
                any(query.lower() in variant['sku'].lower() for variant in shopify_product['variants']) or 
                any(query.lower() in variant['barcode'].lower() for variant in shopify_product['variants'])):
                
                if vendor and shopify_product['vendor'] != vendor:
                    continue  # Skip the product if the vendor does not match the filter
                
                competitor_data = {
                    'id': competitor.id,  # Aggiungi l'ID del competitor per la funzionalità di eliminazione
                    'url': competitor.url,
                    'product_title': shopify_product['title'],
                    'product_handle': shopify_product['handle'],
                    'competitor_price': competitor.competitor_price,
                    'shopify_price': competitor.shopify_price,
                    'vendor': shopify_product['vendor'],
                }
                
                shopify_price = float(competitor.shopify_price.replace(',', '.'))
                competitor_price = float(competitor.competitor_price.replace('.', '').replace(',', '.'))
                if shopify_price < competitor_price:
                    percentage = ((competitor_price - shopify_price) / competitor_price * 100)
                    competitor_data['price_comparison'] = f"Prezzo inferiore del {percentage:.2f}% (€{(competitor_price - shopify_price):.2f})"
                    competitor_data['comparison_class'] = 'lower'
                elif shopify_price > competitor_price:
                    percentage = ((shopify_price - competitor_price) / competitor_price * 100)
                    competitor_data['price_comparison'] = f"Prezzo superiore del {percentage:.2f}% (€{(shopify_price - competitor_price):.2f})"
                    competitor_data['comparison_class'] = 'higher'
                else:
                    competitor_data['price_comparison'] = 'Prezzo uguale'
                    competitor_data['comparison_class'] = 'equal'
                
                results.append(competitor_data)
        
        return jsonify({'results': results})
    except Exception as e:
        app.logger.error(f"Error in search_competitor_product: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

    
@app.route('/update-shopify-prices-manually', methods=['GET'])
def update_shopify_prices_manually():
    update_shopify_prices()
    return "Shopify prices updated manually", 200

@app.route('/get-price-update-stats', methods=['GET'])
@login_required
def get_price_update_stats():
    try:
        from_date = request.args.get('from_date', None)
        to_date = request.args.get('to_date', None)
        
        query = PriceUpdateLog.query
        if from_date:
            query = query.filter(PriceUpdateLog.timestamp >= datetime.strptime(from_date, '%Y-%m-%d'))
        if to_date:
            query = query.filter(PriceUpdateLog.timestamp <= datetime.strptime(to_date, '%Y-%m-%d'))
        
        logs = query.all()
        stats = {
            "total_updates": len(logs),
            "varied": 0,
            "unchanged": 0,
            "vendors": {}
        }

        for log in logs:
            if log.status == "varied":
                stats["varied"] += 1
            else:
                stats["unchanged"] += 1
            
            if log.vendor not in stats["vendors"]:
                stats["vendors"][log.vendor] = {
                    "varied": 0,
                    "unchanged": 0
                }
            stats["vendors"][log.vendor][log.status] += 1
        
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Error in get_price_update_stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    

@app.route('/get-price-change-report', methods=['GET'])
@login_required
def get_price_change_report():
    try:
        from_date = request.args.get('from_date', None)
        to_date = request.args.get('to_date', None)
        vendor = request.args.get('vendor', None)
        
        query = PriceUpdateLog.query
        if from_date:
            query = query.filter(PriceUpdateLog.timestamp >= datetime.strptime(from_date, '%Y-%m-%d'))
        if to_date:
            query = query.filter(PriceUpdateLog.timestamp <= datetime.strptime(to_date, '%Y-%m-%d'))
        if vendor:
            query = query.filter_by(vendor=vendor)
        
        logs = query.all()
        price_changes = []
        for log in logs:
            old_price_normalized = re.sub(r'[^\d]', '', log.old_price)
            new_price_normalized = re.sub(r'[^\d]', '', log.new_price)
            if old_price_normalized != new_price_normalized:  # Aggiungi questo controllo
                competitor = Competitor.query.filter_by(product_id=log.product_id).first()
                price_changes.append({
                    "timestamp": log.timestamp,
                    "product_id": log.product_id,
                    "old_price": log.old_price,
                    "new_price": log.new_price,
                    "vendor": log.vendor,
                    "status": log.status,
                    "url": competitor.url if competitor else None,
                    "product_title": json.loads(competitor.shopify_product)["title"] if competitor else None
                })
        
        return jsonify({'price_changes': price_changes})
    except Exception as e:
        app.logger.error(f"Error in get_price_change_report: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/get-product-vendor', methods=['GET'])
@login_required
def get_product_vendor():
    try:
        product_id = request.args.get('product_id')
        shopify_product = get_shopify_product(product_id)
        if shopify_product:
            vendor = shopify_product.get('vendor', 'Vendor not found')
            return jsonify({'status': 'success', 'vendor': vendor})
        else:
            return jsonify({'status': 'error', 'message': 'Product not found'}), 404
    except Exception as e:
        app.logger.error(f"Error in get_product_vendor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def scrape_price(url, price_selector):
    try:
        app.logger.info(f"Scraping price from URL: {url} with selector: {price_selector}")
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        price_element = soup.select_one(price_selector)
        if price_element:
            raw_price_text = price_element.text.strip()
            app.logger.info(f"Raw price text: {raw_price_text}")

            # Rimuovere eventuali spazi extra e caratteri non-ASCII
            raw_price_text = re.sub(r'[^\x00-\x7F]+', '', raw_price_text)
            raw_price_text = raw_price_text.replace('\xa0', '').replace('\n', '').replace('\r', '').strip()

            # Rimuovere eventuali simboli di valuta e altri caratteri non numerici eccetto ., e ,
            raw_price_text = re.sub(r'[^\d.,]', '', raw_price_text)

            # Trova tutti i possibili prezzi nel testo
            price_matches = re.findall(r'\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?', raw_price_text)
            if not price_matches:
                app.logger.error("Could not extract price from the text")
                return None
            
            # Prendere il primo prezzo trovato
            cleaned_price = price_matches[0]

            # Gestire il formato del prezzo europeo (punto come separatore delle migliaia, virgola come decimale)
            if '.' in cleaned_price and ',' in cleaned_price:
                # Assumiamo che il punto sia il separatore delle migliaia e la virgola il decimale
                cleaned_price = cleaned_price.replace('.', '').replace(',', '.')
            elif ',' in cleaned_price:
                # Caso in cui c'è solo la virgola, assumiamo che sia il separatore decimale
                cleaned_price = cleaned_price.replace('.', '').replace(',', '.')
            elif '.' in cleaned_price:
                # Caso in cui c'è solo il punto, può essere o il separatore delle migliaia o il decimale
                if cleaned_price.count('.') == 1 and len(cleaned_price.split('.')[-1]) == 3:
                    # Caso in cui il punto è il separatore delle migliaia
                    cleaned_price = cleaned_price.replace('.', '')

            # Convertire il prezzo pulito in un formato float standard
            formatted_price = f"{float(cleaned_price):.2f}".replace('.', ',')

            app.logger.info(f"Formatted price: {formatted_price}")
            return formatted_price
        else:
            app.logger.error("Price not found with the given selector")
    except Exception as e:
        app.logger.error(f"Error in scrape_price: {e}")
    return None

def get_shopify_product(product_id):
    try:
        url = f"https://{os.getenv('SHOPIFY_STORE_NAME')}.myshopify.com/admin/api/2023-07/products/{product_id}.json"
        headers = {
            "X-Shopify-Access-Token": os.getenv('SHOPIFY_ACCESS_TOKEN')
        }
        response = requests.get(url, headers=headers)
        product = response.json().get('product', {})
        return product
    except Exception as e:
        app.logger.error(f"Error in get_shopify_product: {e}")
        return {}

def get_cost_per_article(product_id):
    try:
        url = f"https://{os.getenv('SHOPIFY_STORE_NAME')}.myshopify.com/admin/api/2023-07/variants/{product_id}.json"
        headers = {
            "X-Shopify-Access-Token": os.getenv('SHOPIFY_ACCESS_TOKEN')
        }
        response = requests.get(url, headers=headers)
        variant = response.json().get('variant', {})
        return variant.get('cost', 0.0)
    except Exception as e:
        app.logger.error(f"Error in get_cost_per_article: {e}")
        return 0.0

def update_competitor_prices():
    try:
        app.logger.info(f"Updating competitor prices at {datetime.now()}")
        competitors = Competitor.query.all()
        for competitor in competitors:
            old_price = competitor.competitor_price
            new_price = scrape_price(competitor.url, competitor.price_selector)
            if new_price:
                if new_price != old_price:
                    status = "varied"
                    competitor.competitor_price = new_price
                else:
                    status = "unchanged"
                
                # Log the price update
                log = PriceUpdateLog(
                    product_id=competitor.product_id,
                    old_price=old_price,
                    new_price=new_price,
                    vendor=competitor.vendor,
                    status=status
                )
                db.session.add(log)
                
                db.session.commit()
                app.logger.info(f"Updated price for {competitor.url} to {new_price}")
    except Exception as e:
        app.logger.error(f"Error in update_competitor_prices: {e}")

def update_shopify_prices():
    try:
        app.logger.info(f"Updating Shopify prices at {datetime.now()}")
        competitors = Competitor.query.all()
        for competitor in competitors:
            shopify_product = get_shopify_product(competitor.product_id)
            if shopify_product and 'variants' in shopify_product and len(shopify_product['variants']) > 0:
                new_shopify_price = shopify_product['variants'][0]['price']
                if new_shopify_price != competitor.shopify_price:
                    competitor.shopify_price = new_shopify_price
                    db.session.commit()
                    app.logger.info(f"Updated Shopify price for {competitor.url} to {new_shopify_price}")
    except Exception as e:
        app.logger.error(f"Error in update_shopify_prices: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Specifica l'username e la password che desideri
        admin_username = 'Francesco'
        admin_password = '27-Nov1994'

        # Creazione di un utente amministratore se non esiste
        if not User.query.filter_by(username=admin_username).first():
            hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
            new_user = User(username=admin_username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=update_competitor_prices, trigger="interval", hours=24)
    scheduler.add_job(func=update_shopify_prices, trigger="interval", hours=24)
    scheduler.start()

    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        pass