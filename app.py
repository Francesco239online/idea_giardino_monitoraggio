from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import requests
from bs4 import BeautifulSoup
import logging
import re
import os
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from dotenv import load_dotenv
import json  # Importa la libreria json

app = Flask(__name__)

load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///competitors.db'
db = SQLAlchemy(app)

class Competitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    product_id = db.Column(db.String(100), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    price_selector = db.Column(db.String(100), nullable=False)
    competitor_price = db.Column(db.String(50), nullable=False)
    shopify_product = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Competitor {self.url}>"

logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add-competitor', methods=['POST'])
def add_competitor():
    try:
        url = request.form['url']
        product_id = request.form['product_id']
        vendor = request.form['vendor']
        price_selector = request.form['price_selector']

        app.logger.info(f"Adding competitor with URL: {url}, Product ID: {product_id}, Vendor: {vendor}, Price Selector: {price_selector}")

        if not price_selector:
            raise ValueError('Price selector not found')

        # Scrape the competitor's price
        competitor_price = scrape_price(url, price_selector)
        app.logger.info(f"Scraped price: {competitor_price}")

        if not competitor_price:
            raise ValueError('Could not find price with the given selector')

        # Get the product details from Shopify
        shopify_product = get_shopify_product(product_id)
        
        # Add the competitor to the database
        new_competitor = Competitor(url=url, product_id=product_id, vendor=vendor, price_selector=price_selector, competitor_price=competitor_price, shopify_product=json.dumps(shopify_product))
        db.session.add(new_competitor)
        db.session.commit()

        return jsonify({'status': 'success', 'competitor': new_competitor.id})
    except Exception as e:
        app.logger.error(f"Error in add_competitor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete-competitor', methods=['POST'])
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

@app.route('/get-competitors', methods=['GET'])
def get_competitors():
    competitors = Competitor.query.all()
    return jsonify([{
        'id': c.id,
        'url': c.url,
        'product_id': c.product_id,
        'vendor': c.vendor,
        'price_selector': c.price_selector,
        'competitor_price': c.competitor_price,
        'shopify_product': json.loads(c.shopify_product)  # Convert JSON string back to dictionary
    } for c in competitors])

@app.route('/scrape-price', methods=['POST'])
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
    try:
        update_competitor_prices()
        return jsonify({'status': 'success', 'message': 'Prices updated successfully'})
    except Exception as e:
        app.logger.error(f"Error in update_prices: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-shopify-products', methods=['GET'])
def get_shopify_products():
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

@app.route('/get-shopify-vendors', methods=['GET'])
def get_shopify_vendors():
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

def scrape_price(url, price_selector):
    try:
        app.logger.info(f"Scraping price from URL: {url} with selector: {price_selector}")
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        price = soup.select_one(price_selector)
        if price:
            raw_price_text = price.text.strip()
            app.logger.info(f"Raw price text: {raw_price_text}")

            # Use regex to extract the price
            price_match = re.search(r'\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?', raw_price_text)
            if price_match:
                cleaned_price = price_match.group()
                app.logger.info(f"Cleaned price: {cleaned_price}")
                return cleaned_price
            else:
                app.logger.error("Could not extract price from the text")
        else:
            app.logger.error("Price not found with the given selector")
    except Exception as e:
        app.logger.error(f"Error in scrape_price: {e}")
    return None

def get_shopify_product(product_id):
    url = f"https://{os.getenv('SHOPIFY_STORE_NAME')}.myshopify.com/admin/api/2023-07/products/{product_id}.json"
    headers = {
        "X-Shopify-Access-Token": os.getenv('SHOPIFY_ACCESS_TOKEN')
    }
    response = requests.get(url, headers=headers)
    product = response.json().get('product', {})
    return product

def update_competitor_prices():
    app.logger.info(f"Updating competitor prices at {datetime.now()}")
    competitors = Competitor.query.all()
    for competitor in competitors:
        new_price = scrape_price(competitor.url, competitor.price_selector)
        if new_price:
            competitor.competitor_price = new_price
            db.session.commit()
            app.logger.info(f"Updated price for {competitor.url} to {new_price}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=update_competitor_prices, trigger="interval", hours=24)
    scheduler.start()

    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        pass
