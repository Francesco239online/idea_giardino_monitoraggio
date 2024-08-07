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
import json
from urllib.parse import urlparse

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

class DomainSelector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(500), unique=True, nullable=False)
    price_selector = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<DomainSelector {self.domain}>"

logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search-competitor')
def search_competitor():
    return render_template('search_competitor.html')

@app.route('/suggest-selector', methods=['POST'])
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

        # Add the competitor to the database
        new_competitor = Competitor(
            url=url,
            product_id=product_id,
            vendor=vendor,
            price_selector=price_selector,
            competitor_price=competitor_price,
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
            'shopify_product': json.loads(new_competitor.shopify_product)
        }})
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
def search_competitor_product():
    try:
        query = request.args.get('query')
        competitors = Competitor.query.all()
        results = []
        
        for competitor in competitors:
            shopify_product = json.loads(competitor.shopify_product)
            if (query.lower() in shopify_product['title'].lower() or 
                any(query.lower() in variant['sku'].lower() for variant in shopify_product['variants']) or 
                any(query.lower() in variant['barcode'].lower() for variant in shopify_product['variants'])):
                
                competitor_data = {
                    'url': competitor.url,
                    'product_title': shopify_product['title'],
                    'competitor_price': competitor.competitor_price,
                    'shopify_price': shopify_product['variants'][0]['price'],
                    'vendor': shopify_product['vendor'],
                }
                
                shopify_price = float(shopify_product['variants'][0]['price'].replace(',', '.'))
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

                # Normalize the price format
                if '.' in cleaned_price and ',' in cleaned_price:
                    # Case where both '.' and ',' are present; assume ',' is decimal separator
                    if cleaned_price.rfind(',') > cleaned_price.rfind('.'):
                        cleaned_price = cleaned_price.replace('.', '').replace(',', '.')
                    else:
                        cleaned_price = cleaned_price.replace('.', '').replace(',', '.')
                elif ',' in cleaned_price:
                    # Case where only ',' is present, assume ',' is decimal separator
                    cleaned_price = cleaned_price.replace('.', '').replace(',', '.')
                elif '.' in cleaned_price:
                    # Case where only '.' is present
                    cleaned_price = cleaned_price.replace('.', '')

                # Format price for European style (e.g., 1.421,00)
                if '.' in cleaned_price:
                    integer_part, decimal_part = cleaned_price.split('.')
                    formatted_price = f"{integer_part[:-3]}.{integer_part[-3:]},{decimal_part[:2]}"
                else:
                    formatted_price = f"{cleaned_price[:-2]}.{cleaned_price[-2:]}"

                app.logger.info(f"Formatted price: {formatted_price}")
                return formatted_price
            else:
                app.logger.error("Could not extract price from the text")
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
            new_price = scrape_price(competitor.url, competitor.price_selector)
            if (new_price and new_price != competitor.competitor_price):
                competitor.competitor_price = new_price
                db.session.commit()
                app.logger.info(f"Updated price for {competitor.url} to {new_price}")
    except Exception as e:
        app.logger.error(f"Error in update_competitor_prices: {e}")

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
