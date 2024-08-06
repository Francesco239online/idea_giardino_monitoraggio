from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup
import logging
import re
import os
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env
load_dotenv()

app = Flask(__name__)

SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
SHOPIFY_STORE_NAME = "spazio-verde-3315"

# In-memory store for competitors (this should be replaced with a database in production)
competitors = []

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
        
        # Add the competitor to the in-memory store
        competitor = {
            'url': url,
            'product_id': product_id,
            'vendor': vendor,
            'price_selector': price_selector,
            'competitor_price': competitor_price,
            'shopify_product': shopify_product
        }
        competitors.append(competitor)

        return jsonify({'status': 'success', 'competitor': competitor})
    except Exception as e:
        app.logger.error(f"Error in add_competitor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete-competitor', methods=['POST'])
def delete_competitor():
    try:
        index = int(request.form['index'])
        if 0 <= index < len(competitors):
            competitors.pop(index)
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400
    except Exception as e:
        app.logger.error(f"Error in delete_competitor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-competitors', methods=['GET'])
def get_competitors():
    return jsonify(competitors)

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
    url = f"https://{SHOPIFY_STORE_NAME}.myshopify.com/admin/api/2023-07/products/{product_id}.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
    }
    response = requests.get(url, headers=headers)
    product = response.json().get('product', {})
    return product

@app.route('/get-shopify-products', methods=['GET'])
def get_shopify_products():
    url = f"https://{SHOPIFY_STORE_NAME}.myshopify.com/admin/api/2023-07/products.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
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
    url = f"https://{SHOPIFY_STORE_NAME}.myshopify.com/admin/api/2023-07/products.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
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

@app.route('/get-products-by-vendor', methods=['GET'])
def get_products_by_vendor():
    vendor = request.args.get('vendor')
    url = f"https://{SHOPIFY_STORE_NAME}.myshopify.com/admin/api/2023-07/products.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
    }
    
    products = []
    page_info = None

    while True:
        params = {'limit': 250, 'vendor': vendor}
        if page_info:
            params['page_info'] = page_info

        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        if 'products' in data:
            products.extend([product for product in data['products'] if product['vendor'] == vendor])

        if 'link' in response.headers:
            links = requests.utils.parse_header_links(response.headers['link'])
            next_link = next((link for link in links if link['rel'] == 'next'), None)
            if next_link:
                page_info = next_link['url'].split('page_info=')[1]
            else:
                break
        else:
            break

    return jsonify(products)

if __name__ == '__main__':
    app.run(debug=True)
