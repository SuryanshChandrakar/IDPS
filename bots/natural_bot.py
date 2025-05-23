import scrapy
import time
import random
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class NaturalBotSpider(scrapy.Spider):
    name = 'natural_bot'
    start_urls = ['http://localhost:5000']
    
    custom_settings = {
        'CONCURRENT_REQUESTS': 5,
        'DOWNLOAD_DELAY': random.uniform(0.1, 0.5),  # Faster than human
        'USER_AGENT': 'Mozilla/5.0 (compatible; NaturalBot/1.0; +http://example.com/bot)',
        'ROBOTSTXT_OBEY': False,
        'HTTPCACHE_ENABLED': False
    }
    
    def parse(self, response):
        # Parse page with BeautifulSoup for better HTML analysis
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Find all links (including hidden ones)
        all_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Prioritize "interesting" links that bots typically look for
            if any(keyword in href.lower() for keyword in ['admin', 'login', 'config', 'wp-', 'secret']):
                all_links.insert(0, href)  # Higher priority
            else:
                all_links.append(href)
        
        # 2. Find all forms and input fields
        forms = soup.find_all('form')
        for form in forms:
            form_data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('type') in ['text', 'password', 'hidden']:
                    name = input_tag.get('name', '')
                    value = input_tag.get('value', '')
                    
                    # Simulate bot behavior - fill all fields
                    if not value:
                        if 'pass' in name.lower():
                            value = 'bot_password'
                        elif 'user' in name.lower():
                            value = 'bot_user'
                        else:
                            value = 'filled_by_bot'
                    
                    form_data[name] = value
            
            # Submit form very quickly (bot-like)
            form_url = urljoin(response.url, form.get('action', ''))
            yield scrapy.FormRequest(
                form_url,
                formdata=form_data,
                callback=self.handle_form_submission,
                errback=self.handle_error,
                meta={'form_start': time.time()}
            )
        
        # 3. Follow links (prioritizing suspicious ones)
        for link in all_links:
            yield scrapy.Request(
                urljoin(response.url, link),
                callback=self.parse_page,
                errback=self.handle_error
            )
    
    def parse_page(self, response):
        # Just continue crawling
        self.logger.info(f"Visited: {response.url}")
        yield from self.parse(response)
    
    def handle_form_submission(self, response):
        fill_time = time.time() - response.meta['form_start']
        self.logger.info(f"Form submitted in {fill_time:.2f}s to {response.url}")
        
        # Check if we got blocked
        if response.status == 403 and "Access Denied" in response.text:
            self.logger.warning(f"BLOCKED after submitting form to {response.url}")
    
    def handle_error(self, failure):
        self.logger.error(f"Error accessing: {failure.request.url}")