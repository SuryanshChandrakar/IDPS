
import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from scrapy.http import FormRequest
import random
import time
from urllib.parse import urljoin

class BotSpider(CrawlSpider):
    name = 'bot_spider'
    allowed_domains = ['localhost']
    start_urls = ['http://localhost:5000']
    
    # Configure rules for following links
    rules = (
        Rule(LinkExtractor(allow=()), callback='parse_item', follow=True),
    )
    
    def __init__(self, *args, **kwargs):
        super(BotSpider, self).__init__(*args, **kwargs)
        self.visited_urls = set()
        self.session_id = None
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                headers={'User-Agent': self.user_agent},
                dont_filter=True
            )
    
    def parse(self, response):
        # Simulate bot behavior
        if random.random() < 0.3:  # 30% chance to fill forms
            yield from self.handle_forms(response)
        
        # Follow links
        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(response.url, href)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(
                    url=full_url,
                    callback=self.parse_item,
                    headers={'User-Agent': self.user_agent},
                    dont_filter=True
                )
    
    def parse_item(self, response):
        # Simulate page interaction
        time.sleep(random.uniform(0.1, 0.5))  # Simulate page load time
        
        # Handle forms
        yield from self.handle_forms(response)
        
        # Follow more links
        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(response.url, href)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(
                    url=full_url,
                    callback=self.parse_item,
                    headers={'User-Agent': self.user_agent},
                    dont_filter=True
                )
    
    def handle_forms(self, response):
        for form in response.css('form'):
            form_data = {}
            
            # Fill all input fields
            for input_field in form.css('input'):
                field_name = input_field.attrib.get('name', '')
                field_type = input_field.attrib.get('type', 'text')
                
                if field_type == 'hidden':
                    form_data[field_name] = input_field.attrib.get('value', '')
                elif field_type == 'text':
                    form_data[field_name] = f'bot_{random.randint(1000, 9999)}'
                elif field_type == 'password':
                    form_data[field_name] = 'bot_password'
                elif field_type == 'email':
                    form_data[field_name] = f'bot_{random.randint(1000, 9999)}@example.com'
            
            # Submit form
            if form_data:
                yield FormRequest(
                    url=response.urljoin(form.attrib.get('action', '')),
                    formdata=form_data,
                    callback=self.parse_item,
                    headers={'User-Agent': self.user_agent},
                    dont_filter=True
                )

def run_spider():
    process = CrawlerProcess({
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'ROBOTSTXT_OBEY': False,
        'CONCURRENT_REQUESTS': 1,
        'DOWNLOAD_DELAY': 1,
        'COOKIES_ENABLED': True,
        'LOG_LEVEL': 'INFO'
    })
    
    process.crawl(BotSpider)
    process.start()

if __name__ == '__main__':
    run_spider()
