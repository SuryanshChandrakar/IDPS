import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.http import FormRequest
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
import random
import time
from urllib.parse import urljoin
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MaliciousBotSpider(CrawlSpider):
    name = 'malicious_bot'
    allowed_domains = ['localhost']
    start_urls = ['http://localhost:5000']
    
    # Extract all links, including hidden ones
    rules = (
        Rule(LinkExtractor(allow=(), deny=(), tags=('a', 'link'), attrs=('href',)), 
             callback='parse_item', 
             follow=True),
    )
    
    def __init__(self, *args, **kwargs):
        super(MaliciousBotSpider, self).__init__(*args, **kwargs)
        self.visited_urls = set()
        self.forms_submitted = set()
        self.current_session = None
    
    def parse_item(self, response):
        """Parse each page and interact with all discovered elements"""
        # Log the current URL
        logger.info(f"Crawling: {response.url}")
        
        # Extract and follow all links
        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(response.url, href)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(full_url, callback=self.parse_item)
        
        # Find and submit all forms
        for form in response.css('form'):
            form_url = urljoin(response.url, form.attrib.get('action', ''))
            if form_url not in self.forms_submitted:
                self.forms_submitted.add(form_url)
                
                # Extract all input fields
                form_data = {}
                for input_field in form.css('input'):
                    field_name = input_field.attrib.get('name', '')
                    if field_name:
                        # Fill fields with random data
                        field_type = input_field.attrib.get('type', 'text')
                        if field_type == 'email':
                            form_data[field_name] = f"bot{random.randint(1000, 9999)}@example.com"
                        elif field_type == 'url':
                            form_data[field_name] = f"http://example{random.randint(1000, 9999)}.com"
                        elif field_type == 'password':
                            form_data[field_name] = f"password{random.randint(1000, 9999)}"
                        else:
                            form_data[field_name] = f"value{random.randint(1000, 9999)}"
                
                # Submit form with random data
                yield FormRequest(
                    form_url,
                    formdata=form_data,
                    callback=self.parse_item,
                    method=form.attrib.get('method', 'POST')
                )
        
        # Simulate rapid page interactions
        if random.random() < 0.3:  # 30% chance to simulate rapid interactions
            for _ in range(random.randint(3, 8)):
                yield scrapy.Request(
                    response.url,
                    callback=self.parse_item,
                    dont_filter=True,
                    meta={'rapid_interaction': True}
                )
                time.sleep(0.01)  # Very short delay to simulate rapid clicks
        
        # Extract and follow hidden links
        for hidden_link in response.css('.hidden-link a::attr(href)').getall():
            full_url = urljoin(response.url, hidden_link)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(full_url, callback=self.parse_item)
        
        # Extract and interact with hidden forms
        for hidden_form in response.css('.hidden-field form'):
            form_url = urljoin(response.url, hidden_form.attrib.get('action', ''))
            if form_url not in self.forms_submitted:
                self.forms_submitted.add(form_url)
                
                # Fill hidden form fields
                form_data = {}
                for input_field in hidden_form.css('input'):
                    field_name = input_field.attrib.get('name', '')
                    if field_name:
                        form_data[field_name] = f"hidden_value{random.randint(1000, 9999)}"
                
                # Submit hidden form
                yield FormRequest(
                    form_url,
                    formdata=form_data,
                    callback=self.parse_item,
                    method=hidden_form.attrib.get('method', 'POST')
                )

def run_spider():
    """Run the spider with custom settings"""
    process = CrawlerProcess({
        'USER_AGENT': 'Mozilla/5.0 (compatible; MaliciousBot/1.0; +http://example.com/bot)',
        'ROBOTSTXT_OBEY': False,
        'CONCURRENT_REQUESTS': 16,
        'DOWNLOAD_DELAY': 0.1,  # Very short delay to simulate rapid requests
        'COOKIES_ENABLED': True,
        'LOG_LEVEL': 'INFO',
        'RETRY_TIMES': 3,
        'RETRY_HTTP_CODES': [500, 502, 503, 504, 522, 524, 408, 429],
        'DOWNLOAD_TIMEOUT': 15,
        'REDIRECT_ENABLED': True,
        'AJAXCRAWL_ENABLED': True,
    })
    
    process.crawl(MaliciousBotSpider)
    process.start()

if __name__ == '__main__':
    logger.info("Starting malicious bot attack simulation...")
    run_spider()
