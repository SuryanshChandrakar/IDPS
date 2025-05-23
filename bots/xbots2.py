import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.http import FormRequest, Request, HtmlResponse
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
import random
import time
from urllib.parse import urljoin
import logging
import json
import requests
from scrapy import signals
from scrapy.downloadermiddlewares.httpcompression import HttpCompressionMiddleware
from scrapy.downloadermiddlewares.retry import RetryMiddleware
from scrapy.downloadermiddlewares.httpproxy import HttpProxyMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BotBehaviorMiddleware:
    """Middleware to simulate bot behavior"""
    
    def __init__(self):
        self.last_request_time = 0
        self.request_count = 0
        self.start_time = time.time()
    
    def process_request(self, request, spider):
        """Add bot-like behavior to requests"""
        # Simulate rapid requests
        current_time = time.time()
        if self.last_request_time > 0:
            time_diff = current_time - self.last_request_time
            if time_diff < 0.1:  # Very fast requests
                time.sleep(0.01)  # Minimal delay
        
        self.last_request_time = current_time
        self.request_count += 1
        
        # Add bot-like headers
        request.headers['X-Requested-With'] = 'XMLHttpRequest'
        request.headers['Accept'] = '*/*'
        
        # Add behavior data to all requests
        behavior_data = {
            'has_mouse_movement': 'false',
            'scroll_depth': '0',
            'page_load_time': str(random.uniform(0.05, 0.1)),  # Very fast page loads
            'last_click_time': str(random.uniform(0.01, 0.05))  # Very fast clicks
        }
        
        # Add behavior data to form data if it's a form submission
        if isinstance(request, FormRequest):
            request.formdata.update(behavior_data)
        else:
            # Add as query parameters for GET requests
            request.meta['behavior_data'] = behavior_data
        
        return None

class BotDetectionTester(CrawlSpider):
    name = 'bot_detection_tester'
    allowed_domains = ['localhost']
    start_urls = ['http://localhost:5000']
    
    # Extract all links
    rules = (
        Rule(LinkExtractor(allow=(), deny=(), tags=('a', 'link'), attrs=('href',)), 
             callback='parse_item', 
             follow=True),
    )
    
    def __init__(self, *args, **kwargs):
        super(BotDetectionTester, self).__init__(*args, **kwargs)
        self.visited_urls = set()
        self.forms_submitted = set()
        self.request_times = []
    
    def start_requests(self):
        """Start requests with bot-like behavior"""
        for url in self.start_urls:
            yield Request(
                url,
                callback=self.parse_item,
                meta={
                    'dont_redirect': True,
                    'handle_httpstatus_list': [301, 302, 403, 404, 500]
                }
            )
    
    def parse_item(self, response):
        """Parse each page and interact with all elements"""
        logger.info(f"Testing detection mechanisms on: {response.url}")
        
        # Track request timing for rate limiting detection
        self.request_times.append(time.time())
        
        # Send behavior data to tracking endpoint
        behavior_data = {
            'has_mouse_movement': 'false',
            'scroll_depth': '0',
            'page_load_time': str(random.uniform(0.05, 0.1)),
            'last_click_time': str(random.uniform(0.01, 0.05))
        }
        
        yield Request(
            'http://localhost:5000/api/track-behavior',
            method='POST',
            body=json.dumps(behavior_data),
            headers={'Content-Type': 'application/json'},
            callback=self.parse_behavior_response
        )
        
        # Extract and follow all links
        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(response.url, href)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(
                    full_url,
                    callback=self.parse_item,
                    meta={'dont_redirect': True}
                )
        
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
                        # Fill all fields with random data
                        field_type = input_field.attrib.get('type', 'text')
                        if field_type == 'email':
                            form_data[field_name] = f"bot{random.randint(1000, 9999)}@example.com"
                        elif field_type == 'url':
                            form_data[field_name] = f"http://example{random.randint(1000, 9999)}.com"
                        elif field_type == 'password':
                            form_data[field_name] = f"password{random.randint(1000, 9999)}"
                        else:
                            form_data[field_name] = f"value{random.randint(1000, 9999)}"
                
                # Add behavior data
                form_data.update(behavior_data)
                
                # Submit form with random data
                yield FormRequest(
                    form_url,
                    formdata=form_data,
                    callback=self.parse_item,
                    method=form.attrib.get('method', 'POST'),
                    meta={'dont_redirect': True}
                )
        
        # Extract and follow hidden links
        for hidden_link in response.css('.hidden-link a::attr(href)').getall():
            full_url = urljoin(response.url, hidden_link)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                yield scrapy.Request(
                    full_url,
                    callback=self.parse_item,
                    meta={'dont_redirect': True}
                )
        
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
                
                # Add behavior data
                form_data.update(behavior_data)
                
                # Submit hidden form
                yield FormRequest(
                    form_url,
                    formdata=form_data,
                    callback=self.parse_item,
                    method=hidden_form.attrib.get('method', 'POST'),
                    meta={'dont_redirect': True}
                )
    
    def parse_behavior_response(self, response):
        """Handle response from behavior tracking endpoint"""
        try:
            data = json.loads(response.text)
            if data.get('status') == 'blocked':
                logger.warning("IP has been blocked by the server")
        except Exception as e:
            logger.error(f"Error parsing behavior response: {str(e)}")

def run_spider():
    """Run the spider with custom settings"""
    process = CrawlerProcess({
        'USER_AGENT': 'Mozilla/5.0 (compatible; BotDetectionTester/1.0; +http://example.com/bot)',
        'ROBOTSTXT_OBEY': False,
        'CONCURRENT_REQUESTS': 16,
        'DOWNLOAD_DELAY': 0.1,
        'COOKIES_ENABLED': True,
        'LOG_LEVEL': 'INFO',
        'RETRY_TIMES': 3,
        'RETRY_HTTP_CODES': [500, 502, 503, 504, 522, 524, 408, 429],
        'DOWNLOAD_TIMEOUT': 15,
        'REDIRECT_ENABLED': True,
        'AJAXCRAWL_ENABLED': True,
        'DOWNLOADER_MIDDLEWARES': {
            'xbots2.BotBehaviorMiddleware': 543,
            'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
            'scrapy.downloadermiddlewares.retry.RetryMiddleware': 90,
            'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 110,
        }
    })
    
    process.crawl(BotDetectionTester)
    process.start()

if __name__ == '__main__':
    logger.info("Starting bot detection mechanism testing...")
    run_spider()
