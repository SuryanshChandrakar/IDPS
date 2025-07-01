import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.http import FormRequest
import random
import time

class DashboardBotSpider(scrapy.Spider):
    name = 'dashboard_bot'
    allowed_domains = ['localhost']
    start_urls = ['http://localhost:5010/login']
    
    def __init__(self, *args, **kwargs):
        super(DashboardBotSpider, self).__init__(*args, **kwargs)
        self.session_id = None
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    def start_requests(self):
        # Start with login page
        yield scrapy.Request(
            url=self.start_urls[0],
            callback=self.parse_login,
            headers={'User-Agent': self.user_agent},
            dont_filter=True
        )
    
    def parse_login(self, response):
        # Extract form data
        form_data = {
            'username': f'bot_{random.randint(1000, 9999)}',
            'password': 'bot_password',
            'fingerprint': f'fp-{random.randint(1000, 9999)}'
        }
        
        # Add behavior tracking data
        form_data.update({
            'has_mouse_movement': 'true',
            'scroll_depth': '0.5',
            'last_click_time': '0.5',
            'page_load_time': '1.0',
            'mouse_movement_count': '10',
            'time_on_page': '2.0'
        })
        
        # Submit login form
        yield FormRequest(
            url=response.url,
            formdata=form_data,
            callback=self.after_login,
            headers={'User-Agent': self.user_agent},
            dont_filter=True
        )
    
    def after_login(self, response):
        if 'dashboard' in response.url:
            self.logger.info("Successfully logged in!")
            
            # Try to access honeypot links
            honeypot_urls = [
                f"{response.url}?admin_token=123",
                f"{response.url}?debug_mode=true",
                f"{response.url}?api_key=test"
            ]
            
            for url in honeypot_urls:
                yield scrapy.Request(
                    url=url,
                    callback=self.parse_dashboard,
                    headers={'User-Agent': self.user_agent},
                    dont_filter=True
                )
        else:
            self.logger.error("Login failed!")
    
    def parse_dashboard(self, response):
        # Simulate bot behavior on dashboard
        time.sleep(random.uniform(0.1, 0.3))
        
        # Extract and follow all links
        for href in response.css('a::attr(href)').getall():
            if href.startswith('/'):
                full_url = f"http://localhost:5010{href}"
                yield scrapy.Request(
                    url=full_url,
                    callback=self.parse_dashboard,
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
    
    process.crawl(DashboardBotSpider)
    process.start()

if __name__ == '__main__':
    run_spider() 