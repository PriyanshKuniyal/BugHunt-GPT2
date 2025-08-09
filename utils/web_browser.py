import time
import random
import re
import json
import string
from playwright.sync_api import sync_playwright
from playwright_stealth import stealth_sync
from bs4 import BeautifulSoup
import undetected_playwright as up
from fake_useragent import UserAgent

class TextBasedBrowser:
    def __init__(self, headless=False, user_data_dir=None, proxy=None):
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=headless,
            args = [
                '--disable-blink-features=AutomationControlled',
                '--disable-infobars',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                f'--proxy-server={proxy}' if proxy else ''
            ],
            slow_mo=random.uniform(80, 150)
        )
        
        # Random human-like user agent
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        
        self.context = self.browser.new_context(
            user_agent=user_agent,
            viewport={"width": 1366, "height": 768},
            locale="en-US,en;q=0.9",
            timezone_id="America/New_York"
        )
        
        self.page = self.context.new_page()
        
        # Apply stealth techniques
        stealth_sync(self.page)
        
        # Configure human-like behavior parameters
        self.typing_speed = 0.08  # Base seconds per character
        self.scroll_delay_range = (0.5, 2.0)
        self.action_delay_range = (0.2, 1.5)
        
        # State tracking
        self.current_page_text = ""
        self.interactive_elements = []
        self.page_history = []

    def navigate(self, url):
        """Human-like navigation with randomized delays"""
        time.sleep(random.uniform(1.0, 3.0))
        self.page.goto(url)
        time.sleep(random.uniform(2.0, 5.0))
        return self._capture_page_state()

    def _capture_page_state(self):
        """Create detailed text representation of the current page"""
        # Get HTML content
        html = self.page.content()
        
        # Use BeautifulSoup to parse and describe the page
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove scripts and styles
        for script in soup(["script", "style"]):
            script.extract()
        
        # Create page description
        page_description = f"# PAGE: {self.page.title()}\n"
        page_description += f"URL: {self.page.url}\n\n"
        
        # Describe the main content
        main_content = soup.find('main') or soup.body
        if main_content:
            page_description += self._describe_element(main_content)
        
        # Identify interactive elements
        self.interactive_elements = []
        interactive = soup.select('a, button, input, textarea, select, [role="button"], [onclick]')
        
        page_description += "\n## INTERACTIVE ELEMENTS:\n"
        for idx, element in enumerate(interactive[:50]):  # Limit to 50 elements
            element_desc = self._describe_interactive_element(element, idx)
            page_description += element_desc + "\n"
            self.interactive_elements.append({
                "id": idx,
                "element": element,
                "description": element_desc
            })
        
        self.current_page_text = page_description
        return page_description

    def _describe_element(self, element, depth=0):
        """Recursively describe an HTML element and its children"""
        description = ""
        indent = "  " * depth
        
        # Skip invisible elements
        if not element.visible or element.get('style', '').lower().find('display:none') != -1:
            return ""
        
        # Describe element based on type
        if element.name == 'h1':
            description += f"\n{indent}# {element.get_text(strip=True)}\n"
        elif element.name == 'h2':
            description += f"\n{indent}## {element.get_text(strip=True)}\n"
        elif element.name == 'h3':
            description += f"\n{indent}### {element.get_text(strip=True)}\n"
        elif element.name == 'p':
            description += f"{indent}{element.get_text(strip=True)}\n"
        elif element.name == 'ul':
            for li in element.find_all('li', recursive=False):
                description += f"{indent}- {li.get_text(strip=True)}\n"
        elif element.name == 'div' or element.name == 'section':
            description += f"\n{indent}[Container]\n"
        
        # Process children
        for child in element.children:
            if child.name:
                description += self._describe_element(child, depth+1)
        
        return description

    def _describe_interactive_element(self, element, idx):
        """Create text description of an interactive element"""
        element_type = element.name
        text_content = element.get_text(strip=True, separator=' ') or ""
        placeholder = element.get('placeholder', '')
        aria_label = element.get('aria-label', '')
        name = element.get('name', '')
        value = element.get('value', '')
        
        # Clean up text content
        if text_content:
            text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        # Determine element description
        if element_type == 'a':
            href = element.get('href', '')
            return f"{idx}. [LINK] {text_content or aria_label or href} -> {href}"
        elif element_type == 'button':
            return f"{idx}. [BUTTON] {text_content or aria_label or placeholder or value}"
        elif element_type == 'input':
            input_type = element.get('type', 'text')
            return f"{idx}. [INPUT:{input_type}] {placeholder or aria_label or name} {value}"
        elif element_type == 'textarea':
            return f"{idx}. [TEXTAREA] {placeholder or aria_label or name}"
        elif element_type == 'select':
            return f"{idx}. [DROPDOWN] {placeholder or aria_label or name}"
        else:
            return f"{idx}. [INTERACTIVE] {element_type} {text_content or aria_label}"

    def scroll_page(self, scroll_count=3):
        """Simulate human-like scrolling behavior"""
        for _ in range(scroll_count):
            scroll_amount = random.randint(300, 700)
            self.page.mouse.wheel(0, scroll_amount)
            time.sleep(random.uniform(*self.scroll_delay_range))
        return self._capture_page_state()

    def click_element(self, element_id):
        """Click an element with human-like behavior"""
        if element_id < 0 or element_id >= len(self.interactive_elements):
            return "Invalid element ID"
        
        element_info = self.interactive_elements[element_id]
        selector = self._get_element_selector(element_info["element"])
        
        # Human-like mouse movement simulation
        box = self.page.locator(selector).bounding_box()
        target_x = box['x'] + box['width'] / 2
        target_y = box['y'] + box['height'] / 2
        
        # Move mouse in a human-like path
        current_x, current_y = self.page.mouse.position
        steps = random.randint(3, 7)
        for i in range(steps):
            t = i / steps
            x = current_x + (target_x - current_x) * t + random.randint(-10, 10)
            y = current_y + (target_y - current_y) * t + random.randint(-10, 10)
            self.page.mouse.move(x, y)
            time.sleep(random.uniform(0.01, 0.1))
        
        # Random delay before click
        time.sleep(random.uniform(*self.action_delay_range))
        
        # Click with human-like duration
        self.page.locator(selector).click(delay=random.randint(100, 300))
        
        # Random delay after click
        time.sleep(random.uniform(0.5, 3.0))
        
        return self._capture_page_state()

    def type_text(self, element_id, text):
        """Type text with human-like behavior"""
        if element_id < 0 or element_id >= len(self.interactive_elements):
            return "Invalid element ID"
        
        element_info = self.interactive_elements[element_id]
        selector = self._get_element_selector(element_info["element"])
        
        # Click to focus
        self.page.locator(selector).click()
        time.sleep(random.uniform(0.3, 1.2))
        
        # Type with human-like speed and errors
        for char in text:
            # Vary typing speed
            delay = self.typing_speed * random.uniform(0.8, 1.2)
            time.sleep(delay)
            
            # Simulate occasional typos (4% chance)
            if random.random() < 0.04:
                # Type a wrong character
                wrong_char = random.choice(string.ascii_letters + string.digits)
                self.page.keyboard.press(wrong_char)
                time.sleep(random.uniform(0.2, 0.5))
                
                # Correct the mistake
                self.page.keyboard.press('Backspace')
                time.sleep(delay * 1.5)
            
            # Type the correct character
            self.page.keyboard.press(char)
        
        # Final random delay
        time.sleep(random.uniform(0.5, 1.5))
        return self._capture_page_state()

    def _get_element_selector(self, element):
        """Generate a unique selector for an element"""
        # Try to get a stable selector based on attributes
        if element.get('id'):
            return f'#{element["id"]}'
        if element.get('name'):
            return f'[name="{element["name"]}"]'
        if element.get('class'):
            classes = ' '.join(element['class'])
            return f'.{classes.split()[0]}'
        
        # Fallback to text-based selector
        text_content = element.get_text(strip=True)
        if text_content:
            return f'text="{text_content[:30]}"'
        
        # Final fallback
        return f'xpath=//{element.name}[{element.sourceline}]'

    def bypass_security(self):
        """Attempt to bypass security measures"""
        # Cloudflare bypass
        if "Checking if the site connection is secure" in self.page.content():
            time.sleep(random.uniform(5, 15))
            if self.page.locator('text="Verify you are human"').count() > 0:
                self.page.locator('text="Verify you are human"').click()
                time.sleep(3)
        
        # reCAPTCHA handling
        if self.page.locator('[src*="recaptcha"]').count() > 0:
            # Click on the checkbox
            self.page.frame_locator('iframe[src*="recaptcha"]').locator('#recaptcha-anchor').click()
            time.sleep(3)
            
            # Check if challenge appeared
            if self.page.locator('text="Try again later"').count() > 0:
                return "CAPTCHA challenge encountered. Manual intervention may be required."
        
        return "Security bypass attempted. Continue with operations."

    def execute_ai_instructions(self, instructions):
        """Execute a series of AI-generated instructions"""
        results = []
        
        for instruction in instructions:
            action = instruction.get("action")
            element_id = instruction.get("element_id")
            text = instruction.get("text")
            url = instruction.get("url")
            
            try:
                if action == "navigate":
                    results.append(self.navigate(url))
                elif action == "click":
                    results.append(self.click_element(element_id))
                elif action == "type":
                    results.append(self.type_text(element_id, text))
                elif action == "scroll":
                    results.append(self.scroll_page())
                elif action == "bypass_security":
                    results.append(self.bypass_security())
                else:
                    results.append("Unknown action")
            except Exception as e:
                results.append(f"Action failed: {str(e)}")
        
        return results

    def close(self):
        """Clean up resources"""
        self.context.close()
        self.browser.close()
        self.playwright.stop()


# Example usage:
if __name__ == "__main__":
    browser = TextBasedBrowser(
        headless=False,
        user_data_dir="/path/to/user/data",
        proxy="http://user:pass@proxy:port"
    )
    
    # AI-generated instructions based on page analysis
    instructions = [
        {"action": "navigate", "url": "https://example.com/login"},
        {"action": "type", "element_id": 5, "text": "ai_user@example.com"},
        {"action": "type", "element_id": 6, "text": "secure_password123"},
        {"action": "click", "element_id": 7},  # Login button
        {"action": "scroll"},
        {"action": "click", "element_id": 12},  # Profile link
        {"action": "scroll"},
        {"action": "click", "element_id": 15}   # Logout button
    ]
    
    results = browser.execute_ai_instructions(instructions)
    browser.close()
    
    # Save results for AI analysis
    with open("browser_session.json", "w") as f:
        json.dump(results, f, indent=2)
