from playwright.sync_api import sync_playwright
import time

GOOGLE_ADS = "https://adstransparency.google.com/?region=anywhere&domain={}"


def get_google_ads_transperency(domain: str) -> dict:
    """Search domain in google ads transperency servis.

    Args:
        domain (str): domain name.

    Returns:
        dict: return title and google ads details links.
    """
    data = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1920, "height": 1080})
        page = context.new_page()

        page.goto(GOOGLE_ADS.format(domain))

        page.get_by_role("button", name="See all ads").click()
        for i in range(20):  # make the range as long as needed
            page.mouse.wheel(0, 15000)
            time.sleep(1)
            i += 1

        links = page.query_selector_all("creative-preview")
        print(len(links))
        for link in links:
            href = link.query_selector("a")
            href2 = href.get_attribute("href")
            data[link.inner_text()] = "https://adstransparency.google.com{}".format(
                href2
            )
        browser.close()
        return data
