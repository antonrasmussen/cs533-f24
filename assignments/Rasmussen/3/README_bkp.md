## Assignment 3, CS 433/533 Web Security, Fall 2024 
### Anton Rasmussen

For this assignment, we created a script to analyze 100 of the Mozilla top 500 web sites.

This script (`cookie_summary.py`) reads a list of URLs from an input file (`ARASM002@ODU.EDU`), 
fetches each URL, extracts cookies along with their attributes, compiles statistics, and
generates a Markdown report that includes HTTP response details.

```
.
|__ README.md -- the markdown file that you are reading; this is this assignment's final report
|__ cookie_summary.py -- a Python script that reads a list of URLs and helps us produce the final report
|__ output.txt -- the cookie_summary.py script run log (Note that there were two ERRORs)
|__ response_files/ -- directory containing detailed HTTP responses for each site
```

## Extra Credit

- The title of slide 48 in week 4 is a literary reference. Briefly describe this literary reference, both the origin and the meaning in the slides.

I believe the reference in question is "Turtles All The Way Down." From my understanding this comes from a conversation with a teacher 
and a student where the student asks about the Earth and the teacher says the Earth rests on the back of a turtle. 
Then the student asks, "Well, what does the turtle rest on?" and the teacher says "It's turtles all the way down." 
Often this is used when people ask about philosophical concepts like "if God made everything, who made God?" It's this idea that 
at a certain point we have to admit that the problem results in saying something like "God made God," which is infitely recursive. 

Similarly, in the example cited on the slide, if only top-level windows are checked for vulnerabilities then frames can hold malicious code; but, 
if only the first frame within a window is checked then frames within frames can hold vulnerabilites, etc. etc. 

Another way of looking at it is to say that we must be vigilant at every level, all the way down!


## Summary Statistics

| Statistic                  | Value          |
|----------------------------|----------------|
| Total Sites Analyzed       | 100 |
| Total Cookies Collected    | 154 |
| HttpOnly Cookies           | 38 |
| Secure Cookies             | 77 |
| SameSite Cookies           | 63 |
| SameSite Strict            | 4 |
| SameSite Lax               | 15 |
| SameSite None              | 44 |
| Cookies with Path          | 154 |
| Cookies with Non-Root Path | 0 |
| Min Cookies Per Site       | 0 |
| Max Cookies Per Site       | 10 |
| Mean Cookies Per Site      | 1.54 |
| Median Cookies Per Site    | 0.00 |

## Detailed Site Information

| URL | Status Code | Number of Cookies | Cookie Attributes | Final URL |
|-----|-------------|-------------------|-------------------|-----------|
| http://4shared.com | 200 | 1 | day1host:  | https://www.4shared.com |
| http://abcnews.go.com | 200 | 2 | region: ; _dcf:  | https://abcnews.go.com/ |
| http://alibaba.com | 200 | 3 | JSESSIONID: HttpOnly; cna: Secure, SameSite=True: None; ug_se_c: Secure, SameSite=True: None | https://www.alibaba.com/ |
| http://aliexpress.com | 200 | 5 | ali_apache_id: ; intl_common_forever: HttpOnly; intl_locale: ; xman_us_f: Secure, SameSite=True: None; aep_usuc_f: Secure, SameSite=True: None | https://www.aliexpress.us/?gatewayAdapt=glo2usa&_randl_shipto=US |
| http://aol.com | 200 | 0 |  | https://www.aol.com/ |
| http://apache.org | 200 | 0 |  | https://apache.org/ |
| http://apple.com | 200 | 1 | geo:  | https://www.apple.com/ |
| http://arxiv.org | 200 | 0 |  | http://arxiv.org/ |
| http://biblegateway.com | 200 | 0 |  | https://www.biblegateway.com/ |
| http://biglobe.ne.jp | 200 | 0 |  | http://biglobe.ne.jp/ |
| http://bloomberg.com | 200 | 0 |  | https://www.bloomberg.com/tosv2.html?vid=&uuid=8def34e2-9702-11ef-aad8-18303f895785&url=Lw== |
| http://booking.com | 200 | 4 | _implmdnbl: HttpOnly; px_init: HttpOnly, Secure, SameSite=True: Strict; bkng: HttpOnly, Secure, SameSite=True: None; pcm_personalization_disabled: HttpOnly, Secure | https://www.booking.com/index.en-gb.html?label=gen173nr-1BCAEoggI46AdIM1gEaLICiAEBmAEJuAEXyAEM2AEB6AEBiAIBqAIDuALevoq5BsACAdICJDdiMmFmNTAxLWZiMTgtNGMzMy1hZDcxLTFhMTNhMmMxMDQzZdgCBeACAQ&sid=cb3dcda628893cd30c91cbf956e5ad42&keep_landing=1&sb_price_type=total& |
| http://britannica.com | 200 | 6 | bcomID: ; SessionAuth: ; subreturn: ; webstats: ; __mendel: ; __cf_bm: HttpOnly, Secure, SameSite=True: None | https://www.britannica.com:443/ |
| http://buzzfeed.com | 200 | 2 | next-i18next: ; dsl25_frhf:  | https://www.buzzfeed.com/ |
| http://cambridge.org | 200 | 0 |  | https://www.cambridge.org:443/ |
| http://cnil.fr | 200 | 0 |  | https://www.cnil.fr/fr |
| http://cnn.com | 200 | 6 | SecGpc: Secure, SameSite=True: None; countryCode: Secure, SameSite=True: None; stateCode: Secure, SameSite=True: None; geoData: Secure, SameSite=True: None; FastAB: SameSite=True: Lax; wbdFch: Secure, SameSite=True: None | https://www.cnn.com/ |
| http://cointernet.com.co | 200 | 0 |  | https://www.cointernet.com.co/ |
| http://com.com | 200 | 1 | XYZSRV:  | http://com.com/ |
| http://cpanel.net | 200 | 0 |  | https://cpanel.net/ |
| http://discord.com | 200 | 2 | __dcfduid: HttpOnly, Secure, SameSite=True: Lax; __sdcfduid: HttpOnly, Secure, SameSite=True: Lax | https://discord.com/ |
| http://disqus.com | 200 | 0 |  | https://disqus.com/ |
| http://doi.org | 200 | 0 |  | https://www.doi.org/ |
| http://drive.google.com | 200 | 0 |  | https://workspace.google.com/intl/en-US/products/drive/ |
| http://dropbox.com | 200 | 5 | gvc: HttpOnly, Secure, SameSite=True: None; t: HttpOnly, Secure, SameSite=True: None; __Host-js_csrf: Secure, SameSite=True: None; __Host-ss: HttpOnly, Secure, SameSite=True: Strict; locale:  | https://www.dropbox.com/ |
| http://ea.com | 200 | 3 | EDGESCAPE_COUNTRY: ; EDGESCAPE_REGION: ; EDGESCAPE_TIMEZONE:  | https://www.ea.com/ |
| http://elmundo.es | 200 | 0 |  | https://www.elmundo.es/ |
| http://espn.com | 200 | 8 | edition-view: ; edition: ; country: ; connectionspeed: ; region: ; _dcf: ; SWID: ; userab_1:  | https://www.espn.com/ |
| http://feedburner.com | 200 | 0 |  | http://feedburner.google.com/ |
| http://forms.gle | 400 | 0 |  | https://forms.gle/ |
| http://g.co | 200 | 0 |  | https://g.co/ |
| http://get.google.com | 200 | 2 | AEC: HttpOnly, Secure, SameSite=True: lax; NID: HttpOnly, Secure, SameSite=True: none | https://www.google.com/ |
| http://gfycat.com | None | 0 |  | N/A |
| http://globo.com | 200 | 0 |  | https://www.globo.com/ |
| http://godaddy.com | 403 | 3 | market: ; currency: ; akaas_godaddy-com-wildcard: Secure, SameSite=True: None | https://www.godaddy.com/ |
| http://gofundme.com | 200 | 1 | visitor:  | https://www.gofundme.com/ |
| http://goo.ne.jp | 200 | 10 | XSRF-TOKEN: Secure; top_session: HttpOnly, Secure; gootop: Secure; gootopstay: Secure; mental: HttpOnly, Secure; gooproperty: Secure; searchstate: HttpOnly, Secure; TS01ea13e3: ; TS011bfe84: ; TS011667c7:  | https://www.goo.ne.jp |
| http://goodreads.com | 200 | 3 | ccsid: ; locale: ; _session_id2: HttpOnly | https://www.goodreads.com/ |
| http://google.ru | 200 | 1 | NID: HttpOnly, Secure, SameSite=True: none | https://www.google.ru/?gws_rd=ssl |
| http://gravatar.com | 200 | 0 |  | https://gravatar.com/ |
| http://gsmarena.com | 429 | 0 |  | https://www.gsmarena.com/ |
| http://guardian.co.uk | 200 | 2 | GU_mvt_id: Secure; GU_geo_country: Secure | https://www.theguardian.com/us |
| http://hatena.ne.jp | 200 | 1 | b:  | https://www.hatena.ne.jp:443/ |
| http://hindustantimes.com | 200 | 2 | ht-location: ; Meta-Geo:  | https://www.hindustantimes.com/ |
| http://hp.com | 200 | 1 | aka_client_code:  | https://www.hp.com/us-en/home.html |
| http://ign.com | 200 | 1 | geoCC:  | https://www.ign.com/ |
| http://ikea.com | 200 | 2 | _abck: Secure; bm_sz:  | https://www.ikea.com/ |
| http://imageshack.us | 200 | 0 |  | https://imageshack.com/ |
| http://independent.co.uk | 200 | 7 | gdpr: ; subscriber_origin: ; _pc_subscriber_origin: ; feat__support_now_donate_copy: HttpOnly, Secure; feat__pubx_integration: HttpOnly, Secure; esi-uuid: HttpOnly, Secure; esi-permutive-id: Secure | https://www.independent.co.uk/us |
| http://jhu.edu | 200 | 0 |  | https://www.jhu.edu/ |
| http://jstor.org | 200 | 6 | AccessSession: Secure, SameSite=True: Lax; AccessSessionSignature: Secure, SameSite=True: Lax; AccessSessionTimedSignature: Secure, SameSite=True: Lax; UUID: Secure, SameSite=True: None; csrftoken: Secure, SameSite=True: Lax; ReferringRequestId: Secure, SameSite=True: Lax | https://www.jstor.org/ |
| http://justgiving.com | 200 | 0 |  | https://justgiving.com/ |
| http://latimes.com | 200 | 0 |  | https://www.latimes.com:443/ |
| http://liberation.fr | 200 | 0 |  | https://www.liberation.fr/ |
| http://linkedin.com | 200 | 5 | JSESSIONID: Secure, SameSite=True: None; lang: Secure, SameSite=True: None; bcookie: Secure, SameSite=True: None; bscookie: HttpOnly, Secure, SameSite=True: None; lidc: Secure, SameSite=True: None | https://www.linkedin.com/ |
| http://mailchimp.com | 200 | 1 | ak_bmsc: Secure, SameSite=True: None | https://mailchimp.com/ |
| http://marca.com | 200 | 0 |  | https://www.marca.com/ |
| http://naver.com | 200 | 0 |  | https://www.naver.com/ |
| http://news.com.au | 403 | 0 |  | https://www.news.com.au/ |
| http://npr.org | 200 | 0 |  | https://www.npr.org/ |
| http://nytimes.com | 200 | 6 | nyt-a: Secure, SameSite=True: none; nyt-gdpr: ; nyt-purr: Secure, SameSite=True: Lax; nyt-geo: ; datadome: Secure, SameSite=True: Lax; nyt-b3-traceid: Secure, SameSite=True: none | https://www.nytimes.com/ |
| http://offset.com | 200 | 0 |  | https://www.offset.com:443/ |
| http://oup.com | 202 | 0 |  | http://global.oup.com |
| http://outlook.com | 200 | 0 |  | https://www.microsoft.com/en-us/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook?deeplink=%2fowa%2f&sdf=0 |
| http://ovhcloud.com | 200 | 1 | SERVERID116590: HttpOnly | https://us.ovhcloud.com/ |
| http://people.com | 200 | 4 | TMog: ; globalTI_SID: ; Mint: ; pc:  | https://people.com/ |
| http://php.net | 200 | 2 | COUNTRY: ; LAST_NEWS:  | https://www.php.net/ |
| http://pinterest.fr | 200 | 4 | csrftoken: Secure, SameSite=True: lax; _pinterest_sess: HttpOnly, Secure, SameSite=True: none; _auth: HttpOnly, Secure; _routing_id: HttpOnly | https://fr.pinterest.com/ |
| http://pl.wikipedia.org | 200 | 0 |  | https://pl.wikipedia.org/wiki/Wikipedia:Strona_g%C5%82%C3%B3wna |
| http://play.google.com | 200 | 0 |  | https://play.google.com/store/games?device=windows |
| http://playstation.com | 200 | 2 | sbsd_o: Secure, SameSite=True: None; sbsd: HttpOnly, Secure, SameSite=True: None | https://www.playstation.com/en-us/ |
| http://plos.org | 200 | 0 |  | https://plos.org/ |
| http://prezi.com | 200 | 2 | csrftoken: SameSite=True: Lax; __putma: Secure, SameSite=True: none | https://prezi.com/ |
| http://pt.wikipedia.org | 200 | 0 |  | https://pt.wikipedia.org/wiki/Wikip%C3%A9dia:P%C3%A1gina_principal |
| http://reverbnation.com | 200 | 1 | _reverbnation_session: HttpOnly, Secure, SameSite=True: None | https://www.reverbnation.com/ |
| http://sakura.ne.jp | 200 | 0 |  | https://rs.sakura.ad.jp/ |
| http://samsung.com | 200 | 1 | device_type:  | https://www.samsung.com/us/ |
| http://search.yahoo.com | 200 | 1 | PROMO:  | https://search.yahoo.com/ |
| http://sina.com.cn | 200 | 0 |  | https://www.sina.com.cn/ |
| http://spiegel.de | 200 | 0 |  | https://www.spiegel.de/ |
| http://support.google.com | 200 | 2 | NID: HttpOnly, Secure, SameSite=True: none; NID: HttpOnly, Secure, SameSite=True: none | https://support.google.com/ |
| http://thefreedictionary.com | 200 | 0 |  | https://www.thefreedictionary.com |
| http://theverge.com | 200 | 1 | vmidv1: Secure, SameSite=True: Lax | https://www.theverge.com/ |
| http://usgs.gov | 200 | 0 |  | https://www.usgs.gov/ |
| http://vistaprint.com | 200 | 6 | userContext: ; ucSearchParams: ; testUserId: ; optimizelyEndUserId: ; expCtx: ; cf-ipcountry: Secure, SameSite=True: None | https://www.vistaprint.com/ |
| http://walmart.com | 200 | 1 | akavpau_p2: HttpOnly, Secure, SameSite=True: None | https://www.walmart.com/ |
| http://webmd.com | 200 | 6 | ab: ; lrt_wrk: ; gtinfo: ; VisitorId: ; ab: ; __cf_bm: HttpOnly, Secure, SameSite=True: None | https://www.webmd.com/ |
| http://webnode.page | 200 | 6 | PHPSESSID: HttpOnly, Secure, SameSite=True: Lax; ubh: HttpOnly; usi: HttpOnly; tu: ; mfd: ; mfdp:  | https://www.webnode.com/ |
| http://whitehouse.gov | 200 | 0 |  | https://www.whitehouse.gov/ |
| http://wikimedia.org | 200 | 0 |  | https://www.wikimedia.org/ |
| http://wordpress.org | 200 | 0 |  | https://wordpress.org/ |
| http://wp.com | 200 | 6 | tk_ai: Secure, SameSite=True: None; tk_ai_explat: Secure, SameSite=True: None; tk_qs: Secure, SameSite=True: Strict; explat_test_aa_weekly_lohp_2024_week_44: Secure, SameSite=True: None; tk_qs: Secure, SameSite=True: Strict; lohp_headline_copy_test_20241010: Secure, SameSite=True: None | https://wordpress.com/ |
| http://www.gov.uk | 200 | 0 |  | https://www.gov.uk/ |
| http://www.over-blog.com | 200 | 0 |  | http://www.over-blog.com/ |
| http://www.wix.com | 200 | 3 | ssr-caching: ; _wixCIDX: Secure, SameSite=True: None; _wixUIDX: Secure, SameSite=True: None | https://www.wix.com/ |
| http://www.yahoo.com | 200 | 0 |  | https://www.yahoo.com/ |
| http://yadi.sk | 200 | 0 |  | https://360.yandex.com/disk/ |
| http://ytimg.com | None | 0 |  | N/A |
| http://zendesk.com | 200 | 2 | __cf_bm: HttpOnly, Secure, SameSite=True: None; __cfruid: HttpOnly, Secure, SameSite=True: None | https://www.zendesk.com/ |
| http://zippyshare.com | 200 | 0 |  | http://zippyshare.com/ |


## HTTP Response Details

Response details for each site have been saved to individual files in the 'response_files' directory.
