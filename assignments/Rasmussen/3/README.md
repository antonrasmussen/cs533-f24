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
|__ output_2.txt -- the cookie_summary.py script run log for getting response_files_2
|__ response_files -- directory containing detailed HTTP responses for each site
|__ response_files_2 -- the directory containing raw HTTP response headers for each site
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
| Total Cookies Collected    | 180 |
| HttpOnly Cookies           | 14 |
| Secure Cookies             | 32 |
| SameSite Cookies           | 21 |
| SameSite Strict            | 2 |
| SameSite Lax               | 5 |
| SameSite None              | 14 |
| Cookies with Path          | 180 |
| Cookies with Non-Root Path | 0 |
| Min Cookies Per Site       | 0 |
| Max Cookies Per Site       | 25 |
| Mean Cookies Per Site      | 1.80 |
| Median Cookies Per Site    | 0.50 |

## Detailed Site Information

| URL | Status Code | Number of Cookies | Cookie Attributes | Final URL |
|-----|-------------|-------------------|-------------------|-----------|
| http://4shared.com | 200 | 1 | day1host:  | https://www.4shared.com |
| http://abcnews.go.com | 200 | 2 | region: ; _dcf:  | https://abcnews.go.com/ |
| http://alibaba.com | 200 | 3 | JSESSIONID: HttpOnly; cna: ; ug_se_c:  | https://www.alibaba.com/ |
| http://aliexpress.com | 200 | 5 | ali_apache_id: ; intl_common_forever: ; intl_locale: ; xman_us_f: ; aep_usuc_f:  | https://www.aliexpress.us/?gatewayAdapt=glo2usa&_randl_shipto=US |
| http://aol.com | 200 | 0 |  | https://www.aol.com/ |
| http://apache.org | 200 | 0 |  | https://apache.org/ |
| http://apple.com | 200 | 1 | geo:  | https://www.apple.com/ |
| http://arxiv.org | 200 | 0 |  | http://arxiv.org/ |
| http://biblegateway.com | 200 | 0 |  | https://www.biblegateway.com/ |
| http://biglobe.ne.jp | 200 | 0 |  | http://biglobe.ne.jp/ |
| http://bloomberg.com | 200 | 0 |  | https://www.bloomberg.com/tosv2.html?vid=&uuid=e7b312ca-98a9-11ef-bfd0-d079897f148b&url=Lw== |
| http://booking.com | 200 | 4 | _implmdnbl: ; px_init: ; bkng: ; pcm_personalization_disabled:  | https://www.booking.com/index.en-gb.html?label=gen173nr-1BCAEoggI46AdIM1gEaLICiAEBmAEJuAEXyAEM2AEB6AEBiAIBqAIDuAKjy5W5BsACAdICJDljN2ViYWQwLTUzOWYtNDU2Yi1iN2UyLTE3ZmEyZmMxMTdkN9gCBeACAQ&sid=817776c974ecc40cc874114edfdd7f90&keep_landing=1&sb_price_type=total& |
| http://britannica.com | 200 | 6 | bcomID: ; SessionAuth: ; subreturn: ; webstats: ; __mendel: ; __cf_bm:  | https://www.britannica.com:443/ |
| http://buzzfeed.com | 200 | 2 | next-i18next: ; dsl25_frhf:  | https://www.buzzfeed.com/ |
| http://cambridge.org | 403 | 0 |  | https://www.cambridge.org:443/ |
| http://cnil.fr | 200 | 0 |  | https://www.cnil.fr/fr |
| http://cnn.com | 200 | 25 | SecGpc: Secure, SameSite=True: None; countryCode: Secure, SameSite=True: None; stateCode: Secure, SameSite=True: None; geoData: Secure, SameSite=True: None; FastAB: ; 1: ; 2: ; 3: ; 4: ; 5: ; 6: ; 7: ; 8: ; 9: ; 10: ; 11: ; 12: ; 13: ; 14: ; 15: ; 16: ; 17: ; 18: ; 19: ; wbdFch: Secure, SameSite=True: None | https://www.cnn.com/ |
| http://cointernet.com.co | 200 | 0 |  | https://www.cointernet.com.co/ |
| http://com.com | 200 | 1 | XYZSRV:  | http://com.com/ |
| http://cpanel.net | 200 | 0 |  | https://cpanel.net/ |
| http://discord.com | 200 | 2 | __dcfduid: ; __sdcfduid:  | https://discord.com/ |
| http://disqus.com | 200 | 0 |  | https://disqus.com/ |
| http://doi.org | 200 | 0 |  | https://www.doi.org/ |
| http://drive.google.com | 200 | 0 |  | https://workspace.google.com/intl/en-US/products/drive/ |
| http://dropbox.com | 200 | 5 | gvc: ; t: ; __Host-js_csrf: ; __Host-ss: ; locale:  | https://www.dropbox.com/ |
| http://ea.com | 200 | 3 | EDGESCAPE_COUNTRY: ; EDGESCAPE_REGION: ; EDGESCAPE_TIMEZONE:  | https://www.ea.com/ |
| http://elmundo.es | 200 | 0 |  | https://www.elmundo.es/ |
| http://espn.com | 200 | 7 | edition-view: ; country: ; edition: ; connectionspeed: ; region: ; _dcf: ; SWID:  | https://www.espn.com/ |
| http://feedburner.com | 200 | 0 |  | http://feedburner.google.com/ |
| http://forms.gle | 400 | 0 |  | https://forms.gle/ |
| http://g.co | 200 | 0 |  | https://g.co/ |
| http://get.google.com | 200 | 2 | AEC: ; NID:  | https://www.google.com/ |
| http://gfycat.com | None | 0 |  | http://gfycat.com |
| http://globo.com | 200 | 0 |  | https://www.globo.com/ |
| http://godaddy.com | 403 | 3 | market: ; currency: ; akaas_godaddy-com-wildcard: Secure, SameSite=True: None | https://www.godaddy.com/ |
| http://gofundme.com | 200 | 1 | visitor:  | https://www.gofundme.com/ |
| http://goo.ne.jp | 200 | 10 | XSRF-TOKEN: ; top_session: ; gootop: ; gootopstay: ; mental: ; gooproperty: ; searchstate: ; TS01ea13e3: ; TS011bfe84: ; TS011667c7:  | https://www.goo.ne.jp |
| http://goodreads.com | 200 | 3 | ccsid: ; locale: ; _session_id2:  | https://www.goodreads.com/ |
| http://google.ru | 200 | 1 | NID:  | https://www.google.ru/?gws_rd=ssl |
| http://gravatar.com | 200 | 0 |  | https://gravatar.com/ |
| http://gsmarena.com | 429 | 0 |  | https://www.gsmarena.com/ |
| http://guardian.co.uk | 200 | 2 | GU_mvt_id: ; GU_geo_country: Secure | https://www.theguardian.com/us |
| http://hatena.ne.jp | 200 | 1 | b:  | https://www.hatena.ne.jp:443/ |
| http://hindustantimes.com | 200 | 2 | ht-location: ; Meta-Geo:  | https://www.hindustantimes.com/ |
| http://hp.com | 503 | 1 | aka_client_code:  | https://www.hp.com/us-en/home.html |
| http://ign.com | 200 | 1 | geoCC:  | https://www.ign.com/ |
| http://ikea.com | 200 | 2 | _abck: ; bm_sz:  | https://www.ikea.com/ |
| http://imageshack.us | 204 | 0 |  | https://imageshack.com/ |
| http://independent.co.uk | 200 | 14 | gdpr: ; subscriber_origin: ; _pc_subscriber_origin: ; feat__support_now_donate_copy: HttpOnly, Secure; feat__pubx_integration: HttpOnly, Secure; esi-uuid: HttpOnly, Secure; esi-permutive-id: Secure; gdpr: ; subscriber_origin: ; _pc_subscriber_origin: ; feat__support_now_donate_copy: HttpOnly, Secure; feat__pubx_integration: HttpOnly, Secure; esi-uuid: HttpOnly, Secure; esi-permutive-id: Secure | https://www.independent.co.uk/us |
| http://jhu.edu | 200 | 0 |  | https://www.jhu.edu/ |
| http://jstor.org | 200 | 6 | AccessSession: Secure, SameSite=True: Lax; AccessSessionSignature: Secure, SameSite=True: Lax; AccessSessionTimedSignature: Secure, SameSite=True: Lax; UUID: ; csrftoken: ; ReferringRequestId: Secure, SameSite=True: Lax | https://www.jstor.org/ |
| http://justgiving.com | 200 | 0 |  | https://justgiving.com/ |
| http://latimes.com | 200 | 0 |  | https://www.latimes.com:443/ |
| http://liberation.fr | 200 | 0 |  | https://www.liberation.fr/ |
| http://linkedin.com | 200 | 5 | JSESSIONID: Secure, SameSite=True: None; lang: Secure, SameSite=True: None; bcookie: Secure; bscookie: Secure; lidc:  | https://www.linkedin.com/ |
| http://mailchimp.com | 200 | 1 | ak_bmsc:  | https://mailchimp.com/ |
| http://marca.com | 200 | 0 |  | https://www.marca.com/ |
| http://naver.com | 200 | 0 |  | https://www.naver.com/ |
| http://news.com.au | 403 | 0 |  | https://www.news.com.au/ |
| http://npr.org | 200 | 0 |  | https://www.npr.org/ |
| http://nytimes.com | 200 | 6 | nyt-a: ; nyt-gdpr: ; nyt-purr: ; nyt-geo: ; datadome: ; nyt-b3-traceid: Secure, SameSite=True: none | https://www.nytimes.com/ |
| http://offset.com | 200 | 0 |  | https://www.offset.com:443/ |
| http://oup.com | 202 | 0 |  | http://global.oup.com |
| http://outlook.com | 440 | 0 |  | https://www.microsoft.com/en-us/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook?deeplink=%2fowa%2f&sdf=0 |
| http://ovhcloud.com | 200 | 1 | SERVERID116590: HttpOnly | https://us.ovhcloud.com/ |
| http://people.com | 200 | 4 | TMog: ; globalTI_SID: ; Mint: ; pc:  | https://people.com/ |
| http://php.net | 200 | 2 | COUNTRY: ; LAST_NEWS:  | https://www.php.net/ |
| http://pinterest.fr | 200 | 4 | csrftoken: ; _pinterest_sess: ; _auth: ; _routing_id: HttpOnly | https://fr.pinterest.com/ |
| http://pl.wikipedia.org | 200 | 0 |  | https://pl.wikipedia.org/wiki/Wikipedia:Strona_g%C5%82%C3%B3wna |
| http://play.google.com | 200 | 0 |  | https://play.google.com/store/games?device=windows |
| http://playstation.com | 200 | 2 | sbsd_o: Secure, SameSite=True: None; sbsd: HttpOnly, Secure, SameSite=True: None | https://www.playstation.com/en-us/ |
| http://plos.org | 200 | 0 |  | https://plos.org/ |
| http://prezi.com | 406 | 2 | csrftoken: ; __putma:  | https://prezi.com/ |
| http://pt.wikipedia.org | 200 | 0 |  | https://pt.wikipedia.org/wiki/Wikip%C3%A9dia:P%C3%A1gina_principal |
| http://reverbnation.com | 200 | 1 | _reverbnation_session:  | https://www.reverbnation.com/ |
| http://sakura.ne.jp | 200 | 0 |  | https://rs.sakura.ad.jp/ |
| http://samsung.com | 403 | 1 | device_type:  | https://www.samsung.com/us/ |
| http://search.yahoo.com | 200 | 1 | PROMO:  | https://search.yahoo.com/ |
| http://sina.com.cn | 200 | 0 |  | https://www.sina.com.cn/ |
| http://spiegel.de | 200 | 0 |  | https://www.spiegel.de/ |
| http://support.google.com | 404 | 2 | NID: ; NID:  | https://support.google.com/ |
| http://thefreedictionary.com | 200 | 0 |  | https://www.thefreedictionary.com |
| http://theverge.com | 200 | 1 | vmidv1:  | https://www.theverge.com/ |
| http://usgs.gov | 200 | 0 |  | https://www.usgs.gov/ |
| http://vistaprint.com | 200 | 6 | userContext: ; ucSearchParams: ; testUserId: ; optimizelyEndUserId: ; expCtx: ; cf-ipcountry: Secure, SameSite=True: None | https://www.vistaprint.com/ |
| http://walmart.com | 200 | 1 | akavpau_p2: HttpOnly, Secure, SameSite=True: None | https://www.walmart.com/ |
| http://webmd.com | 200 | 6 | ab: ; lrt_wrk: ; gtinfo: ; VisitorId: ; ab: ; __cf_bm:  | https://www.webmd.com/ |
| http://webnode.page | 200 | 6 | PHPSESSID: HttpOnly, Secure, SameSite=True: Lax; ubh: ; usi: HttpOnly; tu: ; mfd: ; mfdp:  | https://www.webnode.com/ |
| http://whitehouse.gov | 200 | 0 |  | https://www.whitehouse.gov/ |
| http://wikimedia.org | 200 | 0 |  | https://www.wikimedia.org/ |
| http://wordpress.org | 200 | 0 |  | https://wordpress.org/ |
| http://wp.com | 200 | 6 | tk_ai: ; tk_ai_explat: ; tk_qs: Secure, SameSite=True: Strict; explat_test_aa_weekly_lohp_2024_week_44: ; tk_qs: Secure, SameSite=True: Strict; lohp_headline_copy_test_20241010:  | https://wordpress.com/ |
| http://www.gov.uk | 200 | 0 |  | https://www.gov.uk/ |
| http://www.over-blog.com | 200 | 0 |  | http://www.over-blog.com/ |
| http://www.wix.com | 200 | 3 | ssr-caching: ; _wixCIDX: ; _wixUIDX:  | https://www.wix.com/ |
| http://www.yahoo.com | 200 | 0 |  | https://www.yahoo.com/ |
| http://yadi.sk | 200 | 1 | _yasc:  | https://360.yandex.com/showcaptcha?cc=1&mt=1A4B9F6E59CDBD8033FE629FF8B90A70B646ED6B1669731244E73C9B0F80C1F252222377A6F54C73930B2A6EBBEBDB143CE9BFEDA2491E1E5DC4E0B2FDE0FEEA0CD5FEE03CCCE18CE9EC28745327BD27BBD0FDF8AC1BECA06135F0A70C567F1FE277C23CDD23249E0961C74CE6AB621DB5784C5E87ED86EFB930B6D8F31D85EF763F5D7D003042F33819F63E969A90620CC89E2EDF9CE79AD41DDE0C04599A51510B0769729DD7BF0A23D309F4DA8FC78D450DE36535F6504DBACE1193A553AEC6F6FFB3AF2978C02C1D35D4E2F735AC4CD269BF760E159C59A9E5F916BD2FA220AF1C9B94A6B5EBB33CCA6DA2114A25F8EE1DD1850FD8&retpath=aHR0cHM6Ly8zNjAueWFuZGV4LmNvbS9kaXNrPw%2C%2C_ac9e0b52b81fb592f059b77cbfdd374e&t=2/1730504321/044623796117116e8ce1bfe951f0acc3&u=5451714703820639203&s=de0928e378cb6aaaade19a75d8dc7d5a |
| http://ytimg.com | None | 0 |  | http://ytimg.com |
| http://zendesk.com | 200 | 2 | __cf_bm: ; __cfruid: HttpOnly, Secure, SameSite=True: None | https://www.zendesk.com/ |
| http://zippyshare.com | 200 | 0 |  | http://zippyshare.com/ |


## HTTP Response Details

Response details for each site have been saved to individual files in the 'response_files' directory.
