
## Assignment 4, CS 433/533 Web Security, Fall 2024
### Anton Rasmussen

For this assignment, we explored website framing vulnerabilities by testing the frameability of 100 popular websites and demonstrating a cookie theft attack using iframes.

The project consists of the following components:

1. A website framing test that checks whether popular websites can be embedded in iframes, documenting the reasons why some sites cannot be framed (e.g. X-Frame-Options headers, Content-Security-Policy).

In the image below we see boxes with both frameable and non-frameable content.

![Screenshot showing rendered and non-rendered frames](images/Rendered_and_Non-Rendered_Frames.png)

2. A demonstration of a cookie theft vulnerability using iframes, showing how cookies scoped only with the Path attribute can be accessed by malicious pages.

In the images below we see a vulnerable page that sets a cookie and then an attacker page that steals the cookie from the vulnerable page via an iFrame.

![Screenshot showing cookie theft vulnerability](images/Vulnerable_Page_Cookie.png)

![Screenshot showing cookie theft attacker](images/Attacker_Page_iFrame_Cookie_Stolen.png)


3. Bypassing 10 sites that are not framable:
- http://localhost:4000/frameable/alibaba.com.html
- http://localhost:4000/frameable/aol.com.html
- http://localhost:4000/frameable/apple.com.html
- http://localhost:4000/frameable/buzzfeed.com.html
- http://localhost:4000/frameable/discord.com.html
- http://localhost:4000/frameable/dropbox.com.html
- http://localhost:4000/frameable/play.google.com.html
- http://localhost:4000/frameable/prezi.com.html
- http://localhost:4000/frameable/whitehouse.gov.html
- http://localhost:4000/frameable/wordpress.org.html

In the first image below, we see that Alibaba appears to be unframeable. However, by running the bypass endpoint with the Alibaba URL we are able to then go back to the Alibaba page and see a new box that shows we have bypassed the frame restriction. 

![Screenshot showing non-frameable box](images/Alibaba_Non-Frameable.png)
![Screenshot showing bypass JSON](images/Alibaba_Bypass.png)
![Screenshot showing bypass JSON](images/Alibaba_Bypass_Box.png)

We were able to test for the ability to bypass using both the proxy technique and the sandbox technique; however, each of the above 10 use the proxy technique.

5. >Week 5 lecture, slide 65 has a literary reference in its title. Briefly describe this literary reference (but "Buzz Lightyear" does not count), both the origin and the meaning in the slides.


    - This is in reference to Coleridge's "Rime of the Ancient Mariner" -- it is a book about a group of sailors who are stranded in the ocean and who become dehydrated but, ironically, are surrounded by water.

    - The quote is "Water, water, everywhere, Nor any drop to drink." 

    - The stranded sailors can't drink the water surrounding them because it's ocean saltwater and if they drink it they'll die. 

    - The reason this relates to the subject of XSS is because there are so many different parsers developers have to employ that it can be hard to know how they will interact because of how complex their interrelationships are. 

    - When input isn't parsed properly (because knowing all the edge cases is difficult), it leads to increased vulnerability to things like XSS.


### The project includes:

- A main index page with links to both demonstrations
- Individual HTML pages for each tested website showing whether it can be framed
    - For the 10 websites above we also show how it can be bypassed in a second box
- An attacker page that attempts to steal cookies from a vulnerable page
- A vulnerable page that sets cookies with only path-based protection
- A directory of all HTTP responses for each site

After completing this project we have the following directory structure:

```
.
├── README.md
├── data
│   ├── ARASM002@ODU.EDU
│   └── ARASM002_test (sample file for testing)
├── frame-path-attack
│   ├── attacker-page
│   │   └── attacker.html
│   └── vulnerable-page
│       └── vulnerable.html
├── frameable
│   ├── 4shared.com.html
│   ├── abcnews.go.com.html
│   ├── alibaba.com.html
│   ├── aliexpress.com.html
│   ├── aol.com.html
│   ├── apache.org.html
│   ├── apple.com.html
│   ├── arxiv.org.html
│   ├── biblegateway.com.html
│   ├── biglobe.ne.jp.html
│   ├── bloomberg.com.html
│   ├── booking.com.html
│   ├── britannica.com.html
│   ├── buzzfeed.com.html
│   ├── cambridge.org.html
│   ├── cnil.fr.html
│   ├── cnn.com.html
│   ├── cointernet.com.co.html
│   ├── com.com.html
│   ├── cpanel.net.html
│   ├── discord.com.html
│   ├── disqus.com.html
│   ├── doi.org.html
│   ├── drive.google.com.html
│   ├── dropbox.com.html
│   ├── ea.com.html
│   ├── elmundo.es.html
│   ├── espn.com.html
│   ├── feedburner.com.html
│   ├── forms.gle.html
│   ├── g.co.html
│   ├── get.google.com.html
│   ├── gfycat.com.html
│   ├── globo.com.html
│   ├── godaddy.com.html
│   ├── gofundme.com.html
│   ├── goo.ne.jp.html
│   ├── goodreads.com.html
│   ├── google.ru.html
│   ├── gravatar.com.html
│   ├── gsmarena.com.html
│   ├── guardian.co.uk.html
│   ├── hatena.ne.jp.html
│   ├── hindustantimes.com.html
│   ├── hp.com.html
│   ├── ign.com.html
│   ├── ikea.com.html
│   ├── imageshack.us.html
│   ├── independent.co.uk.html
│   ├── jhu.edu.html
│   ├── jstor.org.html
│   ├── justgiving.com.html
│   ├── latimes.com.html
│   ├── liberation.fr.html
│   ├── linkedin.com.html
│   ├── mailchimp.com.html
│   ├── marca.com.html
│   ├── naver.com.html
│   ├── news.com.au.html
│   ├── npr.org.html
│   ├── nytimes.com.html
│   ├── offset.com.html
│   ├── oup.com.html
│   ├── outlook.com.html
│   ├── ovhcloud.com.html
│   ├── people.com.html
│   ├── php.net.html
│   ├── pinterest.fr.html
│   ├── pl.wikipedia.org.html
│   ├── play.google.com.html
│   ├── playstation.com.html
│   ├── plos.org.html
│   ├── prezi.com.html
│   ├── pt.wikipedia.org.html
│   ├── reverbnation.com.html
│   ├── sakura.ne.jp.html
│   ├── samsung.com.html
│   ├── search.yahoo.com.html
│   ├── sina.com.cn.html
│   ├── spiegel.de.html
│   ├── support.google.com.html
│   ├── thefreedictionary.com.html
│   ├── theverge.com.html
│   ├── usgs.gov.html
│   ├── vistaprint.com.html
│   ├── walmart.com.html
│   ├── webmd.com.html
│   ├── webnode.page.html
│   ├── whitehouse.gov.html
│   ├── wikimedia.org.html
│   ├── wordpress.org.html
│   ├── wp.com.html
│   ├── www.gov.uk.html
│   ├── www.over-blog.com.html
│   ├── www.wix.com.html
│   ├── www.yahoo.com.html
│   ├── yadi.sk.html
│   ├── ytimg.com.html
│   ├── zendesk.com.html
│   └── zippyshare.com.html
├── index.html
├── output.txt (run log for caputring node.js STDOUT)
├── package-lock.json
├── package.json
├── response_files
│   ├── 4shared.com.txt
│   ├── abcnews.go.com.txt
│   ├── alibaba.com.txt
│   ├── aliexpress.com.txt
│   ├── aol.com.txt
│   ├── apache.org.txt
│   ├── apple.com.txt
│   ├── arxiv.org.txt
│   ├── biblegateway.com.txt
│   ├── biglobe.ne.jp.txt
│   ├── bloomberg.com.txt
│   ├── booking.com.txt
│   ├── buzzfeed.com.txt
│   ├── cnil.fr.txt
│   ├── cnn.com.txt
│   ├── cointernet.com.co.txt
│   ├── com.com.txt
│   ├── cpanel.net.txt
│   ├── discord.com.txt
│   ├── disqus.com.txt
│   ├── doi.org.txt
│   ├── drive.google.com.txt
│   ├── dropbox.com.txt
│   ├── ea.com.txt
│   ├── elmundo.es.txt
│   ├── espn.com.txt
│   ├── feedburner.com.txt
│   ├── g.co.txt
│   ├── get.google.com.txt
│   ├── globo.com.txt
│   ├── gofundme.com.txt
│   ├── goo.ne.jp.txt
│   ├── goodreads.com.txt
│   ├── google.ru.txt
│   ├── gravatar.com.txt
│   ├── gsmarena.com.txt
│   ├── guardian.co.uk.txt
│   ├── hatena.ne.jp.txt
│   ├── hindustantimes.com.txt
│   ├── hp.com.txt
│   ├── ign.com.txt
│   ├── ikea.com.txt
│   ├── imageshack.us.txt
│   ├── independent.co.uk.txt
│   ├── jhu.edu.txt
│   ├── jstor.org.txt
│   ├── justgiving.com.txt
│   ├── latimes.com.txt
│   ├── liberation.fr.txt
│   ├── linkedin.com.txt
│   ├── mailchimp.com.txt
│   ├── marca.com.txt
│   ├── naver.com.txt
│   ├── npr.org.txt
│   ├── nytimes.com.txt
│   ├── offset.com.txt
│   ├── oup.com.txt
│   ├── outlook.com.txt
│   ├── ovhcloud.com.txt
│   ├── people.com.txt
│   ├── php.net.txt
│   ├── pinterest.fr.txt
│   ├── pl.wikipedia.org.txt
│   ├── play.google.com.txt
│   ├── playstation.com.txt
│   ├── plos.org.txt
│   ├── prezi.com.txt
│   ├── pt.wikipedia.org.txt
│   ├── reverbnation.com.txt
│   ├── sakura.ne.jp.txt
│   ├── samsung.com.txt
│   ├── search.yahoo.com.txt
│   ├── sina.com.cn.txt
│   ├── spiegel.de.txt
│   ├── support.google.com.txt
│   ├── thefreedictionary.com.txt
│   ├── theverge.com.txt
│   ├── usgs.gov.txt
│   ├── vistaprint.com.txt
│   ├── walmart.com.txt
│   ├── webmd.com.txt
│   ├── webnode.page.txt
│   ├── whitehouse.gov.txt
│   ├── wikimedia.org.txt
│   ├── wordpress.org.txt
│   ├── wp.com.txt
│   ├── www.gov.uk.txt
│   ├── www.over-blog.com.txt
│   ├── www.wix.com.txt
│   ├── www.yahoo.com.txt
│   ├── yadi.sk.txt
│   ├── zendesk.com.txt
│   └── zippyshare.com.txt
├── server.js
└── templates
    ├── frameable_template.html
    └── index_template.html
```

Note: I ran tree -I 'node_modules' to ignore the verbose node_modules directory; notably this directory is hidden (i.e. configured to be ignored by git).


### The videos demonstrating each of these tasks can be found here:

- [Which public sites are framable?](https://youtu.be/RbsX8UF_SOQ)
- [Frame Path attack](https://youtu.be/E4ytD1ksskY)
- [Bypassing Frames](https://youtu.be/98r6beWKVPg)


# Website Rendering Results

## Frameable Websites (29)
- https://4shared.com
- https://abcnews.go.com
- https://biblegateway.com
- https://booking.com
- https://com.com
- https://disqus.com
- https://doi.org
- https://elmundo.es
- https://g.co
- https://globo.com
- https://gofundme.com
- https://ign.com
- https://liberation.fr
- https://marca.com
- https://npr.org
- https://offset.com
- https://oup.com
- https://outlook.com
- https://pl.wikipedia.org
- https://plos.org
- https://pt.wikipedia.org
- https://sina.com.cn
- https://thefreedictionary.com
- https://usgs.gov
- https://vistaprint.com
- https://webmd.com
- https://wikimedia.org
- https://www.wix.com
- https://zippyshare.com

## Not Frameable Websites (71)
- [https://alibaba.com](frameable/alibaba.com.html) (Reason: X-Frame-Options)
- [https://aliexpress.com](frameable/aliexpress.com.html) (Reason: Error)
- [https://aol.com](frameable/aol.com.html) (Reason: X-Frame-Options)
- [https://apache.org](frameable/apache.org.html) (Reason: Content-Security-Policy)
- [https://apple.com](frameable/apple.com.html) (Reason: X-Frame-Options)
- [https://arxiv.org](frameable/arxiv.org.html) (Reason: X-Frame-Options)
- [https://biglobe.ne.jp](frameable/biglobe.ne.jp.html) (Reason: X-Frame-Options)
- [https://bloomberg.com](frameable/bloomberg.com.html) (Reason: Content-Security-Policy)
- [https://britannica.com](frameable/britannica.com.html) (Reason: Too many redirects)
- [https://buzzfeed.com](frameable/buzzfeed.com.html) (Reason: X-Frame-Options)
- [https://cambridge.org](frameable/cambridge.org.html) (Reason: Error)
- [https://cnil.fr](frameable/cnil.fr.html) (Reason: Content-Security-Policy)
- [https://cnn.com](frameable/cnn.com.html) (Reason: Content-Security-Policy)
- [https://cointernet.com.co](frameable/cointernet.com.co.html) (Reason: X-Frame-Options)
- [https://cpanel.net](frameable/cpanel.net.html) (Reason: X-Frame-Options)
- [https://discord.com](frameable/discord.com.html) (Reason: X-Frame-Options)
- [https://drive.google.com](frameable/drive.google.com.html) (Reason: X-Frame-Options)
- [https://dropbox.com](frameable/dropbox.com.html) (Reason: X-Frame-Options)
- [https://ea.com](frameable/ea.com.html) (Reason: X-Frame-Options)
- [https://espn.com](frameable/espn.com.html) (Reason: Content-Security-Policy)
- [https://feedburner.com](frameable/feedburner.com.html) (Reason: X-Frame-Options)
- [https://forms.gle](frameable/forms.gle.html) (Reason: Error)
- [https://get.google.com](frameable/get.google.com.html) (Reason: X-Frame-Options)
- [https://gfycat.com](frameable/gfycat.com.html) (Reason: Error)
- [https://godaddy.com](frameable/godaddy.com.html) (Reason: Error)
- [https://goo.ne.jp](frameable/goo.ne.jp.html) (Reason: X-Frame-Options)
- [https://goodreads.com](frameable/goodreads.com.html) (Reason: X-Frame-Options)
- [https://google.ru](frameable/google.ru.html) (Reason: X-Frame-Options)
- [https://gravatar.com](frameable/gravatar.com.html) (Reason: X-Frame-Options)
- [https://gsmarena.com](frameable/gsmarena.com.html) (Reason: Content-Security-Policy)
- [https://guardian.co.uk](frameable/guardian.co.uk.html) (Reason: X-Frame-Options)
- [https://hatena.ne.jp](frameable/hatena.ne.jp.html) (Reason: X-Frame-Options)
- [https://hindustantimes.com](frameable/hindustantimes.com.html) (Reason: X-Frame-Options)
- [https://hp.com](frameable/hp.com.html) (Reason: X-Frame-Options)
- [https://ikea.com](frameable/ikea.com.html) (Reason: X-Frame-Options)
- [https://imageshack.us](frameable/imageshack.us.html) (Reason: X-Frame-Options)
- [https://independent.co.uk](frameable/independent.co.uk.html) (Reason: X-Frame-Options)
- [https://jhu.edu](frameable/jhu.edu.html) (Reason: X-Frame-Options)
- [https://jstor.org](frameable/jstor.org.html) (Reason: X-Frame-Options)
- [https://justgiving.com](frameable/justgiving.com.html) (Reason: X-Frame-Options)
- [https://latimes.com](frameable/latimes.com.html) (Reason: X-Frame-Options)
- [https://linkedin.com](frameable/linkedin.com.html) (Reason: X-Frame-Options)
- [https://mailchimp.com](frameable/mailchimp.com.html) (Reason: X-Frame-Options)
- [https://naver.com](frameable/naver.com.html) (Reason: X-Frame-Options)
- [https://news.com.au](frameable/news.com.au.html) (Reason: Error)
- [https://nytimes.com](frameable/nytimes.com.html) (Reason: X-Frame-Options)
- [https://ovhcloud.com](frameable/ovhcloud.com.html) (Reason: X-Frame-Options)
- [https://people.com](frameable/people.com.html) (Reason: Content-Security-Policy)
- [https://php.net](frameable/php.net.html) (Reason: X-Frame-Options)
- [https://pinterest.fr](frameable/pinterest.fr.html) (Reason: X-Frame-Options)
- [https://play.google.com](frameable/play.google.com.html) (Reason: X-Frame-Options)
- [https://playstation.com](frameable/playstation.com.html) (Reason: X-Frame-Options)
- [https://prezi.com](frameable/prezi.com.html) (Reason: X-Frame-Options)
- [https://reverbnation.com](frameable/reverbnation.com.html) (Reason: X-Frame-Options)
- [https://sakura.ne.jp](frameable/sakura.ne.jp.html) (Reason: X-Frame-Options)
- [https://samsung.com](frameable/samsung.com.html) (Reason: X-Frame-Options)
- [https://search.yahoo.com](frameable/search.yahoo.com.html) (Reason: X-Frame-Options)
- [https://spiegel.de](frameable/spiegel.de.html) (Reason: Content-Security-Policy)
- [https://support.google.com](frameable/support.google.com.html) (Reason: X-Frame-Options)
- [https://theverge.com](frameable/theverge.com.html) (Reason: Content-Security-Policy)
- [https://walmart.com](frameable/walmart.com.html) (Reason: X-Frame-Options)
- [https://webnode.page](frameable/webnode.page.html) (Reason: X-Frame-Options)
- [https://whitehouse.gov](frameable/whitehouse.gov.html) (Reason: X-Frame-Options)
- [https://wordpress.org](frameable/wordpress.org.html) (Reason: X-Frame-Options)
- [https://wp.com](frameable/wp.com.html) (Reason: X-Frame-Options)
- [https://www.gov.uk](frameable/www.gov.uk.html) (Reason: X-Frame-Options)
- [https://www.over-blog.com](frameable/www.over-blog.com.html) (Reason: X-Frame-Options)
- [https://www.yahoo.com](frameable/www.yahoo.com.html) (Reason: X-Frame-Options)
- [https://yadi.sk](frameable/yadi.sk.html) (Reason: Content-Security-Policy)
- [https://ytimg.com](frameable/ytimg.com.html) (Reason: Error)
- [https://zendesk.com](frameable/zendesk.com.html) (Reason: Content-Security-Policy)
    
