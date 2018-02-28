## GZD + Mitre
This code (work in progress) scrapes the Mitre CVE database and compares it against the google zero day (GZD) team's database. 

- https://cve.mitre.org/data/downloads/index.html
- https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=&sort=-id&colspec=ID%20Type%20Status%20Priority%20Milestone%20Owner%20Summary

## Intent
GZD team's database often---fantastically!---include dates for when vulnerabilities are identified and fixed. This allows for the potential of statistical analysis on time-to-fix.

Please note, however, that many of the dates should be interpreted as approximate because of the way the dates are frequently documented. For example, CVE-2018-6055 has a reported date of December 1, 2017, but does not have a "fixed" date. Luckily, however, it does have a "closed" date of January 31, 2018. Here's the link: 
- https://bugs.chromium.org/p/project-zero/issues/detail?id=1450

Because it is often the case that CVEs have a similar "fixed" date as "closed" date, we can make an assumption that CVE-2018-6055 was closed on January 31, 2018. _See also_ CVE-2018-0810 (fixed February 13 and closed February 14; CVE-2017-13878 (fixed December 6 and closed December 11). But see Issue 1489 (non-cve number) which was fixed on January 24 and closed on February 15. 

To be sure, these are just _estimates_ based on the valuable date information provided by the GZD team. Other approximations may be found in the cve.py code comments. 

## Outline 
1. scrape Mitre's database per input year (user-selected)
2. scrape GZD team's database for all years (2014 - today)
3. store the result in a pandas dataframe 

## Preliminary Results
This is a simple pandas description of the estimated amount of time between reported and fixed dates (although reported in floats from the description(), these numbers represent days:

**count**|**925.000000**
:-----:|:-----:
mean|72.935135
std|37.140049
min|0.000000 
25%|56.000000
50%|76.000000
75%|87.000000
max|429.000000 

- for min observation: that result is true, the fix date was the same day as the reported date
- for max observation: see CVE-2015-8636 (likely shows my assumption on "closed" and "fixed" is not always true)

# Here's what grouping looks like
![grouping](https://github.com/nathanReitinger/cve/blob/master/Figure_1.png)


## TODO
* clean data in each of the cells during scrape
* remove "reported" before date of reported vulnerability
* add year to "fixed" date
* further analysis 
