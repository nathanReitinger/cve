import sys
import pandas as pd
from lxml import html
import requests
import re
from bs4 import BeautifulSoup

import helpers

def mitre_scrape(year):
    """
    :param year: selected by user on prompt
    :return: dataframe of CVE database | row | CVE ID | description | reported date | fixed date
    """
    print("importing CVEs for the year(s)", year, "from MITRE's database. . .")
    if len(year) == 4:

        print("you've chosen a single year! Importing now. . .")

        automatedFile = pd.DataFrame(columns=('ID', 'Description', 'Reported', 'Fixed'))
        CVEpath = 'https://cve.mitre.org/data/downloads/allitems-cvrf-year-'
        CVEyear = year
        CVEpath = CVEpath + CVEyear + ".xml"
        CVEpage = requests.get(CVEpath)
        if 200 != CVEpage.status_code:
            sys.exit("system exiting...error code received:", CVEpage.status_code)
        CVEsoup = BeautifulSoup(CVEpage.text, "lxml")

        rows = CVEsoup.find_all('vulnerability')
        startRow = 0
        for row in rows:
            matchTitle = row.find("title").get_text()
            matchDescription = row.find('note', {'ordinal': '1'}).get_text()

            automatedFile.loc[startRow, "ID"] = matchTitle
            automatedFile.loc[startRow, "Description"] = matchDescription

            startRow += 1

        print("completed import! Here is a sampling of your table (head, tail). . .")
        print(automatedFile.head(), automatedFile.tail())
        print("-------------------------------------------------------------------")
        print("rows in dataframe:", len(automatedFile.index))

        # automatedFile.to_csv('separate_2.csv')
        return automatedFile

    else:
        allYears = [x.strip() for x in year.split(',')]
        automatedFile = pd.DataFrame(columns=('ID', 'Description', 'Reported', 'Fixed'))

        for i in range(len(allYears)):

            year = allYears[i]
            print("starting to grab", year, ". . .", end=" ")
            CVEpath = 'https://cve.mitre.org/data/downloads/allitems-cvrf-year-' + year + ".xml"
            CVEpage = requests.get(CVEpath)
            if 200 != CVEpage.status_code:
                sys.exit("system exiting...error code received:", CVEpage.status_code)
            CVEsoup = BeautifulSoup(CVEpage.text, "lxml")

            rows = CVEsoup.find_all('vulnerability')
            startRow = len(automatedFile.index)

            for row in rows:
                matchTitle = row.find("title").get_text()
                matchDescription = row.find('note', {'ordinal': '1'}).get_text()

                automatedFile.loc[startRow, "ID"] = matchTitle
                automatedFile.loc[startRow, "Description"] = matchDescription
                startRow += 1

            print("DONE", automatedFile.shape)

        print("completed import! Here is a sampling of your table (head, tail). . .")
        print(automatedFile.head(), automatedFile.tail())
        print("-------------------------------------------------------------------")
        print("rows in dataframe:", len(automatedFile.index))

        return automatedFile


def gzd_scrape(top, dataframe):
    # for each of those rows, match CVE if the CVE is found in the MITRE databse
    for i in range(1, top):  # how many of the rows to look at
        CVE_identified = ""  # crawling for CVE number
        reportDate_identified = ""  # crawling for a reported date (date vulnerability was reported to gzd team)
        fixedDate_identified = ""  # crawling for date gzd team issued a patch
        fixedDate_estimated = ""  # estimated fix date based on "closed" identification

        path = 'https://bugs.chromium.org/p/project-zero/issues/detail?id='
        path = path + str(i)  # iterates over unique IDs in sequence
        page = requests.get(path)  # setting up the DOM tree
        if 200 != page.status_code:
            print(page.status_code)
            sys.exit("there is an error in the web request")
        tree = html.fromstring(page.content)  # useful for testing, see description under ==>if bool(title) == True<==
        title = tree.xpath(
            '//span[@class="h3"]/text()')  # pulling the description header giving a short-hand identification of the vulnerability

        if bool(title) == True:  # project zero skipped a few in-sequence ID numbers, break if no entry for this number
            soup = BeautifulSoup(page.text, "lxml")  # beautiful soup is better for scraping rows
            #         print(title)                                              # CHECK - using xpath for ease of grabbing title

            closedFlag = soup.find('td', {'align': 'left'})  # most CVEs that don't have a fixed date have closed date
            try:
                fixedDate_estimated = closedFlag.get_text().strip()  # TODO, still need to add year
            #             print("....found estimated fixed date via 'closed' flag")
            except AttributeError:
                print("no value listed for closed...move along")

            table = soup.find('td', {'class': 'widemeta'})  # grab applicable left-side table
            rows = table.find_all('a')  # HTML syntax proceeding our valued data

            for i in range(len(rows)):  # loop to walk through rows in table, identifying desired data in cells
                matchCVE = re.search("CVE", rows[i].get_text())  # identify the CVE number in the beautifulSoup row
                matchReport = re.search("Report", rows[i].get_text())  # identify reported date if it exists
                matchFixDate = re.search("Fixed", rows[i].get_text())  # identify fixed date if it exists

                if matchCVE:  # if CVE number is in google's database entry, fill in variables
                    # print("....found CVE number:")
                    CVE_identified = rows[i].get_text()
                    # print(CVE_identified)

                if matchReport:  # if report date is in google's database entry, fill in variables
                    # print("....found Report Date")
                    reportDate_identified = rows[i].get_text()

                if matchFixDate:  # if fix date is in google's database entry, fill in variables
                    # print("....found Fix Date")
                    fixedDate_identified = rows[i].get_text()

        # GZD team's earliest reporting started in 2014
        if (CVE_identified != ""):  # as long as the zero day team included a CVE identifier

            if not helpers.inDatabase("ID", CVE_identified, dataframe).empty:
                indexValue = helpers.indexNumber("ID", CVE_identified, dataframe)  # find appropriate index to change

                if reportDate_identified != "":  # add value to report date
                    #             print(reportDate_identified)
                    helpers.addValue(indexValue, "Reported", reportDate_identified, dataframe)

                if fixedDate_estimated != "":  # if there is a "closed" date, insert that date into "fixed" column
                    #             print(fixedDate_estimated)
                    fixedDate_estimated = fixedDate_estimated
                    helpers.addValue(indexValue, "Fixed", fixedDate_estimated, dataframe)

                if fixedDate_identified != "":  # if there is a "fix date," insert that date into "fixed" column
                    #             print(fixedDate_identified)
                    helpers.addValue(indexValue, "Fixed", fixedDate_identified, dataframe)

                if fixedDate_identified != "" and fixedDate_estimated != "":
                    #             print ("both estimated and identified fixed dates are filled in")
                    helpers.addValue(indexValue, "Fixed", fixedDate_identified,
                                     dataframe)  # pick the "fix date" value over the "closed" date

                print("Added ", CVE_identified, " to database")

        # else:
        #     # print("\n" + 'nothing to see here! MOVE ALONG' + "\n")

    return dataframe