import sys
import re
from lxml import html
import requests
from bs4 import BeautifulSoup
from datetime import datetime

years  = ["2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019", "2020"]
months = {"Jan":1, "January":1,"Feb":2, "February":2, "Mar":3, "March": 3,"Apr":4,"April":4, "May":5, "Jun":6,"June":6,"Jul":7, "July":7,"Aug":8,"August":8,"Sep":9,"September":9,"Oct":10,"October":10,"Nov":11,"November":11,"Dec":12, "December":12}
days   = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31']


def topRow():
    # get the number of rows currently in GZD team's database
    start = 'https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=&sort=-id&colspec=ID%20Type%20Status%20Priority%20Milestone%20Owner%20Summary'
    start_page = requests.get(start)
    if 200 != start_page.status_code:
        print(start_page.status_code)
        sys.exit("there is an error in  the web request")
    start_tree = html.fromstring(
        start_page.content)  # useful for testing, see description under ==>if bool(title) == True<==
    start_soup = BeautifulSoup(start_page.text, "lxml")
    start_col = start_soup.find('td', {'class': 'id col_0'})
    number = start_col.get_text().strip()
    return int(number)

# to identify a specific CVE and returns row that CVE exists in
def inDatabase(column, keyWord, dataframe):
    return dataframe[dataframe[column].str.contains(keyWord)]


# to identify a specific CVE and returns index number in dataframe of that CVE
def indexNumber(column, keyWord, dataframe):
    regex = r'\b' + keyWord + r'\b'  # regex used to pick exact match
    myIndex, = dataframe[dataframe[column].str.contains(regex)].index
    return myIndex  # trailing comma gives integer instead of package, http://stackoverflow.com/questions/34421024/transforming-type-int64index-into-an-integer-index-in-python


# given index number, changes cell to passed-in value
def addValue(index, column, toAdd, dataframe):
    dataframe.iloc[index, dataframe.columns.get_loc(column)] = toAdd


def validYear(year):
    """
    simple validation on whether the user's input will be successfully scraped
    :param year: a year from the CVE database
    :return: exits on failure
    """
    if len(year) == 4:
        if year.isdigit():
            if int(year) >= 1999 and int(year) <= 2018:
                return year

    else:
        allYears = [x.strip() for x in year.split(',')]
        for year in allYears:
            if year.isdigit():
                if int(year) < 1999 or int(year) > 2018:
                    print("Please enter a year between 1999 and 2018--multiple years should be separated by commas")
                    sys.exit()

def get_day(string):
    return (re.match('.*?([0-9]+)$', string).group(1))


def get_yearmonth(string):
    regex = r"(?<=-)(.*?)(?=-)"
    string = string
    match = re.findall(regex, string)
    year = match[0]
    month = match[1]
    if month in months:
        month = months[month]
    return (year + "-" + str(month))


def to_date(string):
    try:
        dateTime = datetime.strptime(string, '%Y-%m-%d')
    except:
        dateTime = datetime.strptime(string, '%d-%m-%Y')
    return (dateTime)


def get_fixed_sparse(string, date_reported):
    fixed = str.split(string)
    year = "<>"
    month = "<>"
    day = "<>"
    for object in fixed:
        if object in years:
            year = object
        if object in months:
            month = months[object]
        if object in days:
            day = object

    # guess on the day, may be taken out later for more realistic analysis
    # day is empty in 387 results
    if day == "<>":
        # print("*****")
        day = "15"

    if year == "<>":
        # if year is missing, we can assume the fixed date has the same year as the reported date when
        # the fixed date has a month less than or equal to december and more than or equal to january
        # 77 dates fall into this category
        if month <= 12 and month >= 6:
            year = str(date_reported.year)
            # print("*****")

        # if the year is missing, we can assume it is the next year if the reported year is late (june or later)
        # and the fixed date is early (prior to june)
        #  37 dates fall into this category
        if int(date_reported.year) >= 6 and month <= 6:
            year = int(date_reported.year + 1)
            year = str(year)
            # print("*****")
    return(to_date(year + "-" + str(month) + "-" + day))
