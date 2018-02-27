import helpers
import scrape
import wordRank      # not used
from datetime import datetime
import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt



##################################
#                                #
#         GZD+MITRE scrape       #
#                                #
##################################

# TODO
#          - for cleaning data -
# - remove "reported" before date of reported vulnerability
# - add year to "fixed" date
#
# # <><><><><><><><><><><><><><><><><><>
# # automated scraping of MITRE's CVEs
# # <><><><><><><><><><><><><><><><><><>
#
# # the intent was to grab all years since the GZD team started reporting
# # 2014,2015,2016,2017,2018date
# year = input('Enter a year between 1999 and today---or multiple years separated by commas (return "all" for 2014-2018): ')
# if year == "all":
#     year = "2014,2015,2016,2017,2018"
# helpers.validYear(year)
# dataframe = scrape.mitre_scrape(year)  # scrape MITRE's CVE DB for year as input
#
# # <><><><><><><><><><><><><><><><><><>
# # scraping GZD DB
# # <><><><><><><><><><><><><><><><><><>
#
# print("Importing  google zero day team's work . . .")
# # get the total number of entries in GZD team's database
# top = helpers.topRow()
# df = scrape.gzd_scrape(top, dataframe)
#
# # <><><><><><><><><><><><><><><><><><>
# # saving
# # <><><><><><><><><><><><><><><><><><>
# df.to_csv('zeroDays.csv')
# print(dataframe.head())


##################################
#                                #
#         GZD+MITRE analysis     #
#                                #
##################################
df = pd.read_csv("zeroDays.csv")


count_reported_or_fixed = 0
count_both = 0

# <><><><><><><><><><><><><><><><><><>
# cleaning up dates from GZD
# <><><><><><><><><><><><><><><><><><>

# this is where the time difference of reported---to---fixed will go
df['time_to_fix'] = np.nan

# only some rows have data from gzd, so separate it out
for index, row in df.iterrows():
    if pd.notnull(row['Reported']) and pd.notnull(row['Fixed']):

        # <><><><><><><><><><><><><><><><><><>
        # cleaning up the reported cell
        # <><><><><><><><><><><><><><><><><><>
        day_reported = helpers.get_day(row['Reported'])
        year_month = helpers.get_yearmonth(row['Reported'])
        date_reported = helpers.to_date (year_month +"-" + day_reported)

        # <><><><><><><><><><><><><><><><><><>
        # cleaning up the fixed cell
        # <><><><><><><><><><><><><><><><><><>
        if "Fixed" in row['Fixed']:
            day_fixed = helpers.get_day(row['Fixed'])
            year_month = helpers.get_yearmonth(row['Fixed'])
            date_fixed = helpers.to_date(year_month +"-" + day_fixed)

        # TODO: double check assumptions (1) if no day listed in month I used 15; (2) if no date I estimated next year
        else:
            date_fixed = helpers.get_fixed_sparse(row['Fixed'], date_reported)

        # print(row['ID'], abs(date_reported.date() - date_fixed.date()))
        days_to_fix = abs(date_reported.date() - date_fixed.date())
        helpers.addValue(index, "time_to_fix", days_to_fix.days, df)


# <><><><><><><><><><><><><><><><><><>
# put the processed data in a new df
# <><><><><><><><><><><><><><><><><><>
df_times = df[df['time_to_fix'].notnull()]
print ( df_times['time_to_fix'].describe() )

# preliminary charting
chart = df_times.groupby(['time_to_fix']).size().plot(kind='bar', title ="Time to Fix", figsize=(500, 500), legend=True, fontsize=12)
chart.set_xlabel("Approximate Days Between Reported and Fixed", fontsize=12)
chart.set_ylabel("Number of CVEs", fontsize=12)

plt.show()
