# SQL-Injection-Lab-DVWA-UNION-Based-Extraction-Log-Correlation-
SQL injection lab against DVWA — went from breaking the query and mapping out the database to pulling real credentials, then checked the whole thing against the Apache logs to see what it looks like from the other side.

SQL Injection Lab (DVWA — UNION-Based Extraction & Log Correlation)

Tools used: DVWA, Kali Linux, Firefox, MariaDB, Apache2 access logs, Linux CLI

Overview

This is a write-up of a SQL injection lab I ran against DVWA (Damn Vulnerable Web Application), hosted at dvwa.structureality.com with the security level set to low. My goal was to actually run the full attack myself instead of just reading about how it works — break the query, work out how many columns it was returning, map out the database, and pull real credentials off it. Then I switched sides and went and read the raw Apache logs to see what that same attack actually looked like sitting in server records.

I've kept the process here close to what actually happened, including the wrong guesses and the messy output I had to dig through, rather than tidying it up into a clean final version.

Objective

Practice SQL injection from both directions — exploit a UNION-based injection to pull sensitive data out as an attacker, then go back and read the corresponding Apache logs as if I were the one investigating it afterward.

Environment

Attacker side: Kali Linux, Firefox
Target: DVWA at dvwa.structureality.com/vulnerabilities/sqli/, security level low, running on MariaDB 10.5.19
Log review: a separate LAMP server accessed through labclient.labondemand.com, logs sitting at /var/log/apache2
Also worked through a set of scored questions on a CompTIA lab platform, mainly around matching log entries back to specific requests

Tools I Used

| Tool | What It Does | Why I Used It |
|------|--------------|----------------|
| DVWA | Deliberately vulnerable web app | Gave me an actual SQL injection point to work against |
| Firefox | Browser | Sent payloads straight through the User ID field |
| MariaDB (via DVWA) | Backend database | What I was actually querying |
| Apache2 access.log | Web server log | Let me check what the server recorded versus what I remembered doing |
| Linux terminal | Command line | Used to get into the LAMP box and read the logs directly |
| CompTIA lab platform | Guided exercise | Structured the log-matching part of this with specific questions |

What I Did

Finding and confirming the injection point

First thing I did was drop a single quote into the User ID field to see if it broke anything. It did, so the next step was figuring out how many columns the query was actually returning, since that number needs to line up before UNION SELECT will work.

I tried:

' ORDER BY 1
' ORDER BY 2

Both went through fine. Bumped it up to 3 and got:

Unknown column '3' in order clause

So two columns. I also ran a quick boolean check just to be sure I actually had a working injection and not a fluke:

1' or '1'='1

That pulled back every row in the table instead of just one, which confirmed the WHERE clause wasn't doing anything anymore.

Mapping out the database

With the column count sorted, I grabbed the database version first, mostly out of habit, just to know what I was dealing with:

' UNION SELECT @@VERSION, NULL

Came back as 10.5.19-MariaDB-0+deb11u2.

From there I queried information_schema.tables to see what actually existed on the server:

' UNION SELECT table_schema, table_name FROM INFORMATION_SCHEMA.tables

This came back with a lot of stuff I didn't care about — mysql, performance_schema, information_schema itself — buried in among the one schema I actually wanted, dvwa, which had a users table and a guestbook table in it. Took a bit of scrolling and squinting to actually pick that out of the noise.

Once I had the table name, I went after the columns:

' UNION SELECT table_name, column_name FROM information_schema.columns

That gave me user, user_id, first_name, last_name, avatar, last_login, password, and failed_login. Worth noting these came back lowercase, which is the real tell that you're looking at actual application columns and not the uppercase metadata rows information_schema also mixes in if you're not paying close attention.

Pulling the credentials

At this point the actual extraction was easy:

' UNION SELECT user, password FROM users

Got back five accounts:

admin — 5f4dcc3b5aa765d61d8327deb882cf99
gordonb — e99a18c428cb38d5f260853678922e03
1337 — 8d3533d75ae2c3966d7e0d4fcc69216b
pablo — 0d107d09f5bbe40cade3de5c71e9e9b7
smithy — 5f4dcc3b5aa765d61d8327deb882cf99

Small thing I noticed right away: admin and smithy have the exact same hash. Didn't even need to crack it to know that's password reuse — you can see it just by comparing the two strings.

Checking it against the logs

After getting the data out, I flipped over to the defender's chair. Logged into the LAMP terminal, used sudo su, and went to /var/log/apache2 to look at the raw access log instead of taking anyone's word for what it said.

Going through the CompTIA questions, I matched my own injection attempts back to specific log lines — things like id=type1, id=Type+7, the ORDER BY attempts, and eventually the UNION SELECT request — by lining up timestamps and response sizes against what I remembered sending. One of the questions asked me to pick out the correct HTTP referrer for a particular request, which meant actually reading the log format properly instead of just scanning for the URL I recognized.

What's in This Repo

sql-injection-lab/
  README.md
  attack/
    payloads.txt
  findings/
    db-enumeration.txt
    extracted-credentials.txt
    apache-log-excerpt.txt
  screenshots/
    01-order-by-column-count.png
    02-boolean-based-confirmation.png
    03-db-version-union-select.png
    04-information-schema-tables.png
    05-information-schema-columns.png
    06-extracted-credentials.png
    07-apache-access-log-review.png

Skills I Picked Up

Confirming column count with ORDER BY before trying UNION SELECT, instead of just guessing at a payload
Telling apart the database's own internal metadata from the actual application tables I was targeting
Catching password reuse just by eyeballing hash output, before doing anything else with it
Tying a specific attacker action back to one exact line in a server log using timestamp, referrer, and response size together
Working through a live terminal on a timer and not losing my place after a small typo (cd/var/log/apache2 instead of cd /var/log/apache2)

How This Applies in the Real World

Unsanitized input leading to SQL injection is still one of the most common ways attackers get straight into a backend database, and UNION-based injection specifically is often the fastest route from "this field isn't sanitized" to "I have your users table." Doing it myself, start to finish, made it click in a way that just reading about it never really does.

The log side matters just as much. Nobody hands an analyst a summary of what an attacker did — you get a raw access log and have to piece it together from timestamps, request paths, and referrers. Doing that against an attack I'd just run myself is what made the log format actually make sense to me.

Where I'm Coming From

I'm switching into cybersecurity after working in healthcare. Different field, but some of it carries over — being careful, documenting what actually happened instead of what I assumed happened, staying calm when something breaks the first time. I'm studying for CompTIA Security+ right now and building labs like this to get real reps in.

I got things wrong along the way here — misjudged the column count at first, got tripped up by the information_schema noise, typo'd a command in the terminal. I'd rather show that than pretend it went perfectly.

What I Want to Learn Next

Blind and time-based SQL injection, not just UNION-based
Running the same process against DVWA's medium and high security settings, where filtering actually gets in the way
Trying sqlmap on the same target and comparing it to what I found by hand
Writing an incident report from the log side only, without my own attack notes to lean on
Getting more comfortable with different log formats beyond just Apache

Limitations & What I'd Do Differently in Production

This was against DVWA on low security, which does zero input filtering — a real target with even basic sanitization would need a completely different approach
The hashes here are unsalted MD5, realistic for a training app but not how most real systems store passwords anymore
I could match my requests to log lines because I already knew what I'd sent — a real analyst doesn't get that shortcut, and that's a harder skill I want more practice with
Didn't test any detection here — in a real environment I'd want to know whether something like a WAF or Wazuh would catch these payloads before they ever succeeded

References

DVWA — GitHub (digininja/DVWA)
OWASP — SQL Injection
PortSwigger — SQL Injection Cheat Sheet
MariaDB Knowledge Base — information_schema
Apache HTTP Server — Log Files documentation
CompTIA Security+ (SY0-701) Exam Objectives
