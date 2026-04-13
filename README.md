# error-buddy
error-buddy is an error auditor and code locator for Canonical products. Best used with sos report directories and log files.

usage: error-buddy [-h] [product_or_path] [input]

Error Buddy: Audit logs or find source code.

positional arguments:
  product_or_path  Nickname, repo, or file/dir path
  input            Error string (triggers GitHub search)

options:
  -h, --help       show this help message and exit

## Usage
There are 2 ways to use error-buddy:

1. Use error-buddy to scan log files or directories. Error Buddy will scan for FATAL, CRITICAL, ERROR, and WARNING level messages, automatically grouping multi-line tracebacks into a clean, readable table.

   example:
     ```error-buddy syslog```
     or
     ```error-buddy ~/sos/sosreport-example-file/var/log/maas```

3. Use error-buddy to search product source code for relevant error messages.

   example:
     ```error-buddy landscape-server "No user with access key"```

   This will generate a search URL for the relevant github repo for the error message
