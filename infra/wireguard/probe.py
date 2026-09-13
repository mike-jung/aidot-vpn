# Probe URLs from inside the gateway. Prints "<url> <status>" per URL:
# an HTTP status (any code is an answer) or NOCONN.
#
# A file in the image rather than `python3 -c '<script>'` from npm
# start: on Windows the multi-line script with its quotes went through
# cmd.exe quoting and arrived mangled, so the check reported 무응답
# while the responder's own log said it was up. A path has nothing to
# quote.
import sys, urllib.request, urllib.error
for url in sys.argv[1:]:
    try:
        print(url, urllib.request.urlopen(url, timeout=3).status)
    except urllib.error.HTTPError as e:
        print(url, e.code)
    except Exception:
        print(url, "NOCONN")
