DeepSearch - Advanced Web Dir Scanner 
--
__DeepSearch__ is a simple command line tool for bruteforce directories and files in websites.

![screen](https://raw.githubusercontent.com/m4ll0k/DeepSearch/master/screen.png)

Installation
--
```sh
$ git clone https://github.com/m4ll0k/DeepSearch.git deepsearch
$ cd deepsearch 
$ pip3 install requests
$ python3 deepsearch.py

```

Usage
--
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -f`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -b`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -l`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -p`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -o 200,301,302`
`python3 deepsearch.py -u http://testphp.vulnweb.com/ -e php -w wordlist.txt -x 501,502,503,401`
`python3 deepsearch.py -u http://testphp.vulnweb.com/user-%1%/index.php -e php -w wordlist.txt`
`python3 deepsearch.py -u http://testphp.vulnweb.com/id/%1%/index.html -e php -w wordlist.txt -f`
