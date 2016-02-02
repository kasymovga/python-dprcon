To install the module globally, run this as root: ./setup.py install
And to try it out, run the Python interpreter and type this:

```
import dprcon
con = dprcon.InsecureRCONConnection('nexuiz.example.com', 26000, 'p4ssw0rd', connect=True)
con.send('echo Hello world')
print(con.read())
```

Or just run ./dprcon.py for a simple interactive client
