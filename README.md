# POWer

A server for providing proofs-of-work (e.g. for CTF challenges)

Intended to be set up by individual teams

Currently has no authentication/DoS mitigation (it's supposed to heat up the CPU of the server it's running on)

## Usage from Python
```
>>> import requests
>>> requests.get('http://localhost:3000/sha256', params={'mask': '00'+'ff'*3+'00'*28, 'goal': '00badc0d'+'00'*28}).text
u'78a3170000000000 has hash fcbadc0d5856bb6eea467a236218eb5e16017a1636e335e2946618feb0aae620\\n'
>>> requests.get('http://localhost:3000/sha256', params={'mask': 'ff'*4+'00'*28, 'goal': '00abcdef'+'00'*28}).text
u'c72b530200000040 has hash 00abcdef83801fd557e1740187560ac4fdc557645e175f5faeb407e54a2d9958\\n'
```

## Benchmarks

```
$ time curl localhost:3000/sha256?mask=$(python -c 'print \"0fff\"+\"00\"*28+\"ff\"*2')\\&goal=$(python -c 'print \"dead\"+\"00\"*28+\"beef\"')
ee00ad0000000060 has hash 2eadd4a8cf0ea220da5570e0ac7855ffc6e416e09c08e0a7b81fbac0fcaabeef

real    0m9.760s
user    0m0.020s
sys     0m0.012s
```
```
$ time curl localhost:3000/sha256?mask=$(python -c 'print "ff"*4+"00"*28')\&goal=$(python -c 'print "00abcdef"+"00"*28')
c72b530200000040 has hash 00abcdef83801fd557e1740187560ac4fdc557645e175f5faeb407e54a2d9958

real    0m31.788s
user    0m0.044s
sys     0m0.008s
```

## TODOs
- Alphanumeric only keyspace
- All the other hash functions that rust-crypto can use
- GPU acceleration
- Double-check whether concurrent requests work properly (i.e. whether hyper's handler blocks while rayon is bruting hashes), look into futures integration if negative

