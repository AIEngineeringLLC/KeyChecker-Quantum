# KeyChecker-Quantum
Tool to run all OQS keys to test if your system can make Quantum Safe PKI
 Step just include openssl.exe in the Directory you are running the tool 


Must have Open Quantum Safe on the local machine !
Run  "openssl list -providers" 

It should say:  

Providers:
  default
    name: OpenSSL Default Provider
    version: 3.4.1
    status: active
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.8.1-dev
    status: active

 
 Future Release Ideas :   Package openssl with OQS module in the build so users do not have build the Open Quantum Safe on the local machine.
