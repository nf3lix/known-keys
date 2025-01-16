# Known keys database
The project's goal is to provide a database that stores publicly known public keys. A possible application 
scenario is a Certificate Authority that wants to sign a public key and needs to check if it already knows it. It might 
be also useful to store keys that are leaked or known for any other reason and should not be reused. Characteristic of this use 
case is the large amount of data. According to the Certificate Transparency Initiative 
(https://certificate.transparency.dev/), over 11 billion certificates have been registered by the initiative since 2013. 
Besides certificates, public key cryptography is also used in other areas, such as for SSH. This underscores the importance of a 
performant solution. The focus of this project is on RSA and EC. However, the code can be easily extended to other 
cryptosystems. It could make sense to extend it to Ed25519 which is used by default for SSH. Currently, only the PEM 
format is supported for uploading public keys.

## Choosing a database system
One challenge in designing the application is the large amount of data. It requires a storage-efficient data structure 
that also allows for performant checking.

One possible solution is the use of a Bloom filter. A Bloom filter is a probabilistic data structure that checks whether 
an element is part of a set. It consists of a bit array and uses multiple hash functions. When adding an element, the 
bits at the positions calculated by the hash functions are set to 1. To check an element, its hash values are calculated 
and checked to see if all the corresponding bits in the array are set to 1. [[1]](https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/)

In theory, a Bloom filter can add an unlimited number of elements without changing its size. However, this increases the 
false positive rate. False negatives do not occur. If the filter indicates that an element is present, it is only present 
with a certain probability. If the filter indicates that an element is not present, then it is definitely not present. 
The error rate depends on the array size and the number of hash functions. A disadvantage of a Bloom filter is that 
elements cannot be deleted, as resetting a single bit could affect multiple elements. [[1]](https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/)

If a certain error rate can be accepted and there's no need for deleting elements, a Bloom filter can be a suitable data 
structure. For our use case, this is assumed. It is assumed that keys can be generated performantly. If the Bloom filter 
falsely claims that a generated public key is known, a new key can simply be generated, regardless of whether it is a 
false positive. Likewise, there is no reason to delete a known public key.

The Cuckoo filter is another data structure that, depending on the error rate, allows for more performant write and 
check operations than a Bloom filter. According to [[2]](https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf), a Cuckoo filter requires less memory per element than a Bloom 
filter for error rates less than 3%. Check operations are more performant with a Cuckoo filter than with a Bloom 
filter. Additionally, deleting elements from a Cuckoo filter is possible. However, the throughput of insert operations 
decreases as the number of elements already in the filter increases. [[2]](https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf)

As a follow-up task to this project, a comparison of both data structures for the use case should be conducted.

## What to store in the filter?
RSA private keys `(m, e, d)` consists of the modulus `m`, the public exponent `e`, and the private exponent `d`. The 
public key contains only `(m, e)`, which is the relevant information for the Known Keys Database. For the public 
exponent, the value 65537 is very often used. Since only probabilistic values are provided due to the limitations 
mentioned before, storing `d` is considered unnecessary overhead and is omitted. When storing an RSA public key, only 
the modulus `m` is added to the Bloom filter or Cuckoo filter.

An EC Public public key is generated through point multiplication on an elliptic curve. A base point `G` is multiplied 
by the private key `d`, resulting in the public key `P` with coordinates `x` and `y`. It is relatively easy to compute 
`P` but relatively difficult to compute `d` from `P`. In addition to the public point `P`, the curve parameters are 
decisive information public key. It is recommended to use a standardized curve for this purpose [[3]](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf). 
Assuming that false positives are acceptable and that the occurrence of the same `P` with different curve parameters is 
unlikely, these are omitted during storage. The same applies to the `y` coordinate, thus only `x` is stored.

## Run locally
Running locally requires a local installation of Docker. The project depends on the following components:
1. A Java Backend written with [Spring Boot](https://spring.io/projects/spring-boot) and [Bouncy Castle](https://www.bouncycastle.org/download/bouncy-castle-java/) as Security Provider
2. A running Redis instance with [RedisBloom Extension](https://github.com/RedisBloom/RedisBloom)

### Run with docker compose
1. `docker-compose up -d`
2. Access [Swagger UI](http://localhost:8080/swagger-ui/index.html)

### Sample requests
RSA:
1. Generate RSA Key Pair: `openssl genrsa -out rsa_private_key.pem 4096 && openssl pkey -in rsa_private_key.pem -pubout -out rsa_public_key.pem`
2. `curl -X POST -F "file=@rsa_public_key.pem" http://localhost:8080/public-keys/rsa/exists`
3. `curl -X POST -F "file=@rsa_public_key.pem" http://localhost:8080/public-keys/rsa`
4. `curl -X POST -F "file=@rsa_public_key.pem" http://localhost:8080/public-keys/rsa/exists`

EC:
1. Generate EC Key Pair: `openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem && openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem`
2. `curl -X POST -F "file=@ec_public_key.pem" http://localhost:8080/public-keys/ec/exists`
3. `curl -X POST -F "file=@ec_public_key.pem" http://localhost:8080/public-keys/ec`
4. `curl -X POST -F "file=@ec_public_key.pem" http://localhost:8080/public-keys/ec/exists`

Insert a large amount of keys:
1. `git clone git@github.com:badkeys/debianopenssl.git <target_directory>`
2. `/bin/bash insert_keys.sh`

The provided bash script asks for a directory containing Public Keys in PEM format.

### Optional: run tests and start app with maven
Run unit tests:
1. `mvn test`
2. generated coverage report: `target/site/jacoco/index.html`

Run app with maven:
1. `docker run --name redis-bloom -p 6380:6379 -d redislabs/rebloom:latest`
2. `mvn clean install`
3. `mvn spring-boot:run`
4. Access [Swagger UI](http://localhost:8080/swagger-ui/index.html)

### Storage Efficiency
To compare the storage efficiency of Bloom Filters and Cuckoo Filters, both were implemented using
[Redis](https://redis.io/docs/latest/). Redis is an in-memory key-value database. When running the app with the 
aforementioned commands, a Bloom Filter is used by default. To run the application with a Cuckoo Filter instead, the 
Spring profile `cuckoo_filter` must be set: `mvn spring-boot:run -Dspring-boot.run.profiles=cuckoo_filter`.
The current memory consumption of the respective Redis keys can be queried via the endpoint.
`/public-keys/{crypto_system}/redis-memory-consumption`. Sample call: `curl http://localhost:8080/public-keys/ec/redis-memory-consumption`

For filters with a capacity of 1 billion, the following values for memory consumption are obtained.

| Data Structure | Memory Consumption in bytes |
|----------------|-----------------------------|
| Bloom Filter   | 1378469320                  |
| Cuckoo Filter  | 1073741936                  |

With this capacity, memory consumption for both filters in Redis remains constant.
In this case, a Cuckoo Filter is more storage efficient. However, this does not allow for a profound decision for one of 
the data structures. The performance of read and write operations must also be considered. Some rudimentary tests have 
not yet yielded significant results

# Limitations
- Currently, only PEM is supported as a format for key upload. OpenSSH uses a slightly different PEM format for some key types that is not supported out-of-the-box by Bouncy Castle. For SSH keys with RSA, a valid PEM file can be created: `ssh-keygen -t rsa -b 2048 -m PEM`
- Currently, only RSA and EC are supported as cryptosystems. An extension to include Ed25519 would be useful.
- A systematic comparison of Bloom Filters and Cuckoo Filters for the use case is still pending.

# Further reading
- Redis docs for Bloom Filters: https://redis.io/docs/latest/develop/data-types/probabilistic/bloom-filter/
- Redis docs for Cuckoo Filters: https://redis.io/docs/latest/develop/data-types/probabilistic/cuckoo-filter/

# References
- [1] https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
- [2] https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf
- [3] https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf
