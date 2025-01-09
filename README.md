# Known keys
According to https://certificate.transparency.dev/, 11 billion certificates have been registered in the Certificate Transparency initiative. 

## Run locally
Requires local installation of Docker.

### Run with docker compose
1. `docker-compose up -d`
2. Access [Swagger UI](http://localhost:8080/swagger-ui/)

### Run with docker and maven (optional)
1. `docker run --name redis-bloom -p 6380:6379 -d redislabs/rebloom:latest`
2. `mvn clean install`
3. `mvn spring-boot:run`
4. Access [Swagger UI](http://localhost:8080/swagger-ui/)

Run unit tests:
1. `mvn test`
2. generated coverage report: `target/site/jacoco/index.html`

Insert a large amount of keys:
1. `git clone git@github.com:badkeys/debianopenssl.git <directory>` 
2. `/bin/bash insert_keys.sh`

### Test with SSH
- ssh-keygen -t rsa -b 2048 -m PEM

### Storage Efficiency
To evaluate storage efficiency, we consider the memory consumption of Redis keys.
We compare the Redis Bloom Filter with a Redis Set. To run the application with a Set instead of a Bloom Filter, the Spring profile `set` must be set: `mvn spring-boot:run -Dspring-boot.run.profiles=set`.
The test is conducted using 4096-bit RSA keys.
Redis stores entries in a Set as strings. The memory consumption of a Set increases approximately linearly with the number of stored moduli (around 1300 bytes per entry).

| Number of Entries | Memory Consumption of the Set |
|-------------------|-------------------------------|
| 10                | 13352                         |
| 100               | 132056                        |
| 1000              | 1312312                       |

For a Bloom Filter, the number of bits to reserve is calculated as `capacity * -ln(error_rate) / ln(2)^2`.
In our case, the capacity is 1 billion, and the error rate is 0.01.
Observed memory consumption for the Bloom Filter in Redis remains constant at 1378469320 bytes.

With a linear increase in memory consumption for a Set, a Bloom filter is worthwhile in this scenario from around 1 million stored public keys.

# Further reading
- Redis docs for Bloom Filters: https://redis.io/docs/latest/develop/data-types/probabilistic/bloom-filter/#total-size-of-a-bloom-filter
