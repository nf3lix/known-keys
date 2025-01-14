package de.dhbw;

import io.rebloom.client.Client;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

@Component
@Profile("cuckoo_filter")
public class CuckooFilterInitializer {

    private static final Logger logger = LoggerFactory.getLogger(BloomFilterInitializer.class);

    public static final String RSA_CUCKOO_FILTER_NAME = "rsa_modulus_cuckoo_filter";
    public static final String EC_CUCKOO_FILTER_NAME = "ec_public_point_cuckoo_filter";

    private static final long EXPECTED_ELEMENTS = 1_000_000_000L;

    private final Client bloomFilterClient;

    public CuckooFilterInitializer(final Client bloomFilterClient) {
        this.bloomFilterClient = bloomFilterClient;
    }

    @PostConstruct
    public void initializeBloomFilters() {
        createCuckooFilter(RSA_CUCKOO_FILTER_NAME);
        createCuckooFilter(EC_CUCKOO_FILTER_NAME);
    }

    private void createCuckooFilter(final String filterName) {
        try {
            bloomFilterClient.cfCreate(filterName, EXPECTED_ELEMENTS);
        } catch (Exception e) {
            logger.info(e.getMessage());
        }
    }

}
