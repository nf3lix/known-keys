package de.dhbw.bloom;

import io.rebloom.client.Client;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Component for initializing Bloom filters in the application.
 * This class is active by default.
 */
@Component
@Profile({"bloom_filter", "default"})
public class BloomFilterInitializer {

    private static final Logger logger = LoggerFactory.getLogger(BloomFilterInitializer.class);

    public static final String RSA_BLOOM_FILTER_NAME = "rsa_modulus";
    public static final String EC_BLOOM_FILTER_NAME = "ec_public_point";

    private static final long EXPECTED_ELEMENTS = 1_000_000_000L;
    private static final double ERROR_RATE = 0.01;

    private final Client bloomFilterClient;

    public BloomFilterInitializer(final Client bloomFilterClient) {
        this.bloomFilterClient = bloomFilterClient;
    }

    @PostConstruct
    public void initializeBloomFilters() {
        createBloomFilter(RSA_BLOOM_FILTER_NAME);
        createBloomFilter(EC_BLOOM_FILTER_NAME);
    }

    private void createBloomFilter(final String filterName) {
        try {
            bloomFilterClient.createFilter(filterName, BloomFilterInitializer.EXPECTED_ELEMENTS, BloomFilterInitializer.ERROR_RATE);
        } catch (Exception e) {
            logger.info(e.getMessage());
        }
    }

}
