package de.dhbw;

import io.rebloom.client.Client;
import jakarta.annotation.PostConstruct;

public class BloomFilterInitializer {

    public static final String RSA_BLOOM_FILTER_NAME = "rsa_modulus";
    public static final String EC_BLOOM_FILTER_NAME = "ec_public_point";

    private static final long RSA_EXPECTED_ELEMENTS = 1_000_000_000L;
    private static final double RSA_ERROR_RATE = 0.01;

    private static final long EC_EXPECTED_ELEMENTS = 1_000_000_000L;
    private static final double EC_ERROR_RATE = 0.01;

    private final Client bloomFilterClient;

    public BloomFilterInitializer(final Client bloomFilterClient) {
        this.bloomFilterClient = bloomFilterClient;
    }

    @PostConstruct
    public void initializeBloomFilters() {
        createBloomFilter(RSA_BLOOM_FILTER_NAME, RSA_EXPECTED_ELEMENTS, RSA_ERROR_RATE);
        createBloomFilter(EC_BLOOM_FILTER_NAME, EC_EXPECTED_ELEMENTS, EC_ERROR_RATE);
    }

    private void createBloomFilter(final String filterName, final long expectedElements, final double errorRate) {
        try {
            bloomFilterClient.createFilter(filterName, expectedElements, errorRate);
        } catch (Exception e) {
            System.out.println("Bloom " + filterName + " already exists");
        }
    }

}
