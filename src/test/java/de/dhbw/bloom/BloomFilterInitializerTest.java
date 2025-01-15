package de.dhbw.bloom;

import io.rebloom.client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static de.dhbw.bloom.BloomFilterInitializer.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class BloomFilterInitializerTest {

    @Autowired
    private BloomFilterInitializer bloomFilterInitializer;

    @MockitoBean
    private Client bloomFilterClient;

    @BeforeEach
    void setUp() {
        reset(bloomFilterClient);
    }

    @Test
    public void testInitializeBloomFilters() {
        bloomFilterInitializer.initializeBloomFilters();
        verify(bloomFilterClient).createFilter(RSA_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
        verify(bloomFilterClient).createFilter(EC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
    }

    @Test
    void testInitializeBloomFiltersAlreadyExists() {
        doThrow(new RuntimeException("Bloom filter already exists")).when(bloomFilterClient).createFilter(anyString(), anyLong(), anyDouble());
        bloomFilterInitializer.initializeBloomFilters();
        verify(bloomFilterClient, times(1)).createFilter(RSA_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
        verify(bloomFilterClient, times(1)).createFilter(EC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
    }

}
