package de.dhbw;

import io.rebloom.client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static de.dhbw.BloomFilterInitializer.*;
import static org.mockito.Mockito.*;

class BloomFilterInitializerTest {

    private Client bloomFilterClient;
    private BloomFilterInitializer bloomFilterInitializer;

    @BeforeEach
    void setUp() {
        bloomFilterClient = Mockito.mock(Client.class);
        bloomFilterInitializer = new BloomFilterInitializer(bloomFilterClient);
    }

    @Test
    public void testInitializeBloomFilters() {
        final Client clientMock = mock(Client.class);
        final BloomFilterInitializer initializer = new BloomFilterInitializer(clientMock);
        initializer.initializeBloomFilters();
        verify(clientMock).createFilter(RSA_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
        verify(clientMock).createFilter(EC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
    }

    @Test
    void testInitializeBloomFiltersAlreadyExists() {
        doThrow(new RuntimeException("Bloom filter already exists")).when(bloomFilterClient).createFilter(anyString(), anyLong(), anyDouble());
        bloomFilterInitializer.initializeBloomFilters();
        verify(bloomFilterClient, times(1)).createFilter(BloomFilterInitializer.RSA_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
        verify(bloomFilterClient, times(1)).createFilter(BloomFilterInitializer.EC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
    }

}
