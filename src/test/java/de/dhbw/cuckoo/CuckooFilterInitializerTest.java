package de.dhbw.cuckoo;

import io.rebloom.client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static de.dhbw.cuckoo.CuckooFilterInitializer.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("cuckoo_filter")
class CuckooFilterInitializerTest {

    @Autowired
    private CuckooFilterInitializer cuckooFilterInitializer;

    @MockitoBean
    private Client bloomFilterClient;

    @BeforeEach
    void setUp() {
        reset(bloomFilterClient);
    }

    @Test
    public void testInitializeBloomFilters() {
        cuckooFilterInitializer.initializeCuckooFilters();
        verify(bloomFilterClient).cfCreate(RSA_CUCKOO_FILTER_NAME, EXPECTED_ELEMENTS);
        verify(bloomFilterClient).cfCreate(EC_CUCKOO_FILTER_NAME, EXPECTED_ELEMENTS);
    }

    @Test
    void testInitializeBloomFiltersAlreadyExists() {
        doThrow(new RuntimeException("Cuckoo filter already exists")).when(bloomFilterClient).cfCreate(anyString(), anyLong());
        cuckooFilterInitializer.initializeCuckooFilters();
        verify(bloomFilterClient, times(1)).cfCreate(RSA_CUCKOO_FILTER_NAME, EXPECTED_ELEMENTS);
        verify(bloomFilterClient, times(1)).cfCreate(EC_CUCKOO_FILTER_NAME, EXPECTED_ELEMENTS);
    }

}
