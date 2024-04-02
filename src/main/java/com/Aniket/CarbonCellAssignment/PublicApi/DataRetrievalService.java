package com.Aniket.CarbonCellAssignment.PublicApi;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;


@Service
public class DataRetrievalService {

//    private static final String API_URL = "https://api.publicapis.org/entries";
//
//    public ResponseEntity<?> getApiEntries(String category, Integer limit) {
//        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(API_URL);
//
//        if (category != null) {
//            builder.queryParam("category", category);
//        }
//
//        if (limit != null) {
//            builder.queryParam("limit", limit);
//        }
//        RestTemplate restTemplate = new RestTemplate();
//        ResponseEntity<String> response = restTemplate.getForEntity(builder.toUriString(), String.class);
//        String responseBody = response.getBody();
//        // Deserialize the response into an array of DataEntries
//        ObjectMapper objectMapper = new ObjectMapper();
//        try {
//            ApiResponse apiResponse = objectMapper.readValue(responseBody, ApiResponse.class);
//            List<DataEntries> dataEntriesList = apiResponse.getEntries();
//
//           // Filter dataEntriesList based on category
//            if (category != null) {
//                dataEntriesList.removeIf(entry -> !entry.getCategory().equals(category));
//            }
//
//            // Apply limit if provided
//            if (limit != null && limit > 0 && dataEntriesList.size() > limit) {
//                dataEntriesList = dataEntriesList.subList(0, limit);
//            }
//            return ResponseEntity.ok(dataEntriesList);
//        } catch (JsonProcessingException e) {
//            e.printStackTrace();
//            return null;
  private static final Logger logger = LoggerFactory.getLogger(DataRetrievalService.class);
    private static final String API_URL = "https://api.publicapis.org/entries";

    public ResponseEntity<?> getApiEntries(String category, Integer limit) {
        logger.info("Building URL with category: {}, limit: {}", category, limit);

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(API_URL);

        if (category != null) {
            builder.queryParam("category", category);
        }

        if (limit != null) {
            builder.queryParam("limit", limit);
        }

        String url = builder.toUriString();
        logger.info("Built URL: {}", url);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response;
        try {
            response = restTemplate.getForEntity(url, String.class);
        } catch (RestClientException e) {
            logger.error("Error fetching data from API: {}", e.getMessage());
            return null;
        }

        String responseBody = response.getBody();
        // Deserialize the response into an array of DataEntries
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            ApiResponse apiResponse = objectMapper.readValue(responseBody, ApiResponse.class);
            List<DataEntries> dataEntriesList = apiResponse.getEntries();

            // Filter dataEntriesList based on category
            if (category != null) {
                dataEntriesList.removeIf(entry -> !entry.getCategory().equals(category));
            }

            // Apply limit if provided
            if (limit != null && limit > 0 && dataEntriesList.size() > limit) {
                dataEntriesList = dataEntriesList.subList(0, limit);
            }
            logger.info("Successfully retrieved {} entries", dataEntriesList.size());
            return ResponseEntity.ok(dataEntriesList);
        } catch (JsonProcessingException e) {
            logger.error("Error deserializing response: {}", e.getMessage());
            return null;
        }
    }
}
